//! Console side of the update channel (port of `update/update_worker.cpp`
//! `check_and_download`/`download`): UpdateCheck (0xC1) -> UpdateManifest (0xC2) -> per blob
//! UpdateChunk (0xC3) / UpdateChunkData (0xC4) of 4096 bytes, exefs first, then the overlay.
//!
//! Pure bookkeeping. The shell sends the requests through [`Conn`](super::Conn), feeds the
//! replies in, and does the file work (`update_io` Stager: `begin` / `append` / `verify`,
//! then the swap) when this machine says so:
//!
//! ```text
//! let req = dl.start(now, ..);                 send UpdateCheck(req.as_bytes())
//! on UpdateManifest bytes: dl.on_manifest(bytes, &PUBKEY)
//! loop on dl.state():
//!   NeedBegin(blob)  -> off = stager.begin(blob.which, &blob.sha256, blob.size)?; dl.begun(off)
//!   Downloading      -> if let Some(r) = dl.next_request(now) { send UpdateChunk(r.as_bytes()) }
//!                       on UpdateChunkData payload: match dl.on_chunk(now, payload) {
//!                          Append{..} => stager.append(&payload[CHUNK_HEADER..])
//!                          Complete{..} => stager.append(..) then the state is NeedVerify
//!                          Failed(_) | Ignored => ..}
//!                       every tick: dl.poll(now)  (reply timeout)
//!   NeedVerify(blob) -> dl.verified(stager.verify())
//!   NeedInstall      -> dl.installed(install_staged(dl.manifest()))
//!   terminal         -> stop
//! ```
//! Failures of the shell's own file work are reported with [`UpdateDl::fail_io`].
use zerocopy::{FromBytes, FromZeros};

use crate::update::{ManifestResult, PUBKEY_LEN, check_manifest};
use crate::wire::{
    UPDATE_CHUNK_SIZE, UpdateChannel, UpdateChunkHeader, UpdateChunkRequest, UpdateCheckRequest, UpdateManifest,
};

/// How long the relay may take to answer (manifest or chunk).
pub const REPLY_TIMEOUT_MS: u64 = 10_000;
/// Pause between chunk requests (~80 KB/s, easy on the relay and the SD card).
pub const CHUNK_PAUSE_MS: u64 = 50;
/// Bytes before the data in an UpdateChunkData payload.
pub const CHUNK_HEADER: usize = core::mem::size_of::<UpdateChunkHeader>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Exefs,
    Overlay,
}

/// One file of the release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blob {
    pub which: Which,
    pub sha256: [u8; 32],
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The relay did not answer in time.
    Timeout,
    /// The relay has no data for the blob (empty or oversized chunk, or a different total size).
    NoData,
    /// The shell could not open, write or flush the staging file.
    Io,
    /// The blob's SHA-256 did not match the manifest.
    HashMismatch,
    /// The swap into place failed.
    InstallFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    /// UpdateCheck sent.
    AwaitManifest,
    /// The shell opens the staging file for this blob and reports the resume offset.
    NeedBegin(Blob),
    Downloading,
    /// The whole blob is staged: the shell checks its hash.
    NeedVerify(Blob),
    /// Both blobs verified: the shell installs them.
    NeedInstall,
    /// Done: restart to finish.
    Staged,
    /// The channel has no release (empty manifest).
    NoRelease,
    /// A manifest the console does not take (bad signature, not newer, rejected, ...).
    Refused(ManifestResult),
    /// A newer build exists, but one is already staged or this boot is on probation.
    WaitRestart,
    Failed(Fail),
}

impl State {
    /// No further steps: only a new `start` leaves it.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Staged | Self::NoRelease | Self::Refused(_) | Self::WaitRestart | Self::Failed(_)
        )
    }
}

/// Result of [`UpdateDl::on_chunk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Not the awaited chunk (other blob or offset, short packet): keep waiting.
    Ignored,
    /// Append `payload[CHUNK_HEADER..]` (`len` bytes) to the staging file. `percent` is
    /// 1..=100 for the whole release (the C++ progress value).
    Append { len: usize, percent: u8 },
    /// Append, then the blob is complete: state is `NeedVerify`.
    Complete { len: usize },
    Failed(Fail),
}

#[derive(Clone, Copy, Debug)]
pub struct UpdateDl {
    state: State,
    running_build: u32,
    rejected_build: u32,
    staged_build: u32,
    on_probation: bool,
    manifest: UpdateManifest,
    offset: u32,
    /// Bytes of the earlier blob(s) already staged, for the progress value.
    done_before: u64,
    deadline_ms: u64,
    /// Chunk request outstanding: (offset, length).
    awaiting: Option<(u32, u32)>,
    next_request_ms: u64,
}

/// Copy at most `dst.len()` bytes of `src`, cut on a char boundary; returns the count.
fn copy_prefix(dst: &mut [u8], src: &str) -> usize {
    let mut n = src.len().min(dst.len());
    while !src.is_char_boundary(n) {
        n = n.saturating_sub(1);
    }
    if let (Some(d), Some(s)) = (dst.get_mut(..n), src.as_bytes().get(..n)) {
        d.copy_from_slice(s);
    }
    n
}

impl UpdateDl {
    pub fn new() -> Self {
        Self {
            state: State::Idle,
            running_build: 0,
            rejected_build: 0,
            staged_build: 0,
            on_probation: false,
            manifest: UpdateManifest::new_zeroed(),
            offset: 0,
            done_before: 0,
            deadline_ms: 0,
            awaiting: None,
            next_request_ms: 0,
        }
    }

    pub const fn state(&self) -> State {
        self.state
    }

    /// The accepted manifest (valid from `NeedBegin` on), for the install step.
    pub fn manifest(&self) -> Option<&UpdateManifest> {
        matches!(
            self.state,
            State::NeedBegin(_) | State::Downloading | State::NeedVerify(_) | State::NeedInstall | State::Staged
        )
        .then_some(&self.manifest)
    }

    /// Start a check. Returns the UpdateCheck payload (`.as_bytes()`); `label` is cut to 32
    /// bytes, `version` (git describe of the running build) to 32, `reserved[0]` is
    /// `ident::UPDATE_MODULE_ID`. `staged_build` is the build installed and waiting for a
    /// restart (0 = none).
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        &mut self,
        now_ms: u64,
        channel: UpdateChannel,
        running_build: u32,
        rejected_build: u32,
        staged_build: u32,
        on_probation: bool,
        label: &str,
        version: &str,
    ) -> UpdateCheckRequest {
        *self = Self::new();
        self.running_build = running_build;
        self.rejected_build = rejected_build;
        self.staged_build = staged_build;
        self.on_probation = on_probation;
        self.state = State::AwaitManifest;
        self.deadline_ms = now_ms.saturating_add(REPLY_TIMEOUT_MS);

        let mut req = UpdateCheckRequest::new_zeroed();
        req.running_build = running_build;
        req.rejected_build = rejected_build;
        req.channel = channel.raw();
        req.label_len = copy_prefix(&mut req.label, label) as u8;
        req.reserved = [crate::ident::UPDATE_MODULE_ID, 0];
        copy_prefix(&mut req.version, version);
        req
    }

    /// The UpdateManifest (0xC2) payload: empty = no release on the channel.
    pub fn on_manifest(&mut self, bytes: &[u8], pubkey: &[u8; PUBKEY_LEN]) -> State {
        if self.state != State::AwaitManifest {
            return self.state;
        }
        self.state = if bytes.is_empty() {
            State::NoRelease
        } else {
            match check_manifest(bytes, pubkey, self.running_build, self.rejected_build, self.staged_build) {
                Err(e) => State::Refused(e),
                Ok(_) if self.staged_build != 0 || self.on_probation => State::WaitRestart,
                Ok(m) => {
                    self.manifest = m;
                    State::NeedBegin(self.blob(Which::Exefs))
                }
            }
        };
        self.state
    }

    fn blob(&self, which: Which) -> Blob {
        let m = &self.manifest;
        match which {
            Which::Exefs => Blob { which, sha256: m.exefs_sha256, size: m.exefs_size },
            Which::Overlay => Blob { which, sha256: m.overlay_sha256, size: m.overlay_size },
        }
    }

    fn total(&self) -> u64 {
        u64::from(self.manifest.exefs_size).saturating_add(u64::from(self.manifest.overlay_size))
    }

    /// The staging file is open and already holds `offset` valid bytes (the resume point; 0
    /// for a fresh start). A complete file goes straight to `NeedVerify`.
    pub fn begun(&mut self, offset: u32) {
        let State::NeedBegin(b) = self.state else { return };
        self.offset = if offset > b.size { 0 } else { offset };
        self.awaiting = None;
        self.state = if self.offset == b.size { State::NeedVerify(b) } else { State::Downloading };
    }

    fn current(&self) -> Option<Blob> {
        match self.state {
            State::NeedBegin(b) | State::NeedVerify(b) => Some(b),
            State::Downloading => {
                let which = if self.done_before == 0 { Which::Exefs } else { Which::Overlay };
                Some(self.blob(which))
            }
            _ => None,
        }
    }

    /// Percent of the whole release staged, 1..=100 (0 before the download starts).
    pub fn percent(&self) -> u8 {
        if self.current().is_none() || self.total() == 0 {
            return 0;
        }
        let done = self.done_before.saturating_add(u64::from(self.offset));
        let pct = done.saturating_mul(100).checked_div(self.total()).unwrap_or(0);
        pct.saturating_add(1).min(100) as u8
    }

    /// The next chunk to ask for, once per reply and no sooner than [`CHUNK_PAUSE_MS`] after
    /// the previous one. Send it as `PacketId::UpdateChunk`.
    pub fn next_request(&mut self, now_ms: u64) -> Option<UpdateChunkRequest> {
        if self.state != State::Downloading || self.awaiting.is_some() || now_ms < self.next_request_ms {
            return None;
        }
        let b = self.current()?;
        let length = (b.size.saturating_sub(self.offset)).min(UPDATE_CHUNK_SIZE as u32);
        self.awaiting = Some((self.offset, length));
        self.deadline_ms = now_ms.saturating_add(REPLY_TIMEOUT_MS);
        Some(UpdateChunkRequest { sha256: b.sha256, offset: self.offset, length })
    }

    /// An UpdateChunkData (0xC4) payload: [`UpdateChunkHeader`] then the data.
    pub fn on_chunk(&mut self, now_ms: u64, payload: &[u8]) -> Progress {
        let (Some((off, want)), Some(b)) = (self.awaiting, self.current()) else { return Progress::Ignored };
        if self.state != State::Downloading {
            return Progress::Ignored;
        }
        let Ok((hdr, data)) = UpdateChunkHeader::read_from_prefix(payload) else { return Progress::Ignored };
        let (h_off, h_total, h_sha) = (hdr.offset, hdr.total_size, hdr.sha256);
        if h_off != off || h_sha != b.sha256 {
            return Progress::Ignored; // an old or foreign reply: keep waiting
        }
        let len = data.len();
        if len == 0 || len > want as usize || h_total != b.size {
            return self.fail(Fail::NoData);
        }
        self.awaiting = None;
        self.next_request_ms = now_ms.saturating_add(CHUNK_PAUSE_MS);
        self.offset = self.offset.saturating_add(len as u32);
        if self.offset >= b.size {
            self.state = State::NeedVerify(b);
            Progress::Complete { len }
        } else {
            Progress::Append { len, percent: self.percent() }
        }
    }

    fn fail(&mut self, f: Fail) -> Progress {
        self.state = State::Failed(f);
        self.awaiting = None;
        Progress::Failed(f)
    }

    /// Reply timeout. Call on every tick; `true` when it just failed.
    pub fn poll(&mut self, now_ms: u64) -> bool {
        let waiting = self.state == State::AwaitManifest || (self.state == State::Downloading && self.awaiting.is_some());
        if waiting && now_ms >= self.deadline_ms {
            self.fail(Fail::Timeout);
            return true;
        }
        false
    }

    /// The staging file could not be opened or written.
    pub fn fail_io(&mut self) {
        if !self.state.is_terminal() && self.state != State::Idle {
            self.fail(Fail::Io);
        }
    }

    /// Result of the hash check after `NeedVerify`.
    pub fn verified(&mut self, ok: bool) {
        let State::NeedVerify(b) = self.state else { return };
        if !ok {
            self.fail(Fail::HashMismatch);
        } else if b.which == Which::Exefs {
            self.done_before = u64::from(b.size);
            self.offset = 0;
            self.state = State::NeedBegin(self.blob(Which::Overlay));
        } else {
            self.state = State::NeedInstall;
        }
    }

    /// Result of the install after `NeedInstall`.
    pub fn installed(&mut self, ok: bool) {
        if self.state == State::NeedInstall {
            self.state = if ok { State::Staged } else { State::Failed(Fail::InstallFailed) };
        }
    }
}

impl Default for UpdateDl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use zerocopy::IntoBytes;
    use crate::update::{SIGNED_LEN, UNSIGNED_LEN};
    use crate::wire::UPDATE_MANIFEST_MAGIC;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use std::vec::Vec;

    fn key() -> (SigningKey, [u8; PUBKEY_LEN]) {
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let pk: [u8; PUBKEY_LEN] = sk.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
        (sk, pk)
    }

    pub(crate) struct Release {
        pub exefs: Vec<u8>,
        pub overlay: Vec<u8>,
        pub signed: [u8; SIGNED_LEN],
        pub exefs_id: [u8; 32],
        pub overlay_id: [u8; 32],
    }

    /// Blobs of the given sizes and a manifest for `build` signed with the test key. The ids
    /// stand in for SHA-256 (this module never hashes; the shell's Stager does).
    pub(crate) fn release(build: u32, exefs: usize, overlay: usize) -> (Release, [u8; PUBKEY_LEN]) {
        let (sk, pk) = key();
        let blob = |n: usize, seed: u8| (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect::<Vec<u8>>();
        let (e, o) = (blob(exefs, 1), blob(overlay, 2));
        let (eid, oid) = ([0xAA; 32], [0xBB; 32]);
        let mut m = [0u8; UNSIGNED_LEN];
        m[0..4].copy_from_slice(&UPDATE_MANIFEST_MAGIC.to_le_bytes());
        m[4..8].copy_from_slice(&2u32.to_le_bytes());
        m[8..12].copy_from_slice(&build.to_le_bytes());
        m[12..16].copy_from_slice(&(exefs as u32).to_le_bytes());
        m[16..48].copy_from_slice(&eid);
        m[48..52].copy_from_slice(&(overlay as u32).to_le_bytes());
        m[52..84].copy_from_slice(&oid);
        m[84..90].copy_from_slice(b"v9.9.9");
        let sig: Signature = sk.sign(&m);
        let mut signed = [0u8; SIGNED_LEN];
        signed[..UNSIGNED_LEN].copy_from_slice(&m);
        signed[UNSIGNED_LEN..].copy_from_slice(&sig.to_bytes());
        (Release { exefs: e, overlay: o, signed, exefs_id: eid, overlay_id: oid }, pk)
    }

    impl Release {
        /// What the relay answers to an UpdateChunk request (lobby.ts `updateChunk`).
        pub(crate) fn chunk_reply(&self, req: &UpdateChunkRequest) -> Vec<u8> {
            let (sha, offset, length) = (req.sha256, req.offset as usize, req.length as usize);
            let blob = if sha == self.exefs_id {
                Some(&self.exefs)
            } else if sha == self.overlay_id {
                Some(&self.overlay)
            } else {
                None
            };
            let total = blob.map_or(0, Vec::len);
            let data: &[u8] = match blob {
                Some(b) if (1..=UPDATE_CHUNK_SIZE).contains(&length) && offset < total => {
                    &b[offset..(offset + length).min(total)]
                }
                _ => &[],
            };
            let h = UpdateChunkHeader { sha256: sha, offset: req.offset, total_size: total as u32 };
            let mut out = h.as_bytes().to_vec();
            out.extend_from_slice(data);
            out
        }
    }

    /// Run the shell's side against the fake relay; returns the staged bytes per blob.
    fn run(dl: &mut UpdateDl, rel: &Release, pk: &[u8; PUBKEY_LEN], resume: Option<(Which, &[u8])>) -> [Vec<u8>; 2] {
        let mut staged: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        let mut now = 1000u64;
        assert_eq!(dl.on_manifest(&rel.signed, pk), dl.state());
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 10_000);
            match dl.state() {
                State::NeedBegin(b) => {
                    let i = (b.which == Which::Overlay) as usize;
                    if let Some((w, bytes)) = resume
                        && w == b.which
                    {
                        staged[i] = bytes.to_vec();
                    }
                    dl.begun(staged[i].len() as u32);
                }
                State::Downloading => {
                    now += 1;
                    dl.poll(now);
                    if let Some(req) = dl.next_request(now) {
                        let reply = rel.chunk_reply(&req);
                        let i = (dl.state() == State::Downloading && dl.current().unwrap().which == Which::Overlay) as usize;
                        match dl.on_chunk(now, &reply) {
                            Progress::Append { len, percent } => {
                                assert!((1..=100).contains(&percent));
                                staged[i].extend_from_slice(&reply[CHUNK_HEADER..CHUNK_HEADER + len]);
                            }
                            Progress::Complete { len } => staged[i].extend_from_slice(&reply[CHUNK_HEADER..CHUNK_HEADER + len]),
                            p => panic!("{p:?}"),
                        }
                    }
                }
                State::NeedVerify(b) => {
                    let i = (b.which == Which::Overlay) as usize;
                    dl.verified(staged[i].len() as u32 == b.size);
                }
                State::NeedInstall => dl.installed(true),
                _ => return staged,
            }
        }
    }

    fn start(dl: &mut UpdateDl, running: u32, rejected: u32, staged: u32, probation: bool) -> UpdateCheckRequest {
        dl.start(0, UpdateChannel::Test, running, rejected, staged, probation, "Switch 1234", "v1.0.0-3-gabc")
    }

    #[test]
    fn check_request_bytes() {
        let mut dl = UpdateDl::new();
        let r = start(&mut dl, 100, 90, 0, false);
        assert_eq!((r.running_build, r.rejected_build, r.channel, r.label_len), (100, 90, 2, 11));
        assert_eq!(r.reserved, [crate::ident::UPDATE_MODULE_ID, 0]);
        assert_eq!(&r.label[..11], b"Switch 1234");
        assert_eq!(&r.version[..13], b"v1.0.0-3-gabc");
        assert!(r.version[13..].iter().all(|&b| b == 0));
        assert_eq!(r.as_bytes().len(), 76);
        assert_eq!(dl.state(), State::AwaitManifest);
        // long label / multibyte: cut at 32 on a char boundary, label_len matches
        let long = "é".repeat(30);
        let r = dl.start(0, UpdateChannel::Stable, 1, 0, 0, false, &long, &long);
        assert_eq!(r.label_len, 32);
        assert!(core::str::from_utf8(&r.label[..32]).is_ok());
    }

    #[test]
    fn full_download_two_blobs() {
        let (rel, pk) = release(200, 10_000, 4096);
        let mut dl = UpdateDl::new();
        start(&mut dl, 100, 0, 0, false);
        let staged = run(&mut dl, &rel, &pk, None);
        assert_eq!(dl.state(), State::Staged);
        assert_eq!(staged[0], rel.exefs);
        assert_eq!(staged[1], rel.overlay);
        assert_eq!({ dl.manifest().unwrap().build }, 200);
    }

    #[test]
    fn resume_from_offset_and_complete_file() {
        let (rel, pk) = release(200, 10_000, 5000);
        let mut dl = UpdateDl::new();
        start(&mut dl, 100, 0, 0, false);
        let part = rel.exefs[..4096 * 2].to_vec();
        let mut seen = Vec::new();
        // watch the first request's offset
        dl.on_manifest(&rel.signed, &pk);
        let State::NeedBegin(b) = dl.state() else { panic!() };
        assert_eq!((b.which, b.size, b.sha256), (Which::Exefs, 10_000, rel.exefs_id));
        dl.begun(part.len() as u32);
        let r = dl.next_request(5).unwrap();
        seen.push((r.offset, r.length));
        assert_eq!(seen, [(8192, 1808)]);
        // a complete staging file skips straight to verification
        let mut dl2 = UpdateDl::new();
        start(&mut dl2, 100, 0, 0, false);
        dl2.on_manifest(&rel.signed, &pk);
        dl2.begun(10_000);
        assert!(matches!(dl2.state(), State::NeedVerify(b) if b.which == Which::Exefs));
        // and the full helper resumes mid-blob with identical results
        let mut dl3 = UpdateDl::new();
        start(&mut dl3, 100, 0, 0, false);
        let staged = run(&mut dl3, &rel, &pk, Some((Which::Exefs, &part)));
        assert_eq!((staged[0].clone(), staged[1].clone()), (rel.exefs.clone(), rel.overlay.clone()));
        // bogus offset beyond the blob restarts at zero
        let mut dl4 = UpdateDl::new();
        start(&mut dl4, 100, 0, 0, false);
        dl4.on_manifest(&rel.signed, &pk);
        dl4.begun(20_000);
        assert_eq!({ dl4.next_request(0).unwrap().offset }, 0);
    }

    #[test]
    fn manifest_outcomes() {
        let (rel, pk) = release(200, 10, 10);
        let mut dl = UpdateDl::new();
        start(&mut dl, 100, 0, 0, false);
        assert_eq!(dl.on_manifest(&[], &pk), State::NoRelease);
        start(&mut dl, 200, 0, 0, false);
        assert_eq!(dl.on_manifest(&rel.signed, &pk), State::Refused(ManifestResult::NotNewer));
        start(&mut dl, 100, 200, 0, false);
        assert_eq!(dl.on_manifest(&rel.signed, &pk), State::Refused(ManifestResult::Rejected));
        start(&mut dl, 100, 0, 200, false);
        assert_eq!(dl.on_manifest(&rel.signed, &pk), State::Refused(ManifestResult::AlreadyStaged));
        start(&mut dl, 100, 0, 150, false);
        assert_eq!(dl.on_manifest(&rel.signed, &pk), State::WaitRestart);
        start(&mut dl, 100, 0, 0, true);
        assert_eq!(dl.on_manifest(&rel.signed, &pk), State::WaitRestart);
        let mut bad = rel.signed;
        bad[100] ^= 1;
        start(&mut dl, 100, 0, 0, false);
        assert_eq!(dl.on_manifest(&bad, &pk), State::Refused(ManifestResult::BadSignature));
        assert!(dl.state().is_terminal());
        assert_eq!(dl.manifest(), None);
        // a second manifest in a terminal state is ignored
        assert_eq!(dl.on_manifest(&rel.signed, &pk), State::Refused(ManifestResult::BadSignature));
    }

    #[test]
    fn chunk_validation_and_failures() {
        let (rel, pk) = release(200, 9000, 100);
        let mut dl = UpdateDl::new();
        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(0);
        // nothing requested yet
        assert_eq!(dl.on_chunk(0, &rel.chunk_reply(&UpdateChunkRequest { sha256: rel.exefs_id, offset: 0, length: 4096 })), Progress::Ignored);
        let req = dl.next_request(0).unwrap();
        assert_eq!((req.offset, req.length), (0, 4096));
        assert_eq!(dl.next_request(1), None, "one outstanding request");
        // wrong offset / wrong sha / short packet are ignored
        let mut wrong = rel.chunk_reply(&UpdateChunkRequest { sha256: rel.exefs_id, offset: 4096, length: 4096 });
        assert_eq!(dl.on_chunk(1, &wrong), Progress::Ignored);
        wrong = rel.chunk_reply(&UpdateChunkRequest { sha256: rel.overlay_id, offset: 0, length: 100 });
        assert_eq!(dl.on_chunk(1, &wrong), Progress::Ignored);
        assert_eq!(dl.on_chunk(1, &[1, 2, 3]), Progress::Ignored);
        // header only = the relay has no data
        let none = rel.chunk_reply(&UpdateChunkRequest { sha256: [9; 32], offset: 0, length: 4096 });
        assert_eq!(dl.on_chunk(1, &none), Progress::Ignored, "different sha");
        let mut empty = rel.chunk_reply(&req)[..CHUNK_HEADER].to_vec();
        assert_eq!(dl.on_chunk(1, &empty), Progress::Failed(Fail::NoData));
        assert_eq!(dl.state(), State::Failed(Fail::NoData));

        // total_size mismatch
        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(0);
        let req = dl.next_request(0).unwrap();
        empty = rel.chunk_reply(&req);
        empty[36..40].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(dl.on_chunk(1, &empty), Progress::Failed(Fail::NoData));
        // oversize data (more than asked)
        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(0);
        let req = dl.next_request(0).unwrap();
        let mut big = rel.chunk_reply(&req);
        big.push(0);
        assert_eq!(dl.on_chunk(1, &big), Progress::Failed(Fail::NoData));
    }

    #[test]
    fn pacing_timeout_hash_and_io() {
        let (rel, pk) = release(200, 9000, 100);
        let mut dl = UpdateDl::new();
        start(&mut dl, 100, 0, 0, false);
        // manifest timeout
        assert!(!dl.poll(REPLY_TIMEOUT_MS - 1));
        assert!(dl.poll(REPLY_TIMEOUT_MS));
        assert_eq!(dl.state(), State::Failed(Fail::Timeout));

        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(0);
        let req = dl.next_request(100).unwrap();
        assert!(!dl.poll(100 + REPLY_TIMEOUT_MS - 1));
        let reply = rel.chunk_reply(&req);
        assert!(matches!(dl.on_chunk(200, &reply), Progress::Append { len: 4096, .. }));
        // 50 ms pause
        assert_eq!(dl.next_request(249), None);
        assert!(dl.next_request(250).is_some());
        assert!(dl.poll(250 + REPLY_TIMEOUT_MS));

        // hash mismatch, io, install failure
        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(9000);
        dl.verified(false);
        assert_eq!(dl.state(), State::Failed(Fail::HashMismatch));
        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.fail_io();
        assert_eq!(dl.state(), State::Failed(Fail::Io));
        start(&mut dl, 100, 0, 0, false);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(9000);
        dl.verified(true);
        dl.begun(100);
        dl.verified(true);
        assert_eq!(dl.state(), State::NeedInstall);
        dl.installed(false);
        assert_eq!(dl.state(), State::Failed(Fail::InstallFailed));
    }

    #[test]
    fn percent_runs_one_to_hundred() {
        let (rel, pk) = release(200, 8192, 4096);
        let mut dl = UpdateDl::new();
        start(&mut dl, 100, 0, 0, false);
        assert_eq!(dl.percent(), 0);
        dl.on_manifest(&rel.signed, &pk);
        dl.begun(0);
        assert_eq!(dl.percent(), 1);
        let mut last = 0;
        let mut now = 0;
        while let State::Downloading | State::NeedBegin(_) | State::NeedVerify(_) = dl.state() {
            now += 100;
            match dl.state() {
                State::NeedBegin(_) => dl.begun(0),
                State::NeedVerify(_) => dl.verified(true),
                _ => {
                    let req = dl.next_request(now).unwrap();
                    if let Progress::Append { percent, .. } = dl.on_chunk(now, &rel.chunk_reply(&req)) {
                        assert!(percent >= last);
                        last = percent;
                    }
                }
            }
        }
        assert_eq!(dl.state(), State::NeedInstall);
        assert!(last > 1 && last < 100);
    }
}
