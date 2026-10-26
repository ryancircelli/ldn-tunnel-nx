//! The update path end to end: `UpdateDl` driven the way `relay_thread.rs` drives it, against a
//! fake relay that answers like `relay.ts` (`updateCheck` / `updateChunk`) and a fake SD-card
//! stager that behaves like `update_io::Stager` (resume a shorter `.new`, delete it when its hash
//! fails). The link can drop at any point; the shell then throws its `UpdateDl` away and checks
//! again on the next link.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, clippy::arithmetic_side_effects)]

use ldn_tunnel_core::conn::update_dl::{CHUNK_HEADER, Fail, Progress, State, UpdateDl};
use ldn_tunnel_core::update::{ManifestResult, PUBKEY_LEN, SIGNED_LEN, UNSIGNED_LEN};
use ldn_tunnel_core::wire::{
    UPDATE_CHUNK_SIZE, UPDATE_MANIFEST_MAGIC, UpdateChannel, UpdateCheckRequest, UpdateChunkHeader, UpdateChunkRequest,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use zerocopy::{FromBytes, IntoBytes};

fn key(seed: u8) -> (SigningKey, [u8; PUBKEY_LEN]) {
    let sk = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
    let pk = sk.verifying_key().to_sec1_point(false).as_bytes().try_into().unwrap();
    (sk, pk)
}

/// One published release: the two blobs and the signed manifest. The blob ids stand in for
/// SHA-256 (the module never hashes; the stager does).
#[derive(Clone)]
struct Release {
    build: u32,
    blobs: [Vec<u8>; 2],
    ids: [[u8; 32]; 2],
    signed: Vec<u8>,
}

fn release(build: u32, sizes: [usize; 2], signer: u8) -> Release {
    let blobs = [0, 1].map(|k| (0..sizes[k]).map(|i| (i as u32 * 7 + build * 3 + k as u32) as u8).collect::<Vec<u8>>());
    let ids = [0, 1].map(|k| [(build as u8) ^ (0xA0 + k as u8); 32]);
    let mut m = [0u8; UNSIGNED_LEN];
    m[0..4].copy_from_slice(&UPDATE_MANIFEST_MAGIC.to_le_bytes());
    m[4..8].copy_from_slice(&2u32.to_le_bytes());
    m[8..12].copy_from_slice(&build.to_le_bytes());
    m[12..16].copy_from_slice(&(sizes[0] as u32).to_le_bytes());
    m[16..48].copy_from_slice(&ids[0]);
    m[48..52].copy_from_slice(&(sizes[1] as u32).to_le_bytes());
    m[52..84].copy_from_slice(&ids[1]);
    m[84..92].copy_from_slice(format!("v{build:07}").as_bytes());
    let sig: Signature = key(signer).0.sign(&m);
    let mut signed = m.to_vec();
    signed.extend_from_slice(&sig.to_bytes());
    assert_eq!(signed.len(), SIGNED_LEN);
    Release { build, blobs, ids, signed }
}

/// relay.ts's update side.
#[derive(Default)]
struct Relay {
    stable: Option<Release>,
    test: Option<Release>,
    /// Flip a byte in the reply to the chunk at this (blob, offset), once.
    corrupt: Option<(usize, u32)>,
    checks: Vec<UpdateCheckRequest>,
    chunks: Vec<(usize, u32, u32)>,
}

impl Relay {
    fn check(&mut self, req: &UpdateCheckRequest) -> Vec<u8> {
        self.checks.push(*req);
        let r = match req.channel {
            1 => &self.stable,
            2 => &self.test,
            _ => panic!("relay.ts ignores channel {}", req.channel),
        };
        r.as_ref().map_or_else(Vec::new, |r| r.signed.clone())
    }

    fn chunk(&mut self, req: &UpdateChunkRequest) -> Vec<u8> {
        let (sha, offset, length) = (req.sha256, req.offset, req.length as usize);
        let found = [&self.stable, &self.test]
            .into_iter()
            .flatten()
            .flat_map(|r| (0..2).map(move |k| (r, k)))
            .find(|(r, k)| r.ids[*k] == sha);
        let total = found.map_or(0, |(r, k)| r.blobs[k].len());
        let mut data = match found {
            Some((r, k)) if (1..=UPDATE_CHUNK_SIZE).contains(&length) && (offset as usize) < total => {
                self.chunks.push((k, offset, length as u32));
                r.blobs[k][offset as usize..(offset as usize + length).min(total)].to_vec()
            }
            _ => vec![],
        };
        if let Some((k, o)) = self.corrupt
            && found.is_some_and(|(_, fk)| fk == k)
            && o == offset
        {
            data[0] ^= 0xFF;
            self.corrupt = None;
        }
        let mut out = UpdateChunkHeader { sha256: sha, offset, total_size: total as u32 }.as_bytes().to_vec();
        out.extend(data);
        out
    }
}

/// The console's persistent side: SD-card staging files and the update status.
struct Console {
    channel: UpdateChannel,
    running: u32,
    rejected: u32,
    staged_build: u32,
    probation: bool,
    /// `.new` staging files.
    files: [Vec<u8>; 2],
    /// What the stager's hash check compares against (the real one hashes the file).
    want: [Vec<u8>; 2],
    installed: Option<[Vec<u8>; 2]>,
    pubkey: [u8; PUBKEY_LEN],
}

/// How one check ended, and how far it got.
#[derive(Debug, PartialEq, Eq)]
enum End {
    Done(State),
    LinkLost,
}

impl Console {
    fn new(channel: UpdateChannel, running: u32) -> Self {
        Self {
            channel,
            running,
            rejected: 0,
            staged_build: 0,
            probation: false,
            files: [vec![], vec![]],
            want: [vec![], vec![]],
            installed: None,
            pubkey: key(1).1,
        }
    }

    /// One update check on one link, the way relay_thread.rs runs it; the link dies after
    /// `link_chunks` chunk replies (None = never).
    fn check(&mut self, relay: &mut Relay, link_chunks: Option<usize>) -> End {
        let mut dl = UpdateDl::new();
        let mut now = 5_000u64;
        let req = dl.start(now, self.channel, self.running, self.rejected, self.staged_build, self.probation, "", "v1");
        assert_eq!(req.reserved, [1, 0], "ldn-tunnel's module id");
        let manifest = relay.check(&req);
        dl.on_manifest(&manifest, &self.pubkey);
        let mut replies = 0;
        loop {
            match dl.state() {
                State::NeedBegin(b) => {
                    let k = b.which as usize;
                    let m = dl.manifest().unwrap();
                    let r = [&relay.stable, &relay.test].into_iter().flatten().find(|r| r.build == m.build).unwrap();
                    self.want[k] = r.blobs[k].clone();
                    // Stager::begin: resume a shorter file, else start over
                    if self.files[k].len() >= b.size as usize {
                        self.files[k].clear();
                    }
                    dl.begun(self.files[k].len() as u32);
                }
                State::Downloading => {
                    now += 50;
                    assert!(!dl.poll(now), "no timeouts here");
                    let Some(req) = dl.next_request(now) else { continue };
                    if link_chunks == Some(replies) {
                        return End::LinkLost; // relay_thread: "link lost at N%", dl = UpdateDl::new()
                    }
                    replies += 1;
                    let reply = relay.chunk(&req);
                    let k = (req.sha256 == dl.manifest().unwrap().overlay_sha256) as usize;
                    match dl.on_chunk(now, &reply) {
                        Progress::Append { len, .. } | Progress::Complete { len } => {
                            self.files[k].extend_from_slice(&reply[CHUNK_HEADER..CHUNK_HEADER + len]);
                        }
                        p => panic!("{p:?}"),
                    }
                }
                State::NeedVerify(b) => {
                    let k = b.which as usize;
                    let ok = self.files[k] == self.want[k];
                    if !ok {
                        self.files[k].clear(); // verify() deletes a bad .new
                    }
                    dl.verified(ok);
                }
                State::NeedInstall => {
                    self.installed = Some(core::mem::take(&mut self.files));
                    self.staged_build = dl.manifest().unwrap().build;
                    dl.installed(true);
                }
                s => return End::Done(s),
            }
        }
    }
}

const SIZES: [usize; 2] = [3 * UPDATE_CHUNK_SIZE + 1000, 2 * UPDATE_CHUNK_SIZE + 17];
const CHUNKS: usize = 4 + 3;

#[test]
fn whole_release_on_one_link() {
    let mut relay = Relay { test: Some(release(200, SIZES, 1)), ..Relay::default() };
    let mut c = Console::new(UpdateChannel::Test, 100);
    assert_eq!(c.check(&mut relay, None), End::Done(State::Staged));
    let rel = relay.test.clone().unwrap();
    assert_eq!(c.installed.as_ref().unwrap(), &rel.blobs);
    assert_eq!(c.staged_build, 200);
    assert_eq!(relay.chunks.len(), CHUNKS, "each chunk asked for once");
    let req = relay.checks[0];
    assert_eq!(({ req.running_build }, { req.channel }), (100, UpdateChannel::Test.raw()));
    // the next check, before the restart, does not download it again
    assert_eq!(c.check(&mut relay, None), End::Done(State::Refused(ManifestResult::AlreadyStaged)));
}

#[test]
fn link_drops_resume_where_the_card_left_off() {
    let mut relay = Relay { stable: Some(release(300, SIZES, 1)), ..Relay::default() };
    let mut c = Console::new(UpdateChannel::Stable, 100);
    // the link dies after 2 chunks, then after 0, then mid-overlay; every check resumes
    for (cut, exefs_have, overlay_have) in [(2, 2, 0), (0, 2, 0), (3, 4, 1)] {
        assert_eq!(c.check(&mut relay, Some(cut)), End::LinkLost);
        let have = |k: usize, n: usize| (n * UPDATE_CHUNK_SIZE).min(SIZES[k]);
        assert_eq!((c.files[0].len(), c.files[1].len()), (have(0, exefs_have), have(1, overlay_have)));
    }
    // a complete exefs .new is not resumed but fetched again (Stager::begin keeps only shorter files)
    assert_eq!(c.check(&mut relay, None), End::Done(State::Staged));
    assert_eq!(c.installed.as_ref().unwrap(), &relay.stable.as_ref().unwrap().blobs);
    // nothing fetched twice except the complete exefs file the stager restarted
    let exefs: Vec<u32> = relay.chunks.iter().filter(|c| c.0 == 0).map(|c| c.1).collect();
    let overlay: Vec<u32> = relay.chunks.iter().filter(|c| c.0 == 1).map(|c| c.1).collect();
    assert_eq!(exefs, [0, 4096, 8192, 12288, 0, 4096, 8192, 12288]);
    assert_eq!(overlay, [0, 4096, 8192]);
}

#[test]
fn a_corrupted_chunk_fails_the_hash_and_the_next_check_starts_clean() {
    let mut relay = Relay { test: Some(release(200, SIZES, 1)), corrupt: Some((1, 4096)), ..Relay::default() };
    let mut c = Console::new(UpdateChannel::Test, 100);
    assert_eq!(c.check(&mut relay, None), End::Done(State::Failed(Fail::HashMismatch)));
    assert!(c.installed.is_none());
    assert!(c.files[1].is_empty(), "the bad file is gone");
    assert_eq!(c.files[0].len(), SIZES[0], "the verified exefs .new stays");
    assert_eq!(c.check(&mut relay, None), End::Done(State::Staged));
    assert_eq!(c.installed.as_ref().unwrap(), &relay.test.as_ref().unwrap().blobs);
}

#[test]
fn manifests_the_console_refuses() {
    use ManifestResult as R;
    let cases: [(Release, u32, State); 5] = [
        (release(200, SIZES, 2), 100, State::Refused(R::BadSignature)), // someone else's key
        (release(100, SIZES, 1), 100, State::Refused(R::NotNewer)),
        (release(99, SIZES, 1), 100, State::Refused(R::NotNewer)),
        (release(200, SIZES, 1), 0, State::Refused(R::NotNewer)), // a developer build never updates
        (release(200, [0, 10], 1), 100, State::Refused(R::BadSizes)),
    ];
    for (rel, running, want) in cases {
        let mut relay = Relay { stable: Some(rel), ..Relay::default() };
        let mut c = Console::new(UpdateChannel::Stable, running);
        assert_eq!(c.check(&mut relay, None), End::Done(want));
        assert!(relay.chunks.is_empty(), "{want:?}: nothing downloaded");
    }
    // a relay with nothing published on the channel
    let mut relay = Relay { test: Some(release(200, SIZES, 1)), ..Relay::default() };
    assert_eq!(Console::new(UpdateChannel::Stable, 100).check(&mut relay, None), End::Done(State::NoRelease));
    // a manifest cut short or padded on the wire
    let mut relay = Relay { stable: Some(release(200, SIZES, 1)), ..Relay::default() };
    for n in [SIGNED_LEN - 1, SIGNED_LEN + 1] {
        relay.stable.as_mut().unwrap().signed.resize(n, 0);
        let got = Console::new(UpdateChannel::Stable, 100).check(&mut relay, None);
        assert_eq!(got, End::Done(State::Refused(R::BadSize)));
    }
}

#[test]
fn channels_probation_and_rollback() {
    let mut relay = Relay {
        stable: Some(release(200, SIZES, 1)),
        test: Some(release(300, SIZES, 1)),
        ..Relay::default()
    };
    // each channel gets its own build
    let mut s = Console::new(UpdateChannel::Stable, 100);
    assert_eq!(s.check(&mut relay, None), End::Done(State::Staged));
    assert_eq!(s.staged_build, 200);
    let mut t = Console::new(UpdateChannel::Test, 100);
    assert_eq!(t.check(&mut relay, None), End::Done(State::Staged));
    assert_eq!(t.staged_build, 300);
    let sent: Vec<u8> = relay.checks.iter().map(|c| c.channel).collect();
    assert_eq!(sent, [1, 2]);

    // restart into 300: on probation, a newer test build waits for the probation to end
    t = Console { running: 300, staged_build: 0, probation: true, ..Console::new(UpdateChannel::Test, 300) };
    relay.test = Some(release(301, SIZES, 1));
    assert_eq!(t.check(&mut relay, None), End::Done(State::WaitRestart));
    assert_eq!(relay.chunks.len(), 2 * CHUNKS, "nothing downloaded on probation");

    // 300 crashed its probation boots: boot_check restored 200 and wrote rejected=300
    t = Console { running: 200, rejected: 300, ..Console::new(UpdateChannel::Test, 200) };
    relay.test = Some(release(300, SIZES, 1));
    assert_eq!(t.check(&mut relay, None), End::Done(State::Refused(ManifestResult::Rejected)));
    assert_eq!({ relay.checks.last().unwrap().rejected_build }, 300, "the relay sees the rollback");
    // the fixed build is taken
    relay.test = Some(release(301, SIZES, 1));
    assert_eq!(t.check(&mut relay, None), End::Done(State::Staged));
    assert_eq!(t.staged_build, 301);

    // switching a test console back to stable never downgrades it
    let mut back = Console::new(UpdateChannel::Stable, 301);
    assert_eq!(back.check(&mut relay, None), End::Done(State::Refused(ManifestResult::NotNewer)));

    // the request bytes the relay reads
    let r = UpdateCheckRequest::read_from_bytes(relay.checks.last().unwrap().as_bytes()).unwrap();
    assert_eq!(({ r.running_build }, { r.channel }, { r.label_len }), (301, 1, 0));
}

/// Link drops at random points: always ends staged, with the right bytes, in a bounded number
/// of checks.
#[test]
fn flaky_link_always_converges() {
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..50 {
        let mut relay = Relay { test: Some(release(200, SIZES, 1)), ..Relay::default() };
        let mut c = Console::new(UpdateChannel::Test, 100);
        let mut checks = 0;
        loop {
            checks += 1;
            assert!(checks < 50);
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let cut = (x % 4 != 0).then_some((x >> 8) as usize % 6);
            if c.check(&mut relay, cut) == End::Done(State::Staged) {
                break;
            }
        }
        assert_eq!(c.installed.as_ref().unwrap(), &relay.test.as_ref().unwrap().blobs);
    }
}
