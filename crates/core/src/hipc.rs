//! Peeking at a CMIF reply as bytes: the bsd:u MitM reads the fd out of a
//! forwarded Socket reply (see switchbrew "IPC_Marshalling").

/// The result and the first 16 bytes of output raw data of a CMIF reply
/// (`msg` starts at the HIPC header), or None if it isn't one. Domain replies
/// (the SDK turns its bsd:u session into a domain) carry a 16-byte header
/// before the CMIF one; its first word, the out object count, is never "SFCO".
pub fn reply_raw(msg: &[u8]) -> Option<(u32, [u8; 16])> {
    let word = |i: usize| -> Option<u32> {
        let at = i.saturating_mul(4);
        Some(u32::from_le_bytes(msg.get(at..at.saturating_add(4))?.try_into().ok()?))
    };
    let (h0, h1) = (word(0)?, word(1)?);
    let mut words = 2usize;
    if h1 >> 31 != 0 {
        let special = word(2)?;
        let pid = if special & 1 != 0 { 2 } else { 0 };
        let handles = ((special >> 1) & 0xF).saturating_add((special >> 5) & 0xF) as usize;
        words = words.saturating_add(1).saturating_add(pid).saturating_add(handles);
    }
    // All nibbles: X descriptors are 2 words, A/B/W 3 words each.
    let x = ((h0 >> 16) & 0xF) as usize;
    let abw = [20, 24, 28].iter().map(|s| ((h0 >> s) & 0xF) as usize).sum::<usize>();
    let data_start = words.saturating_add(x.saturating_mul(2)).saturating_add(abw.saturating_mul(3)).saturating_mul(4);
    let data_end = data_start.saturating_add(((h1 & 0x3FF) as usize).saturating_mul(4)).min(msg.len());
    // CMIF data is 16-byte aligned from the message start, inside the data section.
    let start = data_start.next_multiple_of(16);
    [start, start.saturating_add(16)].into_iter().find_map(|at| {
        let raw = msg.get(at..at.saturating_add(32).min(data_end))?;
        let (magic, rest) = raw.split_first_chunk::<4>()?;
        if magic != b"SFCO" {
            return None;
        }
        let result = u32::from_le_bytes(*rest.get(4..)?.first_chunk::<4>()?);
        Some((result, *rest.get(12..)?.first_chunk::<16>()?))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::reply_raw;

    /// A reply with `data` (words) as its data section, after `x` X descriptors.
    fn reply(x: u32, data: &[u32]) -> [u8; 0x100] {
        let mut msg = [0u8; 0x100];
        let mut put = |i: usize, v: u32| msg[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        put(0, x << 16);
        put(1, data.len() as u32);
        for (i, v) in data.iter().enumerate() {
            put(2 + 2 * x as usize + i, *v);
        }
        msg
    }

    const SFCO: u32 = u32::from_le_bytes(*b"SFCO");

    #[test]
    fn plain_reply() {
        // Header (2 words), data from word 2; CMIF at the 16-byte boundary (word 4).
        let msg = reply(0, &[0, 0, SFCO, 0, 0x1234, 0, 7, 0, 0, 0, 0, 0]);
        let (rc, out) = reply_raw(&msg).unwrap();
        assert_eq!(rc, 0x1234);
        assert_eq!(i32::from_le_bytes(out[..4].try_into().unwrap()), 7);
    }

    #[test]
    fn domain_reply() {
        // Same, behind a domain out header (out object count 0 + padding).
        let msg = reply(0, &[0, 0, 0, 0, 0, 0, SFCO, 0, 0, 0, 5, 0, 0, 0, 0, 0]);
        let (rc, out) = reply_raw(&msg).unwrap();
        assert_eq!(rc, 0);
        assert_eq!(i32::from_le_bytes(out[..4].try_into().unwrap()), 5);
    }

    #[test]
    fn after_descriptors() {
        // One X descriptor: data from word 4, already aligned.
        let msg = reply(1, &[SFCO, 0, 0, 0, 9, 0, 0, 0]);
        assert_eq!(reply_raw(&msg).map(|(_, o)| o[0]), Some(9));
    }

    #[test]
    fn not_cmif() {
        assert_eq!(reply_raw(&reply(0, &[0; 12])), None);
        // Magic present but the data section too short for the output.
        assert_eq!(reply_raw(&reply(0, &[0, 0, SFCO, 0, 0])), None);
        assert_eq!(reply_raw(&[]), None);
    }
}
