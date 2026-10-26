//! HIPC / CMIF / TIPC message encoding written from the public references, independent of nx:
//! Switchbrew "IPC_Marshalling" and libnx `nx/include/switch/sf/{hipc,cmif,tipc}.h`
//! (`hipcMakeRequest`, `hipcParseResponse`, `cmifMakeRequest`, `cmifParseResponse`,
//! `tipcMakeRequest`). These are the expectations nx's own encoder is checked against.

pub const SFCI: u32 = u32::from_le_bytes(*b"SFCI");
pub const SFCO: u32 = u32::from_le_bytes(*b"SFCO");

/// CmifCommandType (libnx cmif.h).
pub const CMIF_REQUEST: u16 = 4;
pub const CMIF_CONTROL: u16 = 5;
/// CmifDomainRequestType_SendMessage.
pub const DOMAIN_SEND_MESSAGE: u8 = 1;

/// X descriptor, HipcStaticDescriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Static {
    pub index: u8,
    pub addr: u64,
    pub size: u16,
}

/// A/B/W descriptor, HipcBufferDescriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Buf {
    pub addr: u64,
    pub size: u64,
    pub mode: u8,
}

/// C descriptor (receive list entry), HipcRecvListEntry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recv {
    pub addr: u64,
    pub size: u16,
}

/// One HIPC message, field by field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hipc {
    pub ty: u16,
    pub pid: Option<u64>,
    pub copy: Vec<u32>,
    pub moves: Vec<u32>,
    pub x: Vec<Static>,
    pub a: Vec<Buf>,
    pub b: Vec<Buf>,
    pub w: Vec<Buf>,
    /// Raw data words.
    pub data: Vec<u32>,
    /// Word index of the first raw data word (set by `decode`).
    pub data_at: usize,
    /// Header receive-list field: 0 none, 2 one buffer for all, n > 2 n - 2 entries.
    pub recv_mode: u8,
    pub c: Vec<Recv>,
}

fn bits(v: u32, lo: u32, len: u32) -> u32 {
    (v >> lo) & ((1u64 << len) - 1) as u32
}

pub fn words(msg: &[u8]) -> Vec<u32> {
    msg.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

/// hipcParseRequest/Response: every field the header announces.
pub fn decode(msg: &[u8]) -> Hipc {
    let w = words(msg);
    let (h0, h1) = (w[0], w[1]);
    let mut h = Hipc { ty: bits(h0, 0, 16) as u16, ..Default::default() };
    let mut at = 2;
    if bits(h1, 31, 1) != 0 {
        let sp = w[at];
        at += 1;
        if bits(sp, 0, 1) != 0 {
            h.pid = Some(w[at] as u64 | (w[at + 1] as u64) << 32);
            at += 2;
        }
        for _ in 0..bits(sp, 1, 4) {
            h.copy.push(w[at]);
            at += 1;
        }
        for _ in 0..bits(sp, 5, 4) {
            h.moves.push(w[at]);
            at += 1;
        }
    }
    for _ in 0..bits(h0, 16, 4) {
        let (d0, lo) = (w[at], w[at + 1]);
        h.x.push(Static {
            index: bits(d0, 0, 6) as u8,
            addr: lo as u64 | (bits(d0, 12, 4) as u64) << 32 | (bits(d0, 6, 6) as u64) << 36,
            size: bits(d0, 16, 16) as u16,
        });
        at += 2;
    }
    for (n, list) in [(bits(h0, 20, 4), 0), (bits(h0, 24, 4), 1), (bits(h0, 28, 4), 2)] {
        for _ in 0..n {
            let (size_lo, addr_lo, d2) = (w[at], w[at + 1], w[at + 2]);
            let b = Buf {
                addr: addr_lo as u64 | (bits(d2, 28, 4) as u64) << 32 | (bits(d2, 2, 22) as u64) << 36,
                size: size_lo as u64 | (bits(d2, 24, 4) as u64) << 32,
                mode: bits(d2, 0, 2) as u8,
            };
            [&mut h.a, &mut h.b, &mut h.w][list].push(b);
            at += 3;
        }
    }
    h.data_at = at;
    let n = bits(h1, 0, 10) as usize;
    h.data = w[at..at + n].to_vec();
    at += n;
    h.recv_mode = bits(h1, 10, 4) as u8;
    let list_at = bits(h1, 20, 11) as usize;
    if list_at != 0 {
        at = list_at;
    }
    let count = match h.recv_mode {
        0 | 1 => 0,
        2 => 1,
        m => m as usize - 2,
    };
    for _ in 0..count {
        let (lo, hi) = (w[at], w[at + 1]);
        h.c.push(Recv { addr: lo as u64 | (bits(hi, 0, 16) as u64) << 32, size: bits(hi, 16, 16) as u16 });
        at += 2;
    }
    h
}

/// hipcMakeRequest: the words of `h` (receive list right after the raw data).
pub fn encode(h: &Hipc) -> Vec<u32> {
    let special = h.pid.is_some() || !h.copy.is_empty() || !h.moves.is_empty();
    let mut w = vec![
        h.ty as u32
            | (h.x.len() as u32) << 16
            | (h.a.len() as u32) << 20
            | (h.b.len() as u32) << 24
            | (h.w.len() as u32) << 28,
        h.data.len() as u32 | (h.recv_mode as u32) << 10 | (special as u32) << 31,
    ];
    if special {
        w.push(h.pid.is_some() as u32 | (h.copy.len() as u32) << 1 | (h.moves.len() as u32) << 5);
        if let Some(pid) = h.pid {
            w.extend([pid as u32, (pid >> 32) as u32]);
        }
        w.extend(&h.copy);
        w.extend(&h.moves);
    }
    for x in &h.x {
        w.push(
            x.index as u32 | ((x.addr >> 36) as u32 & 0x3F) << 6 | ((x.addr >> 32) as u32 & 0xF) << 12 | (x.size as u32) << 16,
        );
        w.push(x.addr as u32);
    }
    for b in h.a.iter().chain(&h.b).chain(&h.w) {
        w.push(b.size as u32);
        w.push(b.addr as u32);
        w.push(
            b.mode as u32
                | ((b.addr >> 36) as u32 & 0x3F_FFFF) << 2
                | ((b.size >> 32) as u32 & 0xF) << 24
                | ((b.addr >> 32) as u32 & 0xF) << 28,
        );
    }
    w.extend(&h.data);
    for c in &h.c {
        w.push(c.addr as u32);
        w.push((c.addr >> 32) as u32 & 0xFFFF | (c.size as u32) << 16);
    }
    w
}

/// Byte offset, from the start of the raw data words, of the 16-aligned CMIF payload
/// (libnx aligns the address; message buffers are 16-aligned, so the offset suffices).
fn cmif_start(data_at: usize) -> usize {
    (data_at * 4).next_multiple_of(16) - data_at * 4
}

fn data_bytes(h: &Hipc) -> Vec<u8> {
    h.data.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn hipc_words_before_data(h: &Hipc) -> usize {
    let special = h.pid.is_some() || !h.copy.is_empty() || !h.moves.is_empty();
    2 + special as usize * (1 + 2 * h.pid.is_some() as usize + h.copy.len() + h.moves.len())
        + 2 * h.x.len()
        + 3 * (h.a.len() + h.b.len() + h.w.len())
}

/// What a CMIF request carries besides the HIPC descriptors, as `cmifMakeRequest` takes it.
#[derive(Clone, Debug, Default)]
pub struct Cmif {
    pub ty: u16,
    pub cmd: u32,
    /// Argument bytes after the CmifInHeader.
    pub raw: Vec<u8>,
    /// Domain object id and input object ids (domain sessions only).
    pub domain: Option<(u32, Vec<u32>)>,
    /// One entry per out pointer / out auto-select buffer (the u16 table).
    pub out_pointer_sizes: Vec<u16>,
}

/// cmifMakeRequest over `h` (descriptors, handles, pid, receive list already set): fills the
/// raw data words.
pub fn cmif_request(mut h: Hipc, c: &Cmif) -> Hipc {
    h.ty = if c.ty == 0 { CMIF_REQUEST } else { c.ty };
    let mut size = 16;
    if let Some((_, objects)) = &c.domain {
        size += 16 + 4 * objects.len();
    }
    size += 16 + c.raw.len();
    size = (size + 1) & !1;
    let out_ptr_offset = size;
    size += 2 * c.out_pointer_sizes.len();
    let words = size.div_ceil(4);
    let mut bytes = vec![0u8; words * 4];
    let mut at = cmif_start(hipc_words_before_data(&h));
    let payload = 16 + c.raw.len();
    if let Some((object_id, objects)) = &c.domain {
        bytes[at] = DOMAIN_SEND_MESSAGE;
        bytes[at + 1] = objects.len() as u8;
        bytes[at + 2..at + 4].copy_from_slice(&(payload as u16).to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&object_id.to_le_bytes());
        let objs_at = at + 16 + payload;
        for (i, o) in objects.iter().enumerate() {
            bytes[objs_at + 4 * i..objs_at + 4 * i + 4].copy_from_slice(&o.to_le_bytes());
        }
        at += 16;
    }
    bytes[at..at + 4].copy_from_slice(&SFCI.to_le_bytes());
    bytes[at + 8..at + 12].copy_from_slice(&c.cmd.to_le_bytes());
    bytes[at + 16..at + 16 + c.raw.len()].copy_from_slice(&c.raw);
    for (i, s) in c.out_pointer_sizes.iter().enumerate() {
        let o = out_ptr_offset + 2 * i;
        bytes[o..o + 2].copy_from_slice(&s.to_le_bytes());
    }
    h.data = words_of(&bytes);
    h
}

fn words_of(bytes: &[u8]) -> Vec<u32> {
    words(bytes)
}

/// A CMIF request as decoded on the receiving side (cmifParseRequest's view).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmifIn {
    pub magic: u32,
    pub version: u32,
    pub cmd: u32,
    pub token: u32,
    /// The `raw_len` argument bytes after the CmifInHeader.
    pub raw: Vec<u8>,
    /// (domain type, object id, input object ids)
    pub domain: Option<(u8, u32, Vec<u32>)>,
    /// The u16 table where cmifMakeRequest puts it.
    pub out_pointer_sizes: Vec<u16>,
    /// Raw data words in the message.
    pub data_words: usize,
}

/// Decodes the CMIF part of a request with `raw_len` argument bytes and `out_pointers`
/// entries in the out-pointer size table.
pub fn cmif_in(h: &Hipc, is_domain: bool, raw_len: usize, out_pointers: usize) -> CmifIn {
    let bytes = data_bytes(h);
    let mut at = cmif_start(h.data_at);
    let mut domain = None;
    let mut objects_len = 0;
    if is_domain {
        let payload = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]) as usize;
        let n = bytes[at + 1] as usize;
        let objs_at = at + 16 + payload;
        let objs = (0..n).map(|i| u32::from_le_bytes(bytes[objs_at + 4 * i..objs_at + 4 * i + 4].try_into().unwrap())).collect();
        domain = Some((bytes[at], u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()), objs));
        objects_len = 16 + 4 * n;
        at += 16;
    }
    let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let table_at = (16 + objects_len + 16 + raw_len + 1) & !1;
    CmifIn {
        magic: u32_at(at),
        version: u32_at(at + 4),
        cmd: u32_at(at + 8),
        token: u32_at(at + 12),
        raw: bytes[at + 16..at + 16 + raw_len].to_vec(),
        domain,
        out_pointer_sizes: (0..out_pointers)
            .map(|i| u16::from_le_bytes([bytes[table_at + 2 * i], bytes[table_at + 2 * i + 1]]))
            .collect(),
        data_words: h.data.len(),
    }
}

/// A CMIF reply as cmifParseResponse reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmifOut {
    pub magic: u32,
    pub result: u32,
    /// Bytes after the CmifOutHeader up to the end of the raw data words (or the domain objects).
    pub raw: Vec<u8>,
    pub objects: Vec<u32>,
}

pub fn cmif_out(h: &Hipc, is_domain: bool, raw_len: usize) -> CmifOut {
    let bytes = data_bytes(h);
    let mut at = cmif_start(h.data_at);
    let mut objects = vec![];
    let mut n = 0;
    if is_domain {
        n = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        at += 16;
    }
    let objs_at = at + 16 + raw_len;
    for i in 0..n {
        objects.push(u32::from_le_bytes(bytes[objs_at + 4 * i..objs_at + 4 * i + 4].try_into().unwrap()));
    }
    CmifOut {
        magic: u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
        result: u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
        raw: bytes[at + 16..(at + 16 + raw_len).min(bytes.len())].to_vec(),
        objects,
    }
}

/// A CMIF reply (cmifMakeResponse's layout, as a real service writes it).
pub fn cmif_reply(mut h: Hipc, result: u32, raw: &[u8], domain_objects: Option<&[u32]>) -> Hipc {
    let mut size = 16 + 16 + raw.len();
    if let Some(objs) = domain_objects {
        size += 16 + 4 * objs.len();
    }
    let mut bytes = vec![0u8; size.div_ceil(4) * 4];
    let mut at = cmif_start(hipc_words_before_data(&h));
    if let Some(objs) = domain_objects {
        bytes[at..at + 4].copy_from_slice(&(objs.len() as u32).to_le_bytes());
        let objs_at = at + 16 + 16 + raw.len();
        for (i, o) in objs.iter().enumerate() {
            bytes[objs_at + 4 * i..objs_at + 4 * i + 4].copy_from_slice(&o.to_le_bytes());
        }
        at += 16;
    }
    bytes[at..at + 4].copy_from_slice(&SFCO.to_le_bytes());
    bytes[at + 8..at + 12].copy_from_slice(&result.to_le_bytes());
    bytes[at + 16..at + 16 + raw.len()].copy_from_slice(raw);
    h.data = words_of(&bytes);
    h
}

/// A TIPC reply (tipcParseResponse): result word, then the out data.
pub fn tipc_reply(mut h: Hipc, result: u32, raw: &[u8]) -> Hipc {
    let mut bytes = result.to_le_bytes().to_vec();
    bytes.extend(raw);
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    h.data = words_of(&bytes);
    h
}

/// Raw data bytes of a message (TIPC: the arguments themselves).
pub fn raw_bytes(h: &Hipc) -> Vec<u8> {
    data_bytes(h)
}

pub fn to_msg(words: &[u32]) -> [u8; 0x100] {
    let mut msg = [0u8; 0x100];
    for (i, w) in words.iter().enumerate() {
        msg[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    msg
}
