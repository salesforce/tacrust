pub mod parser;

#[derive(Clone, Debug)]
pub struct Header {
    major_version: u8,
    minor_version: u8,
    version: u8,
    r#type: u8,
    seq_no: u8,
    flags: u8,
    session_id: u32,
    length: u32,
}

#[derive(Clone, Debug)]
pub struct Packet<'a> {
    header: Header,
    body: &'a [u8],
}
