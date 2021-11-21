pub mod parser;
mod pseudo_pad;
pub mod serializer;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate simple_error;

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug)]
pub enum PacketType {
    Authentication = 0x01,
    Authorization = 0x02,
    Accounting = 0x03,
}

#[derive(Copy, Clone, Debug)]
pub struct Header {
    major_version: u8,
    minor_version: u8,
    version: u8,
    r#type: PacketType,
    seq_no: u8,
    flags: u8,
    session_id: u32,
    length: u32,
}

#[derive(Clone, Debug)]
pub enum Body {
    AuthenticationStart {
        action: u8,
        priv_lvl: u8,
        authen_type: u8,
        authen_service: u8,
        user_len: u8,
        port_len: u8,
        rem_addr_len: u8,
        data_len: u8,
        user: Vec<u8>,
        port: Vec<u8>,
        rem_addr: Vec<u8>,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct Packet {
    header: Header,
    body: Body,
}
