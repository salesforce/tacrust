pub mod parser;
mod pseudo_pad;
pub mod serializer;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate simple_error;

pub const TAC_PLUS_UNENCRYPTED_FLAG: u8 = 0b00000001;
pub const TAC_PLUS_SINGLE_CONNECT_FLAG: u8 = 0b00000100;

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug)]
pub enum PacketType {
    Authentication = 0x01,
    Authorization = 0x02,
    Accounting = 0x03,
}

#[derive(Copy, Clone, Debug)]
pub struct PacketFlags {
    unencrypted: bool,
    single_connect: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct Header {
    #[allow(dead_code)]
    major_version: u8,
    #[allow(dead_code)]
    minor_version: u8,
    version: u8,
    r#type: PacketType,
    seq_no: u8,
    flags: PacketFlags,
    session_id: u32,
}

#[derive(Clone, Debug)]
pub enum Body {
    AuthenticationStart {
        action: u8,
        priv_lvl: u8,
        authen_type: u8,
        authen_service: u8,
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
