pub mod hash;
pub mod parser;
mod pseudo_pad;
pub mod serializer;

#[macro_use]
extern crate num_derive;

#[macro_use]
extern crate simple_error;

pub const TAC_PLUS_UNENCRYPTED_FLAG: u8 = 0b00000001;
pub const TAC_PLUS_SINGLE_CONNECT_FLAG: u8 = 0b00000100;
pub const TAC_PLUS_REPLY_FLAG_NOECHO: u8 = 0b00000001;
pub const TAC_PLUS_CONTINUE_FLAG_ABORT: u8 = 0b00000001;

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug)]
pub enum PacketType {
    Authentication = 0x01,
    Authorization = 0x02,
    Accounting = 0x03,
}

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug)]
pub enum AuthenticationStatus {
    Pass = 0x01,
    Fail = 0x02,
    Getdata = 0x03,
    GetUser = 0x04,
    GetPass = 0x05,
    Restart = 0x06,
    Error = 0x07,
    Follow = 0x21,
}

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug)]
pub enum AuthorizationStatus {
    AuthPassAdd = 0x01,
    AuthPassRepl = 0x02,
    AuthStatusFail = 0x10,
    AuthStatusError = 0x11,
    AuthStatusFollow = 0x21,
}

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug)]
pub enum AuthenticationMethod {
    AuthNotSet = 0x00,
    AuthNone = 0x01,
    AuthKrb5 = 0x02,
    AuthLine = 0x03,
    AuthEnable = 0x04,
    AuthLocal = 0x05,
    AuthTacPLus = 0x06,
    AuthGuest = 0x08,
    AuthRadius = 0x10,
    AUthKrb4 = 0x11,
    AuthRcmd = 0x20,
}

#[derive(Copy, Clone, Debug)]
pub struct PacketFlags {
    pub unencrypted: bool,
    pub single_connect: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct AuthenticationReplyFlags {
    pub no_echo: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct AuthenticationContinueFlags {
    pub abort: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct Header {
    #[allow(dead_code)]
    pub major_version: u8,
    #[allow(dead_code)]
    pub minor_version: u8,
    pub version: u8,
    pub r#type: PacketType,
    pub seq_no: u8,
    pub flags: PacketFlags,
    pub session_id: u32,
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

    AuthenticationReply {
        status: AuthenticationStatus,
        flags: AuthenticationReplyFlags,
        server_msg: Vec<u8>,
        data: Vec<u8>,
    },

    AuthenticationContinue {
        flags: AuthenticationContinueFlags,
        user: Vec<u8>,
        data: Vec<u8>,
    },

    AuthorizationRequest {
        auth_method: AuthenticationMethod,
        priv_lvl: u8,
        authen_type: u8,
        authen_service: u8,
        user: Vec<u8>,
        port: Vec<u8>,
        rem_address: Vec<u8>,
        args: Vec<Vec<u8>>,
    },

    AuthorizationReply {
        status: AuthorizationStatus,
        data: Vec<u8>,
        server_msg: Vec<u8>,
        args: Vec<Vec<u8>>,
    },
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub body: Body,
}
