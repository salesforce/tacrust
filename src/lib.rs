use std::fmt::Display;

pub mod hash;
pub mod parser;
mod pseudo_pad;
pub mod serializer;
pub mod tacacs_codec;

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

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
pub enum AuthenticationType {
    Ascii = 0x01,
    Pap = 0x02,
    Chap = 0x03,
    Mschap = 0x05,
    Mschapv2 = 0x06,
}

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
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

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
pub enum AuthorizationStatus {
    AuthPassAdd = 0x01,
    AuthPassRepl = 0x02,
    AuthStatusFail = 0x10,
    AuthStatusError = 0x11,
    AuthStatusFollow = 0x21,
    AuthForwardUpstream = 0xdead,
}

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
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

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
pub enum AccountingRequestFlags {
    AcctFlagStart = 0x02,
    AcctFlagStop = 0x04,
    AcctFlagWatchDog = 0x08,
}

#[derive(Copy, Clone, FromPrimitive, ToPrimitive, Debug, PartialEq, Eq)]
pub enum AccountingReplyStatus {
    AcctStatusSuccess = 0x01,
    AcctStatusError = 0x02,
    AcctStatusFollow = 0x21,
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

const TAC_PLUS_HEADER_SIZE: usize = 12;

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

    AccountingRequest {
        flags: AccountingRequestFlags,
        authen_method: AuthenticationMethod,
        priv_lvl: u8,
        authen_type: u8,
        authen_service: u8,
        user: Vec<u8>,
        port: Vec<u8>,
        rem_addr: Vec<u8>,
        args: Vec<Vec<u8>>,
    },

    AccountingReply {
        status: AccountingReplyStatus,
        server_msg: Vec<u8>,
        data: Vec<u8>,
    },
}

impl Display for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::AuthenticationStart {
                action: _,
                priv_lvl: _,
                authen_type: _,
                authen_service: _,
                user,
                port: _,
                rem_addr: _,
                data: _,
            } => {
                write!(f, "AuthenticationStart {{ ")?;
                write!(f, "user: \"{}\"", String::from_utf8_lossy(user))?;
                write!(f, " }}")
            }
            Body::AuthenticationReply {
                status,
                flags,
                server_msg,
                data: _,
            } => {
                write!(f, "AuthenticationReply {{ ")?;
                write!(f, "status: {:?}, ", status)?;
                write!(f, "flags: {:?}, ", flags)?;
                write!(f, "server_msg: {:?}", String::from_utf8_lossy(server_msg))?;
                write!(f, " }}")
            }
            Body::AuthenticationContinue {
                flags,
                user,
                data: _,
            } => {
                write!(f, "AuthenticationContinue {{ ")?;
                write!(f, "flags: {:?}, ", flags)?;
                write!(f, "username/password: \"({} bytes)\"", user.len())?;
                write!(f, " }}")
            }
            Body::AuthorizationRequest {
                auth_method: _,
                priv_lvl: _,
                authen_type: _,
                authen_service: _,
                user,
                port: _,
                rem_address: _,
                args,
            } => {
                write!(f, "AuthorizationRequest {{ ")?;
                write!(f, "user: \"{}\", ", String::from_utf8_lossy(user))?;
                let args: Vec<String> = args
                    .iter()
                    .map(|arg| format!("\"{}\"", String::from_utf8_lossy(arg)))
                    .collect();
                write!(f, "args: [{}]", args.join(", "))?;
                write!(f, " }}")
            }
            Body::AuthorizationReply {
                status,
                data: _,
                server_msg: _,
                args,
            } => {
                write!(f, "AuthorizationReply {{ ")?;
                write!(f, "status: {:?}, ", status)?;
                let args: Vec<String> = args
                    .iter()
                    .map(|arg| format!("\"{}\"", String::from_utf8_lossy(arg)))
                    .collect();
                write!(f, "args: [{}]", args.join(", "))?;
                write!(f, " }}")
            }
            Body::AccountingRequest {
                flags: _,
                authen_method: _,
                priv_lvl: _,
                authen_type: _,
                authen_service: _,
                user: _,
                port: _,
                rem_addr: _,
                args: _,
            } => {
                write!(f, "AccountingRequest {{ ")?;
                write!(f, " }}")
            }
            Body::AccountingReply {
                status: _,
                server_msg: _,
                data: _,
            } => {
                write!(f, "AccountingReply {{ ")?;
                write!(f, " }}")
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub body: Body,
}
