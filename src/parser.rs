use crate::{
    pseudo_pad::PseudoPad, pseudo_pad::MD5_DIGEST_LENGTH, AuthenticationStatus, Body, Header,
    Packet, PacketFlags, PacketType, TAC_PLUS_SINGLE_CONNECT_FLAG, TAC_PLUS_UNENCRYPTED_FLAG,
};
use std::fmt::Debug;

use nom::branch::alt;

pub struct ParserError<I, J: Default + Debug> {
    error: nom::error::Error<I>,
    inner_error: nom::Err<nom::error::Error<J>>,
}

impl<I, J: Default + Debug> ParserError<I, J> {
    fn new(
        input: I,
        code: nom::error::ErrorKind,
        inner_error: nom::Err<nom::error::Error<J>>,
    ) -> Self {
        Self {
            error: nom::error::Error::new(input, code),
            inner_error,
        }
    }
}

impl<I, J: Default + Debug> Debug for ParserError<I, J> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parser inner error: {}", self.inner_error)
    }
}

impl<I, J: Default + Debug> nom::error::ParseError<I> for ParserError<I, J> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        Self::new(
            input,
            kind,
            nom::Err::Error(nom::error::Error::new(
                Default::default(),
                nom::error::ErrorKind::Fail,
            )),
        )
    }

    fn append(input: I, kind: nom::error::ErrorKind, other: Self) -> Self {
        Self::new(input, kind, other.inner_error)
    }
}

impl<I, J: Default + Debug> From<ParserError<I, J>> for nom::Err<nom::error::Error<I>> {
    fn from(err: ParserError<I, J>) -> Self {
        nom::Err::Error(err.error)
    }
}

fn parse_header(input: &[u8]) -> nom::IResult<&[u8], (u32, Header)> {
    let (input, version) = nom::number::complete::be_u8(input)?;
    let major_version = (version & 0b11110000) >> 4;
    let minor_version = version & 0b00001111;
    let (input, r#type) = nom::number::complete::be_u8(input)?;
    let r#type = num::FromPrimitive::from_u32(r#type as u32).unwrap_or(PacketType::Authentication);
    let (input, seq_no) = nom::number::complete::be_u8(input)?;
    let (input, flags) = nom::number::complete::be_u8(input)?;
    let flags = PacketFlags {
        unencrypted: flags & TAC_PLUS_UNENCRYPTED_FLAG != 0,
        single_connect: flags & TAC_PLUS_SINGLE_CONNECT_FLAG != 0,
    };
    let (input, session_id) = nom::number::complete::be_u32(input)?;
    let (input, length) = nom::number::complete::be_u32(input)?;

    Ok((
        input,
        (
            length,
            Header {
                major_version,
                minor_version,
                version,
                r#type,
                seq_no,
                flags,
                session_id,
            },
        ),
    ))
}

pub fn parse_authen_start(input: &[u8]) -> nom::IResult<&[u8], Body> {
    let (input, action) = nom::number::complete::be_u8(input)?;
    let (input, priv_lvl) = nom::number::complete::be_u8(input)?;
    let (input, authen_type) = nom::number::complete::be_u8(input)?;
    let (input, authen_service) = nom::number::complete::be_u8(input)?;
    let (input, user_len) = nom::number::complete::be_u8(input)?;
    let (input, port_len) = nom::number::complete::be_u8(input)?;
    let (input, rem_addr_len) = nom::number::complete::be_u8(input)?;
    let (input, data_len) = nom::number::complete::be_u8(input)?;
    let (input, user) = nom::bytes::complete::take(user_len)(input)?;
    let (input, port) = nom::bytes::complete::take(port_len)(input)?;
    let (input, rem_addr) = nom::bytes::complete::take(rem_addr_len)(input)?;
    let (input, data) =
        nom::combinator::all_consuming(nom::bytes::complete::take(data_len))(input)?;

    let body = Body::AuthenticationStart {
        action,
        priv_lvl,
        authen_type,
        authen_service,
        user: user.to_vec(),
        port: port.to_vec(),
        rem_addr: rem_addr.to_vec(),
        data: data.to_vec(),
    };

    Ok((input, body))
}

pub fn parse_authen_reply(input: &[u8]) -> nom::IResult<&[u8], Body> {
    let (input, status) = nom::number::complete::be_u8(input)?;
    let (input, flags) = nom::number::complete::be_u8(input)?;
    let (input, server_msg_len) = nom::number::complete::be_u16(input)?;
    let (input, data_len) = nom::number::complete::be_u16(input)?;
    let (input, server_msg) = nom::bytes::complete::take(server_msg_len)(input)?;
    let (input, data) =
        nom::combinator::all_consuming(nom::bytes::complete::take(data_len))(input)?;

    let body = Body::AuthenticationReply {
        status: num::FromPrimitive::from_u8(status).unwrap_or(AuthenticationStatus::Error),
        flags,
        server_msg: server_msg.to_vec(),
        data: data.to_vec(),
    };

    Ok((input, body))
}

pub fn parse_authen_cont(input: &[u8]) -> nom::IResult<&[u8], Body> {
    let (input, user_len) = nom::number::complete::be_u16(input)?;
    let (input, data_len) = nom::number::complete::be_u16(input)?;
    let (input, flags) = nom::number::complete::be_u8(input)?;
    let (input, user) = nom::bytes::complete::take(user_len)(input)?;
    let (input, data) =
        nom::combinator::all_consuming(nom::bytes::complete::take(data_len))(input)?;

    let body = Body::AuthenticationContinue {
        flags,
        user: user.to_vec(),
        data: data.to_vec(),
    };

    Ok((input, body))
}

pub fn parse_body(input: &[u8], header: Header) -> nom::IResult<&[u8], Body> {
    match header.r#type {
        PacketType::Authentication => {
            alt((parse_authen_start, parse_authen_reply, parse_authen_cont))(input)
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Fail,
        ))),
    }
}

pub type ParserResult<I, J, O> = Result<(I, O), ParserError<I, J>>;

pub fn parse_packet<'a>(input: &'a [u8], key: &'a [u8]) -> ParserResult<&'a [u8], Vec<u8>, Packet> {
    let (input, (length, header)) = parse_header(input)
        .map_err(|e| ParserError::new(input, nom::error::ErrorKind::Fail, e.to_owned()))?;
    let (input, body) = nom::combinator::all_consuming(nom::bytes::complete::take(length))(input)
        .map_err(|e| {
        ParserError::new(
            input,
            nom::error::ErrorKind::Fail,
            nom::Err::<nom::error::Error<&[u8]>>::to_owned(e),
        )
    })?;

    let pseudo_pad = PseudoPad::new(header.session_id, key, header.version, header.seq_no);
    let mut decrypted = vec![];

    for (input_chunk, input_digest) in body.chunks(MD5_DIGEST_LENGTH).zip(pseudo_pad) {
        let decrypted_chunk: Vec<u8> = input_chunk
            .iter()
            .zip(input_digest.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        decrypted.extend_from_slice(&decrypted_chunk);
    }
    let (_, parsed_body) = parse_body(&decrypted, header)
        .map_err(|e| ParserError::new(input, nom::error::ErrorKind::Fail, e.to_owned()))?;
    Ok((
        input,
        Packet {
            header,
            body: parsed_body,
        },
    ))
}
