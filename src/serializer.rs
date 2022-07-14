use crate::{
    pseudo_pad::PseudoPad, pseudo_pad::MD5_DIGEST_LENGTH, Body, Packet, PacketType,
    TAC_PLUS_CONTINUE_FLAG_ABORT, TAC_PLUS_REPLY_FLAG_NOECHO, TAC_PLUS_SINGLE_CONNECT_FLAG,
    TAC_PLUS_UNENCRYPTED_FLAG,
};
use byteorder::{BigEndian, WriteBytesExt};
use std::{error, fmt};

#[derive(Debug, Clone)]
struct SerializerError {
    details: String,
}

impl SerializerError {
    fn new(msg: &str) -> Self {
        Self {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for SerializerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl error::Error for SerializerError {
    fn description(&self) -> &str {
        &self.details
    }
}

fn serialize_authen_start(body: &Body) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut serialized: Vec<u8> = Vec::new();

    match body {
        Body::AuthenticationStart {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            data,
        } => {
            serialized.write_u8(*action)?;
            serialized.write_u8(*priv_lvl)?;
            serialized.write_u8(*authen_type)?;
            serialized.write_u8(*authen_service)?;
            serialized.write_u8(user.len().try_into()?)?;
            serialized.write_u8(port.len().try_into()?)?;
            serialized.write_u8(rem_addr.len().try_into()?)?;
            serialized.write_u8(data.len().try_into()?)?;
            serialized.extend_from_slice(user);
            serialized.extend_from_slice(port);
            serialized.extend_from_slice(rem_addr);
            serialized.extend_from_slice(data);
        }
        Body::AuthenticationReply {
            status,
            flags,
            server_msg,
            data,
        } => {
            let status_der = num::ToPrimitive::to_u8(status)
                .ok_or_else(|| SerializerError::new("invalid status"))?;
            serialized.write_u8(status_der)?;
            let mut f: u8 = 0;
            if flags.no_echo {
                f |= TAC_PLUS_REPLY_FLAG_NOECHO;
            }
            serialized.write_u8(f)?;
            serialized.write_u16::<BigEndian>(server_msg.len().try_into()?)?;
            serialized.write_u16::<BigEndian>(data.len().try_into()?)?;
            serialized.extend_from_slice(server_msg);
            serialized.extend_from_slice(data);
        }

        Body::AuthenticationContinue { flags, user, data } => {
            serialized.write_u16::<BigEndian>(user.len().try_into()?)?;
            serialized.write_u16::<BigEndian>(data.len().try_into()?)?;
            let mut f: u8 = 0;
            if flags.abort {
                f |= TAC_PLUS_CONTINUE_FLAG_ABORT;
            }
            serialized.write_u8(f)?;
            serialized.extend_from_slice(user);
            serialized.extend_from_slice(data);
        }
        _ => bail!("not implemented yet"),
    };

    Ok(serialized)
}

fn serialize_author(body: &Body) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut serialized: Vec<u8> = Vec::new();

    match body {
        Body::AuthorizationRequest {
            auth_method,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_address,
            args,
        } => {
            let auth = num::ToPrimitive::to_u8(auth_method)
                .ok_or_else(|| SerializerError::new("invalid auth method"))?;
            serialized.write_u8(auth)?;
            serialized.write_u8(*priv_lvl)?;
            serialized.write_u8(*authen_type)?;
            serialized.write_u8(*authen_service)?;
            serialized.write_u8(user.len().try_into()?)?;
            serialized.write_u8(port.len().try_into()?)?;
            serialized.write_u8(rem_address.len().try_into()?)?;
            serialized.write_u8(args.len().try_into()?)?;
            for i in 0..args.len() {
                serialized.write_u8(
                    args.get(i)
                        .ok_or_else(|| SerializerError::new("invalid arg"))?
                        .len()
                        .try_into()?,
                )?;
            }
            serialized.extend_from_slice(user);
            serialized.extend_from_slice(port);
            serialized.extend_from_slice(rem_address);
            for i in 0..args.len() {
                serialized.extend_from_slice(
                    args.get(i)
                        .ok_or_else(|| SerializerError::new("invalid arg"))?,
                );
            }
        }

        Body::AuthorizationReply {
            status,
            data,
            server_msg,
            args,
        } => {
            let status_res = num::ToPrimitive::to_u8(status)
                .ok_or_else(|| SerializerError::new("invalid error"))?;
            serialized.write_u8(status_res)?;
            serialized.write_u8(args.len().try_into()?)?;
            serialized.write_u16::<BigEndian>(server_msg.len().try_into()?)?;
            serialized.write_u16::<BigEndian>(data.len().try_into()?)?;
            for i in 0..args.len() {
                serialized.write_u8(
                    args.get(i)
                        .ok_or_else(|| SerializerError::new("invalid arg"))?
                        .len()
                        .try_into()?,
                )?;
            }
            serialized.extend_from_slice(server_msg);
            serialized.extend_from_slice(data);
            for i in 0..args.len() {
                serialized.extend_from_slice(args.get(i).ok_or("invalid arg")?);
            }
        }

        _ => bail!("not implemented yet"),
    }
    Ok(serialized)
}

fn serialize_accounting(body: &Body) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut serialized: Vec<u8> = Vec::new();

    match body {
        Body::AccountingRequest {
            flags,
            authen_method,
            priv_lvl,
            authen_type,
            authen_service,
            user,
            port,
            rem_addr,
            args,
        } => {
            let flg = num::ToPrimitive::to_u8(flags)
                .ok_or_else(|| SerializerError::new("invalid flag"))?;
            serialized.write_u8(flg)?;
            let auth_method = num::ToPrimitive::to_u8(authen_method)
                .ok_or_else(|| SerializerError::new("invalid auth method"))?;
            serialized.write_u8(auth_method)?;
            serialized.write_u8(*priv_lvl)?;
            serialized.write_u8(*authen_type)?;
            serialized.write_u8(*authen_service)?;
            serialized.write_u8(user.len().try_into()?)?;
            serialized.write_u8(port.len().try_into()?)?;
            serialized.write_u8(rem_addr.len().try_into()?)?;
            serialized.write_u8(args.len().try_into()?)?;
            for i in 0..args.len() {
                serialized.write_u8(
                    args.get(i)
                        .ok_or_else(|| SerializerError::new("invalid arg"))?
                        .len()
                        .try_into()?,
                )?;
            }
            serialized.extend_from_slice(user);
            serialized.extend_from_slice(port);
            serialized.extend_from_slice(rem_addr);
            for i in 0..args.len() {
                serialized.extend_from_slice(
                    args.get(i)
                        .ok_or_else(|| SerializerError::new("invalid arg"))?,
                );
            }
        }

        Body::AccountingReply {
            status,
            server_msg,
            data,
        } => {
            serialized.write_u16::<BigEndian>(server_msg.len().try_into()?)?;
            serialized.write_u16::<BigEndian>(data.len().try_into()?)?;
            let status_res = num::ToPrimitive::to_u8(status)
                .ok_or_else(|| SerializerError::new("invalid status"))?;
            serialized.write_u8(status_res)?;
            serialized.extend_from_slice(server_msg);
            serialized.extend_from_slice(data);
        }

        _ => bail!("not implemented yet"),
    };

    Ok(serialized)
}

pub fn serialize_packet(packet: &Packet, key: &[u8]) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let plaintext_body = match packet.header.r#type {
        PacketType::Authentication => serialize_authen_start(&(packet.body)),
        PacketType::Authorization => serialize_author(&(packet.body)),
        PacketType::Accounting => serialize_accounting(&(packet.body)),
    }?;

    let pseudo_pad = PseudoPad::new(
        packet.header.session_id,
        key,
        packet.header.version,
        packet.header.seq_no,
    );
    let mut encrypted = vec![];

    for (input_chunk, input_digest) in plaintext_body.chunks(MD5_DIGEST_LENGTH).zip(pseudo_pad) {
        let decrypted_chunk: Vec<u8> = input_chunk
            .iter()
            .zip(input_digest.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        encrypted.extend_from_slice(&decrypted_chunk);
    }

    let mut serialized: Vec<u8> = Vec::new();

    serialized.write_u8(packet.header.version)?;
    let packet_type = num::ToPrimitive::to_u8(&(packet.header.r#type))
        .ok_or_else(|| SerializerError::new("invalid arg"))?;
    serialized.write_u8(packet_type)?;
    serialized.write_u8(packet.header.seq_no)?;
    let mut flags: u8 = 0;
    if packet.header.flags.unencrypted {
        flags |= TAC_PLUS_UNENCRYPTED_FLAG;
    }
    if packet.header.flags.single_connect {
        flags |= TAC_PLUS_SINGLE_CONNECT_FLAG;
    }
    serialized.write_u8(flags)?;
    serialized.write_u32::<BigEndian>(packet.header.session_id)?;
    serialized.write_u32::<BigEndian>(encrypted.len().try_into()?)?;
    serialized.extend_from_slice(&encrypted);

    Ok(serialized)
}
