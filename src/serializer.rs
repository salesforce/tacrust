use crate::{
    pseudo_pad::PseudoPad, pseudo_pad::MD5_DIGEST_LENGTH, Body, Packet, PacketType,
    TAC_PLUS_SINGLE_CONNECT_FLAG, TAC_PLUS_UNENCRYPTED_FLAG,
};
use byteorder::{BigEndian, WriteBytesExt};
use std::error;
use std::ops::Deref;

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
            serialized.write_u8(user.len().try_into().unwrap())?;
            serialized.write_u8(port.len().try_into().unwrap())?;
            serialized.write_u8(rem_addr.len().try_into().unwrap())?;
            serialized.write_u8(data.len().try_into().unwrap())?;
            serialized.extend_from_slice(user);
            serialized.extend_from_slice(port);
            serialized.extend_from_slice(rem_addr);
            serialized.extend_from_slice(data);
        }
        Body::AuthenticationReply {
            status,
            flags,
            server_msg_len,
            data_len,
            server_msg,
            data,
        } => {
            let status_der = num::ToPrimitive::to_u8(status).unwrap();
            serialized.write_u8(status_der)?;
            serialized.write_u8(*flags)?;
            let bytes = server_msg_len.to_be_bytes();
            serialized.write_u8(bytes[0])?;
            serialized.write_u8(bytes[1])?;
            let bytes_len = data_len.to_be_bytes();
            serialized.write_u8(bytes_len[0])?;
            serialized.write_u8(bytes_len[1])?;
            serialized.extend_from_slice(server_msg);
            serialized.extend_from_slice(data);
        }
    }

    Ok(serialized)
}

pub fn serialize_packet(packet: &Packet, key: &[u8]) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let plaintext_body = match packet.header.r#type {
        PacketType::Authentication => serialize_authen_start(&(packet.body)),
        _ => bail!("not implemented yet"),
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
    let packet_type = num::ToPrimitive::to_u8(&(packet.header.r#type)).unwrap();
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
    serialized.write_u32::<BigEndian>(encrypted.len().try_into().unwrap())?;
    serialized.extend_from_slice(&encrypted);

    Ok(serialized)
}
