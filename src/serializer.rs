use crate::{pseudo_pad::PseudoPad, pseudo_pad::MD5_DIGEST_LENGTH, Body, Packet, PacketType};
use byteorder::{BigEndian, WriteBytesExt};
use std::error;

fn serialize_authen_start(body: &Body) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut serialized: Vec<u8> = Vec::new();

    match body {
        Body::AuthenticationStart {
            action,
            priv_lvl,
            authen_type,
            authen_service,
            user_len,
            port_len,
            rem_addr_len,
            data_len,
            user,
            port,
            rem_addr,
            data,
        } => {
            serialized.write_u8(*action)?;
            serialized.write_u8(*priv_lvl)?;
            serialized.write_u8(*authen_type)?;
            serialized.write_u8(*authen_service)?;
            serialized.write_u8(*user_len)?;
            serialized.write_u8(*port_len)?;
            serialized.write_u8(*rem_addr_len)?;
            serialized.write_u8(*data_len)?;
            serialized.extend_from_slice(user);
            serialized.extend_from_slice(port);
            serialized.extend_from_slice(rem_addr);
            serialized.extend_from_slice(data);
        }
    }

    Ok(serialized)
}

pub fn serialize_packet(packet: &Packet, key: &[u8]) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut serialized: Vec<u8> = Vec::new();

    serialized.write_u8(packet.header.version)?;
    let packet_type = num::ToPrimitive::to_u8(&(packet.header.r#type)).unwrap();
    serialized.write_u8(packet_type)?;
    serialized.write_u8(packet.header.seq_no)?;
    serialized.write_u8(packet.header.flags)?;
    serialized.write_u32::<BigEndian>(packet.header.session_id)?;
    serialized.write_u32::<BigEndian>(packet.header.length)?;

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

    serialized.extend_from_slice(&encrypted);

    Ok(serialized)
}
