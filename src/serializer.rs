use crate::Packet;
use byteorder::{BigEndian, WriteBytesExt};
use std::error;

pub fn serialize_packet(packet: &Packet, key: &[u8]) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut serialized: Vec<u8> = Vec::new();
    serialized.write_u8(packet.header.version)?;
    let packet_type = num::ToPrimitive::to_u8(&(packet.header.r#type)).unwrap();
    serialized.write_u8(packet_type)?;
    serialized.write_u8(packet.header.seq_no)?;
    serialized.write_u8(packet.header.flags)?;
    serialized.write_u32::<BigEndian>(packet.header.session_id)?;
    serialized.write_u32::<BigEndian>(packet.header.length)?;
    Ok(serialized)
}
