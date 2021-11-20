use crate::{Header, Packet};

pub fn parse_header(input: &[u8]) -> nom::IResult<&[u8], Header> {
    let (input, versions) = nom::number::complete::be_u8(input)?;
    let major_version = (versions & 0b11110000) >> 4;
    let minor_version = versions & 0b00001111;
    let (input, r#type) = nom::number::complete::be_u8(input)?;
    let (input, seq_no) = nom::number::complete::be_u8(input)?;
    let (input, flags) = nom::number::complete::be_u8(input)?;
    let (input, session_id) = nom::number::complete::be_u32(input)?;
    let (input, length) = nom::number::complete::be_u32(input)?;

    Ok((
        input,
        Header {
            major_version,
            minor_version,
            versions,
            r#type,
            seq_no,
            flags,
            session_id,
            length,
        },
    ))
}

pub fn parse_packet(input: &[u8]) -> nom::IResult<&[u8], Packet> {
    let (input, header) = parse_header(input)?;
    let (input, body) = nom::bytes::complete::take(header.length)(input)?;
    Ok((input, Packet { header, body }))
}
