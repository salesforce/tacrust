use crate::{Body, Header, Packet, PacketType};
use byteorder::{BigEndian, WriteBytesExt};
use md5;

const MD5_DIGEST_LENGTH: usize = 16;

struct PseudoPad<'a> {
    session_id: Vec<u8>,
    key: &'a [u8],
    version: Vec<u8>,
    seq_no: Vec<u8>,
    digest: md5::Digest,
}

impl<'a> PseudoPad<'a> {
    pub fn new(session_id: u32, key: &'a [u8], version: u8, seq_no: u8) -> Self {
        let mut session_id_be = vec![];
        session_id_be.write_u32::<BigEndian>(session_id).unwrap();

        let mut version_be = vec![];
        version_be.write_u8(version).unwrap();

        let mut seq_no_be = vec![];
        seq_no_be.write_u8(seq_no).unwrap();

        let digest = md5::compute([&session_id_be, key, &version_be, &seq_no_be].concat());

        PseudoPad {
            session_id: session_id_be,
            key,
            version: version_be,
            seq_no: seq_no_be,
            digest,
        }
    }
}

impl<'a> Iterator for PseudoPad<'a> {
    type Item = [u8; MD5_DIGEST_LENGTH];

    fn next(&mut self) -> Option<Self::Item> {
        let previous_digest = self.digest.0;
        self.digest = md5::compute(
            [
                &self.session_id,
                self.key,
                &self.version,
                &self.seq_no,
                &previous_digest,
            ]
            .concat(),
        );
        Some(previous_digest)
    }
}

fn parse_header<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Header> {
    let (input, version) = nom::number::complete::be_u8(input)?;
    let major_version = (version & 0b11110000) >> 4;
    let minor_version = version & 0b00001111;
    let (input, r#type) = nom::number::complete::be_u8(input)?;
    let r#type = num::FromPrimitive::from_u32(r#type as u32).unwrap();
    let (input, seq_no) = nom::number::complete::be_u8(input)?;
    let (input, flags) = nom::number::complete::be_u8(input)?;
    let (input, session_id) = nom::number::complete::be_u32(input)?;
    let (input, length) = nom::number::complete::be_u32(input)?;

    Ok((
        input,
        Header {
            major_version,
            minor_version,
            version,
            r#type,
            seq_no,
            flags,
            session_id,
            length,
        },
    ))
}

pub fn parse_authen_start<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Body> {
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
        user_len,
        port_len,
        rem_addr_len,
        data_len,
        user: user.to_vec(),
        port: port.to_vec(),
        rem_addr: rem_addr.to_vec(),
        data: data.to_vec(),
    };

    Ok((input, body))
}

pub fn parse_body<'a>(input: &'a [u8], header: Header) -> nom::IResult<&'a [u8], Body> {
    match header.r#type {
        PacketType::Authentication => parse_authen_start(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Fail,
        ))),
    }
}

pub fn parse_packet<'a>(input: &'a [u8], key: &'a [u8]) -> nom::IResult<&'a [u8], Packet> {
    let (input, header) = parse_header(input)?;
    let (_, body) =
        nom::combinator::all_consuming(nom::bytes::complete::take(header.length))(input)?;
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

    let (_, parsed_body) = parse_body(&decrypted, header.clone()).unwrap();

    Ok((
        input,
        Packet {
            header,
            body: parsed_body,
        },
    ))
}
