use crate::{parser::parse_header, TAC_PLUS_HEADER_SIZE};
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/*
 * Slightly modified version of `BytesCodec` from:
 * https://github.com/tokio-rs/tokio/blob/master/tokio-util/src/codec/bytes_codec.rs
*/

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct TacacsCodec(());

impl TacacsCodec {
    pub fn new() -> TacacsCodec {
        TacacsCodec(())
    }
}

impl Decoder for TacacsCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        if buf.len() < TAC_PLUS_HEADER_SIZE {
            return Ok(None);
        }

        let (_, (packet_len, _)) = parse_header(buf)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "tacacs header parsing failed"))?;

        let body_len: usize = packet_len.try_into().unwrap_or_default();
        let expected_packet_len = TAC_PLUS_HEADER_SIZE + body_len;
        let buf_len = buf.len();

        if buf_len > expected_packet_len {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "tacacs packet too large, expected: {}, actual: {}",
                    expected_packet_len, buf_len
                ),
            ));
        }

        if buf_len < expected_packet_len {
            return Ok(None);
        }

        Ok(Some(buf.split_to(expected_packet_len)))
    }
}

impl Encoder<Bytes> for TacacsCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        buf.reserve(data.len());
        buf.put(data);
        Ok(())
    }
}
