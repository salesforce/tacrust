use bytes::{BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/*
 * Slightly modified version of `BytesCodec` from:
 * https://github.com/tokio-rs/tokio/blob/master/tokio-util/src/codec/bytes_codec.rs
 * The main difference between `BytesCodec` and `TacacsCodec` is that the latter requires
 * at least 16 bytes (minimum length for TACACS+ header + body) for creating a `Frame`
 *
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
        if buf.len() >= 16 {
            let len = buf.len();
            Ok(Some(buf.split_to(len)))
        } else {
            Ok(None)
        }
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
