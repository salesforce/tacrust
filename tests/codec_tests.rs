use bytes::{Bytes, BytesMut};
use tacrust::tacacs_codec::TacacsCodec;
use tokio_util::codec::Encoder;

#[test]
fn bytes_encoder() {
    let mut codec = TacacsCodec::new();

    const INLINE_CAP: usize = 4 * 8 - 1;

    let mut buf = BytesMut::new();
    codec
        .encode(Bytes::from_static(&[0; INLINE_CAP + 1]), &mut buf)
        .unwrap();

    // Default capacity of Framed Read
    const INITIAL_CAPACITY: usize = 8 * 1024;

    let mut buf = BytesMut::with_capacity(INITIAL_CAPACITY);
    codec
        .encode(Bytes::from_static(&[0; INITIAL_CAPACITY + 1]), &mut buf)
        .unwrap();
}
