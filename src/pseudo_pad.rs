use byteorder::{BigEndian, WriteBytesExt};

pub const MD5_DIGEST_LENGTH: usize = 16;

pub struct PseudoPad<'a> {
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
