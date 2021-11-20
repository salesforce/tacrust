pub mod parser;

#[derive(Clone, Debug)]
pub struct Header<'a> {
    versions: &'a [u8],
}
