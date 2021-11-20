use crate::Header;

pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Header> {
    let (input, versions) = nom::bytes::complete::take(1u32)(input)?;
    Ok((input, Header { versions }))
}
