use pretty_hex::pretty_hex;
use tacrust::{parser, serializer};

#[test]
pub fn test_packet_authen_start() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_authen_start");
    println!("\n >> Reference Packet\n");
    println!("{}", pretty_hex(reference_packet));

    let (_, parsed_packet) = parser::parse_packet(reference_packet, key).unwrap();
    println!("\n >> Parsed\n");
    println!("{:#?}", parsed_packet);

    let serialized = serializer::serialize_packet(&parsed_packet, key).unwrap();
    println!("\n >> Serialized\n");
    println!("{}", pretty_hex(&serialized));

    assert_eq!(&reference_packet[..], serialized);
}
