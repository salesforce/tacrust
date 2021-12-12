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

#[test]
pub fn test_packet_authen_reply() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_authen_reply");
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

#[test]
pub fn test_no_panic() {
    let key = "tackey".as_bytes();
    let input: [u8; 20] = [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
    let result = parser::parse_packet(&input, key);

    assert_eq!(result.is_err(), true);
}

#[test]
pub fn test_bad_key() {
    let key = "badkey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_authen_reply");
    let result = parser::parse_packet(reference_packet, key);

    println!("\n >> Result: {:?}", result);

    assert_eq!(result.is_err(), true);
}

#[test]
pub fn test_packet_authen_continue() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_authen_reply_2");
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

#[test]
pub fn test_packet_author_request() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_author_request");
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
