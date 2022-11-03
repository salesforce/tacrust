use pretty_hex::pretty_hex;
use tacrust::{parser, serializer, AuthorizationStatus, Body};

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
    let reference_packet = include_bytes!("../packets/sample_packet_authen_continue");
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

#[test]
pub fn test_packet_author_reply() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_author_reply");
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
pub fn test_packet_accounting_request() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_acct_request");
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
pub fn test_packet_accounting_reply() {
    let key = "tackey".as_bytes();
    let reference_packet = include_bytes!("../packets/sample_packet_acct_reply");
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
pub fn test_shrubbery_response_parsing() {
    let key = "helloworld123".as_bytes();
    let packet = include_bytes!("../packets/shrubbery_author_response");
    let (_, parsed_packet) = parser::parse_packet(packet, key).unwrap();
    assert!(matches!(
        parsed_packet.body,
        Body::AuthorizationReply { .. }
    ));
    if let Body::AuthorizationReply {
        status,
        data: _,
        server_msg: _,
        args,
    } = parsed_packet.body
    {
        assert_eq!(status, AuthorizationStatus::AuthPassRepl);
        let ref_args = vec![
            b"service=shell".to_vec(),
            b"cmd=".to_vec(),
            b"cisco-av-pair=shell:roles=network-admin vsan-admin".to_vec(),
            b"priv-lvl=15".to_vec(),
            b"brcd-role=Admin".to_vec(),
            b"brcd-AV-Pair1=HomeLF=128;LFRoleList=admin:1-128".to_vec(),
            b"brcd-AV-Pair2=ChassisRole=admin".to_vec(),
        ];
        assert_eq!(args, ref_args);
    }
}
