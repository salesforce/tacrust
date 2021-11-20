use pretty_hex::pretty_hex;
use tacrust::parser;

#[test]
pub fn test_packet_1() {
    let bytes = include_bytes!("../packets/sample_packet_1");
    println!("Packet:");
    println!("{}", pretty_hex(bytes));
    let result = parser::parse_packet(bytes, "tackey".as_bytes());
    println!("Result: {:#?}", result);
}
