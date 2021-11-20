use tacrust::parser;

#[test]
pub fn test_packet_1() {
    let bytes = include_bytes!("../packets/sample_packet_1");
    println!("Bytes: {:?}", bytes);
    let result = parser::parse(bytes);
    println!("Result: {:?}", result);
}
