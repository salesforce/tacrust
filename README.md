# tacrust

TACACS+ implementation in Rust ([RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html), [context](https://salesforce.quip.com/ClnrA3p0oPbQ))

## Status

- [x] Packet header parsing
- [x] Packet body extraction
- [x] Packet body decryption
- [ ] Packet body parsing
  - [x] AuthenticationStart packet parsing
  - [ ] AuthenticationContinue packet parsing
  - [ ] AuthorizationRequest packet parsing
  - [ ] AccountingRequest packet parsing
- [ ] Packet serialization
  - [x] AuthenticationReply serialization
  - [ ] AuthorizationReply serialization
  - [ ] AccountingReply serialization
- [ ] Networking
  - [ ] Packet routing
  - [ ] Single connect mode
- [ ] Configuration support
  - [ ] Client stanzas
  - [ ] Client secret keys

## Testing

```
$ cargo test -- --nocapture
```

```
   Compiling tacrust v0.1.0 (/home/k.khan/rust/tacrust)
    Finished test [unoptimized + debuginfo] target(s) in 0.46s
     Running unittests (target/debug/deps/tacrust-5993dd21aefa1bc8)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/parser_tests.rs (target/debug/deps/parser_tests-1027d2bf91c9c163)

running 1 test
 >> Reference Packet

Length: 50 (0x32) bytes
0000:   c0 01 01 00  8c 44 5c b6  00 00 00 26  c3 04 c4 8a   .....D\....&....
0010:   04 20 77 92  56 d5 fe f6  ca 25 60 d7  f3 89 0a e0   . w.V....%`.....
0020:   f0 5f 0b 5b  0d 24 3f 77  2a 08 93 8f  f4 60 fd f1   ._.[.$?w*....`..
0030:   f8 b2                                                ..

 >> Parsed

Packet {
    header: Header {
        major_version: 12,
        minor_version: 0,
        version: 192,
        type: Authentication,
        seq_no: 1,
        flags: PacketFlags {
            unencrypted: false,
            single_connect: false,
        },
        session_id: 2353290422,
    },
    body: AuthenticationStart {
        action: 1,
        priv_lvl: 0,
        authen_type: 1,
        authen_service: 1,
        user: [
            107,
            114,
            107,
            104,
            97,
            110,
        ],
        port: [
            112,
            121,
            116,
            104,
            111,
            110,
            95,
            116,
            116,
            121,
            48,
        ],
        rem_addr: [
            112,
            121,
            116,
            104,
            111,
            110,
            95,
            100,
            101,
            118,
            105,
            99,
            101,
        ],
        data: [],
    },
}

 >> Serialized

Length: 50 (0x32) bytes
0000:   c0 01 01 00  8c 44 5c b6  00 00 00 26  c3 04 c4 8a   .....D\....&....
0010:   04 20 77 92  56 d5 fe f6  ca 25 60 d7  f3 89 0a e0   . w.V....%`.....
0020:   f0 5f 0b 5b  0d 24 3f 77  2a 08 93 8f  f4 60 fd f1   ._.[.$?w*....`..
0030:   f8 b2                                                ..
test test_packet_authen_start ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests tacrust

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

