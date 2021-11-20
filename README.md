# tacrust

TACACS+ implementation in Rust ([RFC 8907](https://datatracker.ietf.org/doc/html/rfc8907))

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
  - [ ] AuthenticationReply serialization
  - [ ] AuthorizationReply serialization
  - [ ] AccountingReply serialization
- [ ] Configuration support
  - [ ] Client stanzas
  - [ ] Client secret keys

## Testing

```
$ cargo test -- --nocapture
```

```
   Compiling tacrust v0.1.0 (/home/k.khan/rust/tacrust)
    Finished test [unoptimized + debuginfo] target(s) in 0.73s
     Running unittests (target/debug/deps/tacrust-64b9a83a787ed433)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/parser_tests.rs (target/debug/deps/parser_tests-f0e744919812c729)

running 1 test
Packet:
Length: 50 (0x32) bytes
0000:   c0 01 01 00  8c 44 5c b6  00 00 00 26  c3 04 c4 8a   .....D\....&....
0010:   04 20 77 92  56 d5 fe f6  ca 25 60 d7  f3 89 0a e0   . w.V....%`.....
0020:   f0 5f 0b 5b  0d 24 3f 77  2a 08 93 8f  f4 60 fd f1   ._.[.$?w*....`..
0030:   f8 b2                                                ..
Result: Ok(
    (
        [
            195,
            4,
            196,
            138,
            4,
            32,
            119,
            146,
            86,
            213,
            254,
            246,
            202,
            37,
            96,
            215,
            243,
            137,
            10,
            224,
            240,
            95,
            11,
            91,
            13,
            36,
            63,
            119,
            42,
            8,
            147,
            143,
            244,
            96,
            253,
            241,
            248,
            178,
        ],
        Packet {
            header: Header {
                major_version: 12,
                minor_version: 0,
                version: 192,
                type: Authentication,
                seq_no: 1,
                flags: 0,
                session_id: 2353290422,
                length: 38,
            },
            body: AuthenticationStart {
                action: 1,
                priv_lvl: 0,
                authen_type: 1,
                authen_service: 1,
                user_len: 6,
                port_len: 11,
                rem_addr_len: 13,
                data_len: 0,
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
        },
    ),
)
test test_packet_1 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests tacrust

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```
