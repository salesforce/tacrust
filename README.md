# tacrust

TACACS+ implementation in Rust ([RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html), [context](https://salesforce.quip.com/ClnrA3p0oPbQ))

Hardware test matrix and instructions at: [sfdc.co/tacrust-testing](https://sfdc.co/tacrust-testing)

## Status

- [x] Packet header parsing
- [x] Packet body extraction
- [x] Packet body decryption
- [x] Packet body parsing
  - [x] AuthenticationStart packet parsing
  - [x] AuthenticationContinue packet parsing
  - [x] AuthorizationRequest packet parsing
  - [x] AccountingRequest packet parsing
- [x] Packet serialization
  - [x] AuthenticationReply serialization
  - [x] AuthorizationReply serialization
  - [x] AccountingReply serialization
- [x] Networking
  - [x] Packet routing
  - [x] Regex-based ACLs
  - [x] Single connect mode
- [ ] Configuration
  - [x] ACLs
  - [x] Group membership
  - [ ] Per client secret keys
  - [ ] Command and service definitions at user level (instead of requiring groups)
