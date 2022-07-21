# tacrust

TACACS+ implementation in Rust ([RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html), [context](https://salesforce.quip.com/ClnrA3p0oPbQ)), written as a replacement for the unmaintained [TACACS+ daemon from Shrubbery Networks](https://www.shrubbery.net/tac_plus/).

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
- [x] Configuration
  - [x] ACLs
  - [x] Group membership
- [ ] Feature enhancements (things not supported in the Shrubbery daemon)
  - [x] Support multiple groups per user
  - [ ] Per client secret keys
  - [ ] Command and service definitions at user level (instead of requiring groups)
