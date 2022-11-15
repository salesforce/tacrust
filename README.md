# tacrust

TACACS+ implementation in Rust ([RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html), [context](https://salesforce.quip.com/ClnrA3p0oPbQ)), written as a replacement for the unmaintained [TACACS+ daemon from Shrubbery Networks](https://www.shrubbery.net/tac_plus/).

* AuthZ testing matrix to model the original daemon's behavior for reference: [sfdc.co/shrubbery-authz-matrix](https://sfdc.co/shrubbery-authz-matrix)
* Hardware test matrix and instructions at: [sfdc.co/tacrust-testing](https://sfdc.co/tacrust-testing)

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
- [x] Feature enhancements (things not supported in the Shrubbery daemon)
  - [x] Forward/proxy packets to upstream TACACS+ server based for specific users
  - [x] Support multiple groups per user
  - [x] Support for [multiple keys](https://git.soma.salesforce.com/Kuleana/tacacs/pull/3)
  - [x] Support for [debug logging for specific clients](https://git.soma.salesforce.com/Kuleana/tacrust/pull/215)
  - [x] Command and service definitions at user level (instead of requiring groups)
  - [x] Debug logging based on client IP
- [ ] Future improvements
  - [ ] Per client secret keys (obstacle: groups are not known until packet is decrypted)

