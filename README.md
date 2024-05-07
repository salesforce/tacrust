# tacrust

TL;DR
TACACS+ implementation in Rust ([RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html), [context](https://salesforce.quip.com/ClnrA3p0oPbQ)), written as a replacement for the unmaintained [TACACS+ daemon from Shrubbery Networks](https://www.shrubbery.net/tac_plus/).


Tacrust is a grounds-up implementation of the TACACS+ protocol in Rust. The memory-safety features of Rust help in parsing the wire protocol safely, while asynchronous Rust  allows high-performance handling of large-scale traffic (>1 billion reqs/day across 2 dozen sites) that SFDC network devices generate. It serves as a stand-in replacement for the Shrubbery tac_plus daemon which has been unmaintained for a few years now. The following features were added on top to address specific use-cases:
    * Forward/proxy packets to upstream TACACS+ server for specific users/groups
    * Support multiple Authorization groups per user
    * Support for multiple pre-shared secrets (to enable blue-green secret rotation)
    * Ability to turn on debug at run time logging for specific clients (based on IP address)
    * Command and service definitions at user level (instead of requiring groups)
    * Supports integration with PAM for authentication. Also supports local password validation. 

Tacrust has been extensively tested to run with multiple vendors. Here are some of them:
- Cisco Catalyst & Nexus Switches
- F5 LB
- Juniper Firewall
- MRV Jumpbox
- Ciena Waveserver
- OpenGear Jumpbox
- Fortigate Firewall
- Cisco ASA, ASR
- SafeNet Encryptor

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

