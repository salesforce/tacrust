use argon2::{verify_encoded, Config};
use tacrust::{hash::PasswordHash, AuthenticationContinueFlags, Body};

#[test]
pub fn test_password_hash() {
    let val = Body::AuthenticationContinue {
        flags: AuthenticationContinueFlags { abort: false },
        user: vec![b't', b'e', b's', b't'],
        data: vec![],
    };
    let hash = val.generate_hash(Config::default()).unwrap();
    let result = verify_encoded(&hash, &[b't', b'e', b's', b't']).unwrap();
    assert!(result)
}
