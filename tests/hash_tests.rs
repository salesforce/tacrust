use argon2::{verify_encoded, Config};
use std::io::{Read, Seek, SeekFrom, Write};
use tacrust::{hash::PasswordHash, AuthenticationContinueFlags, Body};
use tempfile::tempfile;

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

#[test]
pub fn test_pwd_hash_file() {
    let mut hashfile = tempfile().unwrap();
    let val = Body::AuthenticationContinue {
        flags: AuthenticationContinueFlags { abort: false },
        user: vec![b't', b'e', b's', b's'],
        data: vec![],
    };
    let hash = val.generate_hash(Config::default()).unwrap();
    let _ = hashfile.write(&hash.as_bytes());
    hashfile.seek(SeekFrom::Start(0)).unwrap();
    let mut hashread = String::new();
    hashfile.read_to_string(&mut hashread).unwrap();
    let result = verify_encoded(&hashread, &[b't', b'e', b's', b's']).unwrap();
    assert!(result);
}
