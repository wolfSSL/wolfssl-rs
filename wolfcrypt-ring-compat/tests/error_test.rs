// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright wolfSSL Inc.
// SPDX-License-Identifier: MIT

use ring::error;

#[cfg(feature = "std")]
#[test]
fn unspecified_implements_std_error() {
    fn require_std_error<T: std::error::Error>() {}
    require_std_error::<error::Unspecified>();
}

#[cfg(feature = "std")]
#[test]
fn key_rejected_implements_std_error() {
    fn require_std_error<T: std::error::Error>() {}
    require_std_error::<error::KeyRejected>();
}

#[test]
fn unspecified_is_send_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<error::Unspecified>();
}

#[test]
fn key_rejected_is_send_sync() {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<error::KeyRejected>();
}

#[test]
fn unspecified_debug() {
    let err = error::Unspecified;
    let debug = format!("{:?}", err);
    assert!(!debug.is_empty());
}

#[test]
fn unspecified_display() {
    let err = error::Unspecified;
    let display = format!("{}", err);
    assert!(!display.is_empty());
}

#[test]
fn unspecified_eq() {
    assert_eq!(error::Unspecified, error::Unspecified);
}

#[test]
fn unspecified_clone_copy() {
    let err = error::Unspecified;
    let cloned = err.clone();
    let copied = err;
    assert_eq!(err, cloned);
    assert_eq!(err, copied);
}

#[test]
fn key_rejected_from_invalid_key() {
    // Get a real KeyRejected by trying to parse garbage as a key
    use ring::signature;

    let garbage = &[0u8; 10];
    let err = signature::Ed25519KeyPair::from_pkcs8(garbage).unwrap_err();

    // KeyRejected: Debug, Display, description_
    let debug = format!("{:?}", err);
    assert!(!debug.is_empty(), "KeyRejected Debug should not be empty");

    let display = format!("{}", err);
    assert!(!display.is_empty(), "KeyRejected Display should not be empty");

    let desc = err.description_();
    assert!(
        !desc.is_empty(),
        "KeyRejected description should not be empty"
    );
}

#[test]
fn key_rejected_clone_copy() {
    use ring::signature;

    let garbage = &[0u8; 10];
    let err = signature::Ed25519KeyPair::from_pkcs8(garbage).unwrap_err();

    let cloned = err.clone();
    let copied = err;

    assert_eq!(cloned.description_(), copied.description_());
}
