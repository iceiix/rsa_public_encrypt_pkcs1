# rsa_public_encrypt_pkcs1

[![crate](https://img.shields.io/crates/v/rsa_public_encrypt_pkcs1.svg)](https://crates.io/crates/rsa_public_encrypt_pkcs1)
[![documentation](https://docs.rs/rsa_public_encrypt_pkcs1/badge.svg)](https://docs.rs/rsa_public_encrypt_pkcs1)
[![Travis status](https://travis-ci.org/rust-rsa_public_encrypt_pkcs1/rsa_public_encrypt_pkcs1.svg?branch=master)](https://travis-ci.org/rust-rsa_public_encrypt_pkcs1/rsa_public_encrypt_pkcs1)

RSA PKCS#1 public key encryption using an ASN.1 DER encoded public key.

Implemented in pure Rust based on [RFC8017: PKCS #1: RSA Cryptography Specifications Version 2.2, section 7.2.1 RSAES-PKCS1-v1_5](https://tools.ietf.org/html/rfc8017#section-7.2.1).

**Warning: Use at your own risk. Not extensively tested or reviewed. May contain serious bugs.**

See also: [rust-openssl](https://crates.io/crates/openssl). Example code written for rust-openssl:

```rust
        let mut shared_e = vec![0; rsa.size() as usize];
        let mut token_e = vec![0; rsa.size() as usize];
        rsa.public_encrypt(&shared, &mut shared_e, Padding::PKCS1)?;
        rsa.public_encrypt(&packet.verify_token.data, &mut token_e, Padding::PKCS1)?;
```

could be rewritten using this crate as follows:

```rust
        let shared_e = rsa_public_encrypt_pkcs1::encrypt(&packet.public_key.data, &shared)?;
        let token_e = rsa_public_encrypt_pkcs1::encrypt(&packet.public_key.data, &packet.verify_token.data)?;
```

