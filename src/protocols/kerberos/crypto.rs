// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Kerberos string-to-key and `PA-ENC-TIMESTAMP` helpers (via `kerbcore`).

use kerbcore::client::{
    KU_AS_REQ_PA_ENC_TS, encode_pa_enc_ts_enc, pa_enc_timestamp, unix_to_kerberos_time,
};
use kerbcore::keys::{Enctype, KerberosKey};
use kerbcore::types::{EncryptedData, PaData};

use super::codec::{ETYPE_AES128, ETYPE_AES256, ETYPE_RC4_HMAC};

/// Map an on-wire etype to `kerbcore` [`Enctype`] for supported pre-auth profiles.
#[must_use]
pub fn enctype_from_i32(etype: i32) -> Option<Enctype> {
    match etype {
        ETYPE_AES128 => Some(Enctype::Aes128CtsHmacSha1_96),
        ETYPE_AES256 => Some(Enctype::Aes256CtsHmacSha1_96),
        ETYPE_RC4_HMAC => Some(Enctype::Rc4Hmac),
        _ => None,
    }
}

/// Derive a long-term key for the selected etype.
///
/// AES profiles use PBKDF2 (`iterations`); RC4 ignores `iterations` and uses the NT hash.
#[must_use]
pub fn string_to_key(
    etype: i32,
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Option<KerberosKey> {
    let enctype = enctype_from_i32(etype)?;
    Some(KerberosKey::string_to_key(
        enctype, password, salt, iterations,
    ))
}

/// Build `PA-DATA` `PA-ENC-TIMESTAMP` for the current UTC time.
#[must_use]
pub fn build_pa_enc_timestamp(key: &KerberosKey, now_secs: u64, usec: i32) -> PaData {
    let ts_der = encode_pa_enc_ts_enc(&unix_to_kerberos_time(now_secs), usec);
    let cipher = key.encrypt(KU_AS_REQ_PA_ENC_TS, &ts_der);
    pa_enc_timestamp(&EncryptedData {
        etype: key.enctype().to_i32(),
        kvno: None,
        cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3962_aes256_string_to_key_roundtrip() {
        let key = string_to_key(ETYPE_AES256, "password", b"ATHENA.MIT.EDUraeburn", 1).unwrap();
        let pt = b"rfc3962-self-test";
        let ct = key.encrypt(1, pt);
        let dec = key.decrypt(1, &ct).expect("decrypt");
        assert_eq!(dec, pt);
        assert!(!ct.is_empty());
    }

    #[test]
    fn aes128_string_to_key_roundtrip() {
        let key = string_to_key(ETYPE_AES128, "password", b"ATHENA.MIT.EDUraeburn", 1).unwrap();
        let pt = b"aes128-self-test";
        let ct = key.encrypt(1, pt);
        assert_eq!(key.decrypt(1, &ct).unwrap(), pt);
        assert_eq!(key.enctype().to_i32(), ETYPE_AES128);
    }

    #[test]
    fn rc4_string_to_key_roundtrip() {
        let key = string_to_key(ETYPE_RC4_HMAC, "Password123", b"", 0).unwrap();
        let pt = b"rc4-self-test";
        let ct = key.encrypt(1, pt);
        assert_eq!(key.decrypt(1, &ct).unwrap(), pt);
        assert_eq!(key.enctype().to_i32(), ETYPE_RC4_HMAC);
    }

    #[test]
    fn pa_enc_timestamp_carries_key_etype() {
        let key = string_to_key(ETYPE_AES128, "secret", b"CORP.LOCALalice", 4096).unwrap();
        let pa = build_pa_enc_timestamp(&key, 1_700_000_000, 0);
        assert_eq!(pa.padata_type, 2);
        assert!(!pa.padata_value.is_empty());
    }

    #[test]
    fn unknown_etype_rejected() {
        assert!(string_to_key(99, "x", b"salt", 4096).is_none());
    }
}
