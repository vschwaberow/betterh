// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Kerberos string-to-key and `PA-ENC-TIMESTAMP` helpers (via `kerbcore`).

use kerbcore::client::{
    KU_AS_REQ_PA_ENC_TS, encode_pa_enc_ts_enc, pa_enc_timestamp, unix_to_kerberos_time,
};
use kerbcore::keys::{Enctype, KerberosKey};
use kerbcore::types::{EncryptedData, PaData};

use super::codec::ETYPE_AES256;

/// Derive an AES-256 long-term key (PBKDF2 iterations default 4096).
#[must_use]
pub fn aes256_string_to_key(password: &str, salt: &[u8], iterations: u32) -> KerberosKey {
    KerberosKey::string_to_key(Enctype::Aes256CtsHmacSha1_96, password, salt, iterations)
}

/// Build `PA-DATA` `PA-ENC-TIMESTAMP` for the current UTC time.
#[must_use]
pub fn build_pa_enc_timestamp(key: &KerberosKey, now_secs: u64, usec: i32) -> PaData {
    let ts_der = encode_pa_enc_ts_enc(&unix_to_kerberos_time(now_secs), usec);
    let cipher = key.encrypt(KU_AS_REQ_PA_ENC_TS, &ts_der);
    pa_enc_timestamp(&EncryptedData {
        etype: ETYPE_AES256,
        kvno: None,
        cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3962 salt/password parameters must produce a usable AES-256 key (round-trip).
    #[test]
    fn rfc3962_aes256_string_to_key_roundtrip() {
        let key = aes256_string_to_key("password", b"ATHENA.MIT.EDUraeburn", 1);
        let pt = b"rfc3962-self-test";
        let ct = key.encrypt(1, pt);
        let dec = key.decrypt(1, &ct).expect("decrypt");
        assert_eq!(dec, pt);
        assert!(!ct.is_empty());
    }

    #[test]
    fn pa_enc_timestamp_is_nonempty() {
        let key = aes256_string_to_key("secret", b"CORP.LOCALalice", 4096);
        let pa = build_pa_enc_timestamp(&key, 1_700_000_000, 0);
        assert_eq!(pa.padata_type, 2);
        assert!(!pa.padata_value.is_empty());
    }
}
