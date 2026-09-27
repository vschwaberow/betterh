// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Kerberos v5 wire framing helpers (RFC 4120) built on `kerbcore`.

use kerbcore::client::{PA_ETYPE_INFO2, build_as_req, client_cname, parse_etype_info2};
use kerbcore::messages::{KdcRep, KrbError};
use kerbcore::types::PaData;

use crate::protocols::ProtocolError;

/// AES256-CTS-HMAC-SHA1-96 etype (RFC 3962).
pub const ETYPE_AES256: i32 = 18;
/// AES128-CTS-HMAC-SHA1-96 etype.
pub const ETYPE_AES128: i32 = 17;
/// RC4-HMAC etype (RFC 4757).
pub const ETYPE_RC4_HMAC: i32 = 23;

/// Prefers modern AES etypes, with RC4 as last resort for legacy DCs.
pub const DEFAULT_ETYPES: [i32; 3] = [ETYPE_AES256, ETYPE_AES128, ETYPE_RC4_HMAC];

/// Wrap a Kerberos PDU in the TCP/88 4-byte big-endian length prefix (RFC 4120 §7.2.2).
#[must_use]
pub fn frame_tcp(pdu: &[u8]) -> Vec<u8> {
    let len = u32::try_from(pdu.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4 + pdu.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pdu);
    out
}

/// Split a TCP length-prefixed Kerberos response.
///
/// # Errors
/// Returns an error when the buffer is truncated or claims an impossible length.
pub fn unframe_tcp(buf: &[u8]) -> Result<&[u8], ProtocolError> {
    if buf.len() < 4 {
        return Err(ProtocolError::HandshakeFailed(
            "Kerberos TCP frame truncated (need 4-byte length)".into(),
        ));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let body = buf.get(4..).unwrap_or(&[]);
    if body.len() < len {
        return Err(ProtocolError::HandshakeFailed(format!(
            "Kerberos TCP frame truncated: declared {len}, have {}",
            body.len()
        )));
    }
    Ok(&body[..len])
}

/// Build an AS-REQ (msg-type 10) for `user@realm`.
#[must_use]
pub fn encode_as_req(
    realm: &str,
    user: &str,
    nonce: u32,
    till: &str,
    padata: Vec<PaData>,
) -> Vec<u8> {
    build_as_req(
        realm,
        &client_cname(user),
        nonce,
        till,
        &DEFAULT_ETYPES,
        padata,
    )
}

/// Decoded KDC reply classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdcMessage {
    /// `AS-REP` (APPLICATION 11).
    AsRep,
    /// `KRB-ERROR` with RFC 4120 error-code and optional e-data.
    Error { code: i32, e_data: Option<Vec<u8>> },
}

/// Decode an unframed Kerberos PDU into [`KdcMessage`].
///
/// # Errors
/// Returns an error when neither AS-REP nor KRB-ERROR can be parsed.
pub fn decode_kdc_message(pdu: &[u8]) -> Result<KdcMessage, ProtocolError> {
    if let Ok(err) = KrbError::decode(pdu) {
        return Ok(KdcMessage::Error {
            code: err.error_code,
            e_data: err.e_data,
        });
    }
    if KdcRep::decode(pdu).is_ok() {
        return Ok(KdcMessage::AsRep);
    }
    Err(ProtocolError::HandshakeFailed(
        "Kerberos reply is neither AS-REP nor KRB-ERROR".into(),
    ))
}

/// Pre-auth material selected from KDC `ETYPE-INFO2` (or defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreAuthMaterial {
    pub salt: String,
    pub etype: i32,
    pub iterations: u32,
}

const DEFAULT_AES_ITERATIONS: u32 = 4096;
/// Cap hostile / enormous PBKDF2 counts from `s2kparams`.
const MAX_S2K_ITERATIONS: u32 = 5_000_000;

/// Prefer modern AES etypes, then RC4, matching [`DEFAULT_ETYPES`] order.
fn prefer_etype(offered: &[i32], forced: Option<i32>) -> i32 {
    if let Some(etype) = forced {
        return etype;
    }
    for preferred in DEFAULT_ETYPES {
        if offered.contains(&preferred) {
            return preferred;
        }
    }
    ETYPE_AES256
}

/// Extract salt, etype, and PBKDF2 iterations from `ETYPE-INFO2` inside KRB-ERROR `e-data`.
#[must_use]
pub fn preauth_from_edata(
    e_data: Option<&[u8]>,
    realm: &str,
    user: &str,
    forced_etype: Option<i32>,
) -> PreAuthMaterial {
    let fallback_salt = format!("{realm}{user}");
    let default = PreAuthMaterial {
        salt: fallback_salt.clone(),
        etype: forced_etype.unwrap_or(ETYPE_AES256),
        iterations: DEFAULT_AES_ITERATIONS,
    };
    let Some(bytes) = e_data else {
        return default;
    };
    let mut reader = kerbcore::der::Der::new(bytes);
    let Ok(seq) = reader.expect(kerbcore::der::TAG_SEQUENCE) else {
        return default;
    };
    let mut seq_reader = kerbcore::der::Der::new(seq);
    while !seq_reader.is_empty() {
        let Ok((_, item)) = seq_reader.read_tlv() else {
            break;
        };
        let Ok(pd) = PaData::decode(&kerbcore::der::tlv(kerbcore::der::TAG_SEQUENCE, item)) else {
            continue;
        };
        if pd.padata_type != PA_ETYPE_INFO2 {
            continue;
        }
        let Ok(entries) = parse_etype_info2(&pd.padata_value) else {
            continue;
        };
        let offered: Vec<i32> = entries.iter().map(|e| e.etype).collect();
        let etype = prefer_etype(&offered, forced_etype);
        let entry = entries
            .iter()
            .find(|e| e.etype == etype)
            .or_else(|| entries.first());
        let Some(entry) = entry else {
            return default;
        };
        let salt = entry.salt.clone().unwrap_or_else(|| fallback_salt.clone());
        let iterations = entry
            .s2k_iterations()
            .unwrap_or(DEFAULT_AES_ITERATIONS)
            .min(MAX_S2K_ITERATIONS);
        return PreAuthMaterial {
            salt,
            etype,
            iterations,
        };
    }
    default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_frame_roundtrip() {
        let pdu = b"NTLMSSP\0test";
        let framed = frame_tcp(pdu);
        assert_eq!(
            &framed[..4],
            &u32::try_from(pdu.len()).unwrap().to_be_bytes()
        );
        assert_eq!(unframe_tcp(&framed).unwrap(), pdu);
    }

    #[test]
    fn unframe_rejects_truncated() {
        assert!(unframe_tcp(&[0, 0, 0, 5, 1, 2]).is_err());
    }

    #[test]
    fn encode_as_req_is_application_tagged() {
        let der = encode_as_req(
            "CORP.LOCAL",
            "alice",
            0x1234_5678,
            "20300101000000Z",
            vec![],
        );
        // APPLICATION 10 = 0x6A
        assert_eq!(der.first().copied(), Some(0x6A));
        assert!(der.len() > 32);
    }

    #[test]
    fn prefer_etype_order() {
        assert_eq!(
            prefer_etype(&[ETYPE_RC4_HMAC, ETYPE_AES128, ETYPE_AES256], None),
            ETYPE_AES256
        );
        assert_eq!(
            prefer_etype(&[ETYPE_RC4_HMAC, ETYPE_AES128], None),
            ETYPE_AES128
        );
        assert_eq!(prefer_etype(&[ETYPE_RC4_HMAC], None), ETYPE_RC4_HMAC);
        assert_eq!(
            prefer_etype(&[ETYPE_AES256], Some(ETYPE_RC4_HMAC)),
            ETYPE_RC4_HMAC
        );
    }

    #[test]
    fn preauth_fallback_without_edata() {
        let m = preauth_from_edata(None, "CORP.LOCAL", "alice", None);
        assert_eq!(m.salt, "CORP.LOCALalice");
        assert_eq!(m.etype, ETYPE_AES256);
        assert_eq!(m.iterations, 4096);
    }

    #[test]
    fn decode_krb_error_preauth_required() {
        let err = KrbError {
            stime: kerbcore::types::KerberosTime("20200101000000Z".into()),
            susec: 0,
            error_code: 25,
            realm: "CORP.LOCAL".into(),
            sname: kerbcore::types::PrincipalName {
                name_type: 2,
                name_string: vec!["krbtgt".into(), "CORP.LOCAL".into()],
            },
            e_text: None,
            e_data: None,
        };
        let der = err.encode();
        match decode_kdc_message(&der).unwrap() {
            KdcMessage::Error { code, .. } => assert_eq!(code, 25),
            other @ KdcMessage::AsRep => panic!("unexpected {other:?}"),
        }
    }
}
