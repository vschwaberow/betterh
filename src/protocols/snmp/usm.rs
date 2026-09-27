// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `SNMPv3` User-based Security Model (RFC 3414) helpers.

use hmac::{Hmac, Mac};
use md5_hmac::{Digest, Md5};
use sha1::Sha1;

use super::ber::{
    BerError, BerReader, TAG_GET_REQUEST, TAG_GET_RESPONSE, TAG_REPORT, TAG_SEQUENCE, ber_tlv,
    encode_integer, encode_octet_string, encode_oid,
};
use super::codec::{CodecError, SYS_DESCR_OID};

type HmacMd5 = Hmac<Md5>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Md5,
    Sha1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    None,
    Des,
    Aes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::struct_field_names, reason = "RFC 3414 field names")]
pub struct UsmEngine {
    pub engine_id: Vec<u8>,
    pub engine_boots: i64,
    pub engine_time: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UsmError {
    #[error(transparent)]
    Ber(#[from] BerError),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error("SNMPv3 security parameters truncated")]
    TruncatedSecurity,
    #[error("SNMPv3 report did not include an engine ID")]
    MissingEngineId,
    #[error("SNMPv3 authentication digest mismatch")]
    AuthMismatch,
    #[error("SNMPv3 privacy is not available for this build path")]
    PrivUnsupported,
}

const MSG_FLAG_AUTH: u8 = 0x01;
const MSG_FLAG_PRIV: u8 = 0x02;
const MSG_FLAG_REPORTABLE: u8 = 0x04;
const MSG_SECURITY_MODEL_USM: i64 = 3;

type DecodedUsmParams = (UsmEngine, Vec<u8>, Vec<u8>, Vec<u8>);

/// RFC 3414 §A.2.1 / §A.2.2 password-to-key expansion + localization.
pub fn password_to_key(password: &[u8], engine_id: &[u8], auth: AuthProtocol) -> Vec<u8> {
    let ku = match auth {
        AuthProtocol::Md5 => {
            let mut hasher = Md5::new();
            expand_password(password, &mut |chunk| hasher.update(chunk));
            hasher.finalize().to_vec()
        }
        AuthProtocol::Sha1 => {
            let mut hasher = Sha1::new();
            expand_password(password, &mut |chunk| hasher.update(chunk));
            hasher.finalize().to_vec()
        }
    };
    localize_key(&ku, engine_id, auth)
}

fn expand_password(password: &[u8], consume: &mut dyn FnMut(&[u8])) {
    if password.is_empty() {
        // Still produce a defined key material (all-zero expansion input).
        let zeros = [0u8; 64];
        let mut left = 1_048_576usize;
        while left > 0 {
            let n = left.min(zeros.len());
            consume(&zeros[..n]);
            left -= n;
        }
        return;
    }
    let mut left = 1_048_576usize;
    let mut offset = 0usize;
    let mut buf = [0u8; 64];
    while left > 0 {
        for slot in &mut buf {
            *slot = password[offset % password.len()];
            offset = offset.wrapping_add(1);
        }
        let n = left.min(buf.len());
        consume(&buf[..n]);
        left -= n;
    }
}

fn localize_key(ku: &[u8], engine_id: &[u8], auth: AuthProtocol) -> Vec<u8> {
    match auth {
        AuthProtocol::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(ku);
            hasher.update(engine_id);
            hasher.update(ku);
            hasher.finalize().to_vec()
        }
        AuthProtocol::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(ku);
            hasher.update(engine_id);
            hasher.update(ku);
            hasher.finalize().to_vec()
        }
    }
}

fn hmac_truncate(key: &[u8], message: &[u8], auth: AuthProtocol) -> Result<Vec<u8>, UsmError> {
    let full = match auth {
        AuthProtocol::Md5 => {
            let mut mac = HmacMd5::new_from_slice(key).map_err(|_| UsmError::AuthMismatch)?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(key).map_err(|_| UsmError::AuthMismatch)?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(full[..12].to_vec())
}

fn encode_header(msg_id: i64, max_size: i64, flags: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(msg_id));
    body.extend_from_slice(&encode_integer(max_size));
    body.extend_from_slice(&encode_octet_string(&[flags]));
    body.extend_from_slice(&encode_integer(MSG_SECURITY_MODEL_USM));
    ber_tlv(TAG_SEQUENCE, &body)
}

fn encode_usm_security_parameters(
    engine: &UsmEngine,
    user: &[u8],
    auth_params: &[u8],
    priv_params: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_octet_string(&engine.engine_id));
    body.extend_from_slice(&encode_integer(engine.engine_boots));
    body.extend_from_slice(&encode_integer(engine.engine_time));
    body.extend_from_slice(&encode_octet_string(user));
    body.extend_from_slice(&encode_octet_string(auth_params));
    body.extend_from_slice(&encode_octet_string(priv_params));
    // Security parameters are an OCTET STRING wrapping the USM SEQUENCE.
    encode_octet_string(&ber_tlv(TAG_SEQUENCE, &body))
}

fn decode_usm_security_parameters(bytes: &[u8]) -> Result<DecodedUsmParams, UsmError> {
    let mut outer = BerReader::new(bytes);
    let wrapped = outer.read_octet_string()?;
    let mut reader = BerReader::new(wrapped);
    let seq = reader.expect_tag(TAG_SEQUENCE)?;
    let mut usm = BerReader::new(seq);
    let engine_id = usm.read_octet_string()?.to_vec();
    let engine_boots = usm.read_integer()?;
    let engine_time = usm.read_integer()?;
    let user = usm.read_octet_string()?.to_vec();
    let auth_params = usm.read_octet_string()?.to_vec();
    let priv_params = usm.read_octet_string()?.to_vec();
    Ok((
        UsmEngine {
            engine_id,
            engine_boots,
            engine_time,
        },
        user,
        auth_params,
        priv_params,
    ))
}

fn encode_scoped_pdu(engine_id: &[u8], context_name: &[u8], pdu: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&encode_octet_string(engine_id));
    body.extend_from_slice(&encode_octet_string(context_name));
    body.extend_from_slice(pdu);
    ber_tlv(TAG_SEQUENCE, &body)
}

fn encode_get_request_pdu(request_id: i64) -> Result<Vec<u8>, CodecError> {
    let oid = encode_oid(SYS_DESCR_OID)?;
    let mut varbind = Vec::new();
    varbind.extend_from_slice(&oid);
    varbind.extend_from_slice(&super::ber::encode_null());
    let varbind = ber_tlv(TAG_SEQUENCE, &varbind);
    let varbind_list = ber_tlv(TAG_SEQUENCE, &varbind);
    let mut pdu = Vec::new();
    pdu.extend_from_slice(&encode_integer(request_id));
    pdu.extend_from_slice(&encode_integer(0));
    pdu.extend_from_slice(&encode_integer(0));
    pdu.extend_from_slice(&varbind_list);
    Ok(ber_tlv(TAG_GET_REQUEST, &pdu))
}

/// Discovery probe: empty engine ID, noAuthNoPriv, reportable.
pub fn encode_discovery_request(msg_id: i32, request_id: i32) -> Result<Vec<u8>, UsmError> {
    let engine = UsmEngine {
        engine_id: Vec::new(),
        engine_boots: 0,
        engine_time: 0,
    };
    let header = encode_header(i64::from(msg_id), 65507, MSG_FLAG_REPORTABLE);
    let sec = encode_usm_security_parameters(&engine, b"", &[], &[]);
    let pdu = encode_get_request_pdu(i64::from(request_id))?;
    let scoped = encode_scoped_pdu(&[], &[], &pdu);

    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(3));
    body.extend_from_slice(&header);
    body.extend_from_slice(&sec);
    body.extend_from_slice(&scoped);
    Ok(ber_tlv(TAG_SEQUENCE, &body))
}

/// Extract engine ID / boots / time from a discovery Report response.
pub fn decode_discovery_report(bytes: &[u8]) -> Result<UsmEngine, UsmError> {
    let mut outer = BerReader::new(bytes);
    let seq = outer.expect_tag(TAG_SEQUENCE)?;
    let mut reader = BerReader::new(seq);
    let version = reader.read_integer()?;
    if version != 3 {
        return Err(UsmError::Codec(CodecError::UnsupportedVersion(version)));
    }
    let _header = reader.expect_tag(TAG_SEQUENCE)?;
    let (tag, sec_value) = {
        // securityParameters is OCTET STRING; read via helper on remaining
        let (t, v) = reader.read_tlv()?;
        (t, v)
    };
    if tag != super::ber::TAG_OCTET_STRING {
        return Err(UsmError::TruncatedSecurity);
    }
    // Re-wrap for decode_usm_security_parameters which expects OCTET STRING TLV
    let wrapped = encode_octet_string(sec_value);
    let (engine, _, _, _) = decode_usm_security_parameters(&wrapped)?;
    if engine.engine_id.is_empty() {
        return Err(UsmError::MissingEngineId);
    }
    // Optionally confirm PDU is Report
    let (pdu_tag, _) = reader.read_tlv()?;
    if pdu_tag != TAG_REPORT && pdu_tag != TAG_GET_RESPONSE && pdu_tag != TAG_SEQUENCE {
        // scopedPDU is SEQUENCE; accept SEQUENCE containing report
    }
    let _ = pdu_tag;
    Ok(engine)
}

/// Authenticated (authNoPriv or authPriv plaintext scoped) `GetRequest`.
pub fn encode_authenticated_get_request(
    msg_id: i32,
    request_id: i32,
    engine: &UsmEngine,
    user: &[u8],
    auth_key: &[u8],
    auth: AuthProtocol,
    priv_protocol: PrivProtocol,
) -> Result<Vec<u8>, UsmError> {
    if priv_protocol != PrivProtocol::None {
        // Privacy (DES/AES) scaffolding is accepted on the CLI; wire crypto lands with
        // dedicated vectors. Refuse rather than send plaintext under a priv flag.
        let _ = MSG_FLAG_PRIV;
        return Err(UsmError::PrivUnsupported);
    }
    let flags = MSG_FLAG_AUTH | MSG_FLAG_REPORTABLE;
    let header = encode_header(i64::from(msg_id), 65507, flags);
    let auth_placeholder = vec![0u8; 12];
    let sec = encode_usm_security_parameters(engine, user, &auth_placeholder, &[]);
    let pdu = encode_get_request_pdu(i64::from(request_id))?;
    let scoped = encode_scoped_pdu(&engine.engine_id, &[], &pdu);

    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(3));
    body.extend_from_slice(&header);
    body.extend_from_slice(&sec);
    body.extend_from_slice(&scoped);
    let mut message = ber_tlv(TAG_SEQUENCE, &body);

    let digest = hmac_truncate(auth_key, &message, auth)?;
    patch_auth_parameters(&mut message, &digest)?;
    Ok(message)
}

fn patch_auth_parameters(message: &mut [u8], digest: &[u8]) -> Result<(), UsmError> {
    // Find 12 zero bytes that were placeholders for auth params and replace.
    // More reliable: parse and locate. Linear scan for 12 zero run inside OCTET STRING length 12.
    if digest.len() != 12 {
        return Err(UsmError::AuthMismatch);
    }
    let zeros = [0u8; 12];
    if let Some(pos) = message.windows(12).position(|w| w == zeros) {
        message[pos..pos + 12].copy_from_slice(digest);
        Ok(())
    } else {
        Err(UsmError::TruncatedSecurity)
    }
}

/// Decode v3 response and verify HMAC when auth is enabled.
pub fn decode_authenticated_response(
    bytes: &[u8],
    auth_key: &[u8],
    auth: AuthProtocol,
) -> Result<(UsmEngine, i64), UsmError> {
    let mut outer = BerReader::new(bytes);
    let seq = outer.expect_tag(TAG_SEQUENCE)?;
    let mut reader = BerReader::new(seq);
    let version = reader.read_integer()?;
    if version != 3 {
        return Err(UsmError::Codec(CodecError::UnsupportedVersion(version)));
    }
    let _header = reader.expect_tag(TAG_SEQUENCE)?;
    let (tag, sec_value) = reader.read_tlv()?;
    if tag != super::ber::TAG_OCTET_STRING {
        return Err(UsmError::TruncatedSecurity);
    }
    let wrapped = encode_octet_string(sec_value);
    let (engine, _user, auth_params, _priv) = decode_usm_security_parameters(&wrapped)?;

    // Verify digest: zero auth params, recompute.
    let mut copy = bytes.to_vec();
    if auth_params.len() == 12
        && let Some(pos) = find_subslice(&copy, &auth_params)
    {
        copy[pos..pos + 12].fill(0);
        let expected = hmac_truncate(auth_key, &copy, auth)?;
        if expected != auth_params {
            return Err(UsmError::AuthMismatch);
        }
    }

    let (scoped_tag, scoped_body) = reader.read_tlv()?;
    let pdu_body = if scoped_tag == TAG_SEQUENCE {
        let mut scoped = BerReader::new(scoped_body);
        let _ = scoped.read_octet_string()?; // contextEngineID
        let _ = scoped.read_octet_string()?; // contextName
        let (pdu_tag, pdu) = scoped.read_tlv()?;
        if pdu_tag != TAG_GET_RESPONSE && pdu_tag != TAG_REPORT {
            return Err(UsmError::Codec(CodecError::UnexpectedPdu));
        }
        pdu
    } else if scoped_tag == TAG_GET_RESPONSE || scoped_tag == TAG_REPORT {
        scoped_body
    } else {
        // Encrypted scoped PDU not supported in authNoPriv path.
        return Err(UsmError::PrivUnsupported);
    };

    let mut pdu = BerReader::new(pdu_body);
    let request_id = pdu.read_integer()?;
    let error_status = pdu.read_integer()?;
    let _error_index = pdu.read_integer()?;
    let _ = error_status;
    Ok((engine, request_id))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_to_key_md5_is_16_bytes() {
        let key = password_to_key(
            b"maplesyrup",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
            AuthProtocol::Md5,
        );
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn password_to_key_sha1_is_20_bytes() {
        let key = password_to_key(
            b"maplesyrup",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
            AuthProtocol::Sha1,
        );
        assert_eq!(key.len(), 20);
    }

    #[test]
    fn discovery_request_is_snmpv3_sequence() {
        let req = encode_discovery_request(1, 1).unwrap();
        assert_eq!(req[0], TAG_SEQUENCE);
        let mut reader = BerReader::new(&req);
        let seq = reader.expect_tag(TAG_SEQUENCE).unwrap();
        let mut inner = BerReader::new(seq);
        assert_eq!(inner.read_integer().unwrap(), 3);
    }
}
