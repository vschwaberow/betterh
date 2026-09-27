// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `SNMPv3` User-based Security Model (RFC 3414) helpers.

use aes::Aes128;
use aes::cipher::{
    AsyncStreamCipher, BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::NoPadding,
};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cfb_mode::{Decryptor as CfbDecryptor, Encryptor as CfbEncryptor};
use des::Des;
use hmac::{Hmac, Mac};
use md5_hmac::{Digest, Md5};
use sha1::Sha1;

use super::ber::{
    BerError, BerReader, TAG_GET_REQUEST, TAG_GET_RESPONSE, TAG_OCTET_STRING, TAG_REPORT,
    TAG_SEQUENCE, ber_tlv, encode_integer, encode_octet_string, encode_oid,
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
    #[error("SNMPv3 privacy key too short")]
    PrivKeyTooShort,
    #[error("SNMPv3 privacy parameters invalid")]
    PrivParamsInvalid,
    #[error("SNMPv3 privacy decrypt failed")]
    PrivDecryptFailed,
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

/// First 16 octets of the localized auth key (DES / AES-128 priv material).
#[must_use]
pub fn password_to_priv_key(
    password: &[u8],
    engine_id: &[u8],
    auth: AuthProtocol,
    priv_protocol: PrivProtocol,
) -> Vec<u8> {
    if priv_protocol == PrivProtocol::None {
        return Vec::new();
    }
    let key = password_to_key(password, engine_id, auth);
    key.get(..16).map_or_else(Vec::new, <[u8]>::to_vec)
}

fn expand_password(password: &[u8], consume: &mut dyn FnMut(&[u8])) {
    if password.is_empty() {
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

fn trunc16(key: &[u8]) -> Result<[u8; 16], UsmError> {
    let Some(slice) = key.get(..16) else {
        return Err(UsmError::PrivKeyTooShort);
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(slice);
    Ok(out)
}

/// DES salt: `engineBoots` (4) || local counter (4). AES salt: 8-byte counter.
#[must_use]
pub fn make_priv_params(priv_protocol: PrivProtocol, engine: &UsmEngine, salt: u64) -> [u8; 8] {
    match priv_protocol {
        PrivProtocol::None => [0u8; 8],
        PrivProtocol::Des => {
            let boots = u32::try_from(engine.engine_boots.max(0)).unwrap_or(u32::MAX);
            let mut out = [0u8; 8];
            out[..4].copy_from_slice(&boots.to_be_bytes());
            out[4..].copy_from_slice(&salt.to_be_bytes()[4..]);
            out
        }
        PrivProtocol::Aes => salt.to_be_bytes(),
    }
}

fn des_iv(priv_key: &[u8; 16], salt: [u8; 8]) -> [u8; 8] {
    let mut iv = [0u8; 8];
    for (i, byte) in iv.iter_mut().enumerate() {
        *byte = salt[i] ^ priv_key[8 + i];
    }
    iv
}

fn aes_iv(engine: &UsmEngine, salt: [u8; 8]) -> [u8; 16] {
    let boots = u32::try_from(engine.engine_boots.max(0)).unwrap_or(u32::MAX);
    let time = u32::try_from(engine.engine_time.max(0)).unwrap_or(u32::MAX);
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(&salt);
    iv
}

fn encrypt_scoped(
    plaintext: &[u8],
    engine: &UsmEngine,
    priv_protocol: PrivProtocol,
    priv_key: &[u8],
    salt: [u8; 8],
) -> Result<Vec<u8>, UsmError> {
    let key = trunc16(priv_key)?;
    match priv_protocol {
        PrivProtocol::None => Ok(plaintext.to_vec()),
        PrivProtocol::Des => {
            let iv = des_iv(&key, salt);
            let des_key: [u8; 8] = key[..8].try_into().map_err(|_| UsmError::PrivKeyTooShort)?;
            let mut buf = plaintext.to_vec();
            let pad = (8 - (buf.len() % 8)) % 8;
            buf.extend(std::iter::repeat_n(0u8, pad));
            let encryptor = CbcEncryptor::<Des>::new_from_slices(&des_key, &iv)
                .map_err(|_| UsmError::PrivParamsInvalid)?;
            let len = buf.len();
            let out = encryptor
                .encrypt_padded_mut::<NoPadding>(&mut buf, len)
                .map_err(|_| UsmError::PrivParamsInvalid)?;
            Ok(out.to_vec())
        }
        PrivProtocol::Aes => {
            let iv = aes_iv(engine, salt);
            let mut buf = plaintext.to_vec();
            let encryptor = CfbEncryptor::<Aes128>::new_from_slices(&key, &iv)
                .map_err(|_| UsmError::PrivParamsInvalid)?;
            encryptor.encrypt(&mut buf);
            Ok(buf)
        }
    }
}

fn decrypt_scoped(
    ciphertext: &[u8],
    engine: &UsmEngine,
    priv_protocol: PrivProtocol,
    priv_key: &[u8],
    salt: [u8; 8],
) -> Result<Vec<u8>, UsmError> {
    let key = trunc16(priv_key)?;
    match priv_protocol {
        PrivProtocol::None => Ok(ciphertext.to_vec()),
        PrivProtocol::Des => {
            if !ciphertext.len().is_multiple_of(8) || ciphertext.is_empty() {
                return Err(UsmError::PrivDecryptFailed);
            }
            let iv = des_iv(&key, salt);
            let des_key: [u8; 8] = key[..8].try_into().map_err(|_| UsmError::PrivKeyTooShort)?;
            let decryptor = CbcDecryptor::<Des>::new_from_slices(&des_key, &iv)
                .map_err(|_| UsmError::PrivParamsInvalid)?;
            let mut buf = ciphertext.to_vec();
            let plain = decryptor
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|_| UsmError::PrivDecryptFailed)?;
            trim_ber_scoped(plain)
        }
        PrivProtocol::Aes => {
            let iv = aes_iv(engine, salt);
            let mut buf = ciphertext.to_vec();
            let decryptor = CfbDecryptor::<Aes128>::new_from_slices(&key, &iv)
                .map_err(|_| UsmError::PrivParamsInvalid)?;
            decryptor.decrypt(&mut buf);
            Ok(buf)
        }
    }
}

fn trim_ber_scoped(plain: &[u8]) -> Result<Vec<u8>, UsmError> {
    let mut reader = BerReader::new(plain);
    let (tag, body) = reader.read_tlv().map_err(|_| UsmError::PrivDecryptFailed)?;
    if tag != TAG_SEQUENCE {
        return Err(UsmError::PrivDecryptFailed);
    }
    let rebuilt = ber_tlv(tag, body);
    if !plain.starts_with(&rebuilt) {
        return Err(UsmError::PrivDecryptFailed);
    }
    Ok(rebuilt)
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
    let (tag, sec_value) = reader.read_tlv()?;
    if tag != TAG_OCTET_STRING {
        return Err(UsmError::TruncatedSecurity);
    }
    let wrapped = encode_octet_string(sec_value);
    let (engine, _, _, _) = decode_usm_security_parameters(&wrapped)?;
    if engine.engine_id.is_empty() {
        return Err(UsmError::MissingEngineId);
    }
    let (pdu_tag, _) = reader.read_tlv()?;
    let _ = pdu_tag;
    Ok(engine)
}

/// Authenticated `GetRequest` (authNoPriv or authPriv).
#[expect(
    clippy::too_many_arguments,
    reason = "USM wire encode needs msg/request ids, engine, user, auth+priv material together"
)]
pub fn encode_authenticated_get_request(
    msg_id: i32,
    request_id: i32,
    engine: &UsmEngine,
    user: &[u8],
    auth_key: &[u8],
    auth: AuthProtocol,
    priv_protocol: PrivProtocol,
    priv_key: &[u8],
    priv_salt: u64,
) -> Result<Vec<u8>, UsmError> {
    let mut flags = MSG_FLAG_AUTH | MSG_FLAG_REPORTABLE;
    let auth_placeholder = vec![0u8; 12];
    let pdu = encode_get_request_pdu(i64::from(request_id))?;
    let scoped_plain = encode_scoped_pdu(&engine.engine_id, &[], &pdu);

    let (priv_params, scoped_wire) = if priv_protocol == PrivProtocol::None {
        (Vec::new(), scoped_plain)
    } else {
        flags |= MSG_FLAG_PRIV;
        let salt = make_priv_params(priv_protocol, engine, priv_salt);
        let cipher = encrypt_scoped(&scoped_plain, engine, priv_protocol, priv_key, salt)?;
        (salt.to_vec(), encode_octet_string(&cipher))
    };

    let header = encode_header(i64::from(msg_id), 65507, flags);
    let sec = encode_usm_security_parameters(engine, user, &auth_placeholder, &priv_params);

    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(3));
    body.extend_from_slice(&header);
    body.extend_from_slice(&sec);
    body.extend_from_slice(&scoped_wire);
    let mut message = ber_tlv(TAG_SEQUENCE, &body);

    let digest = hmac_truncate(auth_key, &message, auth)?;
    patch_auth_parameters(&mut message, &digest)?;
    Ok(message)
}

fn patch_auth_parameters(message: &mut [u8], digest: &[u8]) -> Result<(), UsmError> {
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

/// Decode v3 response, verify HMAC, and decrypt scoped PDU when privacy is enabled.
pub fn decode_authenticated_response(
    bytes: &[u8],
    auth_key: &[u8],
    auth: AuthProtocol,
    priv_protocol: PrivProtocol,
    priv_key: &[u8],
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
    if tag != TAG_OCTET_STRING {
        return Err(UsmError::TruncatedSecurity);
    }
    let wrapped = encode_octet_string(sec_value);
    let (engine, _user, auth_params, priv_params) = decode_usm_security_parameters(&wrapped)?;

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
    let scoped_plain = if scoped_tag == TAG_OCTET_STRING {
        if priv_protocol == PrivProtocol::None {
            return Err(UsmError::PrivParamsInvalid);
        }
        let salt: [u8; 8] = priv_params
            .as_slice()
            .try_into()
            .map_err(|_| UsmError::PrivParamsInvalid)?;
        decrypt_scoped(scoped_body, &engine, priv_protocol, priv_key, salt)?
    } else if scoped_tag == TAG_SEQUENCE {
        encode_scoped_from_body(scoped_body)
    } else if scoped_tag == TAG_GET_RESPONSE || scoped_tag == TAG_REPORT {
        return parse_pdu_request_id(scoped_body).map(|id| (engine, id));
    } else {
        return Err(UsmError::Codec(CodecError::UnexpectedPdu));
    };

    let mut scoped = BerReader::new(&scoped_plain);
    let seq = scoped.expect_tag(TAG_SEQUENCE)?;
    let mut inner = BerReader::new(seq);
    let _ = inner.read_octet_string()?;
    let _ = inner.read_octet_string()?;
    let (pdu_tag, pdu) = inner.read_tlv()?;
    if pdu_tag != TAG_GET_RESPONSE && pdu_tag != TAG_REPORT && pdu_tag != TAG_GET_REQUEST {
        return Err(UsmError::Codec(CodecError::UnexpectedPdu));
    }
    let request_id = parse_pdu_request_id(pdu)?;
    Ok((engine, request_id))
}

fn encode_scoped_from_body(body: &[u8]) -> Vec<u8> {
    ber_tlv(TAG_SEQUENCE, body)
}

fn parse_pdu_request_id(pdu_body: &[u8]) -> Result<i64, UsmError> {
    let mut pdu = BerReader::new(pdu_body);
    let request_id = pdu.read_integer()?;
    let _error_status = pdu.read_integer()?;
    let _error_index = pdu.read_integer()?;
    Ok(request_id)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_engine() -> UsmEngine {
        UsmEngine {
            engine_id: b"\x80\x00\x1f\x88\x80\x01".to_vec(),
            engine_boots: 1,
            engine_time: 42,
        }
    }

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

    #[test]
    fn priv_key_truncates_to_16() {
        let engine = sample_engine();
        let key = password_to_priv_key(
            b"secret",
            &engine.engine_id,
            AuthProtocol::Sha1,
            PrivProtocol::Aes,
        );
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn aes_scoped_roundtrip() {
        let engine = sample_engine();
        let priv_key = password_to_priv_key(
            b"privpass",
            &engine.engine_id,
            AuthProtocol::Sha1,
            PrivProtocol::Aes,
        );
        let pdu = encode_get_request_pdu(7).unwrap();
        let plain = encode_scoped_pdu(&engine.engine_id, &[], &pdu);
        let salt = make_priv_params(PrivProtocol::Aes, &engine, 0x0123_4567_89ab_cdef);
        let cipher = encrypt_scoped(&plain, &engine, PrivProtocol::Aes, &priv_key, salt).unwrap();
        let recovered =
            decrypt_scoped(&cipher, &engine, PrivProtocol::Aes, &priv_key, salt).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn des_scoped_roundtrip() {
        let engine = sample_engine();
        let priv_key = password_to_priv_key(
            b"privpass",
            &engine.engine_id,
            AuthProtocol::Md5,
            PrivProtocol::Des,
        );
        let pdu = encode_get_request_pdu(9).unwrap();
        let plain = encode_scoped_pdu(&engine.engine_id, &[], &pdu);
        let salt = make_priv_params(PrivProtocol::Des, &engine, 0x99aa_bbcc);
        let cipher = encrypt_scoped(&plain, &engine, PrivProtocol::Des, &priv_key, salt).unwrap();
        assert_eq!(cipher.len() % 8, 0);
        let recovered =
            decrypt_scoped(&cipher, &engine, PrivProtocol::Des, &priv_key, salt).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn authpriv_aes_message_roundtrip_hmac() {
        let engine = sample_engine();
        let auth_key = password_to_key(b"authpass", &engine.engine_id, AuthProtocol::Sha1);
        let priv_key = password_to_priv_key(
            b"privpass",
            &engine.engine_id,
            AuthProtocol::Sha1,
            PrivProtocol::Aes,
        );
        let msg = encode_authenticated_get_request(
            1,
            2,
            &engine,
            b"auditor",
            &auth_key,
            AuthProtocol::Sha1,
            PrivProtocol::Aes,
            &priv_key,
            0xdead_beef_cafe_u64,
        )
        .unwrap();
        let (eng, req) = decode_authenticated_response(
            &msg,
            &auth_key,
            AuthProtocol::Sha1,
            PrivProtocol::Aes,
            &priv_key,
        )
        .unwrap();
        assert_eq!(eng.engine_id, engine.engine_id);
        assert_eq!(req, 2);
    }
}
