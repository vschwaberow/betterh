// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! RDP NLA authentication (`CredSSP` + `NTLMv2`) on TCP/3389.
//!
//! Auth-only: TPKT / X.224 negotiate → TLS → `CredSSP` `TSRequest`. No graphics,
//! channels, or Kerberos. Extended `CredSSP` (`PROTOCOL_HYBRID_EX`) is accepted when
//! selected; binding uses `CredSSP` version 6 `clientNonce` + SHA-256 (MS-CSSP).

use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use md5_hmac::{Digest, Md5};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::smb::{
    NTLM_NEGOTIATE_56, NTLM_NEGOTIATE_128, NTLM_NEGOTIATE_ALWAYS_SIGN,
    NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLM_NEGOTIATE_NTLM, NTLM_NEGOTIATE_TARGET_INFO,
    NTLM_NEGOTIATE_UNICODE, NTLM_REQUEST_TARGET, NtlmType2, build_client_blob, encode_ntlm_type1,
    encode_ntlm_type3, ntlmv2_nt_proof, ntlmv2_session_base_key, ntowfv2, split_domain_user,
    unwrap_security_blob, wrap_spnego_init,
};
use super::{
    AuthResult, Credential, ProtocolError, ProtocolModule, Target, TransportStream, wrap_tls,
};

type HmacMd5 = Hmac<Md5>;

/// TPKT version byte (ISO transport over TCP).
pub const TPKT_VERSION: u8 = 0x03;

/// X.224 Connection Request TPDU code.
pub const X224_CR: u8 = 0xE0;
/// X.224 Connection Confirm TPDU code.
pub const X224_CC: u8 = 0xD0;

/// `RDP_NEG_REQ` type field.
pub const RDP_NEG_REQ: u8 = 0x01;
/// `RDP_NEG_RSP` type field.
pub const RDP_NEG_RSP: u8 = 0x02;
/// `RDP_NEG_FAILURE` type field.
pub const RDP_NEG_FAILURE: u8 = 0x03;

pub const PROTOCOL_RDP: u32 = 0x0000_0000;
pub const PROTOCOL_SSL: u32 = 0x0000_0001;
pub const PROTOCOL_HYBRID: u32 = 0x0000_0002;
pub const PROTOCOL_HYBRID_EX: u32 = 0x0000_0008;

/// `CredSSP` `TSRequest.version` targeted by the production module.
pub const CREDSSP_VERSION: i32 = 6;

const CLIENT_TO_SERVER_PREFIX: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
const SERVER_TO_CLIENT_PREFIX: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";
const NONCE_LEN: usize = 32;
const SEAL_SIGNATURE_LEN: usize = 16;

const CLIENT_SIGN_MAGIC: &[u8] = b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGN_MAGIC: &[u8] = b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEAL_MAGIC: &[u8] = b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEAL_MAGIC: &[u8] = b"session key to server-to-client sealing key magic constant\0";

/// `SEC_E_LOGON_DENIED` (`CredSSP` `errorCode`).
const SEC_E_LOGON_DENIED: u32 = 0x8009_0311;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tpkt {
    pub payload: Vec<u8>,
}

impl Tpkt {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let total = 4 + self.payload.len();
        debug_assert!(u16::try_from(total).is_ok());
        let mut out = Vec::with_capacity(total);
        out.push(TPKT_VERSION);
        out.push(0x00);
        let len = u16::try_from(total).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// # Errors
    /// Returns an error when the buffer is truncated or the length prefix is inconsistent.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 {
            return Err("TPKT header truncated");
        }
        if bytes[0] != TPKT_VERSION {
            return Err("unsupported TPKT version");
        }
        let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total < 4 {
            return Err("TPKT length too small");
        }
        if bytes.len() < total {
            return Err("TPKT payload truncated");
        }
        Ok(Self {
            payload: bytes[4..total].to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X224ConnectionRequest {
    pub src_ref: u16,
    pub cookie_user: Option<String>,
    pub requested_protocols: u32,
}

impl X224ConnectionRequest {
    /// Build the X.224 CR TPDU bytes (without TPKT).
    #[must_use]
    pub fn encode_tpdu(&self) -> Vec<u8> {
        let mut variable = Vec::new();
        if let Some(user) = &self.cookie_user {
            variable.extend_from_slice(b"Cookie: mstshash=");
            variable.extend_from_slice(user.as_bytes());
            variable.extend_from_slice(b"\r\n");
        }
        variable.push(RDP_NEG_REQ);
        variable.push(0x00);
        variable.extend_from_slice(&8u16.to_le_bytes());
        variable.extend_from_slice(&self.requested_protocols.to_le_bytes());

        let li = 6 + variable.len();
        let mut out = Vec::with_capacity(1 + li);
        out.push(u8::try_from(li).unwrap_or(u8::MAX));
        out.push(X224_CR);
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.src_ref.to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&variable);
        out
    }

    /// Encode as a complete TPKT-framed Connection Request.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        Tpkt {
            payload: self.encode_tpdu(),
        }
        .encode()
    }

    /// # Errors
    /// Returns an error when the TPDU is truncated or fields are inconsistent.
    pub fn decode_tpdu(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 7 {
            return Err("X.224 CR truncated");
        }
        let li = usize::from(bytes[0]);
        if bytes.len() < 1 + li {
            return Err("X.224 CR length inconsistent");
        }
        if bytes[1] != X224_CR {
            return Err("not an X.224 Connection Request");
        }
        let src_ref = u16::from_be_bytes([bytes[4], bytes[5]]);
        let variable = &bytes[7..=li];

        let (cookie_user, rest) = parse_optional_cookie(variable)?;
        if rest.len() < 8 {
            return Err("RDP_NEG_REQ truncated");
        }
        if rest[0] != RDP_NEG_REQ {
            return Err("expected RDP_NEG_REQ");
        }
        let neg_len = u16::from_le_bytes([rest[2], rest[3]]);
        if neg_len != 8 {
            return Err("unexpected RDP_NEG_REQ length");
        }
        let requested_protocols = u32::from_le_bytes([rest[4], rest[5], rest[6], rest[7]]);
        Ok(Self {
            src_ref,
            cookie_user,
            requested_protocols,
        })
    }
}

fn parse_optional_cookie(data: &[u8]) -> Result<(Option<String>, &[u8]), &'static str> {
    const PREFIX: &[u8] = b"Cookie: mstshash=";
    if data.starts_with(PREFIX) {
        let Some(end) = data.windows(2).position(|w| w == b"\r\n") else {
            return Err("cookie missing CRLF");
        };
        let user = std::str::from_utf8(&data[PREFIX.len()..end])
            .map_err(|_| "cookie user is not UTF-8")?;
        Ok((Some(user.to_owned()), &data[end + 2..]))
    } else {
        Ok((None, data))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdpNegResponse {
    pub selected_protocol: u32,
}

impl RdpNegResponse {
    #[must_use]
    pub fn encode(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = RDP_NEG_RSP;
        out[1] = 0x00;
        out[2..4].copy_from_slice(&8u16.to_le_bytes());
        out[4..8].copy_from_slice(&self.selected_protocol.to_le_bytes());
        out
    }

    /// # Errors
    /// Returns an error when the buffer is not a valid 8-byte `RDP_NEG_RSP`.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 8 {
            return Err("RDP_NEG_RSP truncated");
        }
        if bytes[0] != RDP_NEG_RSP {
            return Err("not an RDP_NEG_RSP");
        }
        let len = u16::from_le_bytes([bytes[2], bytes[3]]);
        if len != 8 {
            return Err("unexpected RDP_NEG_RSP length");
        }
        Ok(Self {
            selected_protocol: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// Encode an X.224 Connection Confirm carrying `RDP_NEG_RSP`.
#[must_use]
pub fn encode_x224_cc(dst_ref: u16, src_ref: u16, selected_protocol: u32) -> Vec<u8> {
    let neg = RdpNegResponse { selected_protocol }.encode();
    let li = 6 + neg.len();
    let mut tpdu = Vec::with_capacity(1 + li);
    tpdu.push(u8::try_from(li).unwrap_or(u8::MAX));
    tpdu.push(X224_CC);
    tpdu.extend_from_slice(&dst_ref.to_be_bytes());
    tpdu.extend_from_slice(&src_ref.to_be_bytes());
    tpdu.push(0x00);
    tpdu.extend_from_slice(&neg);
    Tpkt { payload: tpdu }.encode()
}

/// Parse selected protocol from an X.224 CC / `RDP_NEG_*` reply.
///
/// # Errors
/// Returns an error when framing is invalid or negotiation failed.
pub fn parse_selected_protocol(tpdu: &[u8]) -> Result<u32, &'static str> {
    if tpdu.len() < 7 {
        return Err("X.224 CC truncated");
    }
    let li = usize::from(tpdu[0]);
    if tpdu.len() < 1 + li {
        return Err("X.224 CC length inconsistent");
    }
    if tpdu[1] != X224_CC && tpdu[1] != X224_CR {
        return Err("expected X.224 Connection Confirm");
    }
    let variable = &tpdu[7..=li];
    if variable.len() < 8 {
        return Err("RDP_NEG payload truncated");
    }
    match variable[0] {
        RDP_NEG_RSP => Ok(RdpNegResponse::decode(variable)?.selected_protocol),
        RDP_NEG_FAILURE => Err("RDP_NEG_FAILURE from peer"),
        _ => Err("unexpected RDP negotiation type"),
    }
}

/// `CredSSP` `TSRequest` (MS-CSSP) with optional NLA fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TsRequest {
    pub version: i32,
    pub nego_token: Option<Vec<u8>>,
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    pub client_nonce: Option<[u8; NONCE_LEN]>,
}

impl TsRequest {
    #[must_use]
    pub fn with_nego(version: i32, nego_token: Vec<u8>) -> Self {
        Self {
            version,
            nego_token: Some(nego_token),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&der_context(0, &der_integer(self.version)));
        if let Some(token) = &self.nego_token {
            let token_octets = der_octet_string(token);
            let token_ctx = der_context(0, &token_octets);
            let inner_seq = der_sequence(&token_ctx);
            let nego_of = der_sequence(&inner_seq);
            body.extend_from_slice(&der_context(1, &nego_of));
        }
        if let Some(auth) = &self.auth_info {
            body.extend_from_slice(&der_context(2, &der_octet_string(auth)));
        }
        if let Some(pk) = &self.pub_key_auth {
            body.extend_from_slice(&der_context(3, &der_octet_string(pk)));
        }
        if let Some(code) = self.error_code {
            body.extend_from_slice(&der_context(
                4,
                &der_integer(i32::from_ne_bytes(code.to_ne_bytes())),
            ));
        }
        if let Some(nonce) = &self.client_nonce {
            body.extend_from_slice(&der_context(5, &der_octet_string(nonce)));
        }
        der_sequence(&body)
    }

    /// # Errors
    /// Returns an error when DER tags/lengths do not match a `TSRequest`.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let (seq, rest) = expect_tag(bytes, 0x30)?;
        if !rest.is_empty() {
            return Err("trailing data after TSRequest");
        }
        let (v_content, mut rest) = expect_context(seq, 0)?;
        let (version, v_rest) = parse_integer(v_content)?;
        if !v_rest.is_empty() {
            return Err("trailing data in version");
        }
        let mut out = Self {
            version,
            ..Self::default()
        };
        while !rest.is_empty() {
            let tag = rest[0];
            let number = tag & 0x1f;
            let (content, after) = expect_tag(rest, tag)?;
            rest = after;
            match number {
                1 => {
                    let (of_seq, of_rest) = expect_tag(content, 0x30)?;
                    if !of_rest.is_empty() {
                        return Err("trailing data in NegoData");
                    }
                    let (one, one_rest) = expect_tag(of_seq, 0x30)?;
                    if !one_rest.is_empty() {
                        return Err("expected single NegoData element");
                    }
                    let (tok_content, tok_rest) = expect_context(one, 0)?;
                    if !tok_rest.is_empty() {
                        return Err("trailing data in NegoData element");
                    }
                    let (nego_token, oct_rest) = expect_tag(tok_content, 0x04)?;
                    if !oct_rest.is_empty() {
                        return Err("trailing data in negoToken OCTET STRING");
                    }
                    out.nego_token = Some(nego_token.to_vec());
                }
                2 => {
                    let (oct, oct_rest) = expect_tag(content, 0x04)?;
                    if !oct_rest.is_empty() {
                        return Err("trailing data in authInfo");
                    }
                    out.auth_info = Some(oct.to_vec());
                }
                3 => {
                    let (oct, oct_rest) = expect_tag(content, 0x04)?;
                    if !oct_rest.is_empty() {
                        return Err("trailing data in pubKeyAuth");
                    }
                    out.pub_key_auth = Some(oct.to_vec());
                }
                4 => {
                    let (code, code_rest) = parse_integer(content)?;
                    if !code_rest.is_empty() {
                        return Err("trailing data in errorCode");
                    }
                    out.error_code = Some(u32::from_ne_bytes(code.to_ne_bytes()));
                }
                5 => {
                    let (oct, oct_rest) = expect_tag(content, 0x04)?;
                    if !oct_rest.is_empty() {
                        return Err("trailing data in clientNonce");
                    }
                    if oct.len() != NONCE_LEN {
                        return Err("clientNonce must be 32 bytes");
                    }
                    let mut nonce = [0u8; NONCE_LEN];
                    nonce.copy_from_slice(oct);
                    out.client_nonce = Some(nonce);
                }
                _ => return Err("unsupported TSRequest field"),
            }
        }
        Ok(out)
    }
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![u8::try_from(len).unwrap_or(0)]
    } else if len <= 0xff {
        vec![0x81, u8::try_from(len).unwrap_or(0)]
    } else {
        let n = u16::try_from(len).unwrap_or(u16::MAX);
        let b = n.to_be_bytes();
        vec![0x82, b[0], b[1]]
    }
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(0x30);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_context(number: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(0xa0 | (number & 0x1f));
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_octet_string(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(0x04);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_integer(value: i32) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    while bytes.len() > 1 && bytes[0] == 0xff && bytes[1] & 0x80 != 0 {
        bytes.remove(0);
    }
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.push(0x02);
    out.extend_from_slice(&der_len(bytes.len()));
    out.extend_from_slice(&bytes);
    out
}

fn expect_tag(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8]), &'static str> {
    if bytes.first().copied() != Some(tag) {
        return Err("unexpected DER tag");
    }
    let (content, rest) = parse_len(&bytes[1..])?;
    Ok((content, rest))
}

fn expect_context(bytes: &[u8], number: u8) -> Result<(&[u8], &[u8]), &'static str> {
    expect_tag(bytes, 0xa0 | (number & 0x1f))
}

fn parse_len(bytes: &[u8]) -> Result<(&[u8], &[u8]), &'static str> {
    let Some((first, rest)) = bytes.split_first() else {
        return Err("DER length truncated");
    };
    if *first < 0x80 {
        let n = usize::from(*first);
        if rest.len() < n {
            return Err("DER content truncated");
        }
        Ok((&rest[..n], &rest[n..]))
    } else if *first == 0x81 {
        let Some((b0, rest)) = rest.split_first() else {
            return Err("DER length truncated");
        };
        let n = usize::from(*b0);
        if rest.len() < n {
            return Err("DER content truncated");
        }
        Ok((&rest[..n], &rest[n..]))
    } else if *first == 0x82 {
        if rest.len() < 2 {
            return Err("DER length truncated");
        }
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        let rest = &rest[2..];
        if rest.len() < n {
            return Err("DER content truncated");
        }
        Ok((&rest[..n], &rest[n..]))
    } else {
        Err("unsupported DER length form")
    }
}

fn parse_integer(bytes: &[u8]) -> Result<(i32, &[u8]), &'static str> {
    let (content, rest) = expect_tag(bytes, 0x02)?;
    if content.is_empty() || content.len() > 4 {
        return Err("INTEGER length out of range");
    }
    let mut acc: i32 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for b in content {
        acc = (acc << 8) | i32::from(*b);
    }
    Ok((acc, rest))
}

/// Extract `SubjectPublicKeyInfo` DER from an X.509 certificate.
///
/// # Errors
/// Returns an error when the certificate DER is truncated or malformed.
pub fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (cert_seq, _) = expect_tag(cert_der, 0x30)?;
    let (tbs, _) = expect_tag(cert_seq, 0x30)?;
    let mut rest = tbs;
    if rest.first().copied() == Some(0xa0) {
        let (_, after) = expect_tag(rest, 0xa0)?;
        rest = after;
    }
    let (_, rest) = expect_tag(rest, 0x02)?; // serialNumber
    let (_, rest) = expect_tag(rest, 0x30)?; // signature
    let (_, rest) = expect_tag(rest, 0x30)?; // issuer
    let (_, rest) = expect_tag(rest, 0x30)?; // validity
    let (_, rest) = expect_tag(rest, 0x30)?; // subject
    let spki_start = rest;
    let (_, after) = expect_tag(rest, 0x30)?;
    let spki_len = rest.len() - after.len();
    Ok(spki_start[..spki_len].to_vec())
}

#[must_use]
pub fn client_to_server_hash(nonce: &[u8; NONCE_LEN], server_pubkey: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CLIENT_TO_SERVER_PREFIX);
    h.update(nonce);
    h.update(server_pubkey);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[must_use]
pub fn server_to_client_hash(nonce: &[u8; NONCE_LEN], server_pubkey: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SERVER_TO_CLIENT_PREFIX);
    h.update(nonce);
    h.update(server_pubkey);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let Ok(mut mac) = HmacMd5::new_from_slice(key) else {
        return [0u8; 16];
    };
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

fn derive_key(exported: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16 + magic.len());
    buf.extend_from_slice(exported);
    buf.extend_from_slice(magic);
    let d = Md5::digest(&buf);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d);
    out
}

struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = u8::try_from(i).unwrap_or(0);
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            let ki = key[i % key.len()];
            j = j.wrapping_add(s[i]).wrapping_add(ki);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; data.len()];
        for (idx, byte) in data.iter().enumerate() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(
                self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]),
            )];
            out[idx] = byte ^ k;
        }
        out
    }
}

/// NTLMSSP `GSS_Wrap` envelope used by `CredSSP` (`MessageSignature || RC4(plaintext)`).
pub struct CredSspSeal {
    tx_rc4: Rc4,
    rx_rc4: Rc4,
    tx_sign: [u8; 16],
    rx_sign: [u8; 16],
    tx_seq: u32,
    rx_seq: u32,
}

impl CredSspSeal {
    #[must_use]
    pub fn client(exported: &[u8; 16]) -> Self {
        Self::build(
            exported,
            CLIENT_SEAL_MAGIC,
            CLIENT_SIGN_MAGIC,
            SERVER_SEAL_MAGIC,
            SERVER_SIGN_MAGIC,
        )
    }

    #[must_use]
    pub fn server(exported: &[u8; 16]) -> Self {
        Self::build(
            exported,
            SERVER_SEAL_MAGIC,
            SERVER_SIGN_MAGIC,
            CLIENT_SEAL_MAGIC,
            CLIENT_SIGN_MAGIC,
        )
    }

    fn build(
        exp: &[u8; 16],
        tx_seal: &[u8],
        tx_sign: &[u8],
        rx_seal: &[u8],
        rx_sign: &[u8],
    ) -> Self {
        Self {
            tx_rc4: Rc4::new(&derive_key(exp, tx_seal)),
            rx_rc4: Rc4::new(&derive_key(exp, rx_seal)),
            tx_sign: derive_key(exp, tx_sign),
            rx_sign: derive_key(exp, rx_sign),
            tx_seq: 0,
            rx_seq: 0,
        }
    }

    #[must_use]
    pub fn wrap(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let seq = self.tx_seq;
        let mut sig_input = Vec::with_capacity(4 + plaintext.len());
        sig_input.extend_from_slice(&seq.to_le_bytes());
        sig_input.extend_from_slice(plaintext);
        let hmac = hmac_md5(&self.tx_sign, &sig_input);
        let sealed = self.tx_rc4.apply(plaintext);
        let mut sig = [0u8; SEAL_SIGNATURE_LEN];
        sig[0..4].copy_from_slice(&1u32.to_le_bytes());
        sig[4..12].copy_from_slice(&hmac[0..8]);
        sig[12..16].copy_from_slice(&seq.to_le_bytes());
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut out = Vec::with_capacity(SEAL_SIGNATURE_LEN + sealed.len());
        out.extend_from_slice(&sig);
        out.extend_from_slice(&sealed);
        out
    }

    /// # Errors
    /// Returns an error when the sealed blob is truncated or the checksum fails.
    pub fn unwrap(&mut self, wire: &[u8]) -> Result<Vec<u8>, &'static str> {
        if wire.len() < SEAL_SIGNATURE_LEN {
            return Err("sealed blob too short");
        }
        let (sig, sealed) = wire.split_at(SEAL_SIGNATURE_LEN);
        let plaintext = self.rx_rc4.apply(sealed);
        let seq = self.rx_seq;
        let mut sig_input = Vec::with_capacity(4 + plaintext.len());
        sig_input.extend_from_slice(&seq.to_le_bytes());
        sig_input.extend_from_slice(&plaintext);
        let hmac = hmac_md5(&self.rx_sign, &sig_input);
        if sig[4..12] != hmac[0..8] {
            return Err("credssp seal signature mismatch");
        }
        self.rx_seq = self.rx_seq.wrapping_add(1);
        Ok(plaintext)
    }
}

/// Encode `TSPasswordCreds` / `TSCredentials` (`credType` = 1).
#[must_use]
pub fn encode_ts_credentials(domain: &str, user: &str, password: &str) -> Vec<u8> {
    let mut pwd = Vec::new();
    pwd.extend_from_slice(&der_context(0, &der_octet_string(domain.as_bytes())));
    pwd.extend_from_slice(&der_context(1, &der_octet_string(user.as_bytes())));
    pwd.extend_from_slice(&der_context(2, &der_octet_string(password.as_bytes())));
    let password_creds = der_sequence(&pwd);

    let mut creds = Vec::new();
    creds.extend_from_slice(&der_context(0, &der_integer(1)));
    creds.extend_from_slice(&der_context(1, &der_octet_string(&password_creds)));
    der_sequence(&creds)
}

/// Decode password credentials from a `TSCredentials` blob.
///
/// # Errors
/// Returns an error when DER shape does not match password creds.
pub fn decode_ts_credentials(bytes: &[u8]) -> Result<(String, String, String), &'static str> {
    let (seq, rest) = expect_tag(bytes, 0x30)?;
    if !rest.is_empty() {
        return Err("trailing data after TSCredentials");
    }
    let (type_c, after_type) = expect_context(seq, 0)?;
    let (cred_type, type_rest) = parse_integer(type_c)?;
    if !type_rest.is_empty() || cred_type != 1 {
        return Err("unsupported credType");
    }
    let (cred_c, after_cred) = expect_context(after_type, 1)?;
    if !after_cred.is_empty() {
        return Err("trailing TSCredentials fields");
    }
    let (oct, oct_rest) = expect_tag(cred_c, 0x04)?;
    if !oct_rest.is_empty() {
        return Err("trailing password creds octets");
    }
    let (pwd_seq, pwd_rest) = expect_tag(oct, 0x30)?;
    if !pwd_rest.is_empty() {
        return Err("trailing after TSPasswordCreds");
    }
    let (d_c, after_d) = expect_context(pwd_seq, 0)?;
    let (d_oct, d_rest) = expect_tag(d_c, 0x04)?;
    if !d_rest.is_empty() {
        return Err("trailing domain");
    }
    let (u_c, after_u) = expect_context(after_d, 1)?;
    let (u_oct, u_rest) = expect_tag(u_c, 0x04)?;
    if !u_rest.is_empty() {
        return Err("trailing user");
    }
    let (p_c, after_p) = expect_context(after_u, 2)?;
    if !after_p.is_empty() {
        return Err("trailing password fields");
    }
    let (p_oct, p_rest) = expect_tag(p_c, 0x04)?;
    if !p_rest.is_empty() {
        return Err("trailing password octets");
    }
    Ok((
        String::from_utf8_lossy(d_oct).into_owned(),
        String::from_utf8_lossy(u_oct).into_owned(),
        String::from_utf8_lossy(p_oct).into_owned(),
    ))
}

async fn read_tpkt(stream: &mut TcpStream) -> Result<Vec<u8>, ProtocolError> {
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    if hdr[0] != TPKT_VERSION {
        return Err(ProtocolError::HandshakeFailed(
            "unsupported TPKT version".into(),
        ));
    }
    let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
    if total < 4 {
        return Err(ProtocolError::HandshakeFailed(
            "TPKT length too small".into(),
        ));
    }
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&hdr);
    stream
        .read_exact(&mut buf[4..])
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(buf)
}

async fn write_credssp(stream: &mut TransportStream, req: &TsRequest) -> Result<(), ProtocolError> {
    let der = req.encode();
    let len = u32::try_from(der.len()).unwrap_or(u32::MAX);
    let mut frame = Vec::with_capacity(4 + der.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&der);
    stream
        .write_all(&frame)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(())
}

async fn read_credssp(stream: &mut TransportStream) -> Result<TsRequest, ProtocolError> {
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    let len = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(0);
    if len == 0 || len > 1 << 20 {
        return Err(ProtocolError::HandshakeFailed(
            "invalid CredSSP length prefix".into(),
        ));
    }
    let mut der = vec![0u8; len];
    stream
        .read_exact(&mut der)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    TsRequest::decode(&der).map_err(|error| ProtocolError::HandshakeFailed(error.into()))
}

struct Disconnected;
struct Negotiated {
    selected_protocol: u32,
}
struct TlsReady {
    selected_protocol: u32,
    peer_spki: Vec<u8>,
}

struct RdpClient<State> {
    stream: Option<TcpStream>,
    tls: Option<TransportStream>,
    state: State,
    host: String,
    insecure: bool,
}

impl RdpClient<Disconnected> {
    const fn new(host: String, insecure: bool) -> Self {
        Self {
            stream: None,
            tls: None,
            state: Disconnected,
            host,
            insecure,
        }
    }

    async fn connect(
        mut self,
        target: &Target,
        proxy: Option<&str>,
    ) -> Result<Self, ProtocolError> {
        let addr = target.dial_addr();
        let stream = match proxy {
            None => TcpStream::connect(&addr)
                .await
                .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?,
            Some(proxy) => super::socks::connect_socks5(proxy, &addr).await?,
        };
        self.stream = Some(stream);
        Ok(self)
    }

    async fn negotiate(
        mut self,
        cookie_user: &str,
    ) -> Result<RdpClient<Negotiated>, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("RDP stream missing before negotiate".into()))?;
        let cr = X224ConnectionRequest {
            src_ref: 0x1234,
            cookie_user: Some(cookie_user.to_owned()),
            requested_protocols: PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
        };
        stream
            .write_all(&cr.encode())
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        let framed = read_tpkt(stream).await?;
        let tpkt = Tpkt::decode(&framed).map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;
        let selected = parse_selected_protocol(&tpkt.payload)
            .map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;
        if selected == PROTOCOL_RDP {
            return Err(ProtocolError::HandshakeFailed(
                "peer selected legacy PROTOCOL_RDP without TLS; NLA-only audits require Hybrid/SSL"
                    .into(),
            ));
        }
        if selected & (PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX) == 0 {
            return Err(ProtocolError::HandshakeFailed(
                "peer did not select CredSSP/NLA (PROTOCOL_HYBRID*)".into(),
            ));
        }
        Ok(RdpClient {
            stream: self.stream.take(),
            tls: None,
            state: Negotiated {
                selected_protocol: selected,
            },
            host: self.host,
            insecure: self.insecure,
        })
    }
}

impl RdpClient<Negotiated> {
    async fn upgrade_tls(mut self) -> Result<RdpClient<TlsReady>, ProtocolError> {
        let tcp = self
            .stream
            .take()
            .ok_or_else(|| ProtocolError::Internal("RDP stream missing before TLS".into()))?;
        let tls = wrap_tls(tcp, &self.host, self.insecure).await?;
        let cert = tls.peer_certificate_der().ok_or_else(|| {
            ProtocolError::HandshakeFailed("TLS peer certificate missing after handshake".into())
        })?;
        let peer_spki =
            extract_spki(&cert).map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;
        Ok(RdpClient {
            stream: None,
            tls: Some(tls),
            state: TlsReady {
                selected_protocol: self.state.selected_protocol,
                peer_spki,
            },
            host: self.host,
            insecure: self.insecure,
        })
    }
}

impl RdpClient<TlsReady> {
    async fn credssp_ntlm(
        mut self,
        user: &str,
        domain: &str,
        password: &str,
    ) -> Result<AuthResult, ProtocolError> {
        let _ = self.state.selected_protocol;
        let stream = self
            .tls
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("RDP TLS stream missing".into()))?;

        let flags = NTLM_NEGOTIATE_UNICODE
            | NTLM_NEGOTIATE_NTLM
            | NTLM_REQUEST_TARGET
            | NTLM_NEGOTIATE_TARGET_INFO
            | NTLM_NEGOTIATE_ALWAYS_SIGN
            | NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLM_NEGOTIATE_128
            | NTLM_NEGOTIATE_56;
        let type1 = wrap_spnego_init(&encode_ntlm_type1(flags));
        write_credssp(stream, &TsRequest::with_nego(CREDSSP_VERSION, type1)).await?;

        let challenge = read_credssp(stream).await?;
        if let Some(code) = challenge.error_code {
            return Ok(map_credssp_error(code));
        }
        let type2_raw = challenge.nego_token.ok_or_else(|| {
            ProtocolError::HandshakeFailed("CredSSP challenge missing negoToken".into())
        })?;
        let type2 = NtlmType2::decode(&unwrap_security_blob(&type2_raw))
            .map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;

        let user_owned = user.to_owned();
        let domain_owned = domain.to_owned();
        let password_owned = password.to_owned();
        let type2_clone = type2.clone();
        let (nt_response, session_key, type3_flags) = tokio::task::spawn_blocking(move || {
            let mut client_challenge = [0u8; 8];
            fastrand::fill(&mut client_challenge);
            let blob =
                build_client_blob(client_challenge, &type2_clone.target_info, filetime_now());
            let response_key = ntowfv2(&password_owned, &user_owned, &domain_owned);
            let proof = ntlmv2_nt_proof(
                &password_owned,
                &user_owned,
                &domain_owned,
                &type2_clone.server_challenge,
                &blob,
            );
            let session_key = ntlmv2_session_base_key(&response_key, &proof);
            let mut nt_response = Vec::with_capacity(16 + blob.len());
            nt_response.extend_from_slice(&proof);
            nt_response.extend_from_slice(&blob);
            let type3_flags = type2_clone.flags
                | NTLM_NEGOTIATE_ALWAYS_SIGN
                | NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NTLM_NEGOTIATE_128
                | NTLM_NEGOTIATE_56;
            (nt_response, session_key, type3_flags)
        })
        .await
        .map_err(|error| ProtocolError::Internal(format!("NTLMv2 worker failed: {error}")))?;

        let type3 = encode_ntlm_type3(user, domain, "BETTERH", &nt_response, type3_flags);
        let mut nonce = [0u8; NONCE_LEN];
        fastrand::fill(&mut nonce);
        let c2s = client_to_server_hash(&nonce, &self.state.peer_spki);
        let mut seal = CredSspSeal::client(&session_key);
        let sealed_pub = seal.wrap(&c2s);

        let mut auth_req = TsRequest::with_nego(CREDSSP_VERSION, type3);
        auth_req.pub_key_auth = Some(sealed_pub);
        auth_req.client_nonce = Some(nonce);
        write_credssp(stream, &auth_req).await?;

        let server_bind = read_credssp(stream).await?;
        if let Some(code) = server_bind.error_code {
            return Ok(map_credssp_error(code));
        }
        let server_pub = server_bind.pub_key_auth.ok_or_else(|| {
            ProtocolError::HandshakeFailed("CredSSP server pubKeyAuth missing".into())
        })?;
        let recovered = seal
            .unwrap(&server_pub)
            .map_err(|e| ProtocolError::HandshakeFailed(e.into()))?;
        let expected = server_to_client_hash(&nonce, &self.state.peer_spki);
        if recovered.as_slice() != expected.as_slice() {
            return Ok(AuthResult::Failure);
        }

        let creds = encode_ts_credentials(domain, user, password);
        let sealed_auth = seal.wrap(&creds);
        let final_req = TsRequest {
            version: CREDSSP_VERSION,
            auth_info: Some(sealed_auth),
            ..TsRequest::default()
        };
        write_credssp(stream, &final_req).await?;
        Ok(AuthResult::Success)
    }
}

fn map_credssp_error(code: u32) -> AuthResult {
    if code == SEC_E_LOGON_DENIED {
        AuthResult::Failure
    } else {
        AuthResult::Error(format!("CredSSP errorCode 0x{code:08x}"))
    }
}

fn filetime_now() -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let intervals = u64::try_from(nanos / 100).unwrap_or(0);
    intervals.saturating_add(EPOCH_DIFF)
}

/// Production RDP `CredSSP`/NLA module (feature = `rdp`).
#[derive(Debug, Clone, Default)]
pub struct RdpModule {
    proxy: Option<String>,
    insecure: bool,
}

impl RdpModule {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    #[must_use]
    pub fn with_insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
}

#[async_trait]
impl ProtocolModule for RdpModule {
    fn name(&self) -> &'static str {
        "rdp"
    }

    fn default_port(&self) -> u16 {
        3389
    }

    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_budget: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        if timeout_budget.is_zero() {
            return Err(ProtocolError::Timeout);
        }
        let password = credential.password.as_deref().unwrap_or("");
        let (domain, user) = split_domain_user(&credential.username);
        let proxy = self.proxy.clone();
        let insecure = self.insecure;
        let host = target.host.clone();

        let result = timeout(timeout_budget, async {
            let connected = RdpClient::new(host, insecure)
                .connect(target, proxy.as_deref())
                .await?;
            let negotiated = connected.negotiate(&user).await?;
            let tls_ready = negotiated.upgrade_tls().await?;
            tls_ready.credssp_ntlm(&user, &domain, password).await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::smb::encode_ntlm_type2;
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn target_for(port: u16) -> Target {
        Target {
            host: "localhost".into(),
            port,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    fn test_server_config() -> (Arc<ServerConfig>, Vec<u8>) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert");
        let cert_der = CertificateDer::from(certified.cert);
        let cert_bytes = cert_der.as_ref().to_vec();
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        (Arc::new(config), cert_bytes)
    }

    #[test]
    fn tpkt_roundtrip_preserves_payload() {
        let msg = Tpkt {
            payload: b"hello-rdp".to_vec(),
        };
        let encoded = msg.encode();
        let decoded = Tpkt::decode(&encoded).expect("decode");
        assert_eq!(decoded.payload, msg.payload);
    }

    #[test]
    fn x224_cr_with_cookie_and_hybrid_neg_roundtrips() {
        let cr = X224ConnectionRequest {
            src_ref: 0x1234,
            cookie_user: Some("alice".into()),
            requested_protocols: PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX,
        };
        let framed = cr.encode();
        let tpkt = Tpkt::decode(&framed).expect("tpkt");
        let decoded = X224ConnectionRequest::decode_tpdu(&tpkt.payload).expect("cr");
        assert_eq!(decoded, cr);
    }

    #[test]
    fn ts_request_roundtrip_with_nonce_and_pubkey() {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[0] = 7;
        let req = TsRequest {
            version: CREDSSP_VERSION,
            nego_token: Some(b"NTLMSSP\0\x01\x00\x00\x00".to_vec()),
            pub_key_auth: Some(vec![1, 2, 3]),
            client_nonce: Some(nonce),
            ..TsRequest::default()
        };
        let der = req.encode();
        let decoded = TsRequest::decode(&der).expect("tsrequest");
        assert_eq!(decoded, req);
    }

    #[test]
    fn seal_client_server_roundtrip_and_seq_chain() {
        let exp = [0x42u8; 16];
        let mut c = CredSspSeal::client(&exp);
        let mut s = CredSspSeal::server(&exp);
        let a = c.wrap(b"first");
        let b = c.wrap(b"second");
        assert_eq!(s.unwrap(&a).unwrap(), b"first");
        assert_eq!(s.unwrap(&b).unwrap(), b"second");
        let back = s.wrap(b"server-reply");
        assert_eq!(c.unwrap(&back).unwrap(), b"server-reply");
    }

    #[test]
    fn binding_hashes_are_direction_specific() {
        let nonce = [1u8; NONCE_LEN];
        let key = b"pretend-spki";
        assert_ne!(
            client_to_server_hash(&nonce, key),
            server_to_client_hash(&nonce, key)
        );
    }

    #[test]
    fn ts_credentials_roundtrip() {
        let der = encode_ts_credentials("DOM", "alice", "secret");
        let (d, u, p) = decode_ts_credentials(&der).unwrap();
        assert_eq!(
            (d.as_str(), u.as_str(), p.as_str()),
            ("DOM", "alice", "secret")
        );
    }

    #[test]
    fn seal_unwrap_rejects_wrong_binding_payload() {
        let exp = [0x11u8; 16];
        let mut c = CredSspSeal::client(&exp);
        let mut s = CredSspSeal::server(&exp);
        let wire = c.wrap(b"good-binding-hash-bytes!!!!!!!!!");
        let mut tampered = wire;
        tampered[SEAL_SIGNATURE_LEN + 3] ^= 0xff;
        assert!(s.unwrap(&tampered).is_err());
    }

    async fn mock_rdp_nla_peer(
        listener: TcpListener,
        cert_der: Vec<u8>,
        acceptor: TlsAcceptor,
        expected_user: &str,
        expected_password: &str,
        accept: bool,
    ) {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let framed = read_tpkt(&mut tcp).await.unwrap();
        let tpkt = Tpkt::decode(&framed).unwrap();
        let cr = X224ConnectionRequest::decode_tpdu(&tpkt.payload).unwrap();
        assert!(cr.requested_protocols & PROTOCOL_HYBRID != 0);
        let cc = encode_x224_cc(cr.src_ref, 0x5678, PROTOCOL_HYBRID);
        tcp.write_all(&cc).await.unwrap();
        tcp.flush().await.unwrap();

        let mut tls = acceptor.accept(tcp).await.unwrap();
        let spki = extract_spki(&cert_der).unwrap();

        // Type1
        let mut hdr = [0u8; 4];
        tls.read_exact(&mut hdr).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(hdr)).unwrap();
        let mut der = vec![0u8; len];
        tls.read_exact(&mut der).await.unwrap();
        let req1 = TsRequest::decode(&der).unwrap();
        assert!(req1.nego_token.is_some());

        let server_challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let target_info = b"\x02\x00\x0c\x00D\x00O\x00M\x00A\x00I\x00N\x00\x00\x00";
        let type2 = encode_ntlm_type2(server_challenge, target_info);
        let resp2 = TsRequest::with_nego(CREDSSP_VERSION, type2);
        let der2 = resp2.encode();
        let mut type2_frame = Vec::new();
        type2_frame.extend_from_slice(&u32::try_from(der2.len()).unwrap().to_be_bytes());
        type2_frame.extend_from_slice(&der2);
        tls.write_all(&type2_frame).await.unwrap();
        tls.flush().await.unwrap();

        // Type3 + pubKeyAuth + nonce
        tls.read_exact(&mut hdr).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(hdr)).unwrap();
        der = vec![0u8; len];
        tls.read_exact(&mut der).await.unwrap();
        let req3 = TsRequest::decode(&der).unwrap();
        let type3 = unwrap_security_blob(req3.nego_token.as_ref().unwrap());
        let nonce = req3.client_nonce.unwrap();
        let sealed_c2s = req3.pub_key_auth.as_ref().unwrap();

        // Verify NTLMv2 proof against expected password
        let nt_len = u16::from_le_bytes([type3[20], type3[21]]) as usize;
        let nt_off = u32::from_le_bytes(type3[24..28].try_into().unwrap()) as usize;
        let nt_resp = &type3[nt_off..nt_off + nt_len];
        let proof = &nt_resp[..16];
        let blob = &nt_resp[16..];
        let expected_proof = ntlmv2_nt_proof(
            expected_password,
            expected_user,
            "",
            &server_challenge,
            blob,
        );
        let password_ok = proof == expected_proof.as_slice();

        if !password_ok || !accept {
            let err = TsRequest {
                version: CREDSSP_VERSION,
                error_code: Some(SEC_E_LOGON_DENIED),
                ..TsRequest::default()
            };
            let der_err = err.encode();
            let mut frame = Vec::new();
            frame.extend_from_slice(&u32::try_from(der_err.len()).unwrap().to_be_bytes());
            frame.extend_from_slice(&der_err);
            let _ = tls.write_all(&frame).await;
            return;
        }

        let response_key = ntowfv2(expected_password, expected_user, "");
        let mut proof_arr = [0u8; 16];
        proof_arr.copy_from_slice(proof);
        let session_key = ntlmv2_session_base_key(&response_key, &proof_arr);
        let mut seal = CredSspSeal::server(&session_key);
        let recovered = seal.unwrap(sealed_c2s).unwrap();
        assert_eq!(recovered, client_to_server_hash(&nonce, &spki));

        let s2c = server_to_client_hash(&nonce, &spki);
        let sealed_s2c = seal.wrap(&s2c);
        let bind = TsRequest {
            version: CREDSSP_VERSION,
            pub_key_auth: Some(sealed_s2c),
            ..TsRequest::default()
        };
        let der_b = bind.encode();
        let mut frame_b = Vec::new();
        frame_b.extend_from_slice(&u32::try_from(der_b.len()).unwrap().to_be_bytes());
        frame_b.extend_from_slice(&der_b);
        tls.write_all(&frame_b).await.unwrap();
        tls.flush().await.unwrap();

        // authInfo
        tls.read_exact(&mut hdr).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(hdr)).unwrap();
        der = vec![0u8; len];
        tls.read_exact(&mut der).await.unwrap();
        let auth = TsRequest::decode(&der).unwrap();
        let plain = seal.unwrap(auth.auth_info.as_ref().unwrap()).unwrap();
        let (d, u, p) = decode_ts_credentials(&plain).unwrap();
        assert_eq!(u, expected_user);
        assert_eq!(p, expected_password);
        let _ = d;
    }

    #[tokio::test]
    async fn authenticates_against_hermetic_mock_success_and_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (config, cert) = test_server_config();
        let acceptor = TlsAcceptor::from(config);
        let server = tokio::spawn(async move {
            mock_rdp_nla_peer(listener, cert, acceptor, "alice", "correct", true).await;
        });

        let module = RdpModule::new().with_insecure(true);
        let ok = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("correct".into()),
                },
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(ok, AuthResult::Success);
        server.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (config, cert) = test_server_config();
        let acceptor = TlsAcceptor::from(config);
        let server = tokio::spawn(async move {
            mock_rdp_nla_peer(listener, cert, acceptor, "alice", "correct", true).await;
        });
        let bad = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(bad, AuthResult::Failure);
        let _ = server.await;
    }

    #[tokio::test]
    async fn rejects_legacy_protocol_rdp_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let framed = read_tpkt(&mut tcp).await.unwrap();
            let tpkt = Tpkt::decode(&framed).unwrap();
            let cr = X224ConnectionRequest::decode_tpdu(&tpkt.payload).unwrap();
            let cc = encode_x224_cc(cr.src_ref, 0x1111, PROTOCOL_RDP);
            tcp.write_all(&cc).await.unwrap();
        });
        let module = RdpModule::new().with_insecure(true);
        let err = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "alice".into(),
                    password: Some("x".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_path_rejects_non_socks() {
        let module = RdpModule::new().with_proxy(Some("http://127.0.0.1:1".into()));
        let err = module
            .authenticate(
                &target_for(9),
                &Credential {
                    username: "u".into(),
                    password: Some("p".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::ProxyError(_)));
    }
}
