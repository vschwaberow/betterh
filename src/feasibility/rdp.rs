// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Phase 11.2 feasibility prototype: TPKT / X.224 / `RDP_NEG` and `CredSSP` `TSRequest`.
//!
//! Hermetic encode/decode checks only — not a production `ProtocolModule`.
//! `NTLMv2` crypto for NLA is covered by `feasibility-smb` (D.1); this module wraps
//! an opaque `NegoToken` inside `CredSSP` DER.

/// TPKT version byte (ISO transport over TCP).
pub const TPKT_VERSION: u8 = 0x03;

/// X.224 Connection Request TPDU code.
pub const X224_CR: u8 = 0xE0;

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

/// `CredSSP` `TSRequest.version` targeted by the prototype.
pub const CREDSSP_VERSION: i32 = 6;

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
        // RDP_NEG_REQ: type, flags, length=8 LE, requestedProtocols LE
        variable.push(RDP_NEG_REQ);
        variable.push(0x00);
        variable.extend_from_slice(&8u16.to_le_bytes());
        variable.extend_from_slice(&self.requested_protocols.to_le_bytes());

        // Fixed header after LI: CR, DST-REF, SRC-REF, class = 6 bytes
        let li = 6 + variable.len();
        let mut out = Vec::with_capacity(1 + li);
        out.push(u8::try_from(li).unwrap_or(u8::MAX));
        out.push(X224_CR);
        out.extend_from_slice(&0u16.to_be_bytes()); // DST-REF
        out.extend_from_slice(&self.src_ref.to_be_bytes());
        out.push(0x00); // class/options
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

/// Minimal `CredSSP` `TSRequest` with version + a single `NegoToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsRequest {
    pub version: i32,
    pub nego_token: Vec<u8>,
}

impl TsRequest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let version_content = der_integer(self.version);
        let version_field = der_context(0, &version_content);

        let token_octets = der_octet_string(&self.nego_token);
        let token_ctx = der_context(0, &token_octets);
        let inner_seq = der_sequence(&token_ctx);
        let nego_of = der_sequence(&inner_seq);
        let nego_field = der_context(1, &nego_of);

        let mut body = Vec::with_capacity(version_field.len() + nego_field.len());
        body.extend_from_slice(&version_field);
        body.extend_from_slice(&nego_field);
        der_sequence(&body)
    }

    /// # Errors
    /// Returns an error when DER tags/lengths do not match the expected `TSRequest` shape.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let (seq, rest) = expect_tag(bytes, 0x30)?;
        if !rest.is_empty() {
            return Err("trailing data after TSRequest");
        }
        let (v_content, after_v) = expect_context(seq, 0)?;
        let (version, v_rest) = parse_integer(v_content)?;
        if !v_rest.is_empty() {
            return Err("trailing data in version");
        }
        let (n_content, after_n) = expect_context(after_v, 1)?;
        if !after_n.is_empty() {
            return Err("unexpected TSRequest fields beyond negoTokens");
        }
        let (of_seq, of_rest) = expect_tag(n_content, 0x30)?;
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
        Ok(Self {
            version,
            nego_token: nego_token.to_vec(),
        })
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
    // Minimal signed two's-complement encoding (positive small ints).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpkt_roundtrip_preserves_payload() {
        let msg = Tpkt {
            payload: b"hello-rdp".to_vec(),
        };
        let encoded = msg.encode();
        assert_eq!(encoded[0], TPKT_VERSION);
        assert_eq!(encoded[1], 0x00);
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
        assert!(framed.windows(8).any(|w| {
            w.starts_with(&[RDP_NEG_REQ, 0x00, 0x08, 0x00])
                && u32::from_le_bytes([w[4], w[5], w[6], w[7]]) == cr.requested_protocols
        }));
    }

    #[test]
    fn rdp_neg_rsp_selects_hybrid() {
        let rsp = RdpNegResponse {
            selected_protocol: PROTOCOL_HYBRID,
        };
        let bytes = rsp.encode();
        let decoded = RdpNegResponse::decode(&bytes).expect("rsp");
        assert_eq!(decoded.selected_protocol, PROTOCOL_HYBRID);
    }

    #[test]
    fn ts_request_wraps_opaque_nego_token() {
        let token = b"NTLMSSP\0\x01\x00\x00\x00".to_vec();
        let req = TsRequest {
            version: CREDSSP_VERSION,
            nego_token: token.clone(),
        };
        let der = req.encode();
        let decoded = TsRequest::decode(&der).expect("tsrequest");
        assert_eq!(decoded.version, CREDSSP_VERSION);
        assert_eq!(decoded.nego_token, token);
    }

    #[test]
    fn hybrid_path_implies_tls_upgrade_before_credssp() {
        // Architectural assertion for the type-state sketch: HYBRID selection is
        // the gate for CredSSP; the prototype does not invent a custom TLS stack.
        let rsp = RdpNegResponse {
            selected_protocol: PROTOCOL_HYBRID,
        };
        assert_eq!(rsp.selected_protocol & PROTOCOL_HYBRID, PROTOCOL_HYBRID);
        assert_ne!(rsp.selected_protocol, PROTOCOL_RDP);
    }
}
