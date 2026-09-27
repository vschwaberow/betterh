// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! SNMPv1/v2c message and PDU codecs.

use super::ber::{
    BerError, BerReader, TAG_GET_REQUEST, TAG_GET_RESPONSE, TAG_REPORT, TAG_SEQUENCE, ber_tlv,
    encode_integer, encode_null, encode_octet_string, encode_oid,
};

/// `sysDescr.0` — 1.3.6.1.2.1.1.1.0
pub const SYS_DESCR_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}

impl SnmpVersion {
    #[must_use]
    pub const fn wire(self) -> i64 {
        match self {
            Self::V1 => 0,
            Self::V2c => 1,
            Self::V3 => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduErrorStatus {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
    AuthorizationError = 16,
    Other,
}

impl From<i64> for PduErrorStatus {
    fn from(value: i64) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::TooBig,
            2 => Self::NoSuchName,
            3 => Self::BadValue,
            4 => Self::ReadOnly,
            5 => Self::GenErr,
            16 => Self::AuthorizationError,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityResponse {
    pub version: i64,
    pub community: Vec<u8>,
    pub pdu_tag: u8,
    pub request_id: i64,
    pub error_status: PduErrorStatus,
    pub error_index: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    #[error(transparent)]
    Ber(#[from] BerError),
    #[error("unsupported SNMP version {0}")]
    UnsupportedVersion(i64),
    #[error("SNMP message is not a response or report PDU")]
    UnexpectedPdu,
}

/// Build a community-based `GetRequest` for `sysDescr.0`.
pub fn encode_community_get_request(
    version: SnmpVersion,
    community: &[u8],
    request_id: i32,
) -> Result<Vec<u8>, CodecError> {
    let pdu = encode_get_request_pdu(i64::from(request_id))?;
    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(version.wire()));
    body.extend_from_slice(&encode_octet_string(community));
    body.extend_from_slice(&pdu);
    Ok(ber_tlv(TAG_SEQUENCE, &body))
}

fn encode_get_request_pdu(request_id: i64) -> Result<Vec<u8>, CodecError> {
    let oid = encode_oid(SYS_DESCR_OID)?;
    let mut varbind = Vec::new();
    varbind.extend_from_slice(&oid);
    varbind.extend_from_slice(&encode_null());
    let varbind = ber_tlv(TAG_SEQUENCE, &varbind);
    let varbind_list = ber_tlv(TAG_SEQUENCE, &varbind);

    let mut pdu = Vec::new();
    pdu.extend_from_slice(&encode_integer(request_id));
    pdu.extend_from_slice(&encode_integer(0)); // error-status
    pdu.extend_from_slice(&encode_integer(0)); // error-index
    pdu.extend_from_slice(&varbind_list);
    Ok(ber_tlv(TAG_GET_REQUEST, &pdu))
}

/// Decode a community SNMPv1/v2c `GetResponse` or `Report`.
pub fn decode_community_response(bytes: &[u8]) -> Result<CommunityResponse, CodecError> {
    let mut outer = BerReader::new(bytes);
    let seq = outer.expect_tag(TAG_SEQUENCE)?;
    let mut reader = BerReader::new(seq);
    let version = reader.read_integer()?;
    if version != 0 && version != 1 {
        return Err(CodecError::UnsupportedVersion(version));
    }
    let community = reader.read_octet_string()?.to_vec();
    let (pdu_tag, pdu_body) = reader.read_tlv()?;
    if pdu_tag != TAG_GET_RESPONSE && pdu_tag != TAG_REPORT {
        return Err(CodecError::UnexpectedPdu);
    }
    let mut pdu = BerReader::new(pdu_body);
    let request_id = pdu.read_integer()?;
    let error_status = PduErrorStatus::from(pdu.read_integer()?);
    let error_index = pdu.read_integer()?;
    Ok(CommunityResponse {
        version,
        community,
        pdu_tag,
        request_id,
        error_status,
        error_index,
    })
}

/// Encode a `GetResponse` for hermetic mocks (tests).
#[cfg(test)]
pub fn encode_community_get_response(
    version: SnmpVersion,
    community: &[u8],
    request_id: i32,
    error_status: i64,
) -> Result<Vec<u8>, CodecError> {
    let oid = encode_oid(SYS_DESCR_OID)?;
    let mut varbind = Vec::new();
    varbind.extend_from_slice(&oid);
    // OCTET STRING value for sysDescr
    varbind.extend_from_slice(&encode_octet_string(b"mock-agent"));
    let varbind = ber_tlv(TAG_SEQUENCE, &varbind);
    let varbind_list = ber_tlv(TAG_SEQUENCE, &varbind);

    let mut pdu = Vec::new();
    pdu.extend_from_slice(&encode_integer(i64::from(request_id)));
    pdu.extend_from_slice(&encode_integer(error_status));
    pdu.extend_from_slice(&encode_integer(0));
    pdu.extend_from_slice(&varbind_list);
    let pdu = ber_tlv(TAG_GET_RESPONSE, &pdu);

    let mut body = Vec::new();
    body.extend_from_slice(&encode_integer(version.wire()));
    body.extend_from_slice(&encode_octet_string(community));
    body.extend_from_slice(&pdu);
    Ok(ber_tlv(TAG_SEQUENCE, &body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_get_round_trips_through_mock_response() {
        let req = encode_community_get_request(SnmpVersion::V2c, b"public", 42).unwrap();
        let mut reader = BerReader::new(&req);
        let seq = reader.expect_tag(TAG_SEQUENCE).unwrap();
        let mut inner = BerReader::new(seq);
        assert_eq!(inner.read_integer().unwrap(), 1);
        assert_eq!(inner.read_octet_string().unwrap(), b"public");
        let (tag, _) = inner.read_tlv().unwrap();
        assert_eq!(tag, TAG_GET_REQUEST);

        let resp = encode_community_get_response(SnmpVersion::V2c, b"public", 42, 0).unwrap();
        let decoded = decode_community_response(&resp).unwrap();
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.error_status, PduErrorStatus::NoError);
        assert_eq!(decoded.pdu_tag, TAG_GET_RESPONSE);
    }
}
