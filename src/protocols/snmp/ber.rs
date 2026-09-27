// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Minimal ASN.1 BER helpers for SNMP PDUs.

pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_GET_REQUEST: u8 = 0xa0;
pub(crate) const TAG_GET_RESPONSE: u8 = 0xa2;
pub(crate) const TAG_REPORT: u8 = 0xa8;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum BerError {
    #[error("truncated BER value")]
    Truncated,
    #[error("unexpected BER tag {got:#x}, expected {expected:#x}")]
    UnexpectedTag { expected: u8, got: u8 },
    #[error("invalid BER length")]
    InvalidLength,
    #[error("invalid OID")]
    InvalidOid,
}

pub(crate) fn ber_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![u8::try_from(len).unwrap_or(0)]
    } else if len < 0x100 {
        vec![0x81, u8::try_from(len).unwrap_or(0)]
    } else {
        vec![
            0x82,
            u8::try_from((len >> 8) & 0xff).unwrap_or(0),
            u8::try_from(len & 0xff).unwrap_or(0),
        ]
    }
}

pub(crate) fn ber_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tag);
    out.extend_from_slice(&ber_length(value.len()));
    out.extend_from_slice(value);
    out
}

pub(crate) fn encode_integer(value: i64) -> Vec<u8> {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    ber_tlv(TAG_INTEGER, &bytes)
}

pub(crate) fn encode_octet_string(value: &[u8]) -> Vec<u8> {
    ber_tlv(TAG_OCTET_STRING, value)
}

pub(crate) fn encode_null() -> Vec<u8> {
    ber_tlv(TAG_NULL, &[])
}

fn encode_base128(mut value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0];
    }
    let mut tmp = Vec::new();
    while value > 0 {
        tmp.push(u8::try_from(value & 0x7f).unwrap_or(0));
        value >>= 7;
    }
    tmp.reverse();
    let last = tmp.len().saturating_sub(1);
    for (idx, byte) in tmp.iter_mut().enumerate() {
        if idx != last {
            *byte |= 0x80;
        }
    }
    tmp
}

/// Encode an OBJECT IDENTIFIER from dotted decimal arcs (e.g. `1.3.6.1.2.1.1.1.0`).
pub(crate) fn encode_oid(arcs: &[u32]) -> Result<Vec<u8>, BerError> {
    let Some((first, rest)) = arcs.split_first() else {
        return Err(BerError::InvalidOid);
    };
    let Some((second, rest)) = rest.split_first() else {
        return Err(BerError::InvalidOid);
    };
    if *first > 2 || (*first < 2 && *second >= 40) {
        return Err(BerError::InvalidOid);
    }
    let mut body =
        vec![u8::try_from(first.saturating_mul(40).saturating_add(*second)).unwrap_or(0)];
    for &arc in rest {
        body.extend_from_slice(&encode_base128(arc));
    }
    Ok(ber_tlv(TAG_OID, &body))
}

pub(crate) struct BerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), BerError> {
        let tag = *self.data.get(self.pos).ok_or(BerError::Truncated)?;
        self.pos += 1;
        let (len, adv) = decode_length(&self.data[self.pos..])?;
        self.pos += adv;
        let end = self.pos.checked_add(len).ok_or(BerError::InvalidLength)?;
        if end > self.data.len() {
            return Err(BerError::Truncated);
        }
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok((tag, value))
    }

    pub(crate) fn expect_tag(&mut self, expected: u8) -> Result<&'a [u8], BerError> {
        let (tag, value) = self.read_tlv()?;
        if tag != expected {
            return Err(BerError::UnexpectedTag { expected, got: tag });
        }
        Ok(value)
    }

    pub(crate) fn read_integer(&mut self) -> Result<i64, BerError> {
        let value = self.expect_tag(TAG_INTEGER)?;
        decode_integer(value)
    }

    pub(crate) fn read_octet_string(&mut self) -> Result<&'a [u8], BerError> {
        self.expect_tag(TAG_OCTET_STRING)
    }
}

fn decode_length(data: &[u8]) -> Result<(usize, usize), BerError> {
    let first = *data.first().ok_or(BerError::Truncated)?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let nbytes = usize::from(first & 0x7f);
    if nbytes == 0 || nbytes > 2 || data.len() < 1 + nbytes {
        return Err(BerError::InvalidLength);
    }
    let mut len = 0usize;
    for &b in &data[1..=nbytes] {
        len = (len << 8) | usize::from(b);
    }
    if len > 16 * 1024 {
        return Err(BerError::InvalidLength);
    }
    Ok((len, 1 + nbytes))
}

pub(crate) fn decode_integer(value: &[u8]) -> Result<i64, BerError> {
    if value.is_empty() || value.len() > 8 {
        return Err(BerError::InvalidLength);
    }
    let mut acc: i64 = if value[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in value {
        acc = (acc << 8) | i64::from(b);
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_sysdescr_encodes_standard_bytes() {
        let oid = encode_oid(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
        assert_eq!(
            oid,
            vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]
        );
    }

    #[test]
    fn integer_round_trips() {
        for value in [0_i64, 1, 127, 128, 255, 256, -1, -128] {
            let encoded = encode_integer(value);
            let mut reader = BerReader::new(&encoded);
            assert_eq!(reader.read_integer().unwrap(), value);
        }
    }
}
