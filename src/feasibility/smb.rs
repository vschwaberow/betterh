// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Phase 11.1 feasibility prototype: `SMBv2` framing and NTLMSSP / `NTLMv2` proofs.
//!
//! Hermetic encode/decode and crypto checks only — not a production `ProtocolModule`.

use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5_hmac::Md5;

type HmacMd5 = Hmac<Md5>;

/// `NetBIOS` session message type for SMB over TCP.
pub const NBSS_SESSION_MESSAGE: u8 = 0x00;

/// SMB2 protocol identifier (`0xFE 'S' 'M' 'B'`).
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

pub const SMB2_HEADER_SIZE: usize = 64;
pub const SMB2_COMMAND_NEGOTIATE: u16 = 0x0000;
pub const SMB2_COMMAND_SESSION_SETUP: u16 = 0x0001;

pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
pub const NTLM_TYPE1: u32 = 1;
pub const NTLM_TYPE2: u32 = 2;
pub const NTLM_TYPE3: u32 = 3;

/// Common NTLM negotiate flags used by the prototype Type 1 message.
pub const NTLM_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NTLM_NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NTLM_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NTLM_REQUEST_TARGET: u32 = 0x0000_0004;
pub const NTLM_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NTLM_NEGOTIATE_128: u32 = 0x2000_0000;
pub const NTLM_NEGOTIATE_56: u32 = 0x8000_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbiosMessage {
    pub payload: Vec<u8>,
}

impl NetbiosMessage {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len();
        debug_assert!(len <= 0x00FF_FFFF);
        let mut out = Vec::with_capacity(4 + len);
        out.push(NBSS_SESSION_MESSAGE);
        out.push(u8::try_from((len >> 16) & 0xff).unwrap_or(0));
        out.push(u8::try_from((len >> 8) & 0xff).unwrap_or(0));
        out.push(u8::try_from(len & 0xff).unwrap_or(0));
        out.extend_from_slice(&self.payload);
        out
    }

    /// # Errors
    /// Returns an error when the buffer is too short or the length prefix is inconsistent.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 {
            return Err("NetBIOS header truncated");
        }
        if bytes[0] != NBSS_SESSION_MESSAGE {
            return Err("unsupported NetBIOS message type");
        }
        let len =
            (usize::from(bytes[1]) << 16) | (usize::from(bytes[2]) << 8) | usize::from(bytes[3]);
        if bytes.len() < 4 + len {
            return Err("NetBIOS payload truncated");
        }
        Ok(Self {
            payload: bytes[4..4 + len].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Smb2Header {
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub message_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
}

impl Smb2Header {
    #[must_use]
    pub fn negotiate(message_id: u64) -> Self {
        Self {
            command: SMB2_COMMAND_NEGOTIATE,
            credits: 1,
            flags: 0,
            message_id,
            tree_id: 0,
            session_id: 0,
        }
    }

    #[must_use]
    pub fn encode(self) -> [u8; SMB2_HEADER_SIZE] {
        let mut buf = [0u8; SMB2_HEADER_SIZE];
        buf[0..4].copy_from_slice(&SMB2_PROTOCOL_ID);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes()); // StructureSize
        buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // CreditCharge
        buf[8..12].copy_from_slice(&0u32.to_le_bytes()); // Status
        buf[12..14].copy_from_slice(&self.command.to_le_bytes());
        buf[14..16].copy_from_slice(&self.credits.to_le_bytes());
        buf[16..20].copy_from_slice(&self.flags.to_le_bytes());
        buf[20..24].copy_from_slice(&0u32.to_le_bytes()); // NextCommand
        buf[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        buf[32..36].copy_from_slice(&0u32.to_le_bytes()); // ProcessId
        buf[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        buf[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        // Signature [48..64] left zero for unsigned negotiate.
        buf
    }

    /// # Errors
    /// Returns an error when the buffer is too short or the protocol id mismatches.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < SMB2_HEADER_SIZE {
            return Err("SMB2 header truncated");
        }
        if bytes[0..4] != SMB2_PROTOCOL_ID {
            return Err("invalid SMB2 protocol id");
        }
        Ok(Self {
            command: u16::from_le_bytes([bytes[12], bytes[13]]),
            credits: u16::from_le_bytes([bytes[14], bytes[15]]),
            flags: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            message_id: u64::from_le_bytes(bytes[24..32].try_into().unwrap_or([0; 8])),
            tree_id: u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            session_id: u64::from_le_bytes(bytes[40..48].try_into().unwrap_or([0; 8])),
        })
    }
}

/// Minimal SMB2 NEGOTIATE request body (`StructureSize` 36) with one dialect (SMB 2.1 = `0x0210`).
#[must_use]
pub fn encode_negotiate_request(message_id: u64) -> Vec<u8> {
    let header = Smb2Header::negotiate(message_id).encode();
    let mut body = Vec::with_capacity(36 + 2);
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&1u16.to_le_bytes()); // DialectCount
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode signing enabled
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&[0u8; 16]); // ClientGuid
    body.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset / ClientStartTime low
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0x0210u16.to_le_bytes()); // SMB 2.1

    let mut payload = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
    payload.extend_from_slice(&header);
    payload.extend_from_slice(&body);
    NetbiosMessage { payload }.encode()
}

#[must_use]
pub fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[must_use]
pub fn md4_hash(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// NT hash = MD4(UTF-16LE(password)).
#[must_use]
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4_hash(&utf16le(password))
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC-MD5 accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// `NTOWFv2` per MS-NLMP.
#[must_use]
pub fn ntowfv2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let mut identity = utf16le(&user.to_uppercase());
    identity.extend_from_slice(&utf16le(domain));
    hmac_md5(&nt_hash(password), &identity)
}

/// `NTLMv2` NT proof = `HMAC_MD5(NTOWFv2, serverChallenge || clientBlob)`.
#[must_use]
pub fn ntlmv2_nt_proof(
    password: &str,
    user: &str,
    domain: &str,
    server_challenge: &[u8; 8],
    client_blob: &[u8],
) -> [u8; 16] {
    let mut data = Vec::with_capacity(8 + client_blob.len());
    data.extend_from_slice(server_challenge);
    data.extend_from_slice(client_blob);
    hmac_md5(&ntowfv2(password, user, domain), &data)
}

/// Build a minimal NTLMSSP Type 1 (Negotiate) message.
#[must_use]
pub fn encode_ntlm_type1(flags: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&NTLM_TYPE1.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    // DomainNameFields (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    // WorkstationFields (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg
}

/// Parsed subset of an NTLMSSP Type 2 (Challenge) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmType2 {
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub target_info: Vec<u8>,
}

impl NtlmType2 {
    /// # Errors
    /// Returns an error when the buffer is not a well-formed Type 2 message.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 32 || &bytes[0..8] != NTLMSSP_SIGNATURE {
            return Err("invalid NTLMSSP signature");
        }
        let msg_type = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
        if msg_type != NTLM_TYPE2 {
            return Err("not an NTLMSSP Type 2 message");
        }
        // TargetNameFields at 12..20, Flags at 20, Challenge at 24, Reserved 32, TargetInfo 40
        if bytes.len() < 48 {
            return Err("Type 2 message truncated");
        }
        let flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap_or([0; 4]));
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(&bytes[24..32]);
        let info_len = u16::from_le_bytes([bytes[40], bytes[41]]) as usize;
        let info_off = u32::from_le_bytes(bytes[44..48].try_into().unwrap_or([0; 4])) as usize;
        if info_off + info_len > bytes.len() {
            return Err("Type 2 target info out of range");
        }
        Ok(Self {
            flags,
            server_challenge,
            target_info: bytes[info_off..info_off + info_len].to_vec(),
        })
    }
}

/// Build a minimal NTLMSSP Type 2 challenge for hermetic tests.
#[must_use]
pub fn encode_ntlm_type2(server_challenge: [u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; 48];
    msg[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    msg[8..12].copy_from_slice(&NTLM_TYPE2.to_le_bytes());
    // empty target name fields at 12..20
    let flags = NTLM_NEGOTIATE_UNICODE
        | NTLM_NEGOTIATE_NTLM
        | NTLM_REQUEST_TARGET
        | NTLM_NEGOTIATE_TARGET_INFO;
    msg[20..24].copy_from_slice(&flags.to_le_bytes());
    msg[24..32].copy_from_slice(&server_challenge);
    let info_off = 48u32;
    msg[40..42].copy_from_slice(&u16::try_from(target_info.len()).unwrap_or(0).to_le_bytes());
    msg[42..44].copy_from_slice(&u16::try_from(target_info.len()).unwrap_or(0).to_le_bytes());
    msg[44..48].copy_from_slice(&info_off.to_le_bytes());
    msg.extend_from_slice(target_info);
    msg
}

/// Build NTLMSSP Type 3 with `NTLMv2` NT response (`NTProof || clientBlob`; LM response empty).
#[must_use]
pub fn encode_ntlm_type3(
    user: &str,
    domain: &str,
    workstation: &str,
    nt_response: &[u8],
    flags: u32,
) -> Vec<u8> {
    let domain_b = utf16le(domain);
    let user_b = utf16le(user);
    let workstation_b = utf16le(workstation);

    let header_len = 88usize;
    let mut offset = u32::try_from(header_len).unwrap_or(0);
    let mut msg = vec![0u8; header_len];
    msg[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    msg[8..12].copy_from_slice(&NTLM_TYPE3.to_le_bytes());

    // LmChallengeResponse empty
    write_security_buffer(&mut msg, 12, 0, offset);

    let domain_off = offset;
    write_security_buffer(
        &mut msg,
        28,
        u16::try_from(domain_b.len()).unwrap_or(0),
        domain_off,
    );
    offset += u32::try_from(domain_b.len()).unwrap_or(0);

    let user_off = offset;
    write_security_buffer(
        &mut msg,
        36,
        u16::try_from(user_b.len()).unwrap_or(0),
        user_off,
    );
    offset += u32::try_from(user_b.len()).unwrap_or(0);

    let workstation_off = offset;
    write_security_buffer(
        &mut msg,
        44,
        u16::try_from(workstation_b.len()).unwrap_or(0),
        workstation_off,
    );
    offset += u32::try_from(workstation_b.len()).unwrap_or(0);

    let nt_off = offset;
    write_security_buffer(
        &mut msg,
        20,
        u16::try_from(nt_response.len()).unwrap_or(0),
        nt_off,
    );
    offset += u32::try_from(nt_response.len()).unwrap_or(0);

    // SessionKey empty
    write_security_buffer(&mut msg, 52, 0, offset);
    msg[60..64].copy_from_slice(&flags.to_le_bytes());

    msg.extend_from_slice(&domain_b);
    msg.extend_from_slice(&user_b);
    msg.extend_from_slice(&workstation_b);
    msg.extend_from_slice(nt_response);
    msg
}

fn write_security_buffer(msg: &mut [u8], at: usize, length: u16, offset: u32) {
    msg[at..at + 2].copy_from_slice(&length.to_le_bytes());
    msg[at + 2..at + 4].copy_from_slice(&length.to_le_bytes());
    msg[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
}

/// Minimal client blob (temp) for `NTLMv2`: version/hmac reserved + timestamp + client challenge + AV pairs.
#[must_use]
pub fn build_client_blob(client_challenge: [u8; 8], target_info: &[u8], timestamp: u64) -> Vec<u8> {
    let mut blob = Vec::with_capacity(28 + target_info.len());
    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
    blob.extend_from_slice(target_info);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netbios_roundtrip_preserves_payload() {
        let msg = NetbiosMessage {
            payload: b"hello-smb".to_vec(),
        };
        let encoded = msg.encode();
        assert_eq!(encoded[0], NBSS_SESSION_MESSAGE);
        let decoded = NetbiosMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.payload, b"hello-smb");
    }

    #[test]
    fn smb2_header_negotiate_roundtrip() {
        let header = Smb2Header::negotiate(7);
        let bytes = header.encode();
        assert_eq!(&bytes[0..4], &SMB2_PROTOCOL_ID);
        let parsed = Smb2Header::decode(&bytes).unwrap();
        assert_eq!(parsed.command, SMB2_COMMAND_NEGOTIATE);
        assert_eq!(parsed.message_id, 7);
    }

    #[test]
    fn negotiate_request_is_framed_with_netbios_and_smb2() {
        let packet = encode_negotiate_request(1);
        let nb = NetbiosMessage::decode(&packet).unwrap();
        let header = Smb2Header::decode(&nb.payload).unwrap();
        assert_eq!(header.command, SMB2_COMMAND_NEGOTIATE);
        assert!(nb.payload.len() > SMB2_HEADER_SIZE);
    }

    #[test]
    fn nt_hash_of_password_matches_well_known_vector() {
        // Classic NTLM hash of "password"
        let hash = nt_hash("password");
        assert_eq!(
            hash,
            [
                0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7,
                0x58, 0x6c
            ]
        );
    }

    #[test]
    fn ntlm_type1_starts_with_signature_and_type() {
        let flags = NTLM_NEGOTIATE_UNICODE | NTLM_NEGOTIATE_NTLM | NTLM_REQUEST_TARGET;
        let msg = encode_ntlm_type1(flags);
        assert_eq!(&msg[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(
            u32::from_le_bytes(msg[8..12].try_into().unwrap()),
            NTLM_TYPE1
        );
    }

    #[test]
    fn ntlmv2_proof_and_type3_framing_are_self_consistent() {
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let target_info = b"\x02\x00\x0c\x00D\x00O\x00M\x00A\x00I\x00N\x00\x00\x00"; // minimal AV pair blob
        let blob = build_client_blob(client_challenge, target_info, 0x01d7_dd3e_4e00);
        let proof = ntlmv2_nt_proof("Password", "User", "DOMAIN", &server_challenge, &blob);
        assert_eq!(proof.len(), 16);

        let mut nt_response = Vec::with_capacity(16 + blob.len());
        nt_response.extend_from_slice(&proof);
        nt_response.extend_from_slice(&blob);

        let type2 = encode_ntlm_type2(server_challenge, target_info);
        let parsed = NtlmType2::decode(&type2).unwrap();
        assert_eq!(parsed.server_challenge, server_challenge);
        assert_eq!(parsed.target_info, target_info);

        let type3 = encode_ntlm_type3(
            "User",
            "DOMAIN",
            "WORKSTATION",
            &nt_response,
            parsed.flags | NTLM_NEGOTIATE_ALWAYS_SIGN | NTLM_NEGOTIATE_128 | NTLM_NEGOTIATE_56,
        );
        assert_eq!(&type3[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(
            u32::from_le_bytes(type3[8..12].try_into().unwrap()),
            NTLM_TYPE3
        );
        // NT response buffer should appear in the trailing payload.
        assert!(
            type3
                .windows(nt_response.len())
                .any(|window| window == nt_response.as_slice())
        );
    }
}
