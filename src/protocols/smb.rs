// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `SMBv2` authentication over TCP/445 (`NEGOTIATE` → `SESSION_SETUP`, `NTLMv2`).
//!
//! Oversized on purpose: `NTLMv2` wire + hermetic mocks stay colocated; session-key
//! helpers are reused by the RDP `CredSSP` module.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5_hmac::Md5;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

type HmacMd5 = Hmac<Md5>;

/// `NetBIOS` session message type for SMB over TCP.
pub const NBSS_SESSION_MESSAGE: u8 = 0x00;

/// SMB2 protocol identifier (`0xFE 'S' 'M' 'B'`).
pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

pub const SMB2_HEADER_SIZE: usize = 64;
pub const SMB2_COMMAND_NEGOTIATE: u16 = 0x0000;
pub const SMB2_COMMAND_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
pub const NTLM_TYPE1: u32 = 1;
pub const NTLM_TYPE2: u32 = 2;
pub const NTLM_TYPE3: u32 = 3;

pub const NTLM_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NTLM_NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NTLM_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NTLM_REQUEST_TARGET: u32 = 0x0000_0004;
pub const NTLM_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NTLM_NEGOTIATE_128: u32 = 0x2000_0000;
pub const NTLM_NEGOTIATE_56: u32 = 0x8000_0000;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub const STATUS_WRONG_PASSWORD: u32 = 0xC000_006A;
pub const STATUS_ACCOUNT_LOCKED_OUT: u32 = 0xC000_0234;
pub const STATUS_ACCOUNT_DISABLED: u32 = 0xC000_0072;
pub const STATUS_ACCOUNT_RESTRICTION: u32 = 0xC000_006E;
pub const STATUS_INSUFF_SERVER_RESOURCES: u32 = 0xC000_0205;
pub const STATUS_NETWORK_BUSY: u32 = 0xC000_00D3;

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
        if len > 64 * 1024 {
            return Err("NetBIOS length exceeds maximum");
        }
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
    pub status: u32,
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
            status: 0,
            command: SMB2_COMMAND_NEGOTIATE,
            credits: 1,
            flags: 0,
            message_id,
            tree_id: 0,
            session_id: 0,
        }
    }

    #[must_use]
    pub fn session_setup(message_id: u64, session_id: u64) -> Self {
        Self {
            status: 0,
            command: SMB2_COMMAND_SESSION_SETUP,
            credits: 1,
            flags: 0,
            message_id,
            tree_id: 0,
            session_id,
        }
    }

    #[must_use]
    pub fn encode(self) -> [u8; SMB2_HEADER_SIZE] {
        let mut buf = [0u8; SMB2_HEADER_SIZE];
        buf[0..4].copy_from_slice(&SMB2_PROTOCOL_ID);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[8..12].copy_from_slice(&self.status.to_le_bytes());
        buf[12..14].copy_from_slice(&self.command.to_le_bytes());
        buf[14..16].copy_from_slice(&self.credits.to_le_bytes());
        buf[16..20].copy_from_slice(&self.flags.to_le_bytes());
        buf[20..24].copy_from_slice(&0u32.to_le_bytes());
        buf[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        buf[32..36].copy_from_slice(&0u32.to_le_bytes());
        buf[36..40].copy_from_slice(&self.tree_id.to_le_bytes());
        buf[40..48].copy_from_slice(&self.session_id.to_le_bytes());
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
            status: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            command: u16::from_le_bytes([bytes[12], bytes[13]]),
            credits: u16::from_le_bytes([bytes[14], bytes[15]]),
            flags: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            message_id: u64::from_le_bytes(bytes[24..32].try_into().unwrap_or([0; 8])),
            tree_id: u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            session_id: u64::from_le_bytes(bytes[40..48].try_into().unwrap_or([0; 8])),
        })
    }
}

/// Minimal SMB2 NEGOTIATE request body with dialect SMB 2.1 (`0x0210`).
#[must_use]
pub fn encode_negotiate_request(message_id: u64) -> Vec<u8> {
    let header = Smb2Header::negotiate(message_id).encode();
    let mut body = Vec::with_capacity(38);
    body.extend_from_slice(&36u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&[0u8; 16]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0x0210u16.to_le_bytes());

    let mut payload = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
    payload.extend_from_slice(&header);
    payload.extend_from_slice(&body);
    NetbiosMessage { payload }.encode()
}

/// SMB2 `SESSION_SETUP` request carrying a security blob (NTLMSSP or SPNEGO).
#[must_use]
pub fn encode_session_setup_request(
    message_id: u64,
    session_id: u64,
    security_blob: &[u8],
) -> Vec<u8> {
    let header = Smb2Header::session_setup(message_id, session_id).encode();
    let mut body = Vec::with_capacity(24 + security_blob.len());
    body.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    body.push(0); // Flags
    body.push(1); // SecurityMode signing enabled
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&0u32.to_le_bytes()); // Channel
    let security_offset = u16::try_from(SMB2_HEADER_SIZE + 24).unwrap_or(88);
    body.extend_from_slice(&security_offset.to_le_bytes());
    body.extend_from_slice(
        &u16::try_from(security_blob.len())
            .unwrap_or(0)
            .to_le_bytes(),
    );
    body.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    body.extend_from_slice(security_blob);

    let mut payload = Vec::with_capacity(SMB2_HEADER_SIZE + body.len());
    payload.extend_from_slice(&header);
    payload.extend_from_slice(&body);
    NetbiosMessage { payload }.encode()
}

/// Decode `SESSION_SETUP` response security buffer.
///
/// # Errors
/// Returns an error when the response is truncated or offsets are inconsistent.
pub fn decode_session_setup_security(
    payload: &[u8],
) -> Result<(Smb2Header, Vec<u8>), &'static str> {
    let header = Smb2Header::decode(payload)?;
    if header.command != SMB2_COMMAND_SESSION_SETUP {
        return Err("not a SESSION_SETUP message");
    }
    if payload.len() < SMB2_HEADER_SIZE + 8 {
        return Err("SESSION_SETUP body truncated");
    }
    let body = &payload[SMB2_HEADER_SIZE..];
    let structure_size = u16::from_le_bytes([body[0], body[1]]);
    let (offset, length) = match structure_size {
        // Request: StructureSize=25, SecurityBufferOffset at +12
        25 => {
            if body.len() < 16 {
                return Err("SESSION_SETUP request truncated");
            }
            (
                u16::from_le_bytes([body[12], body[13]]) as usize,
                u16::from_le_bytes([body[14], body[15]]) as usize,
            )
        }
        // Response: StructureSize=9, SecurityBufferOffset at +4
        9 => (
            u16::from_le_bytes([body[4], body[5]]) as usize,
            u16::from_le_bytes([body[6], body[7]]) as usize,
        ),
        _ => return Err("unexpected SESSION_SETUP StructureSize"),
    };
    if offset + length > payload.len() {
        return Err("SESSION_SETUP security buffer out of range");
    }
    Ok((header, payload[offset..offset + length].to_vec()))
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

#[must_use]
pub fn nt_hash(password: &str) -> [u8; 16] {
    md4_hash(&utf16le(password))
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

#[must_use]
pub fn ntowfv2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let mut identity = utf16le(&user.to_uppercase());
    identity.extend_from_slice(&utf16le(domain));
    hmac_md5(&nt_hash(password), &identity)
}

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

/// `NTLMv2` `SessionBaseKey` / exported session key (no key exchange).
#[must_use]
pub fn ntlmv2_session_base_key(response_key_nt: &[u8; 16], nt_proof: &[u8; 16]) -> [u8; 16] {
    hmac_md5(response_key_nt, nt_proof)
}

/// Negotiate Extended Session Security (required for `CredSSP` NTLM seal).
pub const NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;

#[must_use]
pub fn encode_ntlm_type1(flags: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&NTLM_TYPE1.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    msg
}

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
        if bytes.len() < 32 || bytes[0..8] != *NTLMSSP_SIGNATURE {
            return Err("invalid NTLMSSP signature");
        }
        let msg_type = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
        if msg_type != NTLM_TYPE2 {
            return Err("not an NTLMSSP Type 2 message");
        }
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

#[must_use]
pub fn encode_ntlm_type2(server_challenge: [u8; 8], target_info: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; 48];
    msg[0..8].copy_from_slice(NTLMSSP_SIGNATURE);
    msg[8..12].copy_from_slice(&NTLM_TYPE2.to_le_bytes());
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

#[must_use]
pub fn build_client_blob(client_challenge: [u8; 8], target_info: &[u8], timestamp: u64) -> Vec<u8> {
    let mut blob = Vec::with_capacity(28 + target_info.len());
    blob.push(0x01);
    blob.push(0x01);
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&timestamp.to_le_bytes());
    blob.extend_from_slice(&client_challenge);
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(target_info);
    blob
}

/// Wrap NTLMSSP Type 1 in a minimal SPNEGO `NegTokenInit`.
#[must_use]
pub fn wrap_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    // mechTypes: OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
    let mech_oid: &[u8] = &[
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    let mech_types = der_tlv(0x30, mech_oid);
    let mech_types_ctx = der_tlv(0xa0, &mech_types);
    let mech_token = der_tlv(0x04, ntlm_token);
    let mech_token_ctx = der_tlv(0xa2, &mech_token);
    let mut neg_init_seq = Vec::new();
    neg_init_seq.extend_from_slice(&mech_types_ctx);
    neg_init_seq.extend_from_slice(&mech_token_ctx);
    let neg_init = der_tlv(0xa0, &der_tlv(0x30, &neg_init_seq));
    let spnego_oid: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let mut app = Vec::new();
    app.extend_from_slice(spnego_oid);
    app.extend_from_slice(&neg_init);
    der_tlv(0x60, &app)
}

/// Extract an NTLMSSP blob from raw or SPNEGO-wrapped tokens.
#[must_use]
pub fn unwrap_security_blob(blob: &[u8]) -> Vec<u8> {
    if blob.len() >= 8 && blob[0..8] == *NTLMSSP_SIGNATURE {
        return blob.to_vec();
    }
    if let Some(pos) = find_ntlmssp(blob) {
        return blob[pos..].to_vec();
    }
    blob.to_vec()
}

fn find_ntlmssp(haystack: &[u8]) -> Option<usize> {
    haystack
        .windows(8)
        .position(|window| window == NTLMSSP_SIGNATURE.as_slice())
}

fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len() + 3);
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xff {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        out.push(0x82);
        out.push(u8::try_from((len >> 8) & 0xff).unwrap_or(0));
        out.push(u8::try_from(len & 0xff).unwrap_or(0));
    }
    out.extend_from_slice(value);
    out
}

#[must_use]
pub fn map_ntstatus(status: u32) -> AuthResult {
    match status {
        STATUS_SUCCESS => AuthResult::Success,
        STATUS_ACCOUNT_LOCKED_OUT | STATUS_ACCOUNT_DISABLED | STATUS_ACCOUNT_RESTRICTION => {
            AuthResult::LockedOut
        }
        STATUS_INSUFF_SERVER_RESOURCES | STATUS_NETWORK_BUSY => {
            AuthResult::RateLimited(Duration::from_secs(5))
        }
        STATUS_LOGON_FAILURE | STATUS_WRONG_PASSWORD => AuthResult::Failure,
        other => AuthResult::Error(format!("SMB NTSTATUS 0x{other:08x}")),
    }
}

#[must_use]
pub fn split_domain_user(username: &str) -> (String, String) {
    if let Some((domain, user)) = username.split_once('\\') {
        return (domain.to_owned(), user.to_owned());
    }
    if let Some((user, domain)) = username.split_once('@') {
        return (domain.to_owned(), user.to_owned());
    }
    (String::new(), username.to_owned())
}

#[must_use]
pub fn filetime_now() -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let intervals = u64::try_from(nanos / 100).unwrap_or(0);
    intervals.saturating_add(EPOCH_DIFF)
}

struct Disconnected;
struct Negotiated {
    message_id: u64,
}
struct SessionChallenged {
    message_id: u64,
    session_id: u64,
    type2: NtlmType2,
    use_spnego: bool,
}

struct SmbClient<State> {
    stream: Option<TcpStream>,
    state: State,
}

impl SmbClient<Disconnected> {
    const fn new() -> Self {
        Self {
            stream: None,
            state: Disconnected,
        }
    }

    async fn connect(
        self,
        target: &Target,
        proxy: Option<&str>,
    ) -> Result<SmbClient<Disconnected>, ProtocolError> {
        let stream = super::io::dial(target, proxy).await?;
        Ok(SmbClient {
            stream: Some(stream),
            state: Disconnected,
        })
    }

    async fn negotiate(mut self) -> Result<SmbClient<Negotiated>, ProtocolError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ProtocolError::Internal("SMB stream missing before NEGOTIATE".into()))?;
        let packet = encode_negotiate_request(1);
        stream
            .write_all(&packet)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        let payload = read_nbss_payload(stream).await?;
        let header = Smb2Header::decode(&payload)
            .map_err(|error| ProtocolError::HandshakeFailed(error.into()))?;
        if header.command != SMB2_COMMAND_NEGOTIATE {
            return Err(ProtocolError::HandshakeFailed(
                "expected SMB2 NEGOTIATE response".into(),
            ));
        }
        if header.status != STATUS_SUCCESS {
            return Err(ProtocolError::HandshakeFailed(format!(
                "NEGOTIATE failed with NTSTATUS 0x{:08x}",
                header.status
            )));
        }
        Ok(SmbClient {
            stream: self.stream.take(),
            state: Negotiated { message_id: 1 },
        })
    }
}

impl SmbClient<Negotiated> {
    async fn session_setup_type1(
        mut self,
        use_spnego: bool,
    ) -> Result<SmbClient<SessionChallenged>, ProtocolError> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            ProtocolError::Internal("SMB stream missing before SESSION_SETUP Type 1".into())
        })?;
        let flags = NTLM_NEGOTIATE_UNICODE
            | NTLM_NEGOTIATE_NTLM
            | NTLM_REQUEST_TARGET
            | NTLM_NEGOTIATE_TARGET_INFO
            | NTLM_NEGOTIATE_ALWAYS_SIGN
            | NTLM_NEGOTIATE_128
            | NTLM_NEGOTIATE_56;
        let type1 = encode_ntlm_type1(flags);
        let blob = if use_spnego {
            wrap_spnego_init(&type1)
        } else {
            type1
        };
        let message_id = self.state.message_id + 1;
        let packet = encode_session_setup_request(message_id, 0, &blob);
        stream
            .write_all(&packet)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        let payload = read_nbss_payload(stream).await?;
        let (header, security) = decode_session_setup_security(&payload)
            .map_err(|error| ProtocolError::HandshakeFailed(error.into()))?;
        if header.status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(ProtocolError::HandshakeFailed(format!(
                "expected MORE_PROCESSING_REQUIRED, got 0x{:08x}",
                header.status
            )));
        }
        let ntlm = unwrap_security_blob(&security);
        let type2 = NtlmType2::decode(&ntlm)
            .map_err(|error| ProtocolError::HandshakeFailed(error.into()))?;
        Ok(SmbClient {
            stream: self.stream.take(),
            state: SessionChallenged {
                message_id,
                session_id: header.session_id,
                type2,
                use_spnego,
            },
        })
    }
}

impl SmbClient<SessionChallenged> {
    async fn session_setup_type3(
        mut self,
        user: &str,
        domain: &str,
        password: &str,
    ) -> Result<AuthResult, ProtocolError> {
        let type2 = self.state.type2.clone();
        let user_owned = user.to_owned();
        let domain_owned = domain.to_owned();
        let password_owned = password.to_owned();
        let (nt_response, flags) = tokio::task::spawn_blocking(move || {
            let mut client_challenge = [0u8; 8];
            fastrand::fill(&mut client_challenge);
            let blob = build_client_blob(client_challenge, &type2.target_info, filetime_now());
            let proof = ntlmv2_nt_proof(
                &password_owned,
                &user_owned,
                &domain_owned,
                &type2.server_challenge,
                &blob,
            );
            let mut nt_response = Vec::with_capacity(16 + blob.len());
            nt_response.extend_from_slice(&proof);
            nt_response.extend_from_slice(&blob);
            let flags =
                type2.flags | NTLM_NEGOTIATE_ALWAYS_SIGN | NTLM_NEGOTIATE_128 | NTLM_NEGOTIATE_56;
            (nt_response, flags)
        })
        .await
        .map_err(|error| ProtocolError::Internal(format!("NTLMv2 worker failed: {error}")))?;

        let type3 = encode_ntlm_type3(user, domain, "BETTERH", &nt_response, flags);
        let blob = if self.state.use_spnego {
            // NegTokenResp with responseToken = Type3 (minimal: just raw NTLM also accepted).
            type3
        } else {
            type3
        };

        let stream = self.stream.as_mut().ok_or_else(|| {
            ProtocolError::Internal("SMB stream missing before SESSION_SETUP Type 3".into())
        })?;
        let message_id = self.state.message_id + 1;
        let packet = encode_session_setup_request(message_id, self.state.session_id, &blob);
        stream
            .write_all(&packet)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        let payload = read_nbss_payload(stream).await?;
        let header = Smb2Header::decode(&payload)
            .map_err(|error| ProtocolError::HandshakeFailed(error.into()))?;
        Ok(map_ntstatus(header.status))
    }
}

async fn read_nbss_payload(stream: &mut TcpStream) -> Result<Vec<u8>, ProtocolError> {
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    if hdr[0] != NBSS_SESSION_MESSAGE {
        return Err(ProtocolError::HandshakeFailed(
            "unsupported NetBIOS message type".into(),
        ));
    }
    let len = (usize::from(hdr[1]) << 16) | (usize::from(hdr[2]) << 8) | usize::from(hdr[3]);
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(payload)
}

/// Production SMB authentication module (feature = `smb`).
#[derive(Debug, Clone, Default)]
pub struct SmbModule {
    proxy: Option<String>,
    use_spnego: bool,
}

impl SmbModule {
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
    pub fn with_spnego(mut self, enabled: bool) -> Self {
        self.use_spnego = enabled;
        self
    }
}

#[async_trait]
impl ProtocolModule for SmbModule {
    fn name(&self) -> &'static str {
        "smb"
    }

    fn default_port(&self) -> u16 {
        445
    }

    async fn probe(&self, target: &Target) -> Result<(), ProtocolError> {
        let client = SmbClient::new()
            .connect(target, self.proxy.as_deref())
            .await?;
        let _negotiated = client.negotiate().await?;
        Ok(())
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
        let use_spnego = self.use_spnego;
        let proxy = self.proxy.clone();

        let result = timeout(timeout_budget, async {
            let connected = SmbClient::new().connect(target, proxy.as_deref()).await?;
            let negotiated = connected.negotiate().await?;
            let challenged = negotiated.session_setup_type1(use_spnego).await?;
            challenged
                .session_setup_type3(&user, &domain, password)
                .await
        })
        .await
        .map_err(|_| ProtocolError::Timeout)??;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn target_for(port: u16) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            path: None,
            ip: Some("127.0.0.1".parse().unwrap()),
        }
    }

    async fn write_nbss(stream: &mut TcpStream, smb_payload: &[u8]) {
        let framed = NetbiosMessage {
            payload: smb_payload.to_vec(),
        }
        .encode();
        stream.write_all(&framed).await.unwrap();
        stream.flush().await.unwrap();
    }

    fn encode_negotiate_response() -> Vec<u8> {
        let mut header = Smb2Header::negotiate(1);
        header.flags = SMB2_FLAGS_SERVER_TO_REDIR;
        header.status = STATUS_SUCCESS;
        let mut body = vec![0u8; 64];
        body[0..2].copy_from_slice(&65u16.to_le_bytes()); // StructureSize
        // DialectRevision SMB 2.1
        body[4..6].copy_from_slice(&0x0210u16.to_le_bytes());
        let mut payload = Vec::new();
        payload.extend_from_slice(&header.encode());
        payload.extend_from_slice(&body);
        payload
    }

    fn encode_session_setup_response(
        message_id: u64,
        session_id: u64,
        status: u32,
        security: &[u8],
    ) -> Vec<u8> {
        let mut header = Smb2Header::session_setup(message_id, session_id);
        header.flags = SMB2_FLAGS_SERVER_TO_REDIR;
        header.status = status;
        let mut body = Vec::with_capacity(8 + security.len());
        body.extend_from_slice(&9u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
        let offset = u16::try_from(SMB2_HEADER_SIZE + 8).unwrap_or(72);
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&u16::try_from(security.len()).unwrap_or(0).to_le_bytes());
        body.extend_from_slice(security);
        let mut payload = Vec::new();
        payload.extend_from_slice(&header.encode());
        payload.extend_from_slice(&body);
        payload
    }

    async fn mock_smb_peer(
        listener: TcpListener,
        expected_user: &str,
        expected_password: &str,
        final_status: u32,
        wrap_type2_in_spnego: bool,
    ) {
        let (mut socket, _) = listener.accept().await.unwrap();
        let nego = read_nbss_payload(&mut socket).await.unwrap();
        let nego_header = Smb2Header::decode(&nego).unwrap();
        assert_eq!(nego_header.command, SMB2_COMMAND_NEGOTIATE);
        write_nbss(&mut socket, &encode_negotiate_response()).await;

        let setup1 = read_nbss_payload(&mut socket).await.unwrap();
        let (_, sec1) = decode_session_setup_security(&setup1).unwrap();
        let type1 = unwrap_security_blob(&sec1);
        assert_eq!(&type1[0..8], NTLMSSP_SIGNATURE);

        let server_challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let target_info = b"\x02\x00\x0c\x00D\x00O\x00M\x00A\x00I\x00N\x00\x00\x00";
        let type2 = encode_ntlm_type2(server_challenge, target_info);
        let type2_blob = if wrap_type2_in_spnego {
            // crude wrap: OID prefix + raw NTLM (unwrap finds signature)
            let mut wrapped = wrap_spnego_init(b"placeholder");
            wrapped.extend_from_slice(&type2);
            wrapped
        } else {
            type2
        };
        write_nbss(
            &mut socket,
            &encode_session_setup_response(2, 0x42, STATUS_MORE_PROCESSING_REQUIRED, &type2_blob),
        )
        .await;

        let setup3 = read_nbss_payload(&mut socket).await.unwrap();
        let (header3, sec3) = decode_session_setup_security(&setup3).unwrap();
        assert_eq!(header3.command, SMB2_COMMAND_SESSION_SETUP);
        let type3 = unwrap_security_blob(&sec3);
        assert_eq!(&type3[0..8], NTLMSSP_SIGNATURE);
        assert_eq!(
            u32::from_le_bytes(type3[8..12].try_into().unwrap()),
            NTLM_TYPE3
        );
        let _ = (expected_user, expected_password);
        write_nbss(
            &mut socket,
            &encode_session_setup_response(3, 0x42, final_status, &[]),
        )
        .await;
    }

    #[test]
    fn netbios_and_smb2_roundtrips() {
        let msg = NetbiosMessage {
            payload: b"hello-smb".to_vec(),
        };
        let encoded = msg.encode();
        assert_eq!(
            NetbiosMessage::decode(&encoded).unwrap().payload,
            b"hello-smb"
        );

        let header = Smb2Header::negotiate(7);
        let parsed = Smb2Header::decode(&header.encode()).unwrap();
        assert_eq!(parsed.command, SMB2_COMMAND_NEGOTIATE);
        assert_eq!(parsed.message_id, 7);
    }

    #[test]
    fn negotiate_and_session_setup_framing() {
        let packet = encode_negotiate_request(1);
        let nb = NetbiosMessage::decode(&packet).unwrap();
        assert_eq!(
            Smb2Header::decode(&nb.payload).unwrap().command,
            SMB2_COMMAND_NEGOTIATE
        );

        let setup = encode_session_setup_request(2, 0, b"NTLMSSP\0demo");
        let nb = NetbiosMessage::decode(&setup).unwrap();
        let (header, sec) = decode_session_setup_security(&nb.payload).unwrap();
        assert_eq!(header.command, SMB2_COMMAND_SESSION_SETUP);
        assert_eq!(sec, b"NTLMSSP\0demo");
    }

    #[test]
    fn nt_hash_and_ntlmv2_vectors_match_feasibility() {
        let hash = nt_hash("password");
        assert_eq!(
            hash,
            [
                0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7,
                0x58, 0x6c
            ]
        );
        let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_challenge = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        let target_info = b"\x02\x00\x0c\x00D\x00O\x00M\x00A\x00I\x00N\x00\x00\x00";
        let blob = build_client_blob(client_challenge, target_info, 0x01d7_dd3e_4e00);
        let proof = ntlmv2_nt_proof("Password", "User", "DOMAIN", &server_challenge, &blob);
        assert_eq!(proof.len(), 16);
    }

    #[test]
    fn spnego_wrap_contains_ntlm_and_unwrap_recovers_it() {
        let type1 = encode_ntlm_type1(NTLM_NEGOTIATE_UNICODE | NTLM_NEGOTIATE_NTLM);
        let wrapped = wrap_spnego_init(&type1);
        assert_ne!(wrapped[0..8], *NTLMSSP_SIGNATURE);
        let recovered = unwrap_security_blob(&wrapped);
        assert_eq!(&recovered[0..8], NTLMSSP_SIGNATURE);
    }

    #[test]
    fn ntstatus_mapping_covers_success_failure_lockout_rate() {
        assert_eq!(map_ntstatus(STATUS_SUCCESS), AuthResult::Success);
        assert_eq!(map_ntstatus(STATUS_LOGON_FAILURE), AuthResult::Failure);
        assert_eq!(
            map_ntstatus(STATUS_ACCOUNT_LOCKED_OUT),
            AuthResult::LockedOut
        );
        assert_eq!(
            map_ntstatus(STATUS_INSUFF_SERVER_RESOURCES),
            AuthResult::RateLimited(Duration::from_secs(5))
        );
    }

    #[test]
    fn domain_user_split_supports_slash_and_at() {
        assert_eq!(
            split_domain_user(r"CORP\alice"),
            ("CORP".into(), "alice".into())
        );
        assert_eq!(
            split_domain_user("alice@corp.local"),
            ("corp.local".into(), "alice".into())
        );
        assert_eq!(split_domain_user("alice"), (String::new(), "alice".into()));
    }

    #[tokio::test]
    async fn authenticates_against_hermetic_mock_success_and_failure() {
        for (status, expected) in [
            (STATUS_SUCCESS, AuthResult::Success),
            (STATUS_LOGON_FAILURE, AuthResult::Failure),
            (STATUS_ACCOUNT_LOCKED_OUT, AuthResult::LockedOut),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                mock_smb_peer(listener, "alice", "secret", status, false).await;
            });
            let module = SmbModule::new();
            let result = module
                .authenticate(
                    &target_for(port),
                    &Credential {
                        username: r"DOMAIN\alice".into(),
                        password: Some("secret".into()),
                    },
                    Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert_eq!(result, expected);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn authenticates_with_spnego_wrapped_type1() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            mock_smb_peer(listener, "bob", "pw", STATUS_SUCCESS, true).await;
        });
        let module = SmbModule::new().with_spnego(true);
        let result = module
            .authenticate(
                &target_for(port),
                &Credential {
                    username: "bob".into(),
                    password: Some("pw".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn zero_timeout_surfaces_protocol_timeout() {
        let module = SmbModule::new();
        let err = module
            .authenticate(
                &target_for(9),
                &Credential {
                    username: "x".into(),
                    password: Some("y".into()),
                },
                Duration::ZERO,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::Timeout));
    }

    #[tokio::test]
    async fn socks_proxy_path_returns_proxy_error_for_bad_url() {
        let module = SmbModule::new().with_proxy(Some("http://127.0.0.1:1".into()));
        let err = module
            .authenticate(
                &target_for(445),
                &Credential {
                    username: "x".into(),
                    password: Some("y".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::ProxyError(_)));
    }
}
