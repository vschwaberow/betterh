// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Phase 11.1 offline SMB/NTLMv2 codec harness.
//!
//! Re-exports production codecs from [`crate::protocols::smb`] so crypto paths stay single-sourced.

pub use crate::protocols::smb::{
    NBSS_SESSION_MESSAGE, NTLM_NEGOTIATE_56, NTLM_NEGOTIATE_128, NTLM_NEGOTIATE_ALWAYS_SIGN,
    NTLM_NEGOTIATE_NTLM, NTLM_NEGOTIATE_TARGET_INFO, NTLM_NEGOTIATE_UNICODE, NTLM_REQUEST_TARGET,
    NTLM_TYPE1, NTLM_TYPE2, NTLM_TYPE3, NTLMSSP_SIGNATURE, NetbiosMessage, NtlmType2,
    SMB2_COMMAND_NEGOTIATE, SMB2_COMMAND_SESSION_SETUP, SMB2_HEADER_SIZE, SMB2_PROTOCOL_ID,
    Smb2Header, build_client_blob, encode_negotiate_request, encode_ntlm_type1, encode_ntlm_type2,
    encode_ntlm_type3, md4_hash, nt_hash, ntlmv2_nt_proof, ntowfv2, utf16le,
};
