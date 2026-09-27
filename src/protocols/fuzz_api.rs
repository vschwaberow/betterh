// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Panic-free decoder entry points for `cargo-fuzz` and CI smoke tests.
//!
//! All helpers reject oversized inputs (`MAX_INPUT`) before invoking wire codecs
//! and swallow parse errors — fuzzing must never abort the process via `unwrap`.

/// Hard ceiling for adversarial wire blobs (64 KiB).
pub const MAX_INPUT: usize = 64 * 1024;

fn capped(data: &[u8]) -> Option<&[u8]> {
    if data.len() > MAX_INPUT {
        return None;
    }
    Some(data)
}

/// SMB `NetBIOS` framing + SMB2 header decode.
pub fn smb_decode(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "smb")]
    {
        use crate::protocols::smb::{NetbiosMessage, Smb2Header, decode_session_setup_security};
        if let Ok(nb) = NetbiosMessage::decode(data) {
            let _ = Smb2Header::decode(&nb.payload);
            let _ = decode_session_setup_security(&nb.payload);
        }
        let _ = Smb2Header::decode(data);
    }
    let _ = data;
}

/// RDP TPKT / X.224 / `CredSSP` `TSRequest` decode surface.
pub fn rdp_decode(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "rdp")]
    {
        use crate::protocols::rdp::{
            Tpkt, TsRequest, X224ConnectionRequest, parse_selected_protocol,
        };
        if let Ok(tpkt) = Tpkt::decode(data) {
            let _ = X224ConnectionRequest::decode_tpdu(&tpkt.payload);
            let _ = parse_selected_protocol(&tpkt.payload);
            let _ = TsRequest::decode(&tpkt.payload);
        }
        let _ = TsRequest::decode(data);
    }
    let _ = data;
}

/// MSSQL TDS packet + PRELOGIN option decode.
pub fn tds_decode(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "mssql")]
    {
        use crate::protocols::mssql::{
            decode_tds_packet, interpret_login_tokens, parse_prelogin_encryption,
        };
        if let Ok((_ty, body)) = decode_tds_packet(data) {
            let _ = parse_prelogin_encryption(&body);
            let _ = interpret_login_tokens(&body);
        }
        let _ = parse_prelogin_encryption(data);
        let _ = interpret_login_tokens(data);
    }
    let _ = data;
}

/// Kerberos KDC message decode (AS-REP / KRB-ERROR).
pub fn kerberos_decode(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "kerberos")]
    {
        crate::protocols::kerberos::fuzz_decode(data);
    }
    let _ = data;
}

/// SNMP community `GetResponse` / Report BER decode.
pub fn snmp_decode(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "snmp")]
    {
        crate::protocols::snmp::fuzz_decode(data);
    }
    let _ = data;
}

/// LDAP ASN.1 BER TLV walk (bind-response shaped messages).
pub fn ldap_ber(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "ldap")]
    {
        let _ = crate::protocols::ldap::fuzz_walk_ber(data);
    }
    let _ = data;
}

/// `MySQL` `HandshakeV10` / ERR packet and Postgres frontend/backend readers.
pub fn db_codecs(data: &[u8]) {
    let Some(data) = capped(data) else {
        return;
    };
    #[cfg(feature = "mysql")]
    {
        crate::protocols::mysql::fuzz_parse_packets(data);
    }
    #[cfg(feature = "postgres")]
    {
        crate::protocols::postgres::fuzz_parse_messages(data);
    }
    let _ = data;
}

/// Run every codec surface once (CI smoke).
pub fn smoke_all(data: &[u8]) {
    smb_decode(data);
    rdp_decode(data);
    tds_decode(data);
    kerberos_decode(data);
    snmp_decode(data);
    ldap_ber(data);
    db_codecs(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_oversized_inputs_are_rejected_quietly() {
        smoke_all(&[]);
        smoke_all(&[0u8; 16]);
        smoke_all(&vec![0xA5; MAX_INPUT + 1]);
    }

    #[test]
    fn seeded_malformed_prefixes_do_not_panic() {
        for seed in [
            &[0x00u8][..],
            &[0xff, 0xff, 0xff, 0xff][..],
            &[0x30, 0x82, 0xff, 0xff][..],       // bogus BER length
            &[0xfe, 0x53, 0x4d, 0x42][..],       // SMB2 magic fragment
            b"\x03\x00\x00\x08\x00\x00\x00\x00", // tiny TPKT
        ] {
            smoke_all(seed);
        }
    }
}
