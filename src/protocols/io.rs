// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Shared dial and line-oriented I/O helpers for protocol modules.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::net::TcpStream;

use super::{ProtocolError, Target};

/// Dial `target` directly or through an optional `socks5://` proxy URL.
///
/// # Errors
/// Returns connection or proxy errors from the underlying dial path.
pub async fn dial(target: &Target, proxy: Option<&str>) -> Result<TcpStream, ProtocolError> {
    let addr = target.dial_addr();
    match proxy {
        None => TcpStream::connect(&addr)
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string())),
        Some(proxy) => super::socks::connect_socks5(proxy, &addr).await,
    }
}

/// Read one CRLF-terminated line from `reader`, trimming the trailing newline bytes.
///
/// # Errors
/// Returns [`ProtocolError::ConnectionError`] on I/O failure.
pub async fn read_crlf_line<R>(reader: &mut R) -> Result<String, ProtocolError>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}
