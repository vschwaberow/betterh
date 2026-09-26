// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Shared SOCKS5 dial helper for protocol modules.

use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use super::ProtocolError;

/// Dial `dest` (`host:port`) through a `socks5://` proxy URL.
///
/// # Errors
/// Returns [`ProtocolError::ProxyError`] for unsupported schemes, bad URLs, or dial failures.
pub async fn connect_socks5(proxy: &str, dest: &str) -> Result<TcpStream, ProtocolError> {
    let url =
        url::Url::parse(proxy).map_err(|error| ProtocolError::ProxyError(error.to_string()))?;
    if url.scheme() != "socks5" {
        return Err(ProtocolError::ProxyError(format!(
            "SOCKS5 proxies only (got {}://)",
            url.scheme()
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ProtocolError::ProxyError("socks5 proxy missing host".into()))?;
    let port = url.port().unwrap_or(1080);
    let proxy_addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let stream = Socks5Stream::connect(proxy_addr.as_str(), dest)
        .await
        .map_err(|error| ProtocolError::ProxyError(error.to_string()))?;
    Ok(stream.into_inner())
}
