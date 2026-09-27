// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! `WinRM` HTTP(S) Negotiate / `NTLMv2` authentication (auth-only, no command execution).
//!
//! Probes `/wsman` for `WWW-Authenticate: Negotiate` or `NTLM`. Never falls back to
//! Basic. Reuses SMB `NTLMv2` helpers for Type 1/2/3 proofs.

use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::{Client, Response, StatusCode, header};
use tokio::time::timeout;

use super::smb::{
    NTLM_NEGOTIATE_56, NTLM_NEGOTIATE_128, NTLM_NEGOTIATE_ALWAYS_SIGN,
    NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLM_NEGOTIATE_NTLM, NTLM_NEGOTIATE_TARGET_INFO,
    NTLM_NEGOTIATE_UNICODE, NTLM_REQUEST_TARGET, NtlmType2, build_client_blob, encode_ntlm_type1,
    encode_ntlm_type3, filetime_now, ntlmv2_nt_proof, split_domain_user, unwrap_security_blob,
    wrap_spnego_init,
};
use super::types::format_host;
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

const DEFAULT_PATH: &str = "/wsman";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthScheme {
    Negotiate,
    Ntlm,
}

impl AuthScheme {
    const fn header_prefix(self) -> &'static str {
        match self {
            Self::Negotiate => "Negotiate",
            Self::Ntlm => "NTLM",
        }
    }
}

/// Production `WinRM` Negotiate/NTLM module (feature = `winrm`).
#[derive(Debug, Clone)]
pub struct WinrmModule {
    client: Client,
}

impl WinrmModule {
    /// Build a pooled HTTP client for `WinRM` auth legs.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Internal`] or [`ProtocolError::ProxyError`] on client setup failure.
    pub fn new(insecure: bool, proxy: Option<String>) -> Result<Self, ProtocolError> {
        let mut builder = Client::builder()
            .pool_max_idle_per_host(2)
            .tcp_keepalive(Duration::from_secs(30))
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(insecure)
            .redirect(reqwest::redirect::Policy::none());

        if let Some(proxy_url) = proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|error| ProtocolError::ProxyError(error.to_string()))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|error| ProtocolError::Internal(error.to_string()))?;
        Ok(Self { client })
    }

    fn url_for(target: &Target) -> String {
        let scheme = if target.ssl { "https" } else { "http" };
        let host = if let Some(ip) = target.ip.filter(|_| !target.ssl) {
            if ip.is_ipv6() {
                format!("[{ip}]")
            } else {
                ip.to_string()
            }
        } else {
            format_host(&target.host).into_owned()
        };
        let path = target.path.as_deref().unwrap_or(DEFAULT_PATH);
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        format!("{scheme}://{host}:{}{path}", target.port)
    }

    /// Parse `WWW-Authenticate` for Negotiate / NTLM (never Basic-only).
    ///
    /// # Errors
    /// Returns an error when Negotiate/NTLM is absent (including Basic-only challenges).
    pub(crate) fn select_auth_scheme(www_authenticate: &str) -> Result<AuthScheme, ProtocolError> {
        let lower = www_authenticate.to_ascii_lowercase();
        let has_negotiate = lower
            .split(',')
            .any(|part| part.trim().starts_with("negotiate"));
        let has_ntlm = lower.split(',').any(|part| {
            let part = part.trim();
            part == "ntlm" || part.starts_with("ntlm ")
        });
        let has_basic = lower
            .split(',')
            .any(|part| part.trim().starts_with("basic"));
        if has_negotiate {
            return Ok(AuthScheme::Negotiate);
        }
        if has_ntlm {
            return Ok(AuthScheme::Ntlm);
        }
        if has_basic {
            return Err(ProtocolError::HandshakeFailed(
                "WinRM offered Basic only; silent Basic fallback is disabled (need Negotiate/NTLM)"
                    .into(),
            ));
        }
        Err(ProtocolError::HandshakeFailed(
            "WinRM challenge missing Negotiate/NTLM WWW-Authenticate".into(),
        ))
    }

    /// Extract base64 token from `Negotiate <b64>` / `NTLM <b64>` header values.
    ///
    /// # Errors
    /// Returns an error when the header shape or base64 payload is invalid.
    pub(crate) fn parse_challenge_token(www_authenticate: &str) -> Result<Vec<u8>, ProtocolError> {
        for part in www_authenticate.split(',') {
            let part = part.trim();
            let lower = part.to_ascii_lowercase();
            let rest = if let Some(rest) = lower.strip_prefix("negotiate ") {
                &part[part.len() - rest.len()..]
            } else if let Some(rest) = lower.strip_prefix("ntlm ") {
                &part[part.len() - rest.len()..]
            } else {
                continue;
            };
            let rest = rest.trim();
            if rest.is_empty() {
                continue;
            }
            return B64.decode(rest).map_err(|error| {
                ProtocolError::HandshakeFailed(format!("invalid NTLM challenge base64: {error}"))
            });
        }
        Err(ProtocolError::HandshakeFailed(
            "WWW-Authenticate missing Negotiate/NTLM token".into(),
        ))
    }

    fn auth_header(scheme: AuthScheme, token: &[u8]) -> String {
        format!("{} {}", scheme.header_prefix(), B64.encode(token))
    }

    fn encode_outbound(scheme: AuthScheme, ntlm: &[u8]) -> Vec<u8> {
        match scheme {
            AuthScheme::Negotiate => wrap_spnego_init(ntlm),
            AuthScheme::Ntlm => ntlm.to_vec(),
        }
    }

    fn www_authenticate(response: &Response) -> String {
        response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ")
    }

    async fn post_empty(&self, url: &str, auth: Option<String>) -> Result<Response, ProtocolError> {
        let mut request = self
            .client
            .post(url)
            .header(header::CONTENT_TYPE, "application/soap+xml;charset=UTF-8");
        if let Some(header_value) = auth {
            request = request.header(header::AUTHORIZATION, header_value);
        }
        request
            .body("")
            .send()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))
    }

    async fn build_type3(
        &self,
        user: &str,
        domain: &str,
        password: &str,
        type2: &NtlmType2,
    ) -> Result<(Vec<u8>, u32), ProtocolError> {
        let user_owned = user.to_owned();
        let domain_owned = domain.to_owned();
        let password_owned = password.to_owned();
        let type2_clone = type2.clone();
        tokio::task::spawn_blocking(move || {
            let mut client_challenge = [0u8; 8];
            fastrand::fill(&mut client_challenge);
            let blob =
                build_client_blob(client_challenge, &type2_clone.target_info, filetime_now());
            let proof = ntlmv2_nt_proof(
                &password_owned,
                &user_owned,
                &domain_owned,
                &type2_clone.server_challenge,
                &blob,
            );
            let mut nt_response = Vec::with_capacity(16 + blob.len());
            nt_response.extend_from_slice(&proof);
            nt_response.extend_from_slice(&blob);
            let type3_flags = type2_clone.flags
                | NTLM_NEGOTIATE_ALWAYS_SIGN
                | NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY
                | NTLM_NEGOTIATE_128
                | NTLM_NEGOTIATE_56;
            (nt_response, type3_flags)
        })
        .await
        .map_err(|error| ProtocolError::Internal(format!("NTLMv2 worker failed: {error}")))
    }

    async fn negotiate_exchange(
        &self,
        url: &str,
        user: &str,
        domain: &str,
        password: &str,
    ) -> Result<AuthResult, ProtocolError> {
        let probe = self.post_empty(url, None).await?;
        let www = Self::www_authenticate(&probe);
        if probe.status() != StatusCode::UNAUTHORIZED && www.is_empty() {
            return Err(ProtocolError::HandshakeFailed(format!(
                "expected 401 Negotiate challenge, got {}",
                probe.status()
            )));
        }
        let scheme = Self::select_auth_scheme(&www)?;

        let flags = NTLM_NEGOTIATE_UNICODE
            | NTLM_NEGOTIATE_NTLM
            | NTLM_REQUEST_TARGET
            | NTLM_NEGOTIATE_TARGET_INFO
            | NTLM_NEGOTIATE_ALWAYS_SIGN
            | NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY
            | NTLM_NEGOTIATE_128
            | NTLM_NEGOTIATE_56;
        let type1_out = Self::encode_outbound(scheme, &encode_ntlm_type1(flags));

        let challenge_resp = self
            .post_empty(url, Some(Self::auth_header(scheme, &type1_out)))
            .await?;
        let www2 = Self::www_authenticate(&challenge_resp);
        if challenge_resp.status() != StatusCode::UNAUTHORIZED {
            return Err(ProtocolError::HandshakeFailed(format!(
                "expected 401 with NTLM Type 2, got {}",
                challenge_resp.status()
            )));
        }
        let type2_bytes = unwrap_security_blob(&Self::parse_challenge_token(&www2)?);
        let type2 = NtlmType2::decode(&type2_bytes)
            .map_err(|error| ProtocolError::HandshakeFailed(error.into()))?;

        let (nt_response, type3_flags) = self.build_type3(user, domain, password, &type2).await?;
        // Type 3: raw NTLMSSP (IIS/WinRM accept this under Negotiate).
        let type3 = encode_ntlm_type3(user, domain, "BETTERH", &nt_response, type3_flags);

        let final_resp = self
            .post_empty(url, Some(Self::auth_header(scheme, &type3)))
            .await?;
        let status = final_resp.status();
        let body = final_resp
            .text()
            .await
            .map_err(|error| ProtocolError::ConnectionError(error.to_string()))?;
        Ok(Self::classify_final(status, &body))
    }

    fn classify_final(status: StatusCode, body: &str) -> AuthResult {
        if status.as_u16() == 429 {
            return AuthResult::RateLimited(Duration::from_secs(1));
        }
        if status.is_success() {
            return AuthResult::Success;
        }
        let lower = body.to_ascii_lowercase();
        if matches!(status.as_u16(), 401 | 403)
            || lower.contains("access denied")
            || lower.contains("authentication failed")
            || (lower.contains("wsmanfault")
                && (lower.contains("logon") || lower.contains("denied")))
            || (status.is_server_error() && lower.contains("fault"))
        {
            return AuthResult::Failure;
        }
        AuthResult::Failure
    }
}

#[async_trait]
impl ProtocolModule for WinrmModule {
    fn name(&self) -> &'static str {
        "winrm"
    }

    fn default_port(&self) -> u16 {
        5985
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
        let url = Self::url_for(target);
        let password = credential.password.as_deref().unwrap_or("");
        let (domain, user) = split_domain_user(&credential.username);

        timeout(
            timeout_budget,
            self.negotiate_exchange(&url, &user, &domain, password),
        )
        .await
        .map_err(|_| ProtocolError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::smb::encode_ntlm_type2;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn target_for(server: &MockServer) -> Target {
        let url = url::Url::parse(&server.uri()).unwrap();
        Target {
            host: url.host_str().unwrap().into(),
            port: url.port_or_known_default().unwrap(),
            ssl: false,
            path: Some("/wsman".into()),
            ip: None,
        }
    }

    struct Negotiator {
        step: AtomicUsize,
        type3_status: u16,
        scheme_label: &'static str,
    }

    impl Respond for Negotiator {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let n = self.step.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => {
                    ResponseTemplate::new(401).insert_header("www-authenticate", self.scheme_label)
                }
                1 => {
                    let type2 = encode_ntlm_type2(
                        [9, 8, 7, 6, 5, 4, 3, 2],
                        b"\x02\x00\x08\x00W\x00I\x00N\x00\x00\x00",
                    );
                    ResponseTemplate::new(401).insert_header(
                        "www-authenticate",
                        format!("{} {}", self.scheme_label, B64.encode(type2)),
                    )
                }
                _ => {
                    let _ = request;
                    ResponseTemplate::new(self.type3_status).set_body_string("<s:Envelope/>")
                }
            }
        }
    }

    #[test]
    fn select_auth_prefers_negotiate_and_rejects_basic_only() {
        assert_eq!(
            WinrmModule::select_auth_scheme("Negotiate, Basic realm=\"x\"").unwrap(),
            AuthScheme::Negotiate
        );
        assert_eq!(
            WinrmModule::select_auth_scheme("NTLM").unwrap(),
            AuthScheme::Ntlm
        );
        let err = WinrmModule::select_auth_scheme("Basic realm=\"x\"").unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
    }

    #[test]
    fn parse_challenge_token_decodes_base64() {
        let raw = b"NTLMSSP\0\x02\x00\x00\x00";
        let header = format!("Negotiate {}", B64.encode(raw));
        let decoded = WinrmModule::parse_challenge_token(&header).unwrap();
        assert_eq!(decoded, raw);
    }

    #[tokio::test]
    async fn negotiate_happy_path_returns_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wsman"))
            .respond_with(Negotiator {
                step: AtomicUsize::new(0),
                type3_status: 200,
                scheme_label: "Negotiate",
            })
            .mount(&server)
            .await;

        let module = WinrmModule::new(false, None).unwrap();
        let result = module
            .authenticate(
                &target_for(&server),
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
    }

    #[tokio::test]
    async fn ntlm_type3_401_is_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wsman"))
            .respond_with(Negotiator {
                step: AtomicUsize::new(0),
                type3_status: 401,
                scheme_label: "NTLM",
            })
            .mount(&server)
            .await;

        let module = WinrmModule::new(false, None).unwrap();
        let result = module
            .authenticate(
                &target_for(&server),
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
    }

    #[tokio::test]
    async fn basic_only_challenge_errors_without_fallback() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/wsman"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("www-authenticate", "Basic realm=\"x\""),
            )
            .mount(&server)
            .await;

        let module = WinrmModule::new(false, None).unwrap();
        let err = module
            .authenticate(
                &target_for(&server),
                &Credential {
                    username: "a".into(),
                    password: Some("b".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, ProtocolError::HandshakeFailed(_)));
    }
}
