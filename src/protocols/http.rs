// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! HTTP Basic, form-POST, and bearer authentication via reqwest.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::{Client, Method, StatusCode, header};

use super::types::format_host;
use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

/// HTTP authentication strategy selected by `-m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpAuthMode {
    #[default]
    Basic,
    PostForm,
    Bearer,
}

/// Construction options for [`HttpModule`].
#[derive(Debug, Clone, Default)]
pub struct HttpOptions {
    pub mode: HttpAuthMode,
    pub body_template: Option<String>,
    pub success_string: Option<String>,
    pub fail_string: Option<String>,
    pub headers: Vec<(String, String)>,
    pub method: Option<String>,
    pub cookie: Option<String>,
    pub insecure: bool,
    pub proxy: Option<String>,
}

/// Native HTTP authentication module with connection pooling (Keep-Alive).
#[derive(Debug, Clone)]
pub struct HttpModule {
    client: Client,
    mode: HttpAuthMode,
    body_template: Option<String>,
    success_string: Option<String>,
    fail_string: Option<String>,
    headers: Vec<(String, String)>,
    method: Method,
    cookie: Option<String>,
}

impl HttpModule {
    /// Build a pooled HTTP client. Connections are reused across attempts.
    ///
    /// # Errors
    /// Returns [`ProtocolError::Internal`] when the client cannot be constructed.
    pub fn new(options: HttpOptions) -> Result<Self, ProtocolError> {
        let mut builder = Client::builder()
            .pool_max_idle_per_host(4)
            .tcp_keepalive(Duration::from_secs(30))
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(options.insecure)
            .redirect(reqwest::redirect::Policy::none());

        if let Some(proxy_url) = &options.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|error| ProtocolError::ProxyError(error.to_string()))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|error| ProtocolError::Internal(error.to_string()))?;

        let method = options
            .method
            .as_deref()
            .unwrap_or(match options.mode {
                HttpAuthMode::PostForm => "POST",
                HttpAuthMode::Basic | HttpAuthMode::Bearer => "GET",
            })
            .parse::<Method>()
            .map_err(|error| ProtocolError::Internal(error.to_string()))?;

        Ok(Self {
            client,
            mode: options.mode,
            body_template: options.body_template,
            success_string: options.success_string,
            fail_string: options.fail_string,
            headers: options.headers,
            method,
            cookie: options.cookie,
        })
    }

    fn url_for(target: &Target) -> (String, Option<String>) {
        let scheme = if target.ssl { "https" } else { "http" };
        // Cleartext: dial the pinned IP and send the original Host header.
        // TLS: keep the hostname in the URL so reqwest can set SNI correctly.
        let (host, host_header) = if let Some(ip) = target.ip.filter(|_| !target.ssl) {
            let ip_str = if ip.is_ipv6() {
                format!("[{ip}]")
            } else {
                ip.to_string()
            };
            let host_header = (target.host != ip_str).then(|| target.host.clone());
            (ip_str, host_header)
        } else {
            (format_host(&target.host).into_owned(), None)
        };
        let path = target.path.as_deref().unwrap_or("/");
        let path = if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        (
            format!("{scheme}://{host}:{}{path}", target.port),
            host_header,
        )
    }

    fn render_body(&self, credential: &Credential) -> Option<String> {
        let template = self.body_template.as_ref()?;
        let user = credential.username.as_str();
        let pass = credential.password.as_deref().unwrap_or("");
        Some(template.replace("{USER}", user).replace("{PASS}", pass))
    }

    fn classify(&self, status: StatusCode, body: &str) -> AuthResult {
        if let Some(needle) = &self.success_string
            && body.contains(needle.as_str())
        {
            return AuthResult::Success;
        }
        if let Some(needle) = &self.fail_string
            && body.contains(needle.as_str())
        {
            return AuthResult::Failure;
        }
        if status.as_u16() == 429 {
            return AuthResult::RateLimited(Duration::from_secs(1));
        }
        if status.is_success() {
            // Without an explicit success marker, 2xx alone is not enough for form posts.
            if self.success_string.is_some() {
                return AuthResult::Failure;
            }
            return AuthResult::Success;
        }
        if matches!(status.as_u16(), 401 | 403) {
            return AuthResult::Failure;
        }
        AuthResult::Failure
    }
}

#[async_trait]
impl ProtocolModule for HttpModule {
    fn name(&self) -> &'static str {
        "http"
    }

    fn default_port(&self) -> u16 {
        80
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
        let (url, host_header) = Self::url_for(target);
        let mut request = self.client.request(self.method.clone(), &url);
        if let Some(host) = host_header {
            request = request.header(header::HOST, host);
        }

        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        if let Some(cookie) = &self.cookie {
            request = request.header(header::COOKIE, cookie);
        }

        match self.mode {
            HttpAuthMode::Basic => {
                request = request.basic_auth(&credential.username, credential.password.as_deref());
            }
            HttpAuthMode::Bearer => {
                let token = credential.password.as_deref().unwrap_or("");
                request = request.bearer_auth(token);
            }
            HttpAuthMode::PostForm => {
                if let Some(body) = self.render_body(credential) {
                    let is_json = body.trim_start().starts_with('{');
                    if is_json {
                        request = request
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(body);
                    } else {
                        request = request
                            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                            .body(body);
                    }
                }
            }
        }

        let response = tokio::time::timeout(timeout_budget, request.send())
            .await
            .map_err(|_| ProtocolError::Timeout)?
            .map_err(|error| {
                if error.is_timeout() {
                    ProtocolError::Timeout
                } else if error.is_connect() {
                    ProtocolError::ConnectionError(error.to_string())
                } else {
                    ProtocolError::HandshakeFailed(error.to_string())
                }
            })?;

        let status = response.status();
        // Tolerate missing Content-Length: always read the body stream.
        let body = response.text().await.unwrap_or_default();
        Ok(self.classify(status, &body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{basic_auth, body_string, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn target_for(server: &MockServer, path: &str) -> Target {
        let url = url::Url::parse(&server.uri()).unwrap();
        Target {
            host: url.host_str().unwrap().into(),
            port: url.port_or_known_default().unwrap(),
            ssl: false,
            path: Some(path.into()),
            ip: None,
        }
    }

    #[tokio::test]
    async fn basic_auth_success_and_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/basic"))
            .and(basic_auth("alice", "secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/basic"))
            .respond_with(ResponseTemplate::new(401).set_body_string("nope"))
            .mount(&server)
            .await;

        let module = HttpModule::new(HttpOptions {
            mode: HttpAuthMode::Basic,
            ..HttpOptions::default()
        })
        .unwrap();
        let target = target_for(&server, "/basic");
        assert_eq!(
            module
                .authenticate(
                    &target,
                    &Credential {
                        username: "alice".into(),
                        password: Some("secret".into()),
                    },
                    Duration::from_secs(2),
                )
                .await
                .unwrap(),
            AuthResult::Success
        );
        assert_eq!(
            module
                .authenticate(
                    &target,
                    &Credential {
                        username: "alice".into(),
                        password: Some("wrong".into()),
                    },
                    Duration::from_secs(2),
                )
                .await
                .unwrap(),
            AuthResult::Failure
        );
    }

    #[tokio::test]
    async fn form_post_uses_placeholders_and_body_markers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string("user=alice&pass=secret"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Welcome back"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/login"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Invalid credentials"))
            .mount(&server)
            .await;

        let module = HttpModule::new(HttpOptions {
            mode: HttpAuthMode::PostForm,
            body_template: Some("user={USER}&pass={PASS}".into()),
            success_string: Some("Welcome back".into()),
            fail_string: Some("Invalid credentials".into()),
            method: Some("POST".into()),
            ..HttpOptions::default()
        })
        .unwrap();
        let target = target_for(&server, "/login");
        assert_eq!(
            module
                .authenticate(
                    &target,
                    &Credential {
                        username: "alice".into(),
                        password: Some("secret".into()),
                    },
                    Duration::from_secs(2),
                )
                .await
                .unwrap(),
            AuthResult::Success
        );
        assert_eq!(
            module
                .authenticate(
                    &target,
                    &Credential {
                        username: "alice".into(),
                        password: Some("nope".into()),
                    },
                    Duration::from_secs(2),
                )
                .await
                .unwrap(),
            AuthResult::Failure
        );
    }

    #[tokio::test]
    async fn tolerates_missing_content_length_on_failure_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(403).set_body_string("denied"))
            .mount(&server)
            .await;

        let module = HttpModule::new(HttpOptions {
            mode: HttpAuthMode::Basic,
            fail_string: Some("denied".into()),
            ..HttpOptions::default()
        })
        .unwrap();
        let result = module
            .authenticate(
                &target_for(&server, "/x"),
                &Credential {
                    username: "u".into(),
                    password: Some("p".into()),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Failure);
    }
}
