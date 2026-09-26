// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! SSH password and public-key authentication via russh.

use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate, load_secret_key};
use russh::{Disconnect, Preferred, client};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{AuthResult, Credential, ProtocolError, ProtocolModule, Target};

/// Native SSH authentication module.
#[derive(Debug, Clone, Default)]
pub struct SshModule {
    key_path: Option<PathBuf>,
    proxy: Option<String>,
}

impl SshModule {
    #[must_use]
    pub fn new(key_path: Option<PathBuf>, proxy: Option<String>) -> Self {
        Self { key_path, proxy }
    }

    fn client_config(timeout_budget: Duration) -> Arc<client::Config> {
        Arc::new(client::Config {
            inactivity_timeout: Some(timeout_budget),
            // Prefer the broad default algorithm set so negotiation tolerates
            // unusual but standards-compliant server identification strings.
            preferred: Preferred::default(),
            ..client::Config::default()
        })
    }

    async fn open_stream(
        &self,
        target: &Target,
        timeout_budget: Duration,
    ) -> Result<TcpStream, ProtocolError> {
        let addr = target.dial_addr();
        let connect = async {
            match self.proxy.as_deref() {
                None => TcpStream::connect(&addr)
                    .await
                    .map_err(|error| ProtocolError::ConnectionError(error.to_string())),
                Some(proxy) => super::socks::connect_socks5(proxy, &addr).await,
            }
        };
        timeout(timeout_budget, connect)
            .await
            .map_err(|_| ProtocolError::Timeout)?
    }

    async fn authenticate_inner(
        &self,
        target: &Target,
        credential: &Credential,
        timeout_budget: Duration,
    ) -> Result<AuthResult, ProtocolError> {
        let stream = self.open_stream(target, timeout_budget).await?;
        let config = Self::client_config(timeout_budget);
        let handler = ClientHandler;
        let mut handle = timeout(
            timeout_budget,
            client::connect_stream(config, stream, handler),
        )
        .await
        .map_err(|_| ProtocolError::Timeout)?
        .map_err(map_russh_error)?;

        let auth = async {
            if let Some(key_path) = &self.key_path {
                let key = load_secret_key(key_path, None).map_err(|error| {
                    ProtocolError::Internal(format!("failed to load SSH key: {error}"))
                })?;
                let key = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                handle
                    .authenticate_publickey(credential.username.clone(), key)
                    .await
                    .map_err(map_russh_error)
            } else {
                let password = credential.password.clone().unwrap_or_default();
                handle
                    .authenticate_password(credential.username.clone(), password)
                    .await
                    .map_err(map_russh_error)
            }
        };

        let auth_result = timeout(timeout_budget, auth)
            .await
            .map_err(|_| ProtocolError::Timeout)??;

        // Always tear down the session so sockets are not leaked across attempts.
        let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;

        Ok(if auth_result.success() {
            AuthResult::Success
        } else {
            AuthResult::Failure
        })
    }
}

#[async_trait]
impl ProtocolModule for SshModule {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn default_port(&self) -> u16 {
        22
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
        self.authenticate_inner(target, credential, timeout_budget)
            .await
    }
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // Host-key pinning is out of scope for credential auditing.
        Ok(true)
    }
}

fn map_russh_error(error: russh::Error) -> ProtocolError {
    match error {
        russh::Error::Disconnect => ProtocolError::ConnectionError("disconnected".into()),
        russh::Error::IO(ref io) if io.kind() == std::io::ErrorKind::TimedOut => {
            ProtocolError::Timeout
        }
        russh::Error::IO(io) => ProtocolError::ConnectionError(io.to_string()),
        russh::Error::Version => {
            // Tolerate unexpected identification strings by reporting handshake failure
            // rather than panicking; callers may retry with a fresh connection.
            ProtocolError::HandshakeFailed("invalid or unexpected SSH identification".into())
        }
        other => {
            let msg = other.to_string();
            let lower = msg.to_ascii_lowercase();
            if lower.contains("cipher")
                || lower.contains("algorithm")
                || lower.contains("kex")
                || lower.contains("no common")
                || lower.contains("incompatible")
            {
                ProtocolError::IncompatibleCipher(msg)
            } else {
                ProtocolError::HandshakeFailed(msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;
    use russh::server::{self, Auth, Server as _};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    // Public domain test vector from the `ssh-key` crate (not a secret).
    const MOCK_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----";

    #[derive(Clone)]
    struct MockSshServer {
        expected_user: &'static str,
        expected_pass: &'static str,
    }

    impl server::Server for MockSshServer {
        type Handler = Self;

        fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
            self.clone()
        }
    }

    impl server::Handler for MockSshServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            if user == self.expected_user && password == self.expected_pass {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    async fn start_mock_server() -> (u16, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let key = PrivateKey::from_openssh(MOCK_HOST_KEY).unwrap();
        let config = Arc::new(server::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::ZERO),
            keys: vec![key],
            preferred: Preferred::default(),
            ..server::Config::default()
        });
        let cancel = CancellationToken::new();
        let cancel_worker = cancel.clone();
        let mut server = MockSshServer {
            expected_user: "alice",
            expected_pass: "secret",
        };
        tokio::spawn(async move {
            tokio::select! {
                () = cancel_worker.cancelled() => {}
                result = server.run_on_socket(config, &listener) => {
                    let _ = result;
                }
            }
        });
        // Give the accept loop a tick to start.
        tokio::task::yield_now().await;
        (port, cancel)
    }

    #[tokio::test]
    async fn password_auth_success_and_failure() {
        let (port, cancel) = start_mock_server().await;
        let module = SshModule::new(None, None);
        let target = Target {
            host: "127.0.0.1".into(),
            port,
            ssl: false,
            path: None,
            ip: None,
        };

        let ok = module
            .authenticate(
                &target,
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(ok, AuthResult::Success);

        let bad = module
            .authenticate(
                &target,
                &Credential {
                    username: "alice".into(),
                    password: Some("wrong".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(bad, AuthResult::Failure);

        cancel.cancel();
    }

    #[tokio::test]
    async fn tolerates_default_algorithm_negotiation() {
        // Default Preferred on both sides must negotiate without disconnecting.
        let (port, cancel) = start_mock_server().await;
        let module = SshModule::new(None, None);
        let result = module
            .authenticate(
                &Target {
                    host: "127.0.0.1".into(),
                    port,
                    ssl: false,
                    path: None,
                    ip: None,
                },
                &Credential {
                    username: "alice".into(),
                    password: Some("secret".into()),
                },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
        cancel.cancel();
    }
}
