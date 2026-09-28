// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Authentication contract shared by native protocol modules.

pub mod fuzz_api;
#[cfg(any(
    feature = "ftp",
    feature = "ssh",
    feature = "smtp",
    feature = "mysql",
    feature = "postgres",
    feature = "redis",
    feature = "imap",
    feature = "ldap",
    feature = "smb",
    feature = "rdp",
    feature = "mssql",
    feature = "winrm",
    feature = "pop3",
    feature = "kerberos"
))]
pub mod io;
pub mod mock;
#[cfg(any(
    feature = "ftp",
    feature = "ssh",
    feature = "smtp",
    feature = "mysql",
    feature = "postgres",
    feature = "redis",
    feature = "imap",
    feature = "ldap",
    feature = "smb",
    feature = "rdp",
    feature = "mssql",
    feature = "winrm",
    feature = "pop3",
    feature = "kerberos"
))]
pub mod socks;
pub mod types;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "ftp")]
pub mod ftp;

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "ssh")]
pub mod ssh;

#[cfg(feature = "smtp")]
pub mod smtp;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "imap")]
pub mod imap;

#[cfg(feature = "ldap")]
pub mod ldap;

#[cfg(feature = "smb")]
pub mod smb;

#[cfg(feature = "rdp")]
pub mod rdp;

#[cfg(feature = "mssql")]
pub mod mssql;

#[cfg(feature = "winrm")]
pub mod winrm;

#[cfg(feature = "pop3")]
pub mod pop3;

#[cfg(feature = "kerberos")]
pub mod kerberos;

#[cfg(feature = "snmp")]
pub mod snmp;

#[cfg(feature = "vnc")]
pub mod vnc;

use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

pub use fuzz_api::{MAX_INPUT, smoke_all};
pub use types::{AuthResult, CanaryStatus, Credential, ProtocolError, Target};

#[async_trait]
pub trait ProtocolModule: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_port(&self) -> u16;

    /// Perform an optional connectivity check.
    ///
    /// # Errors
    /// Returns a protocol or transport error when the check fails.
    async fn probe(&self, _target: &Target) -> Result<(), ProtocolError> {
        Ok(())
    }

    /// Check whether the target accepts random credentials.
    ///
    /// # Errors
    /// Returns transport errors or an error when rejection cannot be established.
    async fn canary_probe(&self, target: &Target) -> Result<CanaryStatus, ProtocolError> {
        let credential = Credential {
            username: format!("__canary_{}__", Uuid::new_v4().simple()),
            password: Some(format!("__canary_{}__", Uuid::new_v4().simple())),
        };
        match self
            .authenticate(target, &credential, Duration::from_secs(5))
            .await?
        {
            AuthResult::Success => Ok(CanaryStatus::WildcardDetected(
                "Target authenticated random canary credentials; catch-all suspected".into(),
            )),
            AuthResult::Failure => Ok(CanaryStatus::Normal),
            _ => Err(ProtocolError::Internal(
                "Canary probe was inconclusive".into(),
            )),
        }
    }

    /// Attempt authentication within the supplied timeout.
    ///
    /// # Errors
    /// Returns a protocol or transport error when the attempt cannot complete.
    async fn authenticate(
        &self,
        target: &Target,
        credential: &Credential,
        timeout: Duration,
    ) -> Result<AuthResult, ProtocolError>;
}

#[cfg(feature = "tls")]
pub use tls::{TransportStream, wrap_tls};

#[cfg(feature = "ftp")]
pub use ftp::FtpModule;

#[cfg(feature = "http")]
pub use http::{HttpAuthMode, HttpModule, HttpOptions};

#[cfg(feature = "ssh")]
pub use ssh::SshModule;

#[cfg(feature = "smtp")]
pub use smtp::SmtpModule;

#[cfg(feature = "mysql")]
pub use mysql::MysqlModule;

#[cfg(feature = "postgres")]
pub use postgres::PostgresModule;

#[cfg(feature = "redis")]
pub use redis::RedisModule;

#[cfg(feature = "imap")]
pub use imap::ImapModule;

#[cfg(feature = "ldap")]
pub use ldap::LdapModule;

#[cfg(feature = "smb")]
pub use smb::SmbModule;

#[cfg(feature = "rdp")]
pub use rdp::RdpModule;

#[cfg(feature = "mssql")]
pub use mssql::MssqlModule;

#[cfg(feature = "winrm")]
pub use winrm::WinrmModule;

#[cfg(feature = "pop3")]
pub use pop3::Pop3Module;

#[cfg(feature = "kerberos")]
pub use kerberos::{EtypeMode as KerberosEtypeMode, KerberosModule};

#[cfg(feature = "snmp")]
pub use snmp::SnmpModule;

#[cfg(feature = "vnc")]
pub use vnc::VncModule;
