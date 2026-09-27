// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Canonical service / URL-scheme registry shared by CLI and the attack runner.

use clap::ValueEnum;

/// Network authentication service selectable via positional name or URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Service {
    Ftp,
    Ssh,
    Http,
    Https,
    Smtp,
    Smtps,
    Mysql,
    Postgres,
    Redis,
    Imap,
    Imaps,
    Ldap,
    Ldaps,
    Smb,
    Rdp,
    Mssql,
}

impl Service {
    /// Default TCP port when the operator omits an explicit port.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Ftp => 21,
            Self::Ssh => 22,
            Self::Http => 80,
            Self::Https => 443,
            Self::Smtp => 25,
            Self::Smtps => 465,
            Self::Mysql => 3306,
            Self::Postgres => 5432,
            Self::Redis => 6379,
            Self::Imap => 143,
            Self::Imaps => 993,
            Self::Ldap => 389,
            Self::Ldaps => 636,
            Self::Smb => 445,
            Self::Rdp => 3389,
            Self::Mssql => 1433,
        }
    }

    /// Canonical URL scheme / CLI token for this service.
    #[must_use]
    pub const fn scheme(self) -> &'static str {
        match self {
            Self::Ftp => "ftp",
            Self::Ssh => "ssh",
            Self::Http => "http",
            Self::Https => "https",
            Self::Smtp => "smtp",
            Self::Smtps => "smtps",
            Self::Mysql => "mysql",
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Imap => "imap",
            Self::Imaps => "imaps",
            Self::Ldap => "ldap",
            Self::Ldaps => "ldaps",
            Self::Smb => "smb",
            Self::Rdp => "rdp",
            Self::Mssql => "mssql",
        }
    }

    /// Human-readable list of supported scheme tokens for diagnostics.
    #[must_use]
    pub const fn supported_schemes() -> &'static str {
        "ftp, ssh, http, https, smtp, smtps, mysql, postgres (or postgresql), redis, imap, imaps, ldap, ldaps, smb, rdp, mssql"
    }

    #[must_use]
    pub(crate) const fn is_http(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    #[must_use]
    pub(crate) const fn is_database(self) -> bool {
        matches!(self, Self::Mysql | Self::Postgres | Self::Mssql)
    }

    /// Whether the default transport implies TLS without STARTTLS negotiation.
    #[must_use]
    pub(crate) const fn uses_ssl(self) -> bool {
        matches!(self, Self::Https | Self::Smtps | Self::Imaps | Self::Ldaps)
    }

    /// Whether `--insecure` / `-k` is meaningful (TLS present on the path).
    #[must_use]
    pub(crate) const fn allows_insecure(self) -> bool {
        matches!(
            self,
            Self::Https
                | Self::Smtp
                | Self::Smtps
                | Self::Imap
                | Self::Imaps
                | Self::Ldap
                | Self::Ldaps
                | Self::Rdp
                | Self::Mssql
        )
    }

    /// Parse a CLI / URL scheme token into a [`Service`].
    ///
    /// # Errors
    /// Returns `None` when the token is unknown.
    #[must_use]
    pub fn from_scheme(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ftp" => Some(Self::Ftp),
            "ssh" => Some(Self::Ssh),
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            "smtp" => Some(Self::Smtp),
            "smtps" => Some(Self::Smtps),
            "mysql" => Some(Self::Mysql),
            "postgres" | "postgresql" => Some(Self::Postgres),
            "redis" => Some(Self::Redis),
            "imap" => Some(Self::Imap),
            "imaps" => Some(Self::Imaps),
            "ldap" => Some(Self::Ldap),
            "ldaps" => Some(Self::Ldaps),
            "smb" => Some(Self::Smb),
            "rdp" => Some(Self::Rdp),
            "mssql" => Some(Self::Mssql),
            _ => None,
        }
    }
}
