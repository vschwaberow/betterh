// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Feature-gated `Service` → [`ProtocolModule`] construction.

use std::sync::Arc;

use crate::cli::Cli;
#[cfg(feature = "http")]
use crate::cli::HttpAuth;
use crate::config::Config;
use crate::protocols::ProtocolModule;
use crate::service::Service;

use super::RunError;

/// Build the protocol module for `service` from CLI / config options.
///
/// # Errors
/// Returns [`RunError::Message`] when the service feature is disabled or options are invalid.
pub(crate) fn build_module(
    cli: &Cli,
    config: &Config,
    service: Service,
) -> Result<Arc<dyn ProtocolModule>, RunError> {
    let proxy = config.proxy.clone();
    match service {
        Service::Ftp => ftp_module(cli, proxy),
        Service::Ssh => ssh_module(cli, proxy),
        Service::Http | Service::Https => http_module(cli, proxy),
        Service::Smtp | Service::Smtps => smtp_module(cli, proxy),
        Service::Mysql => mysql_module(cli, proxy),
        Service::Postgres => postgres_module(cli, proxy),
        Service::Redis => redis_module(proxy),
        Service::Imap | Service::Imaps => imap_module(cli, proxy),
        Service::Ldap | Service::Ldaps => ldap_module(cli, proxy),
        Service::Smb => smb_module(proxy),
        Service::Rdp => rdp_module(cli, proxy),
    }
}

macro_rules! gated {
    ($feature:literal, $label:literal, $body:expr) => {{
        #[cfg(feature = $feature)]
        {
            Ok(Arc::new($body) as Arc<dyn ProtocolModule>)
        }
        #[cfg(not(feature = $feature))]
        {
            Err(RunError::Message(format!(concat!(
                $label,
                " support was not compiled in (enable feature `",
                $feature,
                "`)"
            ))))
        }
    }};
}

fn ftp_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "ftp",
        "FTP",
        crate::protocols::FtpModule::new(cli.module.ftp_passive).with_proxy(proxy)
    )
}

fn ssh_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "ssh",
        "SSH",
        crate::protocols::SshModule::new(cli.module.ssh_key.clone(), proxy)
    )
}

fn http_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    #[cfg(feature = "http")]
    {
        let mode = match cli.module.http_auth.unwrap_or(HttpAuth::Basic) {
            HttpAuth::Basic => crate::protocols::HttpAuthMode::Basic,
            HttpAuth::PostForm => crate::protocols::HttpAuthMode::PostForm,
            HttpAuth::Bearer => crate::protocols::HttpAuthMode::Bearer,
        };
        let headers = cli
            .module
            .headers
            .iter()
            .filter_map(|header| header.split_once(':'))
            .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
            .collect();
        let module = crate::protocols::HttpModule::new(crate::protocols::HttpOptions {
            mode,
            body_template: cli.module.body.clone(),
            success_string: cli.module.success_string.clone(),
            fail_string: cli.module.fail_string.clone(),
            headers,
            method: cli.module.http_method.clone(),
            cookie: cli.module.cookie.clone(),
            insecure: cli.module.insecure,
            proxy,
        })?;
        Ok(Arc::new(module))
    }
    #[cfg(not(feature = "http"))]
    {
        let _ = (cli, proxy);
        Err(RunError::Message(
            "HTTP support was not compiled in (enable feature `http`)".into(),
        ))
    }
}

fn smtp_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "smtp",
        "SMTP",
        crate::protocols::SmtpModule::new()
            .with_proxy(proxy)
            .with_insecure(cli.module.insecure)
    )
}

fn mysql_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "mysql",
        "MySQL",
        crate::protocols::MysqlModule::new()
            .with_database(cli.module.database.clone())
            .with_proxy(proxy)
    )
}

fn postgres_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "postgres",
        "PostgreSQL",
        crate::protocols::PostgresModule::new()
            .with_database(cli.module.database.clone())
            .with_proxy(proxy)
    )
}

fn redis_module(proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "redis",
        "Redis",
        crate::protocols::RedisModule::new().with_proxy(proxy)
    )
}

fn imap_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "imap",
        "IMAP",
        crate::protocols::ImapModule::new()
            .with_proxy(proxy)
            .with_insecure(cli.module.insecure)
    )
}

fn ldap_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "ldap",
        "LDAP",
        crate::protocols::LdapModule::new()
            .with_proxy(proxy)
            .with_insecure(cli.module.insecure)
    )
}

fn smb_module(proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "smb",
        "SMB",
        crate::protocols::SmbModule::new().with_proxy(proxy)
    )
}

fn rdp_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "rdp",
        "RDP",
        crate::protocols::RdpModule::new()
            .with_proxy(proxy)
            .with_insecure(cli.module.insecure)
    )
}
