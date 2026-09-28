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
        Service::Mssql => mssql_module(cli, proxy),
        Service::Winrm | Service::Winrms => winrm_module(cli, proxy),
        Service::Pop3 | Service::Pop3s => pop3_module(cli, proxy),
        Service::Kerberos => kerberos_module(cli, proxy),
        Service::Snmp => snmp_module(cli),
        Service::Vnc => vnc_module(proxy),
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

fn mssql_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "mssql",
        "MSSQL",
        crate::protocols::MssqlModule::new()
            .with_proxy(proxy)
            .with_insecure(cli.module.insecure)
            .with_database(cli.module.database.clone())
    )
}

fn winrm_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    #[cfg(feature = "winrm")]
    {
        let module = crate::protocols::WinrmModule::new(cli.module.insecure, proxy)?;
        Ok(Arc::new(module))
    }
    #[cfg(not(feature = "winrm"))]
    {
        let _ = (cli, proxy);
        Err(RunError::Message(
            "WinRM support was not compiled in (enable feature `winrm`)".into(),
        ))
    }
}

fn pop3_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "pop3",
        "POP3",
        crate::protocols::Pop3Module::new()
            .with_proxy(proxy)
            .with_insecure(cli.module.insecure)
    )
}

fn kerberos_module(cli: &Cli, proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!("kerberos", "Kerberos", {
        use crate::protocols::KerberosEtypeMode;
        let etype = match cli.module.kerberos_etype.as_str() {
            "aes256" => KerberosEtypeMode::Aes256,
            "aes128" => KerberosEtypeMode::Aes128,
            "rc4" => KerberosEtypeMode::Rc4,
            _ => KerberosEtypeMode::Auto,
        };
        crate::protocols::KerberosModule::new()
            .with_proxy(proxy)
            .with_realm(cli.module.realm.clone())
            .with_etype(etype)
    })
}

fn snmp_module(cli: &Cli) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!("snmp", "SNMP", {
        use crate::protocols::snmp::{SnmpAuthProtocol, SnmpModule, SnmpPrivProtocol, Version};
        let version = match cli.module.snmp_version.as_str() {
            "1" => Version::V1,
            "3" => Version::V3,
            _ => Version::V2c,
        };
        let auth = match cli.module.snmp_auth.as_str() {
            "md5" => SnmpAuthProtocol::Md5,
            _ => SnmpAuthProtocol::Sha1,
        };
        let priv_protocol = match cli.module.snmp_priv.as_str() {
            "des" => SnmpPrivProtocol::Des,
            "aes" => SnmpPrivProtocol::Aes,
            _ => SnmpPrivProtocol::None,
        };
        SnmpModule::new()
            .with_version(version)
            .with_auth(auth)
            .with_priv(priv_protocol)
            .with_priv_password(cli.module.snmp_priv_password.clone())
    })
}

fn vnc_module(proxy: Option<String>) -> Result<Arc<dyn ProtocolModule>, RunError> {
    gated!(
        "vnc",
        "VNC",
        crate::protocols::VncModule::new().with_proxy(proxy)
    )
}
