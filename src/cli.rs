// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! CLI grammar and normalization of URL and positional targets.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use url::{Host, Url};

use crate::{
    config::{self, Config, ConfigError, ConfigOptions},
    protocols::Target,
};

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
}

impl Service {
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
        }
    }

    const fn is_http(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }

    const fn is_database(self) -> bool {
        matches!(self, Self::Mysql | Self::Postgres)
    }

    pub(crate) const fn uses_ssl(self) -> bool {
        matches!(self, Self::Https | Self::Smtps | Self::Imaps | Self::Ldaps)
    }

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
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AttackMode {
    BruteForce,
    Spray,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HttpAuth {
    Basic,
    PostForm,
    Bearer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ManglingRule {
    #[value(name = "n")]
    Empty,
    #[value(name = "s")]
    Same,
    #[value(name = "r")]
    Reverse,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Configure an audit interactively (UI phase).
    Wizard,
    /// Generate shell completions (UI phase).
    Completions { shell: clap_complete::Shell },
    /// Generate a manual page (UI phase).
    Man,
}

#[derive(Debug, Args)]
pub struct ModuleOptions {
    /// HTTP authentication mechanism.
    #[arg(short = 'm', long = "http-auth", value_enum)]
    pub http_auth: Option<HttpAuth>,
    /// HTTP payload template containing {USER} and {PASS}.
    #[arg(long)]
    pub body: Option<String>,
    #[arg(long)]
    pub fail_string: Option<String>,
    #[arg(long)]
    pub success_string: Option<String>,
    /// HTTP header (repeatable).
    #[arg(short = 'H', long = "header", value_parser = parse_header)]
    pub headers: Vec<String>,
    #[arg(long, value_parser = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])]
    pub http_method: Option<String>,
    #[arg(long)]
    pub cookie: Option<String>,
    #[arg(long)]
    pub ssh_key: Option<PathBuf>,
    #[arg(long)]
    pub ftp_passive: bool,
    /// Database name (`MySQL`, `PostgreSQL`).
    #[arg(long)]
    pub database: Option<String>,
    /// Skip TLS certificate validation.
    #[arg(short = 'k', long)]
    pub insecure: bool,
}

// These independent switches mirror the documented CLI rather than domain state.
#[expect(
    clippy::struct_excessive_bools,
    reason = "CLI exposes independent switches from the specification"
)]
#[derive(Debug, Parser)]
#[command(
    version,
    about = "Network authentication auditing",
    args_conflicts_with_subcommands = true,
    after_help = "Quickstart:\n  betterh ssh://admin@127.0.0.1:2222 -P passwords.txt\n  betterh ssh 127.0.0.1 -L users.txt -P passwords.txt\n  betterh https://localhost/login -m post-form --body 'user={USER}&pass={PASS}'\n  betterh wizard\n\nExecution: live attacks run after scope/canary checks; use --dry-run to audit combinations only."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Service name or target URL.
    #[arg(value_name = "SERVICE_OR_URL")]
    pub service_or_url: Option<String>,
    /// Host, host:port, or CIDR (positional syntax).
    #[arg(value_name = "TARGET", conflicts_with = "target_file")]
    pub target: Option<String>,
    /// Target file, used with a service name.
    #[arg(short = 'M', conflicts_with = "target")]
    pub target_file: Option<PathBuf>,
    #[arg(long, value_parser = parse_network)]
    pub exclude: Vec<IpNet>,
    #[arg(long)]
    pub exclude_file: Option<PathBuf>,
    #[arg(short = 'u', conflicts_with_all = ["user_list", "combo_list"])]
    pub username: Option<String>,
    #[arg(short = 'p', allow_hyphen_values = true, conflicts_with_all = ["password_list", "combo_list"])]
    pub password: Option<String>,
    /// Username file, or - for stdin.
    #[arg(short = 'L', conflicts_with = "combo_list")]
    pub user_list: Option<PathBuf>,
    /// Password file, or - for stdin.
    #[arg(short = 'P', conflicts_with = "combo_list")]
    pub password_list: Option<PathBuf>,
    /// username:password file, or - for stdin.
    #[arg(short = 'C')]
    pub combo_list: Option<PathBuf>,
    /// Extra password candidates: n (empty), s (username), r (reversed username).
    #[arg(short = 'e', value_enum, value_delimiter = ',')]
    pub mangling: Vec<ManglingRule>,
    #[arg(long, value_enum, default_value = "brute-force")]
    pub mode: AttackMode,
    #[arg(long, value_parser = parse_duration, default_value = "15m")]
    pub spray_cooldown: Duration,
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value = "true")]
    pub exit_user: bool,
    #[arg(long)]
    pub exit_host: bool,
    #[arg(long)]
    pub exit_first: bool,
    #[arg(long)]
    pub on_found: Option<String>,
    #[arg(long)]
    pub bell: bool,
    #[arg(long)]
    pub proxy_list: Option<PathBuf>,
    #[arg(long, value_parser = parse_duration, default_value = "0ms")]
    pub delay: Duration,
    #[arg(long, value_parser = parse_duration, default_value = "0ms")]
    pub jitter: Duration,
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub interactive: bool,
    #[arg(short = 'q', long)]
    pub quiet: bool,
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,
    /// Write reports to a new file; choose an unused path (existing paths are rejected).
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub resume: Option<PathBuf>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[command(flatten)]
    pub settings: ConfigOptions,
    #[command(flatten)]
    pub module: ModuleOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSource {
    Single(Target),
    Network(IpNet),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInput {
    pub service: Service,
    pub source: TargetSource,
    pub username: Option<String>,
}

impl Cli {
    /// Normalize targets and reject incompatible inputs.
    ///
    /// # Errors
    /// Returns a CLI diagnostic for invalid syntax or conflicting options.
    pub fn validate(&self) -> Result<Option<TargetInput>, clap::Error> {
        if self.user_list.as_deref() == Some(Path::new("-"))
            && self.password_list.as_deref() == Some(Path::new("-"))
        {
            return Err(invalid(
                "-L and -P cannot both read stdin; use a file for one list",
            ));
        }
        if self.command.is_some() || self.interactive {
            return Ok(None);
        }
        if self.resume.is_some() {
            if self.service_or_url.is_some() || self.target.is_some() || self.target_file.is_some()
            {
                return Err(invalid("--resume cannot be combined with a new target"));
            }
            return Ok(None);
        }
        let first = self
            .service_or_url
            .as_deref()
            .ok_or_else(|| invalid("Provide a target URL or a service and target; see --help"))?;
        let mut input = if first.contains("://") {
            if self.target.is_some() || self.target_file.is_some() {
                return Err(invalid(
                    "A target URL cannot be combined with another target or -M",
                ));
            }
            parse_url(first)?
        } else {
            let service = parse_service(first)?;
            let source = if let Some(path) = &self.target_file {
                TargetSource::File(path.clone())
            } else {
                let target = self.target.as_deref().ok_or_else(|| {
                    invalid("Provide a target after the service, or use -M <file>")
                })?;
                if let Ok(network) = target.parse::<IpNet>() {
                    TargetSource::Network(network)
                } else {
                    if target.contains("://") || target.contains(['/', '?', '#', '@']) {
                        return Err(invalid(
                            "Use a standalone URL for paths and embedded usernames; otherwise provide a host or CIDR",
                        ));
                    }
                    parse_positional(service, target)?
                }
            };
            TargetInput {
                service,
                source,
                username: None,
            }
        };
        if self.user_list.is_some() || self.combo_list.is_some() {
            input.username = None;
        } else if let Some(username) = &self.username {
            input.username = Some(username.clone());
        }
        self.validate_module(input.service)?;
        Ok(Some(input))
    }

    fn validate_module(&self, service: Service) -> Result<(), clap::Error> {
        let module = &self.module;
        if !service.is_http()
            && (module.http_auth.is_some()
                || module.body.is_some()
                || module.fail_string.is_some()
                || module.success_string.is_some()
                || !module.headers.is_empty()
                || module.http_method.is_some()
                || module.cookie.is_some()
                || self.settings.user_agent.is_some())
        {
            return Err(invalid("HTTP options require an http or https target"));
        }
        if module.insecure && !service.allows_insecure() {
            return Err(invalid(
                "--insecure requires a TLS-capable target (https, smtp/smtps, imap/imaps, ldap/ldaps)",
            ));
        }
        if module.ssh_key.is_some() && service != Service::Ssh {
            return Err(invalid("--ssh-key requires an ssh target"));
        }
        if module.ftp_passive && service != Service::Ftp {
            return Err(invalid("--ftp-passive requires an ftp target"));
        }
        if module.database.is_some() && !service.is_database() {
            return Err(invalid("--database requires a mysql or postgres target"));
        }
        Ok(())
    }

    /// Read configuration after CLI validation.
    ///
    /// # Errors
    /// Returns errors for invalid sources or a proxy conflict after merging.
    pub async fn load_config(&self) -> Result<Config, ConfigError> {
        let config = config::load(self.settings.clone(), self.config.as_deref()).await?;
        if self.proxy_list.is_some() && config.proxy.is_some() {
            return Err(ConfigError::ProxyConflict);
        }
        Ok(config)
    }
}

fn invalid(message: &str) -> clap::Error {
    Cli::command().error(ErrorKind::ValueValidation, message)
}

fn parse_service(value: &str) -> Result<Service, clap::Error> {
    match value.to_ascii_lowercase().as_str() {
        "ftp" => Ok(Service::Ftp),
        "ssh" => Ok(Service::Ssh),
        "http" => Ok(Service::Http),
        "https" => Ok(Service::Https),
        "smtp" => Ok(Service::Smtp),
        "smtps" => Ok(Service::Smtps),
        "mysql" => Ok(Service::Mysql),
        "postgres" | "postgresql" => Ok(Service::Postgres),
        "redis" => Ok(Service::Redis),
        "imap" => Ok(Service::Imap),
        "imaps" => Ok(Service::Imaps),
        "ldap" => Ok(Service::Ldap),
        "ldaps" => Ok(Service::Ldaps),
        _ => Err(invalid(
            "Supported services: ftp, ssh, http, https, smtp, smtps, mysql, postgres (or postgresql), redis, imap, imaps, ldap, ldaps",
        )),
    }
}

pub(crate) fn parse_url(value: &str) -> Result<TargetInput, clap::Error> {
    let url = Url::parse(value)
        .map_err(|_| invalid("Invalid target URL; check scheme, host, and port"))?;
    let service = parse_service(url.scheme())?;
    if url.password().is_some() || url.fragment().is_some() {
        return Err(invalid(
            "Target URLs cannot contain passwords or fragments; use -p or -P for passwords",
        ));
    }
    if !service.is_http() && (!matches!(url.path(), "" | "/") || url.query().is_some()) {
        return Err(invalid("Paths and query strings require an HTTP target"));
    }
    let host = match url.host() {
        Some(Host::Domain(host)) if !host.is_empty() => host.to_owned(),
        Some(Host::Ipv4(ip)) => ip.to_string(),
        Some(Host::Ipv6(ip)) => ip.to_string(),
        _ => return Err(invalid("Target URL requires a host")),
    };
    let port = url.port().unwrap_or_else(|| service.default_port());
    if port == 0 {
        return Err(invalid("Target port must be between 1 and 65535"));
    }
    let username = if url.username().is_empty() {
        None
    } else {
        Some(
            percent_decode_str(url.username())
                .decode_utf8()
                .map_err(|_| invalid("URL username must be valid UTF-8"))?
                .into_owned(),
        )
    };
    let path = service.is_http().then(|| {
        let mut path = url.path().to_owned();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        path
    });
    let ip = host.parse().ok();
    Ok(TargetInput {
        service,
        source: TargetSource::Single(Target {
            host,
            port,
            ssl: service.uses_ssl(),
            path,
            ip,
        }),
        username,
    })
}

pub(crate) fn parse_positional(service: Service, value: &str) -> Result<TargetSource, clap::Error> {
    let host = match value.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
        _ => value.to_owned(),
    };
    let scheme = match service {
        Service::Ftp => "ftp",
        Service::Ssh => "ssh",
        Service::Http => "http",
        Service::Https => "https",
        Service::Smtp => "smtp",
        Service::Smtps => "smtps",
        Service::Mysql => "mysql",
        Service::Postgres => "postgres",
        Service::Redis => "redis",
        Service::Imap => "imap",
        Service::Imaps => "imaps",
        Service::Ldap => "ldap",
        Service::Ldaps => "ldaps",
    };
    Ok(parse_url(&format!("{scheme}://{host}"))?.source)
}

fn parse_network(value: &str) -> Result<IpNet, String> {
    value
        .parse::<IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| "Expected an IP address or CIDR subnet".into())
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let units = [("ms", 1_u64), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)];
    for (suffix, multiplier) in units {
        if let Some(number) = value.strip_suffix(suffix) {
            let millis = number
                .parse::<u64>()
                .ok()
                .and_then(|number| number.checked_mul(multiplier))
                .ok_or_else(|| {
                    "Duration must be a nonnegative whole number within range".to_owned()
                })?;
            return Ok(Duration::from_millis(millis));
        }
    }
    Err("Duration requires a unit: ms, s, m, or h (for example 200ms or 15m)".into())
}

fn parse_header(value: &str) -> Result<String, String> {
    if let Some((name, _)) = value.split_once(':')
        && !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
        && !value.contains(['\r', '\n'])
    {
        return Ok(value.into());
    }
    Err("Expected a header in 'Name: value' format without line breaks".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(args: &[&str]) -> TargetInput {
        Cli::try_parse_from(args)
            .unwrap()
            .validate()
            .unwrap()
            .unwrap()
    }

    #[test]
    fn cli_schema_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn url_and_positional_syntax_are_equivalent() {
        assert_eq!(
            input(&[
                "betterh",
                "ssh://admin@127.0.0.1:2222",
                "-P",
                "passwords.txt"
            ]),
            input(&[
                "betterh",
                "ssh",
                "127.0.0.1:2222",
                "-u",
                "admin",
                "-P",
                "passwords.txt"
            ])
        );
    }

    #[test]
    fn https_preserves_port_path_and_query() {
        let parsed = input(&[
            "betterh",
            "https://localhost:8443/login?next=%2Fhome",
            "-m",
            "post-form",
            "--body",
            "user={USER}&pass={PASS}",
        ]);
        assert_eq!(
            parsed.source,
            TargetSource::Single(Target {
                host: "localhost".into(),
                port: 8443,
                ssl: true,
                path: Some("/login?next=%2Fhome".into()),
                ip: None,
            })
        );
    }

    #[test]
    fn service_defaults_and_ipv6_are_normalized() {
        for (service, port) in [
            ("ftp", 21),
            ("ssh", 22),
            ("http", 80),
            ("https", 443),
            ("smtp", 25),
            ("smtps", 465),
            ("mysql", 3306),
            ("postgres", 5432),
            ("postgresql", 5432),
            ("redis", 6379),
            ("imap", 143),
            ("imaps", 993),
            ("ldap", 389),
            ("ldaps", 636),
        ] {
            let TargetSource::Single(target) = input(&["betterh", service, "::1"]).source else {
                panic!()
            };
            assert_eq!((target.host.as_str(), target.port), ("::1", port));
        }
        let TargetSource::Single(target) = input(&["betterh", "ssh://[::1]:2222"]).source else {
            panic!()
        };
        assert_eq!(target.to_string(), "[::1]:2222");
    }

    #[test]
    fn username_decoding_and_explicit_source_precedence() {
        assert_eq!(
            input(&["betterh", "ssh://a%40b@localhost"])
                .username
                .as_deref(),
            Some("a@b")
        );
        assert_eq!(
            input(&["betterh", "ssh://embedded@localhost", "-u", "explicit"])
                .username
                .as_deref(),
            Some("explicit")
        );
        assert!(
            input(&["betterh", "ssh://embedded@localhost", "-L", "users.txt"])
                .username
                .is_none()
        );
    }

    #[test]
    fn accepts_cidr_target_files_exclusions_and_stdin() {
        let cli = Cli::try_parse_from([
            "betterh",
            "ssh",
            "192.168.1.0/24",
            "--exclude",
            "192.168.1.1",
            "--exclude",
            "192.168.1.128/25",
            "-u",
            "admin",
            "-P",
            "-",
            "-e",
            "n,s,r",
        ])
        .unwrap();
        assert!(matches!(
            cli.validate().unwrap().unwrap().source,
            TargetSource::Network(_)
        ));
        assert_eq!(cli.exclude.len(), 2);
        assert_eq!(
            cli.mangling,
            [
                ManglingRule::Empty,
                ManglingRule::Same,
                ManglingRule::Reverse
            ]
        );
        assert!(matches!(
            input(&["betterh", "ssh", "-M", "targets.txt", "-C", "combos.txt"]).source,
            TargetSource::File(_)
        ));
    }

    #[test]
    fn rejects_conflicting_credential_and_proxy_sources() {
        for args in [
            vec!["-u", "admin", "-L", "users"],
            vec!["-p", "secret", "-P", "passwords"],
            vec!["-C", "combos", "-u", "admin"],
            vec!["--proxy", "http://localhost", "--proxy-list", "proxies"],
            vec!["--concurrency", "0"],
            vec!["--timeout-secs", "0"],
        ] {
            let mut argv = vec!["betterh", "ssh", "localhost"];
            argv.extend(args);
            assert!(Cli::try_parse_from(argv).is_err());
        }
        let cli =
            Cli::try_parse_from(["betterh", "ssh", "localhost", "-L", "-", "-P", "-"]).unwrap();
        assert!(cli.validate().is_err());
    }

    #[test]
    fn rejects_invalid_targets_and_wrong_module_options() {
        for args in [
            vec!["ssh://user:secret@localhost"],
            vec!["ssh://localhost/path"],
            vec!["https://localhost/#fragment"],
            vec!["ssh://localhost:0"],
            vec!["ssh://localhost:99999"],
            vec!["ssh://"],
            vec!["telnet", "localhost"],
            vec!["ssh", "192.168.1.0/33"],
            vec!["ssh", "localhost", "--body", "test"],
            vec!["https://localhost", "--ssh-key", "key"],
            vec!["ssh://localhost", "--ftp-passive"],
            vec!["ssh", "localhost", "--database", "test"],
            vec!["ssh://localhost", "extra"],
            vec!["ssh://localhost", "-M", "targets"],
        ] {
            let mut argv = vec!["betterh"];
            argv.extend(args);
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(cli.validate().is_err());
        }
    }

    #[test]
    fn parses_operational_options_and_duration_units() {
        let cli = Cli::try_parse_from([
            "betterh",
            "ssh",
            "localhost",
            "--mode",
            "spray",
            "--spray-cooldown",
            "15m",
            "--delay",
            "200ms",
            "--jitter",
            "50ms",
            "--exit-user=false",
            "--exit-host",
            "--exit-first",
            "--bell",
            "--on-found",
            "notify",
            "--dry-run",
            "--format",
            "jsonl",
            "--output",
            "found.jsonl",
        ])
        .unwrap();
        assert_eq!(cli.mode, AttackMode::Spray);
        assert_eq!(cli.spray_cooldown, Duration::from_mins(15));
        assert_eq!(cli.delay, Duration::from_millis(200));
        assert_eq!(cli.jitter, Duration::from_millis(50));
        assert!(!cli.exit_user);
        assert_eq!(cli.format, Some(OutputFormat::Jsonl));
    }

    #[test]
    fn rejects_invalid_durations_and_headers() {
        for value in ["5", "-1s", "1.5m", "18446744073709551615h", "1day"] {
            assert!(parse_duration(value).is_err());
        }
        for value in [
            "MissingColon",
            ": empty-name",
            "Bad Name: value",
            "X: value\r\nInjected: true",
        ] {
            assert!(parse_header(value).is_err());
        }
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_hours(2));
    }

    #[test]
    fn parses_commands_and_resume_without_target() {
        for args in [
            vec!["betterh", "wizard"],
            vec!["betterh", "completions", "bash"],
            vec!["betterh", "man"],
            vec!["betterh", "--interactive"],
            vec!["betterh", "--resume", "session.json"],
        ] {
            assert!(
                Cli::try_parse_from(args)
                    .unwrap()
                    .validate()
                    .unwrap()
                    .is_none()
            );
        }
    }
}
