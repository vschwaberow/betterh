// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Per-field configuration precedence: CLI, environment, TOML, defaults.

use std::{
    ffi::OsString,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
};

use clap::Args;
use directories::BaseDirs;
use serde::Deserialize;
use thiserror::Error;

/// Optional settings; absence must survive parsing so lower layers can apply.
#[derive(Debug, Clone, Default, Args, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigOptions {
    /// Maximum concurrent authentication attempts.
    #[arg(long)]
    pub concurrency: Option<NonZeroUsize>,
    /// Timeout for one attempt, in seconds.
    #[arg(long)]
    pub timeout_secs: Option<NonZeroU64>,
    /// Minimum request admission interval per target, in milliseconds (default: 1000).
    #[arg(long)]
    pub request_interval_ms: Option<NonZeroU64>,
    /// HTTP User-Agent value.
    #[arg(long)]
    pub user_agent: Option<String>,
    /// SOCKS5 or HTTP proxy URL.
    #[arg(long, conflicts_with = "proxy_list")]
    #[serde(rename = "default_proxy", alias = "proxy")]
    pub proxy: Option<String>,
    /// Wordlist search directory (repeatable).
    #[arg(long = "wordlist-path")]
    pub wordlist_paths: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub concurrency: NonZeroUsize,
    pub timeout_secs: NonZeroU64,
    pub request_interval_ms: NonZeroU64,
    pub user_agent: String,
    pub proxy: Option<String>,
    pub wordlist_paths: Vec<PathBuf>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Cannot read config {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Invalid config {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("Invalid {0} environment setting")]
    Environment(&'static str),
    #[error("Cannot determine current directory: {0}")]
    CurrentDirectory(std::io::Error),
    #[error(
        "Proxy must be an http:// or socks5:// URL with a host and no path, query, or fragment"
    )]
    Proxy,
    #[error("--proxy-list conflicts with the proxy selected by CLI, environment, or config")]
    ProxyConflict,
}

impl ConfigOptions {
    fn overlay(self, lower: Self) -> Self {
        Self {
            concurrency: self.concurrency.or(lower.concurrency),
            timeout_secs: self.timeout_secs.or(lower.timeout_secs),
            request_interval_ms: self.request_interval_ms.or(lower.request_interval_ms),
            user_agent: self.user_agent.or(lower.user_agent),
            proxy: self.proxy.or(lower.proxy),
            wordlist_paths: self.wordlist_paths.or(lower.wordlist_paths),
        }
    }

    fn from_environment(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let text = |key| {
            lookup(key)
                .map(|value| {
                    value
                        .into_string()
                        .map_err(|_| ConfigError::Environment(key))
                })
                .transpose()
        };
        Ok(Self {
            concurrency: text("BETTERH_CONCURRENCY")?
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| ConfigError::Environment("BETTERH_CONCURRENCY"))
                })
                .transpose()?,
            timeout_secs: text("BETTERH_TIMEOUT_SECS")?
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| ConfigError::Environment("BETTERH_TIMEOUT_SECS"))
                })
                .transpose()?,
            request_interval_ms: text("BETTERH_REQUEST_INTERVAL_MS")?
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| ConfigError::Environment("BETTERH_REQUEST_INTERVAL_MS"))
                })
                .transpose()?,
            user_agent: text("BETTERH_USER_AGENT")?,
            proxy: text("BETTERH_PROXY")?,
            wordlist_paths: lookup("BETTERH_WORDLIST_PATHS")
                .map(|value| std::env::split_paths(&value).collect()),
        })
    }

    fn resolve(self) -> Result<Config, ConfigError> {
        if let Some(proxy) = &self.proxy {
            validate_proxy(proxy)?;
        }
        Ok(Config {
            concurrency: self
                .concurrency
                .unwrap_or(NonZeroUsize::MIN.saturating_add(15)),
            timeout_secs: self
                .timeout_secs
                .unwrap_or(NonZeroU64::MIN.saturating_add(4)),
            request_interval_ms: self
                .request_interval_ms
                .unwrap_or(NonZeroU64::MIN.saturating_add(999)),
            user_agent: self
                .user_agent
                .unwrap_or_else(|| concat!("betterh/", env!("CARGO_PKG_VERSION")).into()),
            proxy: self.proxy,
            wordlist_paths: self.wordlist_paths.unwrap_or_default(),
        })
    }
}

/// Validate a supported proxy endpoint without connecting to it.
///
/// # Errors
/// Returns an error for an unsupported or malformed proxy URL.
pub fn validate_proxy(value: &str) -> Result<(), ConfigError> {
    let url = url::Url::parse(value).map_err(|_| ConfigError::Proxy)?;
    if !matches!(url.scheme(), "http" | "socks5")
        || url.host_str().is_none()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(ConfigError::Proxy);
    }
    Ok(())
}

/// Load settings using the process environment and standard config locations.
///
/// # Errors
/// Returns an error for inaccessible or invalid configuration sources.
pub async fn load(cli: ConfigOptions, explicit: Option<&Path>) -> Result<Config, ConfigError> {
    let cwd = std::env::current_dir().map_err(ConfigError::CurrentDirectory)?;
    let user_config = BaseDirs::new().map(|dirs| dirs.config_dir().join("betterh/config.toml"));
    load_from(cli, explicit, &cwd, user_config.as_deref(), |key| {
        std::env::var_os(key)
    })
    .await
}

async fn read_file(path: &Path, required: bool) -> Result<Option<ConfigOptions>, ConfigError> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(text) => text,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.into(),
                source,
            });
        }
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|source| ConfigError::Parse {
            path: path.into(),
            source,
        })
}

async fn load_from(
    cli: ConfigOptions,
    explicit: Option<&Path>,
    cwd: &Path,
    user_config: Option<&Path>,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Result<Config, ConfigError> {
    let file = if let Some(path) = explicit {
        read_file(path, true).await?
    } else if let Some(local) = read_file(&cwd.join("betterh.toml"), false).await? {
        Some(local)
    } else if let Some(path) = user_config {
        read_file(path, false).await?
    } else {
        None
    };
    let env = ConfigOptions::from_environment(lookup)?;
    for options in [Some(&cli), Some(&env), file.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(proxy) = &options.proxy {
            validate_proxy(proxy)?;
        }
    }
    cli.overlay(env).overlay(file.unwrap_or_default()).resolve()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_each_field_in_priority_order() {
        let file: ConfigOptions = toml::from_str("concurrency = 4\ntimeout_secs = 9\nuser_agent = 'from-file'\nwordlist_paths = ['/lists']").unwrap();
        let env = ConfigOptions::from_environment(|key| match key {
            "BETTERH_CONCURRENCY" => Some("8".into()),
            "BETTERH_TIMEOUT_SECS" => Some("12".into()),
            "BETTERH_PROXY" => Some("socks5://localhost:9050".into()),
            _ => None,
        })
        .unwrap();
        let cli = ConfigOptions {
            concurrency: NonZeroUsize::new(32),
            ..Default::default()
        };
        let config = cli.overlay(env).overlay(file).resolve().unwrap();
        assert_eq!(config.concurrency.get(), 32);
        assert_eq!(config.timeout_secs.get(), 12);
        assert_eq!(config.user_agent, "from-file");
        assert_eq!(config.proxy.as_deref(), Some("socks5://localhost:9050"));
        assert_eq!(config.wordlist_paths, [PathBuf::from("/lists")]);
    }

    #[test]
    fn environment_rejects_invalid_numbers_without_global_mutation() {
        for value in ["0", "-1", "abc", ""] {
            assert!(
                ConfigOptions::from_environment(
                    |key| (key == "BETTERH_CONCURRENCY").then(|| value.into())
                )
                .is_err()
            );
            assert!(
                ConfigOptions::from_environment(
                    |key| (key == "BETTERH_TIMEOUT_SECS").then(|| value.into())
                )
                .is_err()
            );
        }
    }

    #[test]
    fn environment_path_list_uses_platform_separator() {
        let paths = [PathBuf::from("/one"), PathBuf::from("/two")];
        let joined = std::env::join_paths(&paths).unwrap();
        let options = ConfigOptions::from_environment(|key| {
            (key == "BETTERH_WORDLIST_PATHS").then(|| joined.clone())
        })
        .unwrap();
        assert_eq!(options.wordlist_paths.unwrap(), paths);
    }

    #[tokio::test]
    async fn missing_implicit_files_use_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = load_from(ConfigOptions::default(), None, dir.path(), None, |_| None)
            .await
            .unwrap();
        assert_eq!(config.concurrency.get(), 16);
        assert_eq!(config.timeout_secs.get(), 5);
        assert_eq!(config.request_interval_ms.get(), 1000);
        assert_eq!(config.user_agent, "betterh/0.1.0");
        assert!(config.proxy.is_none());
        assert!(config.wordlist_paths.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn request_interval_precedence_reaches_the_guard() {
        use crate::{cli::Cli, engine::request_guard::RequestGuard};
        use clap::Parser;
        use tokio_util::sync::CancellationToken;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("betterh.toml");
        tokio::fs::write(&path, "request_interval_ms = 1300")
            .await
            .unwrap();
        for (cli_value, env_value, expected) in [
            (None, None, 1300),
            (None, Some("1700"), 1700),
            (Some("2100"), Some("1700"), 2100),
        ] {
            let mut args = vec!["betterh"];
            if let Some(value) = cli_value {
                args.extend(["--request-interval-ms", value]);
            }
            let cli = Cli::try_parse_from(args).unwrap();
            let config = load_from(cli.settings, Some(&path), dir.path(), None, |key| {
                if key == "BETTERH_REQUEST_INTERVAL_MS" {
                    env_value.map(OsString::from)
                } else {
                    None
                }
            })
            .await
            .unwrap();
            assert_eq!(config.request_interval_ms.get(), expected);

            let guard = RequestGuard::from_config(&config).unwrap();
            let cancellation = CancellationToken::new();
            guard.wait(&cancellation).await.unwrap();
            let start = tokio::time::Instant::now();
            guard.wait(&cancellation).await.unwrap();
            assert_eq!(start.elapsed(), std::time::Duration::from_millis(expected));
        }
    }

    #[test]
    fn request_interval_rejects_invalid_values_in_every_source() {
        use crate::cli::Cli;
        use clap::Parser;

        for value in ["0", "-1", "1.5", "18446744073709551616", "abc", "1s"] {
            assert!(
                Cli::try_parse_from(["betterh", &format!("--request-interval-ms={value}")])
                    .is_err(),
                "CLI accepted {value}"
            );
            assert!(
                ConfigOptions::from_environment(|key| {
                    (key == "BETTERH_REQUEST_INTERVAL_MS").then(|| OsString::from(value))
                })
                .is_err(),
                "environment accepted {value}"
            );
            assert!(
                toml::from_str::<ConfigOptions>(&format!("request_interval_ms = {value}")).is_err(),
                "TOML accepted {value}"
            );
        }
    }

    #[tokio::test]
    async fn config_path_order_is_explicit_then_local_then_user() {
        let dir = tempfile::tempdir().unwrap();
        let local = dir.path().join("betterh.toml");
        let user = dir.path().join("user.toml");
        let custom = dir.path().join("custom.toml");
        tokio::fs::write(&user, "concurrency = 2").await.unwrap();
        let config = load_from(
            ConfigOptions::default(),
            None,
            dir.path(),
            Some(&user),
            |_| None,
        )
        .await
        .unwrap();
        assert_eq!(config.concurrency.get(), 2);
        tokio::fs::write(&local, "concurrency = 3").await.unwrap();
        tokio::fs::write(&custom, "concurrency = 4").await.unwrap();
        let config = load_from(
            ConfigOptions::default(),
            None,
            dir.path(),
            Some(&user),
            |_| None,
        )
        .await
        .unwrap();
        assert_eq!(config.concurrency.get(), 3);
        let config = load_from(
            ConfigOptions::default(),
            Some(&custom),
            dir.path(),
            Some(&user),
            |_| None,
        )
        .await
        .unwrap();
        assert_eq!(config.concurrency.get(), 4);
    }

    #[tokio::test]
    async fn selected_invalid_or_missing_config_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("betterh.toml");
        assert!(matches!(
            load_from(
                ConfigOptions::default(),
                Some(&path),
                dir.path(),
                None,
                |_| None
            )
            .await,
            Err(ConfigError::Read { .. })
        ));
        for text in [
            "concurrency = 0",
            "unknown = 1",
            "[broken",
            "timeout_secs = -1",
        ] {
            tokio::fs::write(&path, text).await.unwrap();
            assert!(matches!(
                load_from(ConfigOptions::default(), None, dir.path(), None, |_| None).await,
                Err(ConfigError::Parse { .. })
            ));
        }
    }

    #[test]
    fn proxy_validation_rejects_unsupported_or_malformed_urls() {
        for value in [
            "localhost:9000",
            "ftp://localhost",
            "http://",
            "http://localhost/path",
            "http://localhost:0",
            "socks5://localhost#fragment",
        ] {
            assert!(validate_proxy(value).is_err(), "{value}");
        }
        for value in ["http://localhost:8080", "socks5://user:pass@[::1]:9050"] {
            assert!(validate_proxy(value).is_ok(), "{value}");
        }
    }

    #[tokio::test]
    async fn invalid_selected_proxy_is_reported_even_when_overridden() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("betterh.toml"), "default_proxy = 'invalid'")
            .await
            .unwrap();
        let cli = ConfigOptions {
            proxy: Some("http://localhost:8080".into()),
            ..Default::default()
        };
        assert!(matches!(
            load_from(cli, None, dir.path(), None, |_| None).await,
            Err(ConfigError::Proxy)
        ));
    }
}
