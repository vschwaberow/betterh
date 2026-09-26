// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Lazy target expansion with exclusion ranges skipped before emission.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::{
    StreamExt,
    stream::{self, BoxStream},
};
use ipnet::IpNet;
use thiserror::Error;
use tokio::io::BufReader;

use super::{
    scope::{Scope, ScopeDecision, open_lines},
    wordlist::{Wordlist, WordlistError},
};
use crate::{
    cli::{Service, TargetInput, TargetSource, parse_positional, parse_url},
    protocols::Target,
};

pub type TargetStream = BoxStream<'static, Result<Target, TargetError>>;

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("Cannot read targets: {0}")]
    Read(#[from] WordlistError),
    #[error("Invalid target entry {entry}: {reason}")]
    InvalidEntry { entry: u64, reason: &'static str },
}

/// Expand normalized CLI input without collecting targets or resolving names.
///
/// Literal exclusions are applied immediately. Before connecting, callers must
/// enforce `Scope::classify_ip` for the actual socket address, including DNS results.
/// Input errors appear as stream items and terminate the stream.
#[must_use]
pub fn expand(input: TargetInput, scope: Scope) -> TargetStream {
    let state = Expander {
        service: input.service,
        pending: Some(input.source),
        file: None,
        range: None,
        scope,
        entry: 0,
    };
    stream::unfold(Some(state), |state| async move {
        let mut state = state?;
        match state.next_target().await {
            Ok(Some(target)) => Some((Ok(target), Some(state))),
            Ok(None) => None,
            Err(error) => Some((Err(error), None)),
        }
    })
    .fuse()
    .boxed()
}

struct Expander {
    service: Service,
    pending: Option<TargetSource>,
    file: Option<Wordlist<BufReader<tokio::fs::File>>>,
    range: Option<Addresses>,
    scope: Scope,
    entry: u64,
}

impl Expander {
    async fn next_target(&mut self) -> Result<Option<Target>, TargetError> {
        loop {
            if let Some(range) = &mut self.range {
                if let Some(ip) = range.next_allowed(&self.scope) {
                    return Ok(Some(Target {
                        host: ip.to_string(),
                        port: self.service.default_port(),
                        ssl: self.service == Service::Https,
                        path: matches!(self.service, Service::Http | Service::Https)
                            .then(|| "/".into()),
                        ip: Some(ip),
                    }));
                }
                self.range = None;
            }
            let source = if let Some(source) = self.pending.take() {
                source
            } else {
                let Some(file) = &mut self.file else {
                    return Ok(None);
                };
                let Some(line) = file.next_word().await? else {
                    return Ok(None);
                };
                self.entry = self.entry.saturating_add(1);
                if line.starts_with('#') {
                    continue;
                }
                parse_entry(self.service, &line).map_err(|reason| TargetError::InvalidEntry {
                    entry: self.entry,
                    reason,
                })?
            };
            match source {
                TargetSource::Single(target) => {
                    if self.scope.classify(&target) != ScopeDecision::Excluded {
                        return Ok(Some(target));
                    }
                }
                TargetSource::Network(network) => self.range = Some(Addresses::new(network)),
                TargetSource::File(path) => self.file = Some(open_lines(&path).await?),
            }
        }
    }
}

fn parse_entry(service: Service, value: &str) -> Result<TargetSource, &'static str> {
    if value.contains("://") {
        let parsed = parse_url(value).map_err(|_| "Invalid target URL")?;
        if parsed.username.is_some() {
            return Err("Use -u or -L instead of embedded users in target-file URLs");
        }
        let both_http = matches!(service, Service::Http | Service::Https)
            && matches!(parsed.service, Service::Http | Service::Https);
        if service != parsed.service && !both_http {
            return Err("URL protocol does not match the selected service");
        }
        return Ok(parsed.source);
    }
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(TargetSource::Network(network));
    }
    if value.contains(['/', '?', '#', '@']) {
        return Err("Expected a host, host:port pair, CIDR, or URL");
    }
    parse_positional(service, value).map_err(|_| "Invalid host or port")
}

struct Addresses {
    next: Option<IpAddr>,
    end: IpAddr,
}

impl Addresses {
    fn new(network: IpNet) -> Self {
        let (start, end) = if let IpNet::V4(network) = network
            && network.prefix_len() < 31
        {
            (
                IpAddr::V4(Ipv4Addr::from(u32::from(network.network()) + 1)),
                IpAddr::V4(Ipv4Addr::from(u32::from(network.broadcast()) - 1)),
            )
        } else {
            (network.network(), network.broadcast())
        };
        Self {
            next: Some(start),
            end,
        }
    }

    fn next_allowed(&mut self, scope: &Scope) -> Option<IpAddr> {
        while let Some(ip) = self.next {
            if ip > self.end {
                self.next = None;
                return None;
            }
            if let Some(end) = scope.excluded_end(ip) {
                self.next = successor(end);
                continue;
            }
            self.next = successor(ip);
            return Some(ip);
        }
        None
    }
}

fn successor(ip: IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V4(ip) => u32::from(ip)
            .checked_add(1)
            .map(|value| IpAddr::V4(Ipv4Addr::from(value))),
        IpAddr::V6(ip) => u128::from(ip)
            .checked_add(1)
            .map(|value| IpAddr::V6(Ipv6Addr::from(value))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::TryStreamExt;

    fn input(source: TargetSource) -> TargetInput {
        TargetInput {
            service: Service::Ssh,
            source,
            username: None,
        }
    }

    fn network(value: &str) -> TargetSource {
        TargetSource::Network(value.parse().unwrap())
    }

    async fn hosts(source: TargetSource, excludes: &[&str]) -> Vec<String> {
        let scope = Scope::new(
            excludes
                .iter()
                .map(|value| {
                    value
                        .parse::<IpNet>()
                        .unwrap_or_else(|_| value.parse::<IpAddr>().unwrap().into())
                })
                .collect(),
        );
        expand(input(source), scope)
            .map_ok(|target| target.host)
            .try_collect()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn ipv4_hosts_exclude_network_and_broadcast_but_keep_small_subnets() {
        assert_eq!(
            hosts(network("10.0.0.3/30"), &[]).await,
            ["10.0.0.1", "10.0.0.2"]
        );
        assert_eq!(
            hosts(network("10.0.0.0/31"), &[]).await,
            ["10.0.0.0", "10.0.0.1"]
        );
        assert_eq!(hosts(network("10.0.0.0/32"), &[]).await, ["10.0.0.0"]);
    }

    #[tokio::test]
    async fn ipv6_keeps_every_address_including_the_network_address() {
        assert_eq!(
            hosts(network("fd00::3/126"), &[]).await,
            ["fd00::", "fd00::1", "fd00::2", "fd00::3"]
        );
    }

    #[tokio::test]
    async fn exclusions_remove_individual_addresses_and_whole_subnets() {
        assert_eq!(
            hosts(network("10.0.0.0/29"), &["10.0.0.1", "10.0.0.4/30"]).await,
            ["10.0.0.2", "10.0.0.3"]
        );
        assert_eq!(
            hosts(network("fd00::/125"), &["fd00::1", "fd00::4/126"]).await,
            ["fd00::", "fd00::2", "fd00::3"]
        );
        assert_eq!(
            hosts(network("::ffff:10.0.0.0/126"), &["10.0.0.0/31"]).await,
            ["::ffff:10.0.0.2", "::ffff:10.0.0.3"]
        );
    }

    #[test]
    fn enormous_excluded_ranges_are_skipped_in_one_step() {
        let scope = Scope::new(vec!["::/1".parse().unwrap()]);
        let mut addresses = Addresses::new("::/0".parse().unwrap());
        assert_eq!(
            addresses.next_allowed(&scope),
            Some("8000::".parse().unwrap())
        );
        let scope = Scope::new(vec!["::/0".parse().unwrap()]);
        assert_eq!(addresses.next_allowed(&scope), None);
    }

    #[tokio::test]
    async fn address_limits_do_not_wrap_or_repeat() {
        assert_eq!(
            hosts(network("255.255.255.255/32"), &[]).await,
            ["255.255.255.255"]
        );
        assert_eq!(
            hosts(network("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), &[]).await,
            ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        );
        assert!(hosts(network("0.0.0.0/0"), &["0.0.0.0/0"]).await.is_empty());
    }

    #[tokio::test]
    async fn enormous_network_streams_first_targets_without_materializing_range() {
        let actual: Vec<_> = expand(input(network("fd00::/8")), Scope::default())
            .take(3)
            .map_ok(|target| target.host)
            .try_collect()
            .await
            .unwrap();
        assert_eq!(actual, ["fd00::", "fd00::1", "fd00::2"]);
    }

    #[tokio::test]
    async fn target_file_preserves_order_ports_and_exclusions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("targets");
        tokio::fs::write(
            &path,
            "# comment\r\nlocalhost:2222\n\n10.0.0.0/30\nssh://[::1]:2223\nlocalhost:2222\n",
        )
        .await
        .unwrap();
        let scope = Scope::new(vec!["10.0.0.2/32".parse().unwrap()]);
        let actual: Vec<_> = expand(input(TargetSource::File(path)), scope)
            .map_ok(|target| target.to_string())
            .try_collect()
            .await
            .unwrap();
        assert_eq!(
            actual,
            [
                "localhost:2222",
                "10.0.0.1:22",
                "[::1]:2223",
                "localhost:2222"
            ]
        );
    }

    #[tokio::test]
    async fn http_urls_and_cidrs_preserve_tls_ports_and_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("targets");
        tokio::fs::write(
            &path,
            "http://localhost:8080/login?q=1\nhttps://localhost/login\n127.0.0.1/32\n",
        )
        .await
        .unwrap();
        let mut input = input(TargetSource::File(path));
        input.service = Service::Https;
        let actual: Vec<_> = expand(input, Scope::default()).try_collect().await.unwrap();
        assert_eq!(
            actual[0],
            Target {
                host: "localhost".into(),
                port: 8080,
                ssl: false,
                path: Some("/login?q=1".into()),
                ip: None,
            }
        );
        assert_eq!(
            actual[1],
            Target {
                host: "localhost".into(),
                port: 443,
                ssl: true,
                path: Some("/login".into()),
                ip: None,
            }
        );
        assert_eq!(
            actual[2],
            Target {
                host: "127.0.0.1".into(),
                port: 443,
                ssl: true,
                path: Some("/".into()),
                ip: Some("127.0.0.1".parse().unwrap()),
            }
        );
    }

    #[tokio::test]
    async fn invalid_target_entry_terminates_stream_without_echoing_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("targets");
        for invalid in [
            "10.0.0.0/33",
            "ssh://user:secret@localhost",
            "ssh://user@localhost",
            "http://localhost",
            "localhost:0",
            "localhost/path",
        ] {
            tokio::fs::write(&path, format!("{invalid}\n127.0.0.1\n"))
                .await
                .unwrap();
            let mut targets = expand(input(TargetSource::File(path.clone())), Scope::default());
            let error = targets.next().await.unwrap().unwrap_err();
            assert!(matches!(error, TargetError::InvalidEntry { .. }));
            assert!(!error.to_string().contains("secret"));
            assert!(targets.next().await.is_none());
            assert!(targets.next().await.is_none());
        }
    }

    #[tokio::test]
    async fn target_files_open_lazily_and_report_read_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("targets");
        let mut targets = expand(input(TargetSource::File(path.clone())), Scope::default());
        tokio::fs::write(&path, "127.0.0.1\n").await.unwrap();
        assert_eq!(targets.next().await.unwrap().unwrap().host, "127.0.0.1");
        tokio::fs::write(&path, b"\xff").await.unwrap();
        let mut targets = expand(input(TargetSource::File(path)), Scope::default());
        assert!(matches!(
            targets.next().await,
            Some(Err(TargetError::Read(_)))
        ));
        assert!(targets.next().await.is_none());
    }

    #[tokio::test]
    async fn single_target_keeps_path_or_is_excluded() {
        let target = Target {
            host: "127.0.0.1".into(),
            port: 8443,
            ssl: true,
            path: Some("/login".into()),
            ip: Some("127.0.0.1".parse().unwrap()),
        };
        let actual: Vec<_> = expand(
            input(TargetSource::Single(target.clone())),
            Scope::default(),
        )
        .try_collect()
        .await
        .unwrap();
        assert_eq!(actual, std::slice::from_ref(&target));
        assert!(
            hosts(TargetSource::Single(target), &["127.0.0.1"])
                .await
                .is_empty()
        );
    }
}
