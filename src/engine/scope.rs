// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Exclusion matching and pre-connection scope classification.

use std::{net::IpAddr, path::Path};

use ipnet::IpNet;
use thiserror::Error;
use tokio::io::BufReader;

use super::wordlist::{Wordlist, WordlistError};
use crate::protocols::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecision {
    Excluded,
    Local,
    ConfirmationRequired,
    NeedsResolution,
}

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("Cannot read exclusions: {0}")]
    Read(#[from] WordlistError),
    #[error("Exclusion entries must be IP addresses or CIDR networks")]
    InvalidEntry,
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    exclusions: Vec<IpNet>,
}

impl Scope {
    #[must_use]
    pub fn new(exclusions: Vec<IpNet>) -> Self {
        Self { exclusions }
    }

    /// Combine CLI exclusions with a regular UTF-8 exclusion file.
    ///
    /// # Errors
    /// Returns an error for unreadable files, invalid UTF-8, or invalid entries.
    pub async fn load(mut exclusions: Vec<IpNet>, file: Option<&Path>) -> Result<Self, ScopeError> {
        if let Some(path) = file {
            let mut reader = open_lines(path).await?;
            while let Some(line) = reader.next_word().await? {
                if line.starts_with('#') {
                    continue;
                }
                let network = line
                    .parse::<IpNet>()
                    .or_else(|_| line.parse::<IpAddr>().map(IpNet::from))
                    .map_err(|_| ScopeError::InvalidEntry)?;
                exclusions.push(network);
            }
        }
        Ok(Self::new(exclusions))
    }

    /// Classify a literal IP, or require DNS resolution for a hostname.
    /// This does not authorize a connection. Check each resolved socket IP again.
    #[must_use]
    pub fn classify(&self, target: &Target) -> ScopeDecision {
        target
            .host
            .parse::<IpAddr>()
            .map_or(ScopeDecision::NeedsResolution, |ip| self.classify_ip(ip))
    }

    #[must_use]
    pub fn classify_ip(&self, ip: IpAddr) -> ScopeDecision {
        if self.excluded_end(ip).is_some() {
            return ScopeDecision::Excluded;
        }
        let local = match ip.to_canonical() {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
        };
        if local {
            ScopeDecision::Local
        } else {
            ScopeDecision::ConfirmationRequired
        }
    }

    // The returned address has the input's family, so a cursor can skip the range.
    pub(crate) fn excluded_end(&self, ip: IpAddr) -> Option<IpAddr> {
        self.exclusions
            .iter()
            .filter_map(|network| {
                if network.contains(&ip) {
                    return Some(network.broadcast());
                }
                if let IpAddr::V4(ip) = ip
                    && let IpNet::V6(network) = network
                    && network.prefix_len() >= 96
                    && network.contains(&ip.to_ipv6_mapped())
                {
                    return network.broadcast().to_ipv4_mapped().map(IpAddr::V4);
                }
                if let IpAddr::V6(ip) = ip
                    && let Some(mapped) = ip.to_ipv4_mapped()
                    && network.contains(&IpAddr::V4(mapped))
                    && let IpAddr::V4(end) = network.broadcast()
                {
                    return Some(IpAddr::V6(end.to_ipv6_mapped()));
                }
                None
            })
            .max()
    }
}

pub(crate) async fn open_lines(
    path: &Path,
) -> Result<Wordlist<BufReader<tokio::fs::File>>, WordlistError> {
    if path == Path::new("-") || !tokio::fs::metadata(path).await?.is_file() {
        return Err(WordlistError::NotRegularFile);
    }
    Ok(Wordlist::new(BufReader::new(
        tokio::fs::File::open(path).await?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_local_nonlocal_and_mapped_addresses() {
        let scope = Scope::default();
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "::1",
            "fd12::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert_eq!(
                scope.classify_ip(ip.parse().unwrap()),
                ScopeDecision::Local,
                "{ip}"
            );
        }
        for ip in [
            "8.8.8.8",
            "172.32.0.1",
            "2001:4860::1",
            "0.0.0.0",
            "::",
            "::ffff:8.8.8.8",
        ] {
            assert_eq!(
                scope.classify_ip(ip.parse().unwrap()),
                ScopeDecision::ConfirmationRequired,
                "{ip}"
            );
        }
    }

    #[test]
    fn exclusions_take_precedence_and_cover_mapped_ipv4() {
        let scope = Scope::new(vec![
            "10.0.0.0/8".parse().unwrap(),
            "fd12::/16".parse().unwrap(),
        ]);
        for ip in ["10.1.2.3", "::ffff:10.1.2.3", "fd12::1"] {
            assert_eq!(
                scope.classify_ip(ip.parse().unwrap()),
                ScopeDecision::Excluded
            );
        }
        let target = Target {
            host: "localhost".into(),
            port: 22,
            ssl: false,
            path: None,
            ip: None,
        };
        assert_eq!(scope.classify(&target), ScopeDecision::NeedsResolution);
    }

    #[test]
    fn mapped_exclusions_also_cover_ipv4_without_crossing_general_ipv6_scope() {
        let scope = Scope::new(vec!["::ffff:10.0.0.0/104".parse().unwrap()]);
        assert_eq!(
            scope.classify_ip("10.1.2.3".parse().unwrap()),
            ScopeDecision::Excluded
        );
        assert_eq!(
            scope.excluded_end("10.1.2.3".parse().unwrap()),
            Some("10.255.255.255".parse().unwrap())
        );
        let scope = Scope::new(vec!["::/0".parse().unwrap()]);
        assert_eq!(
            scope.classify_ip("10.1.2.3".parse().unwrap()),
            ScopeDecision::Local
        );
    }

    #[tokio::test]
    async fn combines_cli_and_file_exclusions_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exclusions");
        tokio::fs::write(&path, "# comment\r\n\n10.1.2.3\r\nfd12::/16\n")
            .await
            .unwrap();
        let scope = Scope::load(vec!["192.168.0.0/16".parse().unwrap()], Some(&path))
            .await
            .unwrap();
        for ip in ["10.1.2.3", "fd12::1", "192.168.1.1"] {
            assert_eq!(
                scope.classify_ip(ip.parse().unwrap()),
                ScopeDecision::Excluded
            );
        }
        assert_eq!(
            scope.classify_ip("10.1.2.4".parse().unwrap()),
            ScopeDecision::Local
        );
    }

    #[tokio::test]
    async fn invalid_exclusion_files_fail_instead_of_weakening_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exclusions");
        assert!(Scope::load(vec![], Some(&path)).await.is_err());
        for entry in ["example.com", "10.0.0.0/33", "10.0.0.1:22", "::/129"] {
            tokio::fs::write(&path, entry).await.unwrap();
            assert!(matches!(
                Scope::load(vec![], Some(&path)).await,
                Err(ScopeError::InvalidEntry)
            ));
        }
        tokio::fs::write(&path, b"\xff").await.unwrap();
        assert!(Scope::load(vec![], Some(&path)).await.is_err());
        assert!(Scope::load(vec![], Some(Path::new("-"))).await.is_err());
        assert!(Scope::load(vec![], Some(dir.path())).await.is_err());
    }
}
