// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Proxy pool rotation and inter-request pacing.

use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use thiserror::Error;
use url::Url;

use super::{scope::open_lines, wordlist::WordlistError};
use crate::config::validate_proxy;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Cannot read proxy list: {0}")]
    Read(#[from] WordlistError),
    #[error("Invalid proxy URL at entry {entry}: {reason}")]
    InvalidProxy { entry: u64, reason: &'static str },
    #[error("Proxy list file is empty or contains only comments")]
    EmptyList,
}

/// Thread-safe round-robin proxy pool.
#[derive(Debug, Default)]
pub struct ProxyPool {
    proxies: Vec<Url>,
    cursor: AtomicUsize,
}

impl ProxyPool {
    #[must_use]
    pub fn new(proxies: Vec<Url>) -> Self {
        Self {
            proxies,
            cursor: AtomicUsize::new(0),
        }
    }

    /// Single proxy configuration.
    #[must_use]
    pub fn from_single(url: Url) -> Self {
        Self::new(vec![url])
    }

    /// Load proxies from a regular UTF-8 file, ignoring `#` comments and empty lines.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, contains malformed proxy URLs, or is empty.
    pub async fn load(path: &Path) -> Result<Self, ProxyError> {
        let mut reader = open_lines(path).await?;
        let mut proxies = Vec::new();
        let mut entry = 0u64;

        while let Some(line) = reader.next_word().await? {
            entry = entry.saturating_add(1);
            if line.starts_with('#') {
                continue;
            }
            validate_proxy(&line).map_err(|_| ProxyError::InvalidProxy {
                entry,
                reason: "Expected http:// or socks5:// proxy URL with valid host and port",
            })?;
            let url = Url::parse(&line).map_err(|_| ProxyError::InvalidProxy {
                entry,
                reason: "Failed to parse proxy URL",
            })?;
            proxies.push(url);
        }

        if proxies.is_empty() {
            return Err(ProxyError::EmptyList);
        }

        Ok(Self::new(proxies))
    }

    /// Returns the next proxy in round-robin order, or `None` if the pool is empty.
    #[must_use]
    pub fn next_proxy(&self) -> Option<&Url> {
        if self.proxies.is_empty() {
            return None;
        }
        let index = self.cursor.fetch_add(1, Ordering::Relaxed) % self.proxies.len();
        self.proxies.get(index)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.proxies.len()
    }
}

/// Request delay and jitter pacer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pacer {
    delay: Duration,
    jitter: Duration,
}

impl Pacer {
    #[must_use]
    pub const fn new(delay: Duration, jitter: Duration) -> Self {
        Self { delay, jitter }
    }

    #[must_use]
    pub const fn delay(&self) -> Duration {
        self.delay
    }

    #[must_use]
    pub const fn jitter(&self) -> Duration {
        self.jitter
    }

    /// Calculate the next delay duration adding randomized jitter within `[0, jitter]`.
    #[must_use]
    pub fn next_delay(&self) -> Duration {
        if self.delay.is_zero() && self.jitter.is_zero() {
            return Duration::ZERO;
        }
        if self.jitter.is_zero() {
            return self.delay;
        }
        let jitter_nanos = u64::try_from(self.jitter.as_nanos()).unwrap_or(u64::MAX);
        let random_nanos = fastrand::u64(0..=jitter_nanos);
        self.delay
            .saturating_add(Duration::from_nanos(random_nanos))
    }

    /// Sleep for the computed delay + jitter duration.
    pub async fn pace(&self) {
        let duration = self.next_delay();
        if !duration.is_zero() {
            tokio::time::sleep(duration).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_proxy_always_returns_same_url() {
        let url: Url = "http://127.0.0.1:8080".parse().unwrap();
        let pool = ProxyPool::from_single(url.clone());
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());
        for _ in 0..5 {
            assert_eq!(pool.next_proxy(), Some(&url));
        }
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ProxyPool::default();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
        assert_eq!(pool.next_proxy(), None);
    }

    #[test]
    fn round_robin_rotates_fairly() {
        let p1: Url = "http://127.0.0.1:8080".parse().unwrap();
        let p2: Url = "socks5://127.0.0.1:1080".parse().unwrap();
        let p3: Url = "http://proxy.local:3128".parse().unwrap();
        let pool = ProxyPool::new(vec![p1.clone(), p2.clone(), p3.clone()]);
        assert_eq!(pool.len(), 3);

        assert_eq!(pool.next_proxy(), Some(&p1));
        assert_eq!(pool.next_proxy(), Some(&p2));
        assert_eq!(pool.next_proxy(), Some(&p3));
        assert_eq!(pool.next_proxy(), Some(&p1));
        assert_eq!(pool.next_proxy(), Some(&p2));
    }

    #[tokio::test]
    async fn loads_valid_proxy_file_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxies.txt");
        tokio::fs::write(
            &path,
            "# Local proxies\nhttp://127.0.0.1:8080\n\nsocks5://127.0.0.1:9050\n# End\n",
        )
        .await
        .unwrap();

        let pool = ProxyPool::load(&path).await.unwrap();
        assert_eq!(pool.len(), 2);
        assert_eq!(
            pool.next_proxy().map(Url::as_str),
            Some("http://127.0.0.1:8080/")
        );
        assert_eq!(
            pool.next_proxy().map(Url::as_str),
            Some("socks5://127.0.0.1:9050")
        );
    }

    #[tokio::test]
    async fn rejects_invalid_proxy_urls_and_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxies.txt");

        tokio::fs::write(&path, "# Only comments\n\n")
            .await
            .unwrap();
        assert!(matches!(
            ProxyPool::load(&path).await,
            Err(ProxyError::EmptyList)
        ));

        for invalid in [
            "ftp://127.0.0.1:21",
            "http://",
            "not-a-url",
            "http://127.0.0.1:0",
        ] {
            tokio::fs::write(&path, format!("{invalid}\n"))
                .await
                .unwrap();
            assert!(
                matches!(
                    ProxyPool::load(&path).await,
                    Err(ProxyError::InvalidProxy { .. })
                ),
                "Should reject {invalid}"
            );
        }
    }

    #[test]
    fn pacer_zero_delay_and_jitter() {
        let pacer = Pacer::new(Duration::ZERO, Duration::ZERO);
        assert_eq!(pacer.next_delay(), Duration::ZERO);
    }

    #[test]
    fn pacer_delay_without_jitter() {
        let pacer = Pacer::new(Duration::from_millis(100), Duration::ZERO);
        for _ in 0..10 {
            assert_eq!(pacer.next_delay(), Duration::from_millis(100));
        }
    }

    #[test]
    fn pacer_delay_with_jitter_stays_in_range() {
        let base = Duration::from_millis(100);
        let jitter = Duration::from_millis(50);
        let pacer = Pacer::new(base, jitter);
        let max = base + jitter;

        for _ in 0..100 {
            let delay = pacer.next_delay();
            assert!(delay >= base, "Delay {delay:?} must be >= {base:?}");
            assert!(delay <= max, "Delay {delay:?} must be <= {max:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pacer_pace_advances_virtual_clock() {
        let base = Duration::from_millis(100);
        let pacer = Pacer::new(base, Duration::ZERO);
        let start = tokio::time::Instant::now();
        pacer.pace().await;
        assert_eq!(tokio::time::Instant::now() - start, base);
    }
}
