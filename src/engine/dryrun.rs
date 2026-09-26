// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Pre-flight `--dry-run` combination audit (no authentication attempts).

use std::{fmt, future::Future, net::SocketAddr, time::Duration};

use futures::StreamExt;
use thiserror::Error;
use tokio::io::BufReader;
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::cli::{Cli, Service, TargetInput, TargetSource};
use crate::config::Config;
use crate::engine::proxy::{ProxyError, ProxyPool};
use crate::engine::scope::{Scope, ScopeDecision, ScopeError};
use crate::engine::targets::{TargetError, expand};
use crate::engine::wordlist::{
    CredentialInput, InputSource, Wordlist, WordlistError, credentials, mangled, normalized_rules,
};
use crate::protocols::Target;

/// Summary produced by a dry-run audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunReport {
    pub service: Service,
    pub target_summary: String,
    pub targets: u64,
    pub proxies: u64,
    pub users: u64,
    pub passwords: u64,
    pub combinations: u64,
    pub concurrency: u64,
    pub request_interval_ms: u64,
    pub estimated: Duration,
    pub reachability: Reachability,
}

/// Connectivity probe outcome for dry-run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    Reachable,
    Unreachable(String),
    Skipped(&'static str),
    Sampled {
        probed: u64,
        reachable: u64,
        unreachable: u64,
        skipped: u64,
    },
}

#[derive(Debug, Error)]
pub enum DryRunError {
    #[error("Dry-run cancelled")]
    Cancelled,
    #[error("Dry-run cannot count candidates from stdin; pass a file path instead of `-`")]
    StdinNotSupported,
    #[error("Dry-run requires credentials: use -u/-L and -p/-P, or -C")]
    MissingCredentials,
    #[error(transparent)]
    Wordlist(#[from] WordlistError),
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Target(#[from] TargetError),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
}

/// Run an audit that can be cancelled without producing a partial report.
///
/// # Errors
/// Returns [`DryRunError::Cancelled`] on cancellation, or an input/audit error.
pub async fn audit_with_cancellation(
    cli: &Cli,
    config: &Config,
    input: &TargetInput,
    cancellation: &CancellationToken,
) -> Result<DryRunReport, DryRunError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DryRunError::Cancelled),
        result = audit(cli, config, input) => result,
    }
}

/// Run a pre-flight audit: expand targets, count combinations, estimate duration, TCP probe.
///
/// Credential combination counts stay \(O(1)\) memory by counting wordlist lines rather than
/// materializing the cartesian product. Target expansion streams from Phase 3 helpers.
///
/// # Errors
/// Returns [`DryRunError`] for missing credentials, stdin lists, scope, or wordlist failures.
pub async fn audit(
    cli: &Cli,
    config: &Config,
    input: &TargetInput,
) -> Result<DryRunReport, DryRunError> {
    let (users, passwords, cred_combinations) = count_combinations(cli, input).await?;
    let scope = Scope::load(cli.exclude.clone(), cli.exclude_file.as_deref()).await?;
    let (targets, sample) = count_targets(input.clone(), scope.clone()).await?;
    let combinations = cred_combinations.saturating_mul(targets);
    let concurrency = u64::try_from(config.concurrency.get()).unwrap_or(u64::MAX);
    let request_interval_ms = config.request_interval_ms.get();
    let estimated = estimate_duration(cred_combinations, targets, concurrency, request_interval_ms);
    let proxies = count_proxies(cli, config).await?;
    let reachability = probe_sample(&sample, &scope, cli.force, config.timeout_secs.get()).await;
    Ok(DryRunReport {
        service: input.service,
        target_summary: summarize_target(&input.source),
        targets,
        proxies,
        users,
        passwords,
        combinations,
        concurrency,
        request_interval_ms,
        estimated,
        reachability,
    })
}

/// Render a plain-text audit table for TTY operators.
#[must_use]
pub fn render_table(report: &DryRunReport) -> String {
    let service = format!("{:?}", report.service).to_ascii_lowercase();
    let reach = &report.reachability;
    format!(
        "Dry-run audit\n\
         -------------\n\
         Service:       {service}\n\
         Target:        {target}\n\
         Targets:       {targets}\n\
         Proxies:       {proxies}\n\
         Users:         {users}\n\
         Passwords:     {passwords}\n\
         Combinations:  {combinations}\n\
         Concurrency:   {concurrency}\n\
         Min. interval: {request_interval_ms} ms per target\n\
         Est. duration: {estimated:?}\n\
         Reachability:  {reach}\n\
         \n\
         No authentication attempts were sent.\n",
        target = report.target_summary,
        targets = report.targets,
        proxies = report.proxies,
        users = report.users,
        passwords = report.passwords,
        combinations = report.combinations,
        concurrency = report.concurrency,
        request_interval_ms = report.request_interval_ms,
        estimated = report.estimated,
    )
}

async fn count_proxies(cli: &Cli, config: &Config) -> Result<u64, DryRunError> {
    if let Some(path) = &cli.proxy_list {
        let pool = ProxyPool::load(path).await?;
        return Ok(u64::try_from(pool.len()).unwrap_or(u64::MAX));
    }
    if config.proxy.is_some() {
        return Ok(1);
    }
    Ok(0)
}

async fn count_combinations(
    cli: &Cli,
    input: &TargetInput,
) -> Result<(u64, u64, u64), DryRunError> {
    if let Some(combo) = &cli.combo_list {
        let source = InputSource::from_path(combo.clone());
        if matches!(source, InputSource::Stdin) {
            return Err(DryRunError::StdinNotSupported);
        }
        let mut stream = credentials(CredentialInput::Combos(source), &cli.mangling)?;
        let mut count = 0u64;
        while let Some(item) = stream.next().await {
            item?;
            count = count.saturating_add(1);
            tokio::task::coop::consume_budget().await;
        }
        return Ok((0, 0, count));
    }

    let rule_year = cli.rule_year;
    let mangling_rules = normalized_rules(&cli.mangling);
    let mangling_per_user = if mangling_rules.iter().any(Option::is_some) {
        let sample = cli
            .username
            .as_deref()
            .or(input.username.as_deref())
            .unwrap_or("user");
        let mut count = 0u64;
        let mut stream = mangled(sample, mangling_rules, rule_year);
        while stream.next().await.is_some() {
            count = count.saturating_add(1);
        }
        count
    } else {
        0
    };

    let users = if let Some(path) = &cli.user_list {
        count_source(InputSource::from_path(path.clone())).await?
    } else if let Some(user) = cli.username.as_ref().or(input.username.as_ref()) {
        count_source(InputSource::Single(user.clone())).await?
    } else {
        return Err(DryRunError::MissingCredentials);
    };

    let base_passwords = if let Some(path) = &cli.password_list {
        count_source(InputSource::from_path(path.clone())).await?
    } else if let Some(password) = &cli.password {
        count_source(InputSource::Single(password.clone())).await?
    } else if mangling_per_user == 0 {
        return Err(DryRunError::MissingCredentials);
    } else {
        0
    };

    let rule_set = cli
        .rules_file
        .as_deref()
        .map(crate::engine::mutations::RuleSet::from_file)
        .transpose()
        .map_err(|e| DryRunError::Wordlist(WordlistError::from(e)))?;
    let rule_multiplier = u64::try_from(
        rule_set
            .as_ref()
            .map_or(1, |rs| if rs.is_empty() { 1 } else { rs.len() }),
    )
    .unwrap_or(u64::MAX);

    let effective_base_passwords = base_passwords.saturating_mul(rule_multiplier);
    let passwords = effective_base_passwords.saturating_add(mangling_per_user);
    let combinations = users.saturating_mul(passwords);
    Ok((users, passwords, combinations))
}

async fn count_source(source: InputSource) -> Result<u64, DryRunError> {
    match source {
        InputSource::Single(_) => Ok(1),
        InputSource::Stdin => Err(DryRunError::StdinNotSupported),
        InputSource::File(path) => {
            if !tokio::fs::metadata(&path)
                .await
                .map_err(WordlistError::from)?
                .is_file()
            {
                return Err(WordlistError::NotRegularFile.into());
            }
            let file = tokio::fs::File::open(path)
                .await
                .map_err(WordlistError::from)?;
            let mut reader = Wordlist::new(BufReader::new(file));
            let mut count = 0u64;
            while reader.next_word().await?.is_some() {
                count += 1;
                tokio::task::coop::consume_budget().await;
            }
            Ok(count)
        }
    }
}

const MAX_PROBE_SAMPLES: u64 = 3;

async fn count_targets(
    input: TargetInput,
    scope: Scope,
) -> Result<(u64, Vec<Target>), DryRunError> {
    let mut stream = expand(input, scope);
    let mut count = 0u64;
    let mut sample = Vec::new();
    while let Some(item) = stream.next().await {
        let target = item?;
        if u64::try_from(sample.len()).unwrap_or(u64::MAX) < MAX_PROBE_SAMPLES {
            sample.push(target);
        }
        count += 1;
        // CIDR streams can stay ready indefinitely without performing any I/O.
        tokio::task::coop::consume_budget().await;
    }
    Ok((count, sample))
}

impl fmt::Display for Reachability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reachable => f.write_str("reachable"),
            Self::Unreachable(reason) => write!(f, "unreachable ({reason})"),
            Self::Skipped(reason) => write!(f, "skipped ({reason})"),
            Self::Sampled {
                probed,
                reachable,
                unreachable,
                skipped,
            } => {
                write!(
                    f,
                    "sampled {probed} (up={reachable}, down={unreachable}, skipped={skipped})"
                )
            }
        }
    }
}

#[derive(Debug, Error)]
enum ProbeError {
    #[error("{0}")]
    Unreachable(String),
    #[error("{0}")]
    Skipped(&'static str),
}

async fn probe_sample(
    sample: &[Target],
    scope: &Scope,
    force: bool,
    timeout_secs: u64,
) -> Reachability {
    if sample.is_empty() {
        return Reachability::Skipped("no targets after exclusions");
    }
    if sample.len() == 1 {
        return match probe_tcp(&sample[0], scope, force, timeout_secs).await {
            Ok(()) => Reachability::Reachable,
            Err(ProbeError::Unreachable(reason)) => Reachability::Unreachable(reason),
            Err(ProbeError::Skipped(reason)) => Reachability::Skipped(reason),
        };
    }
    let mut reachable = 0u64;
    let mut unreachable = 0u64;
    let mut skipped = 0u64;
    for target in sample {
        match probe_tcp(target, scope, force, timeout_secs).await {
            Ok(()) => reachable += 1,
            Err(ProbeError::Unreachable(_)) => unreachable += 1,
            Err(ProbeError::Skipped(_)) => skipped += 1,
        }
    }
    Reachability::Sampled {
        probed: reachable + unreachable,
        reachable,
        unreachable,
        skipped,
    }
}

fn estimate_duration(
    candidates: u64,
    targets: u64,
    concurrency: u64,
    interval_ms: u64,
) -> Duration {
    if targets == 0 {
        return Duration::ZERO;
    }
    let combinations = candidates.saturating_mul(targets);
    let workers = concurrency.max(1);
    let millis = combinations.saturating_mul(250) / workers;
    let pacing_millis = candidates.saturating_sub(1).saturating_mul(interval_ms);
    Duration::from_millis(millis.max(pacing_millis))
}

fn summarize_target(source: &TargetSource) -> String {
    match source {
        TargetSource::Single(target) => target.to_string(),
        TargetSource::Network(net) => net.to_string(),
        TargetSource::File(path) => format!("file:{}", path.display()),
    }
}

async fn probe_tcp(
    target: &Target,
    scope: &Scope,
    force: bool,
    timeout_secs: u64,
) -> Result<(), ProbeError> {
    let probe = async {
        let addresses = lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|error| ProbeError::Unreachable(error.to_string()))?;
        probe_addresses(addresses, scope, force, |address| async move {
            TcpStream::connect(address).await.map(|_stream| ())
        })
        .await
    };
    timeout(Duration::from_secs(timeout_secs.max(1)), probe)
        .await
        .map_err(|_| ProbeError::Unreachable("resolution or connection timed out".into()))?
}

// The connector accepts only a checked socket address, so it cannot resolve the hostname again.
async fn probe_addresses<F: Future<Output = std::io::Result<()>>>(
    addresses: impl Iterator<Item = SocketAddr>,
    scope: &Scope,
    force: bool,
    mut connect: impl FnMut(SocketAddr) -> F,
) -> Result<(), ProbeError> {
    let mut last_error = None;
    let mut blocked = false;
    for address in addresses {
        let decision = scope.classify_ip(address.ip());
        if decision != ScopeDecision::Local
            && !(force && decision == ScopeDecision::ConfirmationRequired)
        {
            blocked = true;
            continue;
        }
        match connect(address).await {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(if let Some(error) = last_error {
        ProbeError::Unreachable(error.to_string())
    } else if blocked {
        ProbeError::Skipped("no permitted addresses: exclusions or non-local scope without --force")
    } else {
        ProbeError::Unreachable("name resolved to no addresses".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;
    use std::num::{NonZeroU64, NonZeroUsize};

    fn config() -> Config {
        Config {
            concurrency: NonZeroUsize::new(16).unwrap(),
            timeout_secs: NonZeroU64::new(1).unwrap(),
            request_interval_ms: NonZeroU64::new(1000).unwrap(),
            user_agent: "betterh-test".into(),
            proxy: None,
            wordlist_paths: Vec::new(),
        }
    }

    fn target(address: SocketAddr) -> Target {
        Target {
            host: address.ip().to_string(),
            port: address.port(),
            ssl: false,
            path: None,
            ip: Some(address.ip()),
        }
    }

    #[tokio::test]
    async fn pre_cancelled_audit_does_not_open_missing_input_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.txt");
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.1",
            "-L",
            missing.to_str().unwrap(),
            "-p",
            "unused",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            audit_with_cancellation(&cli, &config(), &input, &cancellation).await,
            Err(DryRunError::Cancelled)
        ));
    }

    #[tokio::test]
    async fn huge_cidr_audit_yields_so_another_future_can_cancel_it() {
        let cli = Cli::parse_from(["betterh", "ssh", "::/0", "-u", "test", "-p", "unused"]);
        let input = cli.validate().unwrap().unwrap();
        let config = config();
        let cancellation = CancellationToken::new();
        let cancel = async {
            tokio::task::yield_now().await;
            cancellation.cancel();
        };
        let ((), result) = timeout(Duration::from_secs(1), async {
            tokio::join!(
                cancel,
                audit_with_cancellation(&cli, &config, &input, &cancellation)
            )
        })
        .await
        .unwrap();
        assert!(matches!(result, Err(DryRunError::Cancelled)));
    }

    #[tokio::test]
    async fn uncancelled_audit_preserves_results_and_input_errors() {
        let mut cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.1",
            "-u",
            "test",
            "-p",
            "unused",
            "--exclude",
            "127.0.0.1",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let cancellation = CancellationToken::new();
        let report = audit_with_cancellation(&cli, &config(), &input, &cancellation)
            .await
            .unwrap();
        assert_eq!(report.targets, 0);
        assert_eq!(report.combinations, 0);

        let dir = tempfile::tempdir().unwrap();
        cli.password = None;
        cli.password_list = Some(dir.path().join("missing.txt"));
        assert!(matches!(
            audit_with_cancellation(&cli, &config(), &input, &cancellation).await,
            Err(DryRunError::Wordlist(_))
        ));
    }

    #[tokio::test]
    async fn resolved_addresses_are_checked_and_force_never_overrides_exclusions() {
        let scope = Scope::new(vec!["127.0.0.2/32".parse().unwrap()]);
        let addresses: Vec<SocketAddr> = [
            "127.0.0.2:22",
            "[::ffff:127.0.0.2]:22",
            "198.51.100.1:22",
            "127.0.0.1:22",
        ]
        .iter()
        .map(|address| address.parse().unwrap())
        .collect();
        for force in [false, true] {
            let mut attempted = Vec::new();
            let result = probe_addresses(addresses.iter().copied(), &scope, force, |address| {
                attempted.push(address);
                std::future::ready(Err(std::io::ErrorKind::ConnectionRefused.into()))
            })
            .await;
            assert!(matches!(result, Err(ProbeError::Unreachable(_))));
            let expected = if force {
                &addresses[2..]
            } else {
                &addresses[3..]
            };
            assert_eq!(attempted, expected);
        }
    }

    #[tokio::test]
    async fn all_blocked_addresses_are_skipped_without_calling_the_connector() {
        let scope = Scope::new(vec!["127.0.0.1/32".parse().unwrap()]);
        let addresses = [
            "127.0.0.1:22".parse().unwrap(),
            "198.51.100.1:22".parse().unwrap(),
        ];
        let mut calls = 0;
        let result = probe_addresses(addresses.into_iter(), &scope, false, |_| {
            calls += 1;
            std::future::ready(Ok(()))
        })
        .await;
        assert!(matches!(result, Err(ProbeError::Skipped(_))));
        assert_eq!(calls, 0);
    }

    #[tokio::test]
    async fn local_probe_connects_without_sending_application_bytes() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target(listener.local_addr().unwrap());
        let scope = Scope::default();
        let receive = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        };
        let (result, ()) = timeout(Duration::from_secs(1), async {
            tokio::join!(probe_tcp(&target, &scope, false, 1), receive)
        })
        .await
        .unwrap();
        result.unwrap();
    }

    #[tokio::test]
    async fn hostname_resolving_to_excluded_loopbacks_is_skipped_even_when_forced() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut target = target(listener.local_addr().unwrap());
        target.host = "localhost".into();
        let scope = Scope::new(vec![
            "127.0.0.0/8".parse().unwrap(),
            "::1/128".parse().unwrap(),
        ]);
        assert!(matches!(
            probe_tcp(&target, &scope, true, 1).await,
            Err(ProbeError::Skipped(_))
        ));
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn sample_counts_skips_separately_from_failed_probes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sample = [
            target(listener.local_addr().unwrap()),
            target("198.51.100.1:22".parse().unwrap()),
        ];
        let result = probe_sample(&sample, &Scope::default(), false, 1).await;
        assert_eq!(
            result,
            Reachability::Sampled {
                probed: 1,
                reachable: 1,
                unreachable: 0,
                skipped: 1
            }
        );
        assert_eq!(result.to_string(), "sampled 1 (up=1, down=0, skipped=1)");
    }

    #[tokio::test]
    async fn invalid_proxy_input_fails_before_any_reachability_probe() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let proxies = dir.path().join("proxies.txt");
        tokio::fs::write(&proxies, "invalid proxy\n").await.unwrap();
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            &listener.local_addr().unwrap().to_string(),
            "-u",
            "test",
            "-p",
            "unused",
            "--dry-run",
            "--proxy-list",
            proxies.to_str().unwrap(),
        ]);
        let input = cli.validate().unwrap().unwrap();
        assert!(matches!(
            audit(&cli, &config(), &input).await,
            Err(DryRunError::Proxy(_))
        ));
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn empty_resolution_and_permitted_connection_failures_are_unreachable() {
        let scope = Scope::default();
        let empty = probe_addresses(std::iter::empty(), &scope, false, |_| {
            std::future::ready(Ok(()))
        })
        .await;
        assert!(matches!(empty, Err(ProbeError::Unreachable(_))));
        let addresses = [
            "127.0.0.1:22".parse().unwrap(),
            "198.51.100.1:22".parse().unwrap(),
        ];
        let failed = probe_addresses(addresses.into_iter(), &scope, false, |_| {
            std::future::ready(Err(std::io::ErrorKind::ConnectionRefused.into()))
        })
        .await;
        assert!(matches!(failed, Err(ProbeError::Unreachable(_))));
    }

    #[tokio::test]
    async fn counts_cartesian_product_and_mangling() {
        let dir = tempfile::tempdir().unwrap();
        let users = dir.path().join("users.txt");
        let passwords = dir.path().join("pass.txt");
        std::fs::write(&users, "alice\nbob\n").unwrap();
        std::fs::write(&passwords, "one\ntwo\nthree\n").unwrap();

        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.1",
            "-L",
            users.to_str().unwrap(),
            "-P",
            passwords.to_str().unwrap(),
            "-e",
            "n,s",
            "--dry-run",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let report = audit(&cli, &config(), &input).await.unwrap();
        assert_eq!(report.targets, 1);
        assert_eq!(report.proxies, 0);
        assert_eq!(report.users, 2);
        assert_eq!(report.passwords, 5);
        assert_eq!(report.combinations, 10);
        assert!(render_table(&report).contains("Targets:       1"));
    }

    #[tokio::test]
    async fn product_counts_match_generated_candidates_with_repeated_rules() {
        use futures::TryStreamExt;

        let dir = tempfile::tempdir().unwrap();
        let users = dir.path().join("users.txt");
        let passwords = dir.path().join("passwords.txt");
        tokio::fs::write(&users, "alice\nbob\n").await.unwrap();
        tokio::fs::write(&passwords, "one\n\ntwo\n").await.unwrap();
        for supplied_passwords in [false, true] {
            let mut args = vec![
                "betterh",
                "ssh",
                "127.0.0.1",
                "-L",
                users.to_str().unwrap(),
                "-e",
                "n,n,s,r,s",
            ];
            if supplied_passwords {
                args.extend(["-P", passwords.to_str().unwrap()]);
            }
            let cli = Cli::parse_from(args);
            let input = cli.validate().unwrap().unwrap();
            let counts = count_combinations(&cli, &input).await.unwrap();
            let generated = credentials(
                CredentialInput::Product {
                    users: InputSource::from_path(users.clone()),
                    passwords: supplied_passwords
                        .then(|| InputSource::from_path(passwords.clone())),
                },
                &cli.mangling,
            )
            .unwrap()
            .try_fold(0u64, |count, _| std::future::ready(Ok(count + 1)))
            .await
            .unwrap();
            assert_eq!(counts.2, generated);
            assert_eq!(
                counts,
                if supplied_passwords {
                    (2, 5, 10)
                } else {
                    (2, 3, 6)
                }
            );
        }
    }

    #[tokio::test]
    async fn combo_audit_retains_duplicate_rows_and_empty_passwords_but_collapses_rules() {
        let dir = tempfile::tempdir().unwrap();
        let combos = dir.path().join("combos.txt");
        tokio::fs::write(&combos, "alice:one:two\nbob:\n alice:one:two \n")
            .await
            .unwrap();
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.1",
            "-C",
            combos.to_str().unwrap(),
            "-e",
            "n,n,s,s",
        ]);
        let input = cli.validate().unwrap().unwrap();
        assert_eq!(count_combinations(&cli, &input).await.unwrap(), (0, 0, 9));
    }

    #[tokio::test]
    async fn invalid_combo_rows_fail_before_probes_without_echoing_contents() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let combos = dir.path().join("combos.txt");
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            &listener.local_addr().unwrap().to_string(),
            "-C",
            combos.to_str().unwrap(),
            "--dry-run",
        ]);
        let input = cli.validate().unwrap().unwrap();
        for invalid in [
            "sensitive-no-colon",
            ":sensitive-password",
            "  :sensitive-password",
        ] {
            tokio::fs::write(&combos, format!("alice:one\n{invalid}\nbob:two\n"))
                .await
                .unwrap();
            let error = audit(&cli, &config(), &input).await.unwrap_err();
            assert!(matches!(
                &error,
                DryRunError::Wordlist(WordlistError::InvalidCombo)
            ));
            assert!(!error.to_string().contains("sensitive"));
        }
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn combo_stdin_is_rejected_without_reading_it() {
        let cli = Cli::parse_from(["betterh", "ssh", "127.0.0.1", "-C", "-"]);
        let input = cli.validate().unwrap().unwrap();
        assert!(matches!(
            count_combinations(&cli, &input).await,
            Err(DryRunError::StdinNotSupported)
        ));
    }

    #[tokio::test]
    async fn multiplies_combinations_by_expanded_cidr_targets() {
        let dir = tempfile::tempdir().unwrap();
        let users = dir.path().join("u.txt");
        let passwords = dir.path().join("p.txt");
        std::fs::write(&users, "alice\n").unwrap();
        std::fs::write(&passwords, "secret\n").unwrap();
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.3/30",
            "-L",
            users.to_str().unwrap(),
            "-P",
            passwords.to_str().unwrap(),
            "--dry-run",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let report = audit(&cli, &config(), &input).await.unwrap();
        // Small /30 keeps two usable hosts (see targets expander tests).
        assert_eq!(report.targets, 2);
        assert_eq!(report.combinations, 2);
    }

    #[tokio::test]
    async fn combo_list_counts_rows_plus_mangling() {
        let dir = tempfile::tempdir().unwrap();
        let combos = dir.path().join("c.txt");
        std::fs::write(&combos, "a:1\nb:2\n\nc:3\n").unwrap();
        let cli = Cli::parse_from([
            "betterh",
            "ftp",
            "127.0.0.1",
            "-C",
            combos.to_str().unwrap(),
            "-e",
            "n",
            "--dry-run",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let report = audit(&cli, &config(), &input).await.unwrap();
        assert_eq!(report.combinations, 6);
    }

    #[tokio::test]
    async fn rejects_stdin_wordlists() {
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.1",
            "-u",
            "admin",
            "-P",
            "-",
            "--dry-run",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let err = audit(&cli, &config(), &input).await.unwrap_err();
        assert!(matches!(err, DryRunError::StdinNotSupported));
    }

    #[tokio::test]
    async fn reports_proxy_list_size() {
        let dir = tempfile::tempdir().unwrap();
        let users = dir.path().join("u.txt");
        let passwords = dir.path().join("p.txt");
        let proxies = dir.path().join("proxies.txt");
        std::fs::write(&users, "alice\n").unwrap();
        std::fs::write(&passwords, "secret\n").unwrap();
        std::fs::write(&proxies, "http://127.0.0.1:8080\nsocks5://127.0.0.1:9050\n").unwrap();
        let cli = Cli::parse_from([
            "betterh",
            "ssh",
            "127.0.0.1",
            "-L",
            users.to_str().unwrap(),
            "-P",
            passwords.to_str().unwrap(),
            "--proxy-list",
            proxies.to_str().unwrap(),
            "--dry-run",
        ]);
        let input = cli.validate().unwrap().unwrap();
        let report = audit(&cli, &config(), &input).await.unwrap();
        assert_eq!(report.proxies, 2);
        assert!(render_table(&report).contains("Proxies:       2"));
    }

    #[test]
    fn estimate_scales_with_combinations() {
        assert!(estimate_duration(160, 1, 16, 1000) >= Duration::from_secs(159));
    }

    #[test]
    fn concurrency_cannot_reduce_the_per_target_spacing_estimate() {
        for concurrency in [1, 16, u64::MAX] {
            assert_eq!(
                estimate_duration(4, 1, concurrency, 2000),
                Duration::from_secs(6)
            );
        }
        assert_eq!(estimate_duration(4, 8, 16, 2000), Duration::from_secs(6));
    }

    #[test]
    fn estimate_handles_empty_scopes_and_saturates_large_counts() {
        assert_eq!(estimate_duration(100, 0, 16, 1000), Duration::ZERO);
        assert_eq!(estimate_duration(0, 5, 16, 1000), Duration::ZERO);
        assert_eq!(estimate_duration(1, 1, 1, 1000), Duration::from_millis(250));
        assert_eq!(
            estimate_duration(u64::MAX, 2, 16, u64::MAX),
            Duration::from_millis(u64::MAX)
        );
    }
}
