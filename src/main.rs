// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

use anyhow::{Context, Result, bail};
use betterh::cli::{Cli, Command};
use betterh::engine::{DryRunError, audit_with_cancellation, render_table, run_attack};
use betterh::report::{ReportEvent, ReporterMode, SessionReporter};
use betterh::ui::{Diagnostic, generate_completions, generate_manpage, run_interactive};
use clap::{CommandFactory, Parser};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args_os().len() == 1 {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }

    let cli = Cli::parse();
    let target = cli.validate().unwrap_or_else(|error| error.exit());

    match cli.command {
        Some(Command::Wizard) => return run_wizard(),
        Some(Command::Completions { shell }) => {
            let mut command = Cli::command();
            generate_completions(shell, &mut command, &mut std::io::stdout())?;
            return Ok(());
        }
        Some(Command::Man) => {
            generate_manpage(&Cli::command(), &mut std::io::stdout())?;
            return Ok(());
        }
        #[cfg(feature = "mcp")]
        Some(Command::Mcp { stdio }) => {
            if !stdio {
                bail!("Only the stdio MCP transport is supported; pass --stdio");
            }
            return run_mcp_server().await;
        }
        None if cli.interactive => return run_wizard(),
        None => {}
    }

    let config = match cli.load_config().await {
        Ok(config) => config,
        Err(error) => {
            eprint!("{}", Diagnostic::from_config_error(&error));
            std::process::exit(2);
        }
    };

    if cli.dry_run {
        let Some(input) = target else {
            bail!("--dry-run requires a target invocation");
        };
        let cancellation = CancellationToken::new();
        let result = tokio::select! {
            biased;
            signal = tokio::signal::ctrl_c() => {
                signal.context("Cannot listen for Ctrl+C")?;
                cancellation.cancel();
                Err(DryRunError::Cancelled)
            }
            result = audit_with_cancellation(&cli, &config, &input, &cancellation) => result,
        };
        let report = match result {
            Err(DryRunError::Cancelled) => {
                if !cli.quiet {
                    eprintln!("Dry-run cancelled.");
                }
                std::process::exit(130);
            }
            result => result.context("Dry-run audit failed")?,
        };

        // Dry-run prints a summary table by default; JSON only when --format requests it.
        let mode = match cli.format {
            Some(betterh::cli::OutputFormat::Jsonl) => ReporterMode::Jsonl,
            Some(betterh::cli::OutputFormat::Json) => ReporterMode::Json,
            _ => ReporterMode::Text,
        };
        if cli.output.is_some() || matches!(mode, ReporterMode::Jsonl | ReporterMode::Json) {
            // Dry-run uses the summary table, so never start a live dashboard.
            let mut session = SessionReporter::open(
                mode,
                true,
                cli.output.as_deref(),
                Some(report.combinations),
            )?;
            session.emit(&ReportEvent::DryRun {
                service: format!("{:?}", report.service).to_ascii_lowercase(),
                target: report.target_summary.clone(),
                targets: report.targets,
                proxies: report.proxies,
                users: report.users,
                passwords: report.passwords,
                combinations: report.combinations,
                concurrency: report.concurrency,
                estimated_ms: report.estimated.as_millis(),
                request_interval_ms: report.request_interval_ms,
                reachability: report.reachability.to_string(),
            })?;
            session.finish();
        }
        if matches!(mode, ReporterMode::Text) && !cli.quiet {
            print!("{}", render_table(&report));
        }
        return Ok(());
    }

    let Some(input) = target else {
        bail!("Provide a target URL or a service and target; see --help");
    };
    let findings = run_attack(&cli, &config, &input)
        .await
        .context("Attack execution failed")?;
    if !cli.quiet {
        eprintln!("Finished with {} finding(s)", findings.len());
    }
    Ok(())
}

fn run_wizard() -> Result<()> {
    let plan = run_interactive().context("Interactive wizard failed")?;
    eprintln!("{}", plan.ready_message());
    Ok(())
}

#[cfg(feature = "mcp")]
async fn run_mcp_server() -> Result<()> {
    use betterh::mcp::{McpError, run_stdio_server};

    let cancel = CancellationToken::new();
    let ctrl = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ctrl.cancel();
    });

    match run_stdio_server(&cancel).await {
        Ok(()) => Ok(()),
        Err(McpError::Cancelled) => {
            eprintln!("MCP server cancelled.");
            std::process::exit(130);
        }
        Err(err) => Err(err).context("MCP server failed"),
    }
}
