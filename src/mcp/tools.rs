// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! MCP tool schemas and dispatch into Betterh engine modules.

use std::{net::IpAddr, path::PathBuf};

use clap::Parser;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::cli::Cli;
use crate::engine::Finding;
use crate::engine::checkpoint::{self, Checkpoint};
use crate::engine::dryrun::{self, DryRunReport, Reachability};
use crate::engine::runner;
use crate::engine::scope::{Scope, ScopeDecision};
use crate::protocols::Target;

/// Lightweight MCP-side session snapshot for `session_status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ToolRuntime {
    /// Last tool name successfully or unsuccessfully invoked.
    pub last_tool: Option<String>,
    /// Whether the last tool completed without `isError`.
    pub last_ok: bool,
    /// Findings recorded by the last successful `audit_execute`.
    pub findings: u64,
    /// High-level phase label.
    pub phase: SessionPhase,
}

/// Coarse MCP session activity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionPhase {
    /// No audit tool is active.
    #[default]
    Idle,
    /// Last activity was a dry-run.
    DryRun,
    /// Last activity was a live execute.
    Execute,
}

/// Tool invocation failures returned as MCP `isError` results (not JSON-RPC errors).
#[derive(Debug, Error)]
pub enum ToolError {
    /// Unknown tool name.
    #[error("unknown tool: {0}")]
    Unknown(String),
    /// Arguments failed schema or clap validation.
    #[error("invalid tool arguments: {0}")]
    InvalidArgs(String),
    /// Operator confirmation required for live execution.
    #[error("audit_execute requires confirm=true")]
    ConfirmRequired,
    /// Dry-run engine failure.
    #[error("dry-run failed: {0}")]
    DryRun(String),
    /// Live attack engine failure.
    #[error("audit execute failed: {0}")]
    Execute(String),
    /// Scope classification failure.
    #[error("scope validation failed: {0}")]
    Scope(String),
    /// Checkpoint load failure.
    #[error("session status failed: {0}")]
    Session(String),
    /// Cooperative cancellation.
    #[error("tool cancelled")]
    Cancelled,
}

/// One MCP tool descriptor for `tools/list`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    /// Tool name.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// JSON Schema for arguments.
    pub input_schema: Value,
}

/// MCP `tools/call` result envelope.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    /// Textual content blocks (MCP content array).
    pub content: Vec<ToolContent>,
    /// True when the tool failed.
    pub is_error: bool,
}

/// MCP content block.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolContent {
    /// Content type (`text`).
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// UTF-8 payload.
    pub text: String,
}

impl ToolResult {
    /// Encode a structured JSON value as a successful text content block.
    #[must_use]
    pub fn ok_json(value: &Value) -> Self {
        Self {
            content: vec![ToolContent {
                kind: "text",
                text: value.to_string(),
            }],
            is_error: false,
        }
    }

    /// Encode an error message as an `isError` tool result.
    #[must_use]
    pub fn err_message(message: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent {
                kind: "text",
                text: message.into(),
            }],
            is_error: true,
        }
    }
}

/// Static catalog of Betterh MCP tools.
#[must_use]
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "audit_dryrun",
            description: "Validate targets and options, count credential combinations, estimate duration, and optionally TCP-probe reachability without sending authentication attempts.",
            input_schema: audit_args_schema(false),
        },
        ToolDefinition {
            name: "audit_execute",
            description: "Run a controlled authentication audit or password spray with rate limiting and scope guardrails. Requires confirm=true.",
            input_schema: audit_args_schema(true),
        },
        ToolDefinition {
            name: "validate_scope",
            description: "Classify an IP or CIDR against exclusion lists and report whether confirmation is required for public targets.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "IPv4/IPv6 address or hostname to classify"
                    },
                    "exclude": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "CIDR or IP exclusions"
                    },
                    "exclude_file": {
                        "type": "string",
                        "description": "Path to an exclusion file"
                    }
                },
                "required": ["address"],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "list_protocols",
            description: "Return supported protocols, default ports, and compiled Cargo feature states.",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "session_status",
            description: "Inspect MCP runtime status and optionally load a checkpoint file.",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "checkpoint": {
                        "type": "string",
                        "description": "Optional path to a .betterh-session-*.json checkpoint"
                    }
                },
                "additionalProperties": false
            }),
        },
    ]
}

fn audit_args_schema(require_confirm: bool) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert(
        "service".into(),
        json!({
            "type": "string",
            "description": "Service name (ssh, ftp, http, …) when not using url"
        }),
    );
    properties.insert(
        "target".into(),
        json!({
            "type": "string",
            "description": "Host, host:port, or CIDR"
        }),
    );
    properties.insert(
        "url".into(),
        json!({
            "type": "string",
            "description": "Full target URL (alternative to service+target)"
        }),
    );
    properties.insert("username".into(), json!({ "type": "string" }));
    properties.insert("password".into(), json!({ "type": "string" }));
    properties.insert("user_list".into(), json!({ "type": "string" }));
    properties.insert("password_list".into(), json!({ "type": "string" }));
    properties.insert("combo_list".into(), json!({ "type": "string" }));
    properties.insert(
        "exclude".into(),
        json!({
            "type": "array",
            "items": { "type": "string" }
        }),
    );
    properties.insert("exclude_file".into(), json!({ "type": "string" }));
    properties.insert("force".into(), json!({ "type": "boolean" }));
    properties.insert(
        "mode".into(),
        json!({
            "type": "string",
            "enum": ["brute-force", "spray"]
        }),
    );
    properties.insert(
        "concurrency".into(),
        json!({ "type": "integer", "minimum": 1 }),
    );
    properties.insert(
        "timeout_secs".into(),
        json!({ "type": "integer", "minimum": 1 }),
    );
    properties.insert(
        "request_interval_ms".into(),
        json!({ "type": "integer", "minimum": 1 }),
    );
    properties.insert("quiet".into(), json!({ "type": "boolean" }));
    if require_confirm {
        properties.insert(
            "confirm".into(),
            json!({
                "type": "boolean",
                "description": "Must be true to authorize live authentication attempts"
            }),
        );
    }
    let required = if require_confirm {
        vec!["confirm"]
    } else {
        Vec::<&str>::new()
    };
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

/// Arguments shared by dry-run and execute tools.
#[derive(Debug, Clone, Deserialize)]
struct AuditArgs {
    service: Option<String>,
    target: Option<String>,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    user_list: Option<String>,
    password_list: Option<String>,
    combo_list: Option<String>,
    #[serde(default)]
    exclude: Vec<String>,
    exclude_file: Option<String>,
    #[serde(default)]
    force: bool,
    mode: Option<String>,
    concurrency: Option<u64>,
    timeout_secs: Option<u64>,
    request_interval_ms: Option<u64>,
    #[serde(default)]
    quiet: bool,
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ValidateScopeArgs {
    address: String,
    #[serde(default)]
    exclude: Vec<String>,
    exclude_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct SessionStatusArgs {
    checkpoint: Option<String>,
}

/// Dispatch a named tool with JSON arguments.
///
/// # Errors
/// Returns [`ToolError`] for unknown tools, bad arguments, cancellation, or engine failures.
pub async fn call_tool(
    name: &str,
    arguments: Value,
    runtime: &mut ToolRuntime,
    cancel: &CancellationToken,
) -> Result<ToolResult, ToolError> {
    if cancel.is_cancelled() {
        return Err(ToolError::Cancelled);
    }
    // Snapshot session_status against the prior runtime, then record this invocation.
    let result = match name {
        "audit_dryrun" => call_audit_dryrun(arguments, runtime, cancel).await,
        "audit_execute" => call_audit_execute(arguments, runtime, cancel).await,
        "validate_scope" => call_validate_scope(arguments).await,
        "list_protocols" => Ok(ToolResult::ok_json(&list_protocols_payload())),
        "session_status" => call_session_status(arguments, runtime).await,
        other => Err(ToolError::Unknown(other.to_owned())),
    };
    runtime.last_tool = Some(name.to_owned());
    runtime.last_ok = result.as_ref().is_ok_and(|r| !r.is_error);
    result
}

async fn call_audit_dryrun(
    arguments: Value,
    runtime: &mut ToolRuntime,
    cancel: &CancellationToken,
) -> Result<ToolResult, ToolError> {
    let args: AuditArgs =
        serde_json::from_value(arguments).map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    let (cli, input) = build_cli(&args)?;
    let config = cli
        .load_config()
        .await
        .map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    runtime.phase = SessionPhase::DryRun;
    let report = dryrun::audit_with_cancellation(&cli, &config, &input, cancel)
        .await
        .map_err(|err| {
            if matches!(err, dryrun::DryRunError::Cancelled) {
                ToolError::Cancelled
            } else {
                ToolError::DryRun(err.to_string())
            }
        })?;
    Ok(ToolResult::ok_json(&dry_run_to_json(&report)))
}

async fn call_audit_execute(
    arguments: Value,
    runtime: &mut ToolRuntime,
    cancel: &CancellationToken,
) -> Result<ToolResult, ToolError> {
    let args: AuditArgs =
        serde_json::from_value(arguments).map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    if !args.confirm {
        return Err(ToolError::ConfirmRequired);
    }
    if cancel.is_cancelled() {
        return Err(ToolError::Cancelled);
    }
    let (cli, input) = build_cli(&args)?;
    let config = cli
        .load_config()
        .await
        .map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    runtime.phase = SessionPhase::Execute;
    let findings = runner::run_attack(&cli, &config, &input)
        .await
        .map_err(|err| {
            if matches!(err, runner::RunError::Cancelled) {
                ToolError::Cancelled
            } else {
                ToolError::Execute(err.to_string())
            }
        })?;
    runtime.findings = u64::try_from(findings.len()).unwrap_or(u64::MAX);
    Ok(ToolResult::ok_json(&findings_to_json(&findings)))
}

async fn call_validate_scope(arguments: Value) -> Result<ToolResult, ToolError> {
    let args: ValidateScopeArgs =
        serde_json::from_value(arguments).map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    let mut exclusions = Vec::new();
    for entry in &args.exclude {
        let network = entry
            .parse::<IpNet>()
            .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| ToolError::InvalidArgs(format!("invalid exclude entry: {entry}")))?;
        exclusions.push(network);
    }
    let scope = Scope::load(
        exclusions,
        args.exclude_file.as_ref().map(PathBuf::from).as_deref(),
    )
    .await
    .map_err(|err| ToolError::Scope(err.to_string()))?;

    let decision = if let Ok(ip) = args.address.parse::<IpAddr>() {
        scope.classify_ip(ip)
    } else if let Ok(network) = args.address.parse::<IpNet>() {
        // Classify the network address itself for a coarse CIDR check.
        scope.classify_ip(network.addr())
    } else {
        let target = Target {
            host: args.address.clone(),
            port: 0,
            ssl: false,
            path: None,
            ip: None,
        };
        scope.classify(&target)
    };

    Ok(ToolResult::ok_json(&json!({
        "address": args.address,
        "decision": scope_decision_name(decision),
        "requires_confirmation": matches!(decision, ScopeDecision::ConfirmationRequired),
        "excluded": matches!(decision, ScopeDecision::Excluded),
    })))
}

async fn call_session_status(
    arguments: Value,
    runtime: &ToolRuntime,
) -> Result<ToolResult, ToolError> {
    let args: SessionStatusArgs =
        serde_json::from_value(arguments).map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    let checkpoint = if let Some(path) = args.checkpoint {
        let loaded = checkpoint::load(path.as_ref())
            .await
            .map_err(|err| ToolError::Session(err.to_string()))?;
        Some(checkpoint_to_json(&loaded))
    } else {
        None
    };
    Ok(ToolResult::ok_json(&json!({
        "phase": runtime.phase,
        "last_tool": runtime.last_tool,
        "last_ok": runtime.last_ok,
        "findings": runtime.findings,
        "checkpoint": checkpoint,
    })))
}

fn build_cli(args: &AuditArgs) -> Result<(Cli, crate::cli::TargetInput), ToolError> {
    let mut cli_argv = vec!["betterh".to_owned()];
    if let Some(url) = &args.url {
        cli_argv.push(url.clone());
    } else {
        let service = args
            .service
            .as_deref()
            .ok_or_else(|| ToolError::InvalidArgs("service or url is required".into()))?;
        let target = args.target.as_deref().ok_or_else(|| {
            ToolError::InvalidArgs("target is required when url is omitted".into())
        })?;
        cli_argv.push(service.to_owned());
        cli_argv.push(target.to_owned());
    }
    if let Some(user) = &args.username {
        cli_argv.push("-u".into());
        cli_argv.push(user.clone());
    }
    if let Some(password) = &args.password {
        cli_argv.push("-p".into());
        cli_argv.push(password.clone());
    }
    if let Some(path) = &args.user_list {
        cli_argv.push("-L".into());
        cli_argv.push(path.clone());
    }
    if let Some(path) = &args.password_list {
        cli_argv.push("-P".into());
        cli_argv.push(path.clone());
    }
    if let Some(path) = &args.combo_list {
        cli_argv.push("-C".into());
        cli_argv.push(path.clone());
    }
    for entry in &args.exclude {
        cli_argv.push("--exclude".into());
        cli_argv.push(entry.clone());
    }
    if let Some(path) = &args.exclude_file {
        cli_argv.push("--exclude-file".into());
        cli_argv.push(path.clone());
    }
    if args.force {
        cli_argv.push("--force".into());
    }
    if let Some(mode) = &args.mode {
        cli_argv.push("--mode".into());
        cli_argv.push(mode.clone());
    }
    if let Some(value) = args.concurrency {
        cli_argv.push(format!("--concurrency={value}"));
    }
    if let Some(value) = args.timeout_secs {
        cli_argv.push(format!("--timeout-secs={value}"));
    }
    if let Some(value) = args.request_interval_ms {
        cli_argv.push(format!("--request-interval-ms={value}"));
    }
    if args.quiet {
        cli_argv.push("--quiet".into());
    }

    let cli =
        Cli::try_parse_from(&cli_argv).map_err(|err| ToolError::InvalidArgs(err.to_string()))?;
    let input = cli
        .validate()
        .map_err(|err| ToolError::InvalidArgs(err.to_string()))?
        .ok_or_else(|| ToolError::InvalidArgs("target invocation required".into()))?;
    Ok((cli, input))
}

fn dry_run_to_json(report: &DryRunReport) -> Value {
    json!({
        "service": format!("{:?}", report.service).to_ascii_lowercase(),
        "target": report.target_summary,
        "targets": report.targets,
        "proxies": report.proxies,
        "users": report.users,
        "passwords": report.passwords,
        "combinations": report.combinations,
        "concurrency": report.concurrency,
        "request_interval_ms": report.request_interval_ms,
        "estimated_ms": report.estimated.as_millis(),
        "reachability": reachability_to_json(&report.reachability),
    })
}

fn reachability_to_json(reachability: &Reachability) -> Value {
    match reachability {
        Reachability::Reachable => json!({ "status": "reachable" }),
        Reachability::Unreachable(reason) => json!({ "status": "unreachable", "reason": reason }),
        Reachability::Skipped(reason) => json!({ "status": "skipped", "reason": reason }),
        Reachability::Sampled {
            probed,
            reachable,
            unreachable,
            skipped,
        } => json!({
            "status": "sampled",
            "probed": probed,
            "reachable": reachable,
            "unreachable": unreachable,
            "skipped": skipped,
        }),
    }
}

fn findings_to_json(findings: &[Finding]) -> Value {
    json!({
        "findings": findings.len(),
        "targets": findings.iter().map(|finding| {
            json!({
                "host": finding.target.host,
                "port": finding.target.port,
                "username": finding.credential.username,
            })
        }).collect::<Vec<_>>(),
    })
}

fn checkpoint_to_json(checkpoint: &Checkpoint) -> Value {
    json!({
        "version": checkpoint.version,
        "hash": checkpoint.hash,
        "service": checkpoint.service,
        "completed": checkpoint.completed.len(),
        "findings": checkpoint.findings.len(),
        "next_index": checkpoint.next_index,
    })
}

fn scope_decision_name(decision: ScopeDecision) -> &'static str {
    match decision {
        ScopeDecision::Excluded => "excluded",
        ScopeDecision::Local => "local",
        ScopeDecision::ConfirmationRequired => "confirmation_required",
        ScopeDecision::NeedsResolution => "needs_resolution",
    }
}

fn list_protocols_payload() -> Value {
    let mut protocols = Vec::new();
    push_protocol(&mut protocols, "ftp", 21, cfg!(feature = "ftp"));
    push_protocol(&mut protocols, "ssh", 22, cfg!(feature = "ssh"));
    push_protocol(&mut protocols, "http", 80, cfg!(feature = "http"));
    push_protocol(&mut protocols, "https", 443, cfg!(feature = "http"));
    push_protocol(&mut protocols, "smtp", 25, cfg!(feature = "smtp"));
    push_protocol(&mut protocols, "smtps", 465, cfg!(feature = "smtp"));
    push_protocol(&mut protocols, "mysql", 3306, cfg!(feature = "mysql"));
    push_protocol(&mut protocols, "postgres", 5432, cfg!(feature = "postgres"));
    push_protocol(&mut protocols, "redis", 6379, cfg!(feature = "redis"));
    push_protocol(&mut protocols, "imap", 143, cfg!(feature = "imap"));
    push_protocol(&mut protocols, "imaps", 993, cfg!(feature = "imap"));
    push_protocol(&mut protocols, "ldap", 389, cfg!(feature = "ldap"));
    push_protocol(&mut protocols, "ldaps", 636, cfg!(feature = "ldap"));
    json!({ "protocols": protocols })
}

fn push_protocol(out: &mut Vec<Value>, name: &str, default_port: u16, enabled: bool) {
    out.push(json!({
        "name": name,
        "default_port": default_port,
        "enabled": enabled,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::checkpoint::{Checkpoint, CheckpointEntry, save};
    use crate::protocols::Credential;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn tool_catalog_exposes_five_tools_with_object_schemas() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 5);
        let names: Vec<_> = tools.iter().map(|tool| tool.name).collect();
        assert_eq!(
            names,
            [
                "audit_dryrun",
                "audit_execute",
                "validate_scope",
                "list_protocols",
                "session_status"
            ]
        );
        for tool in &tools {
            assert_eq!(tool.input_schema["type"], "object");
            assert!(tool.input_schema.get("properties").is_some());
        }
        assert_eq!(
            tools[1].input_schema["properties"]["confirm"]["type"],
            "boolean"
        );
    }

    #[tokio::test]
    async fn list_protocols_reports_compiled_features() {
        let mut runtime = ToolRuntime::default();
        let cancel = CancellationToken::new();
        let result = call_tool("list_protocols", json!({}), &mut runtime, &cancel)
            .await
            .unwrap();
        assert!(!result.is_error);
        let payload: Value = serde_json::from_str(&result.content[0].text).unwrap();
        let protocols = payload["protocols"].as_array().unwrap();
        assert!(
            protocols
                .iter()
                .any(|p| p["name"] == "ssh" && p["enabled"] == true)
        );
        assert!(runtime.last_ok);
        assert_eq!(runtime.last_tool.as_deref(), Some("list_protocols"));
    }

    #[tokio::test]
    async fn validate_scope_classifies_local_and_public() {
        let mut runtime = ToolRuntime::default();
        let cancel = CancellationToken::new();

        let local = call_tool(
            "validate_scope",
            json!({ "address": "127.0.0.1" }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap();
        let local_json: Value = serde_json::from_str(&local.content[0].text).unwrap();
        assert_eq!(local_json["decision"], "local");

        let public = call_tool(
            "validate_scope",
            json!({ "address": "8.8.8.8", "exclude": ["10.0.0.0/8"] }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap();
        let public_json: Value = serde_json::from_str(&public.content[0].text).unwrap();
        assert_eq!(public_json["decision"], "confirmation_required");
        assert_eq!(public_json["requires_confirmation"], true);

        let excluded = call_tool(
            "validate_scope",
            json!({ "address": "10.1.2.3", "exclude": ["10.0.0.0/8"] }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap();
        let excluded_json: Value = serde_json::from_str(&excluded.content[0].text).unwrap();
        assert_eq!(excluded_json["decision"], "excluded");
    }

    #[tokio::test]
    async fn audit_dryrun_counts_excluded_targets_without_attacking() {
        let mut runtime = ToolRuntime::default();
        let cancel = CancellationToken::new();
        let result = call_tool(
            "audit_dryrun",
            json!({
                "service": "ssh",
                "target": "127.0.0.1",
                "username": "test",
                "password": "unused",
                "exclude": ["127.0.0.1"],
                "quiet": true
            }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap();
        assert!(!result.is_error);
        let payload: Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert_eq!(payload["targets"], 0);
        assert_eq!(payload["combinations"], 0);
        assert_eq!(payload["service"], "ssh");
        assert_eq!(runtime.phase, SessionPhase::DryRun);
    }

    #[tokio::test]
    async fn audit_execute_requires_confirm() {
        let mut runtime = ToolRuntime::default();
        let cancel = CancellationToken::new();
        let err = call_tool(
            "audit_execute",
            json!({
                "service": "ssh",
                "target": "127.0.0.1",
                "username": "test",
                "password": "unused",
                "confirm": false
            }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ToolError::ConfirmRequired));
    }

    #[tokio::test]
    async fn audit_execute_with_confirm_fails_closed_when_all_targets_excluded() {
        let mut runtime = ToolRuntime::default();
        let cancel = CancellationToken::new();
        let err = call_tool(
            "audit_execute",
            json!({
                "service": "ssh",
                "target": "127.0.0.1",
                "username": "test",
                "password": "unused",
                "exclude": ["127.0.0.1"],
                "confirm": true,
                "quiet": true
            }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ToolError::Execute(_)));
        assert_eq!(runtime.phase, SessionPhase::Execute);
    }

    #[tokio::test]
    async fn session_status_loads_checkpoint_and_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".betterh-session-deadbeef.json");
        let mut checkpoint = Checkpoint::new("deadbeef", "ssh");
        checkpoint.completed.push(CheckpointEntry::new(
            "10.0.0.1:22",
            &Credential {
                username: "alice".into(),
                password: Some("secret".into()),
            },
        ));
        save(&path, &checkpoint).await.unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let mut runtime = ToolRuntime {
            last_tool: Some("list_protocols".into()),
            last_ok: true,
            findings: 0,
            phase: SessionPhase::Idle,
        };
        let cancel = CancellationToken::new();
        let result = call_tool(
            "session_status",
            json!({ "checkpoint": path.to_str().unwrap() }),
            &mut runtime,
            &cancel,
        )
        .await
        .unwrap();
        let payload: Value = serde_json::from_str(&result.content[0].text).unwrap();
        assert_eq!(payload["checkpoint"]["hash"], "deadbeef");
        assert_eq!(payload["checkpoint"]["completed"], 1);
        assert_eq!(payload["last_tool"], "list_protocols");
    }

    #[tokio::test]
    async fn unknown_tool_is_rejected() {
        let mut runtime = ToolRuntime::default();
        let cancel = CancellationToken::new();
        let err = call_tool("nope", json!({}), &mut runtime, &cancel)
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::Unknown(_)));
    }
}
