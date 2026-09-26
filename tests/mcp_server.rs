// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Hermetic MCP duplex integration: initialize, list tools, dry-run, shutdown.

#![cfg(feature = "mcp")]

use betterh::cli::Cli;
use betterh::mcp::{JsonRpcResponse, McpSession, McpTransport, PROTOCOL_VERSION, serve};
use clap::{CommandFactory, Parser};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
use tokio_util::sync::CancellationToken;

fn initialize_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-server-test", "version": "0.0.1"}
        }
    })
}

async fn read_response(
    reader: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
) -> JsonRpcResponse {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("response line");
    serde_json::from_str(line.trim()).expect("json response")
}

async fn write_json(writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>, value: &Value) {
    let mut encoded = serde_json::to_vec(value).expect("encode");
    encoded.push(b'\n');
    writer.write_all(&encoded).await.expect("write");
    writer.flush().await.expect("flush");
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Hermetic MCP duplex scenario keeps handshake, tools, dry-run, and resources in one flow"
)]
async fn duplex_initialize_list_tools_dryrun_and_shutdown() {
    let (client, server) = duplex(16_384);
    let (client_read, mut client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();
    let server_task = tokio::spawn(async move {
        let mut transport = McpTransport::new(BufReader::new(server_read), server_write);
        let mut session = McpSession::new();
        serve(&mut transport, &mut session, &server_cancel).await
    });

    let mut client_reader = BufReader::new(client_read);

    write_json(&mut client_write, &initialize_request(1)).await;
    let init_resp = read_response(&mut client_reader).await;
    assert!(init_resp.error.is_none(), "{init_resp:?}");
    let result = init_resp.result.expect("initialize result");
    assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    assert!(result["capabilities"]["tools"].is_object());
    assert!(result["capabilities"]["resources"].is_object());

    write_json(
        &mut client_write,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    )
    .await;

    write_json(
        &mut client_write,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
    )
    .await;
    let list_resp = read_response(&mut client_reader).await;
    assert!(list_resp.error.is_none(), "{list_resp:?}");
    let list_result = list_resp.result.expect("tools");
    let tools = list_result["tools"].as_array().expect("tools array");
    let names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"audit_dryrun"));
    assert!(names.contains(&"list_protocols"));

    write_json(
        &mut client_write,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "audit_dryrun",
                "arguments": {
                    "service": "ssh",
                    "target": "127.0.0.1",
                    "username": "test",
                    "password": "unused",
                    "exclude": ["127.0.0.1"],
                    "quiet": true
                }
            }
        }),
    )
    .await;
    let dry_resp = read_response(&mut client_reader).await;
    assert!(dry_resp.error.is_none(), "{dry_resp:?}");
    let tool_result = dry_resp.result.expect("tool result");
    assert_eq!(tool_result["isError"], false);
    let text = tool_result["content"][0]["text"].as_str().unwrap();
    let payload: Value = serde_json::from_str(text).unwrap();
    assert_eq!(payload["targets"], 0);
    assert_eq!(payload["combinations"], 0);

    write_json(
        &mut client_write,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/list"
        }),
    )
    .await;
    let resources_resp = read_response(&mut client_reader).await;
    assert!(resources_resp.error.is_none(), "{resources_resp:?}");
    let resources_result = resources_resp.result.expect("resources");
    let resources = resources_result["resources"]
        .as_array()
        .expect("resources array");
    assert!(
        resources
            .iter()
            .any(|item| item["uri"] == "betterh://protocols")
    );

    cancel.cancel();
    let server_result = tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
        .await
        .expect("server shutdown timed out")
        .expect("server join");
    assert!(
        matches!(
            server_result,
            Ok(()) | Err(betterh::mcp::McpError::Cancelled)
        ),
        "unexpected server result: {server_result:?}"
    );
}

#[test]
fn cli_exposes_mcp_subcommand() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("mcp"));
    let mcp = Cli::try_parse_from(["betterh", "mcp"]).expect("parse mcp");
    match mcp.command {
        Some(betterh::cli::Command::Mcp { stdio }) => assert!(stdio),
        other => panic!("expected Command::Mcp, got {other:?}"),
    }
}
