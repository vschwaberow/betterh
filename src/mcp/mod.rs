// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Model Context Protocol (MCP) server over stdio JSON-RPC 2.0.
//!
//! Phase 12.1: framing and lifecycle.
//! Phase 12.2: tool schemas and engine dispatch.
//! Phase 12.3: resources and secure report reads.
//! Phase 12.4: CLI subcommand and stdio server loop.

use tokio::io::{BufReader, stdin, stdout};
use tokio_util::sync::CancellationToken;

pub mod resources;
pub mod tools;
pub mod transport;

pub use resources::{
    ResourceContent, ResourceDescriptor, ResourceError, SessionMetrics, SharedSessionMetrics,
    list_resources, read_resource,
};
pub use tools::{
    SessionPhase, ToolContent, ToolDefinition, ToolError, ToolResult, ToolRuntime, call_tool,
    tool_definitions,
};
pub use transport::{
    Implementation, IncomingKind, InitializeParams, InitializeResult, JsonRpcError, JsonRpcId,
    JsonRpcRequest, JsonRpcResponse, McpError, McpSession, McpTransport, OutgoingMessage,
    PROTOCOL_VERSION, SERVER_NAME, ServerCapabilities, SessionState, error_code, run_until_ready,
    serve,
};

/// Serve MCP over asynchronous standard input/output until EOF or cancellation.
///
/// # Errors
/// Returns transport, session, or cancellation failures from the server loop.
pub async fn run_stdio_server(cancel: &CancellationToken) -> Result<(), McpError> {
    let mut transport = McpTransport::new(BufReader::new(stdin()), stdout());
    let mut session = McpSession::new();
    serve(&mut transport, &mut session, cancel).await
}
