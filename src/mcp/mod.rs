// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Model Context Protocol (MCP) server over stdio JSON-RPC 2.0.
//!
//! Phase 12.1 provides framing, lifecycle (`initialize`, `notifications/initialized`,
//! `ping`), and cancellation-safe I/O. Tools and resources land in later tasks.

pub mod transport;

pub use transport::{
    Implementation, IncomingKind, InitializeParams, InitializeResult, JsonRpcError, JsonRpcId,
    JsonRpcRequest, JsonRpcResponse, McpError, McpSession, McpTransport, OutgoingMessage,
    PROTOCOL_VERSION, SERVER_NAME, ServerCapabilities, SessionState, error_code, run_until_ready,
};
