// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Async newline-delimited JSON-RPC 2.0 transport and MCP lifecycle.

use std::io;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// MCP protocol version negotiated during `initialize`.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Server identity advertised in `initialize` results.
pub const SERVER_NAME: &str = "betterh";

/// JSON-RPC 2.0 version literal.
const JSONRPC_VERSION: &str = "2.0";

/// Standard JSON-RPC error codes used by the transport.
pub mod error_code {
    /// Invalid JSON was received by the server.
    pub const PARSE_ERROR: i64 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i64 = -32600;
    /// The method does not exist or is not available.
    pub const METHOD_NOT_FOUND: i64 = -32601;
    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i64 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i64 = -32603;
}

/// Transport and lifecycle failures.
#[derive(Debug, Error)]
pub enum McpError {
    /// Underlying reader or writer failed.
    #[error("MCP I/O error: {0}")]
    Io(#[from] io::Error),
    /// Message was not valid JSON.
    #[error("MCP JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// Cooperative cancellation was signalled.
    #[error("MCP transport cancelled")]
    Cancelled,
    /// Lifecycle transition was illegal for the current session state.
    #[error("MCP session error: {0}")]
    Session(String),
}

/// JSON-RPC request or response identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcId {
    /// Numeric id.
    Number(i64),
    /// String id.
    String(String),
}

/// JSON-RPC error object carried in error responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric error code.
    pub code: i64,
    /// Short human-readable description.
    pub message: String,
    /// Optional structured details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Build an error object without optional data.
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }
}

/// Incoming JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Correlation id for the response.
    pub id: JsonRpcId,
    /// Method name.
    pub method: String,
    /// Optional params object or array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Incoming JSON-RPC notification (no response expected).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Method name.
    pub method: String,
    /// Optional params object or array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Outgoing JSON-RPC success or error response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Correlation id from the request.
    pub id: JsonRpcId,
    /// Success payload when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Successful result response.
    #[must_use]
    pub fn result(id: JsonRpcId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Error response.
    #[must_use]
    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// Messages the server may write on the wire.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum OutgoingMessage {
    /// JSON-RPC response.
    Response(JsonRpcResponse),
    /// JSON-RPC notification (reserved for later phases).
    Notification(JsonRpcNotification),
}

/// Client or server implementation metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Implementation {
    /// Implementation name.
    pub name: String,
    /// Implementation version.
    pub version: String,
}

/// Client `initialize` parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// Requested MCP protocol version.
    pub protocol_version: String,
    /// Client capability advertisement.
    #[serde(default)]
    pub capabilities: Value,
    /// Client name and version.
    pub client_info: Implementation,
}

/// Server capability advertisement returned from `initialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerCapabilities {
    /// Tools capability (populated in task 12.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    /// Resources capability (populated in task 12.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Value>,
}

/// Server `initialize` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    /// Negotiated MCP protocol version.
    pub protocol_version: String,
    /// Server capabilities.
    pub capabilities: ServerCapabilities,
    /// Server name and version.
    pub server_info: Implementation,
}

impl InitializeResult {
    /// Build the Betterh initialize result for the supported protocol version.
    #[must_use]
    pub fn betterh() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.into(),
            capabilities: ServerCapabilities::default(),
            server_info: Implementation {
                name: SERVER_NAME.into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
        }
    }
}

/// MCP session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Waiting for the client's `initialize` request.
    WaitingInitialize,
    /// `initialize` answered; waiting for `notifications/initialized`.
    WaitingInitialized,
    /// Ready for application methods (`ping`, later tools/resources).
    Ready,
}

/// Newline-delimited JSON-RPC reader/writer over any async byte streams.
#[derive(Debug)]
pub struct McpTransport<R, W> {
    reader: R,
    writer: W,
    line_buf: Vec<u8>,
}

impl<R, W> McpTransport<R, W>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Wrap an async reader/writer pair (stdio in production, duplex in tests).
    #[must_use]
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            line_buf: Vec::new(),
        }
    }

    /// Read the next JSON-RPC message, or `None` on clean EOF.
    ///
    /// # Errors
    /// Returns I/O, JSON parse, or cancellation errors.
    pub async fn read_message(
        &mut self,
        cancel: &CancellationToken,
    ) -> Result<Option<Value>, McpError> {
        loop {
            self.line_buf.clear();
            let read = tokio::select! {
                biased;
                () = cancel.cancelled() => return Err(McpError::Cancelled),
                read = self.reader.read_until(b'\n', &mut self.line_buf) => read?,
            };
            if read == 0 {
                return Ok(None);
            }
            let line = std::str::from_utf8(&self.line_buf)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value = serde_json::from_str(trimmed)?;
            return Ok(Some(value));
        }
    }

    /// Write one JSON-RPC message followed by a newline and flush.
    ///
    /// # Errors
    /// Returns I/O or serialization errors.
    pub async fn write_message(&mut self, message: &OutgoingMessage) -> Result<(), McpError> {
        let mut encoded = serde_json::to_vec(message)?;
        encoded.push(b'\n');
        self.writer.write_all(&encoded).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Write a JSON-RPC response.
    ///
    /// # Errors
    /// Returns I/O or serialization errors.
    pub async fn write_response(&mut self, response: JsonRpcResponse) -> Result<(), McpError> {
        self.write_message(&OutgoingMessage::Response(response))
            .await
    }
}

/// Stateful MCP handshake handler (`initialize` / `initialized` / `ping`).
#[derive(Debug, Clone)]
pub struct McpSession {
    state: SessionState,
}

impl Default for McpSession {
    fn default() -> Self {
        Self::new()
    }
}

impl McpSession {
    /// Create a session waiting for `initialize`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SessionState::WaitingInitialize,
        }
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Parse a raw JSON value into a request or notification.
    ///
    /// # Errors
    /// Returns a JSON-RPC error object when the envelope is invalid.
    pub fn classify(value: &Value) -> Result<IncomingKind, JsonRpcError> {
        let obj = value.as_object().ok_or_else(|| {
            JsonRpcError::new(
                error_code::INVALID_REQUEST,
                "JSON-RPC message must be an object",
            )
        })?;

        let jsonrpc = obj
            .get("jsonrpc")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::new(error_code::INVALID_REQUEST, "missing jsonrpc"))?;
        if jsonrpc != JSONRPC_VERSION {
            return Err(JsonRpcError::new(
                error_code::INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ));
        }

        let method = obj
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::new(error_code::INVALID_REQUEST, "missing method"))?;

        let params = obj.get("params").cloned();

        match obj.get("id") {
            None => Ok(IncomingKind::Notification(JsonRpcNotification {
                jsonrpc: JSONRPC_VERSION.into(),
                method: method.into(),
                params,
            })),
            Some(id_value) if id_value.is_null() => Err(JsonRpcError::new(
                error_code::INVALID_REQUEST,
                "id must not be null for requests",
            )),
            Some(id_value) => {
                let id: JsonRpcId = serde_json::from_value(id_value.clone()).map_err(|_| {
                    JsonRpcError::new(error_code::INVALID_REQUEST, "invalid id type")
                })?;
                Ok(IncomingKind::Request(JsonRpcRequest {
                    jsonrpc: JSONRPC_VERSION.into(),
                    id,
                    method: method.into(),
                    params,
                }))
            }
        }
    }

    /// Handle one inbound JSON value and optionally produce a response.
    ///
    /// Notifications yield `Ok(None)`. Invalid JSON that already parsed as a
    /// `Value` but fails classification yields an error response when an `id`
    /// is present; otherwise the error is returned as [`McpError::Session`].
    ///
    /// # Errors
    /// Returns [`McpError::Session`] for notifications that cannot be answered
    /// with a JSON-RPC error response.
    pub fn handle_value(&mut self, value: &Value) -> Result<Option<JsonRpcResponse>, McpError> {
        match Self::classify(value) {
            Ok(IncomingKind::Request(request)) => Ok(Some(self.handle_request(request))),
            Ok(IncomingKind::Notification(notification)) => {
                self.handle_notification(&notification)?;
                Ok(None)
            }
            Err(err) => {
                if let Some(id) = value.get("id").cloned().and_then(|id| {
                    if id.is_null() {
                        None
                    } else {
                        serde_json::from_value(id).ok()
                    }
                }) {
                    Ok(Some(JsonRpcResponse::error(id, err)))
                } else {
                    Err(McpError::Session(err.message))
                }
            }
        }
    }

    fn handle_request(&mut self, request: JsonRpcRequest) -> JsonRpcResponse {
        match request.method.as_str() {
            "initialize" => self.handle_initialize(request),
            "ping" => self.handle_ping(request),
            other => JsonRpcResponse::error(
                request.id,
                JsonRpcError::new(
                    error_code::METHOD_NOT_FOUND,
                    format!("method not found: {other}"),
                ),
            ),
        }
    }

    fn handle_initialize(&mut self, request: JsonRpcRequest) -> JsonRpcResponse {
        if self.state != SessionState::WaitingInitialize {
            return JsonRpcResponse::error(
                request.id,
                JsonRpcError::new(error_code::INVALID_REQUEST, "initialize already completed"),
            );
        }

        let Some(params) = request.params else {
            return JsonRpcResponse::error(
                request.id,
                JsonRpcError::new(error_code::INVALID_PARAMS, "initialize requires params"),
            );
        };

        let parsed: InitializeParams = match serde_json::from_value(params) {
            Ok(parsed) => parsed,
            Err(err) => {
                return JsonRpcResponse::error(
                    request.id,
                    JsonRpcError::new(
                        error_code::INVALID_PARAMS,
                        format!("invalid initialize params: {err}"),
                    ),
                );
            }
        };

        if parsed.protocol_version != PROTOCOL_VERSION {
            return JsonRpcResponse::error(
                request.id,
                JsonRpcError::new(
                    error_code::INVALID_PARAMS,
                    format!(
                        "unsupported protocolVersion '{}'; only {PROTOCOL_VERSION} is supported",
                        parsed.protocol_version
                    ),
                ),
            );
        }

        let result = InitializeResult::betterh();
        let value = match serde_json::to_value(result) {
            Ok(value) => value,
            Err(err) => {
                return JsonRpcResponse::error(
                    request.id,
                    JsonRpcError::new(
                        error_code::INTERNAL_ERROR,
                        format!("failed to encode initialize result: {err}"),
                    ),
                );
            }
        };

        self.state = SessionState::WaitingInitialized;
        JsonRpcResponse::result(request.id, value)
    }

    fn handle_ping(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        if self.state != SessionState::Ready {
            return JsonRpcResponse::error(
                request.id,
                JsonRpcError::new(
                    error_code::INVALID_REQUEST,
                    "ping requires an initialized session",
                ),
            );
        }
        JsonRpcResponse::result(request.id, Value::Object(serde_json::Map::new()))
    }

    fn handle_notification(&mut self, notification: &JsonRpcNotification) -> Result<(), McpError> {
        match notification.method.as_str() {
            "notifications/initialized" => {
                if self.state != SessionState::WaitingInitialized {
                    return Err(McpError::Session(
                        "notifications/initialized received out of order".into(),
                    ));
                }
                self.state = SessionState::Ready;
                Ok(())
            }
            other => Err(McpError::Session(format!(
                "unsupported notification: {other}"
            ))),
        }
    }
}

/// Public classification result for tests and higher layers.
#[derive(Debug, Clone, PartialEq)]
pub enum IncomingKind {
    /// JSON-RPC request with id.
    Request(JsonRpcRequest),
    /// JSON-RPC notification without id.
    Notification(JsonRpcNotification),
}

/// Drive framing + lifecycle until the session is [`SessionState::Ready`] or EOF.
///
/// # Errors
/// Propagates transport, JSON, session, and cancellation failures.
pub async fn run_until_ready<R, W>(
    transport: &mut McpTransport<R, W>,
    session: &mut McpSession,
    cancel: &CancellationToken,
) -> Result<(), McpError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while session.state() != SessionState::Ready {
        let Some(value) = transport.read_message(cancel).await? else {
            return Err(McpError::Session(
                "EOF before MCP session became ready".into(),
            ));
        };

        match session.handle_value(&value) {
            Ok(Some(response)) => transport.write_response(response).await?,
            Ok(None) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader, duplex};

    fn initialize_request(id: i64, version: &str) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "0.0.1"}
            }
        })
    }

    #[test]
    fn request_response_and_error_round_trip() {
        let request = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.into(),
            id: JsonRpcId::Number(7),
            method: "ping".into(),
            params: None,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: JsonRpcRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);

        let ok = JsonRpcResponse::result(JsonRpcId::String("a".into()), serde_json::json!({}));
        let ok_val = serde_json::to_value(&ok).unwrap();
        assert_eq!(ok_val["jsonrpc"], "2.0");
        assert_eq!(ok_val["id"], "a");
        assert!(ok_val.get("error").is_none());

        let err = JsonRpcResponse::error(
            JsonRpcId::Number(1),
            JsonRpcError::new(error_code::METHOD_NOT_FOUND, "nope"),
        );
        let err_val = serde_json::to_value(&err).unwrap();
        assert_eq!(err_val["error"]["code"], error_code::METHOD_NOT_FOUND);
        assert!(err_val.get("result").is_none());
    }

    #[test]
    fn classify_distinguishes_request_and_notification() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping"
        });
        match McpSession::classify(&request).unwrap() {
            IncomingKind::Request(req) => assert_eq!(req.method, "ping"),
            IncomingKind::Notification(_) => panic!("expected request"),
        }

        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        match McpSession::classify(&notification).unwrap() {
            IncomingKind::Notification(n) => {
                assert_eq!(n.method, "notifications/initialized");
            }
            IncomingKind::Request(_) => panic!("expected notification"),
        }
    }

    #[test]
    fn lifecycle_initialize_initialized_and_ping() {
        let mut session = McpSession::new();
        assert_eq!(session.state(), SessionState::WaitingInitialize);

        let response = session
            .handle_value(&initialize_request(1, PROTOCOL_VERSION))
            .unwrap()
            .expect("initialize response");
        assert!(response.error.is_none());
        let result: InitializeResult =
            serde_json::from_value(response.result.expect("result")).unwrap();
        assert_eq!(result.protocol_version, PROTOCOL_VERSION);
        assert_eq!(result.server_info.name, SERVER_NAME);
        assert_eq!(session.state(), SessionState::WaitingInitialized);

        session
            .handle_value(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }))
            .unwrap();
        assert_eq!(session.state(), SessionState::Ready);

        let ping = session
            .handle_value(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "ping"
            }))
            .unwrap()
            .expect("ping response");
        assert_eq!(ping.result, Some(serde_json::json!({})));
    }

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        let mut session = McpSession::new();
        let response = session
            .handle_value(&initialize_request(1, "1999-01-01"))
            .unwrap()
            .expect("error response");
        let error = response.error.expect("error");
        assert_eq!(error.code, error_code::INVALID_PARAMS);
        assert_eq!(session.state(), SessionState::WaitingInitialize);
    }

    #[test]
    fn ping_before_ready_is_rejected() {
        let mut session = McpSession::new();
        let response = session
            .handle_value(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping"
            }))
            .unwrap()
            .expect("error response");
        assert_eq!(
            response.error.expect("error").code,
            error_code::INVALID_REQUEST
        );
    }

    #[tokio::test]
    async fn duplex_framing_completes_lifecycle() {
        let (client, server) = duplex(4096);
        let (client_read, client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server);

        let server_task = tokio::spawn(async move {
            let mut transport = McpTransport::new(BufReader::new(server_read), server_write);
            let mut session = McpSession::new();
            let cancel = CancellationToken::new();
            run_until_ready(&mut transport, &mut session, &cancel).await?;
            assert_eq!(session.state(), SessionState::Ready);

            let value = transport
                .read_message(&cancel)
                .await?
                .expect("ping message");
            let response = session.handle_value(&value)?.expect("ping response");
            transport.write_response(response).await?;
            Ok::<_, McpError>(())
        });

        let mut client_writer = client_write;
        let mut client_reader = BufReader::new(client_read);

        let init = format!("{}\n", initialize_request(1, PROTOCOL_VERSION));
        client_writer.write_all(init.as_bytes()).await.unwrap();
        client_writer.flush().await.unwrap();

        let mut line = String::new();
        client_reader.read_line(&mut line).await.unwrap();
        let response: JsonRpcResponse = serde_json::from_str(line.trim()).unwrap();
        assert!(response.error.is_none());
        assert_eq!(response.id, JsonRpcId::Number(1));

        client_writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
            .await
            .unwrap();
        client_writer.flush().await.unwrap();

        client_writer
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n")
            .await
            .unwrap();
        client_writer.flush().await.unwrap();

        line.clear();
        client_reader.read_line(&mut line).await.unwrap();
        let ping: JsonRpcResponse = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(ping.result, Some(serde_json::json!({})));

        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancellation_aborts_read() {
        let (client, server) = duplex(64);
        let (_client_read, _client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server);

        let mut transport = McpTransport::new(BufReader::new(server_read), server_write);
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let reader = tokio::spawn(async move { transport.read_message(&cancel_clone).await });

        tokio::task::yield_now().await;
        cancel.cancel();

        let err = reader.await.unwrap().expect_err("cancelled");
        assert!(matches!(err, McpError::Cancelled));
    }

    #[tokio::test]
    async fn invalid_json_line_surfaces_parse_error() {
        let (client, server) = duplex(256);
        let (_client_read, mut client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server);

        let mut transport = McpTransport::new(BufReader::new(server_read), server_write);
        let cancel = CancellationToken::new();

        client_write.write_all(b"{not-json}\n").await.unwrap();
        client_write.flush().await.unwrap();

        let err = transport
            .read_message(&cancel)
            .await
            .expect_err("parse error");
        assert!(matches!(err, McpError::Json(_)));
    }
}
