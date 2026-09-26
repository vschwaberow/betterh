// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Interactive runtime keybindings for live attack control.

use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Commands emitted by the background key listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeCommand {
    StatusSnapshot,
    TogglePause,
    /// Positive values add permits; negative values release them.
    AdjustConcurrency(i32),
    SaveCheckpoint,
    Shutdown,
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Key listener channel closed")]
    ChannelClosed,
    #[error("Terminal event error: {0}")]
    Terminal(String),
}

/// Map a key event to a runtime command, if any.
#[must_use]
pub fn interpret_key(event: KeyEvent) -> Option<RuntimeCommand> {
    // Ignore key-release / repeat noise on terminals that emit them.
    if event.kind != KeyEventKind::Press {
        return None;
    }
    if event.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(event.code, KeyCode::Char('c' | 'C'))
    {
        return Some(RuntimeCommand::Shutdown);
    }

    let shift = event.modifiers.contains(KeyModifiers::SHIFT);
    match event.code {
        KeyCode::Char(' ' | 's' | 'S') => Some(RuntimeCommand::StatusSnapshot),
        KeyCode::Char('p' | 'P') => Some(RuntimeCommand::TogglePause),
        KeyCode::Char('+' | '=') => {
            Some(RuntimeCommand::AdjustConcurrency(if shift { 5 } else { 1 }))
        }
        KeyCode::Char('-' | '_') => Some(RuntimeCommand::AdjustConcurrency(if shift {
            -5
        } else {
            -1
        })),
        KeyCode::Char('c' | 'C') => Some(RuntimeCommand::SaveCheckpoint),
        KeyCode::Char('q' | 'Q') => Some(RuntimeCommand::Shutdown),
        _ => None,
    }
}

/// Interpret a crossterm [`Event`], ignoring non-key events.
#[must_use]
pub fn interpret_event(event: &Event) -> Option<RuntimeCommand> {
    match event {
        Event::Key(key) => interpret_key(*key),
        _ => None,
    }
}

/// Background task: read terminal keys and forward commands until cancelled.
///
/// # Errors
/// Returns when the command channel closes or the event stream fails.
pub async fn listen(
    tx: mpsc::Sender<RuntimeCommand>,
    cancel: CancellationToken,
) -> Result<(), KeyError> {
    let mut events = EventStream::new();
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            next = events.next() => {
                let Some(item) = next else { return Ok(()); };
                let event = item.map_err(|error| KeyError::Terminal(error.to_string()))?;
                let Some(command) = interpret_event(&event) else { continue; };
                if tx.send(command).await.is_err() {
                    return Err(KeyError::ChannelClosed);
                }
                if command == RuntimeCommand::Shutdown {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn press_shift(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::SHIFT)
    }

    fn press_ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::CONTROL)
    }

    #[test]
    fn maps_status_pause_checkpoint_and_quit() {
        assert_eq!(
            interpret_key(press(KeyCode::Char(' '))),
            Some(RuntimeCommand::StatusSnapshot)
        );
        assert_eq!(
            interpret_key(press(KeyCode::Char('s'))),
            Some(RuntimeCommand::StatusSnapshot)
        );
        assert_eq!(
            interpret_key(press(KeyCode::Char('p'))),
            Some(RuntimeCommand::TogglePause)
        );
        assert_eq!(
            interpret_key(press(KeyCode::Char('c'))),
            Some(RuntimeCommand::SaveCheckpoint)
        );
        assert_eq!(
            interpret_key(press(KeyCode::Char('q'))),
            Some(RuntimeCommand::Shutdown)
        );
        assert_eq!(
            interpret_key(press_ctrl(KeyCode::Char('c'))),
            Some(RuntimeCommand::Shutdown)
        );
    }

    #[test]
    fn concurrency_adjustments_honor_shift_magnitude() {
        assert_eq!(
            interpret_key(press(KeyCode::Char('+'))),
            Some(RuntimeCommand::AdjustConcurrency(1))
        );
        assert_eq!(
            interpret_key(press_shift(KeyCode::Char('+'))),
            Some(RuntimeCommand::AdjustConcurrency(5))
        );
        assert_eq!(
            interpret_key(press(KeyCode::Char('-'))),
            Some(RuntimeCommand::AdjustConcurrency(-1))
        );
        assert_eq!(
            interpret_key(press_shift(KeyCode::Char('-'))),
            Some(RuntimeCommand::AdjustConcurrency(-5))
        );
    }

    #[test]
    fn ignores_unrelated_keys_and_non_key_events() {
        assert_eq!(interpret_key(press(KeyCode::Char('x'))), None);
        assert_eq!(interpret_event(&Event::FocusGained), None);
    }
}
