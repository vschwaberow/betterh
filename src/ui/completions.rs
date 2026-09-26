// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Shell completion scripts and man-page generation.

use std::io::{self, Write};

use clap::Command;
use clap_complete::{Shell, generate};
use clap_mangen::Man;

/// Write shell completions for `shell` to `writer` using the given clap command.
///
/// # Errors
/// Returns an I/O error if writing to `writer` fails.
pub fn generate_completions(
    shell: Shell,
    command: &mut Command,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let name = command.get_name().to_owned();
    generate(shell, command, name, writer);
    Ok(())
}

/// Write a roff man page for `command` to `writer`.
///
/// # Errors
/// Returns an I/O error if writing to `writer` fails.
pub fn generate_manpage(command: &Command, writer: &mut dyn Write) -> io::Result<()> {
    Man::new(command.clone()).render(writer)
}

/// Convenience: detect whether a shell name is supported by `clap_complete`.
#[must_use]
pub fn parse_shell(name: &str) -> Option<Shell> {
    name.parse::<Shell>().ok()
}

/// List shells Betterh can emit completions for (stable display order).
#[must_use]
pub fn supported_shells() -> &'static [Shell] {
    &[
        Shell::Bash,
        Shell::Elvish,
        Shell::Fish,
        Shell::PowerShell,
        Shell::Zsh,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use clap_complete::Generator;

    #[derive(Debug, Parser)]
    #[command(name = "betterh", about = "test harness")]
    struct HarnessCli {
        #[command(subcommand)]
        command: Option<HarnessCommand>,
    }

    #[derive(Debug, clap::Subcommand)]
    enum HarnessCommand {
        Wizard,
        Completions { shell: String },
        Man,
    }

    #[test]
    fn bash_completions_include_core_subcommands() {
        let mut cmd = HarnessCli::command();
        let mut buf = Vec::new();
        generate_completions(Shell::Bash, &mut cmd, &mut buf).unwrap();
        let script = String::from_utf8(buf).unwrap();
        assert!(script.contains("wizard"));
        assert!(script.contains("completions"));
        assert!(script.contains("man"));
    }

    #[test]
    fn manpage_contains_binary_name() {
        let cmd = HarnessCli::command();
        let mut buf = Vec::new();
        generate_manpage(&cmd, &mut buf).unwrap();
        let roff = String::from_utf8(buf).unwrap();
        assert!(roff.contains("betterh"));
    }

    #[test]
    fn parse_shell_accepts_common_names() {
        assert!(matches!(parse_shell("zsh"), Some(Shell::Zsh)));
        assert!(parse_shell("not-a-shell").is_none());
        assert!(!supported_shells().is_empty());
        let _ = Shell::Bash.file_name("betterh");
    }
}
