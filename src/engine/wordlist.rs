// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Bounded wordlist readers and lazy credential combinations.

use std::{io, path::PathBuf};

use futures::{
    StreamExt, TryStreamExt,
    stream::{self, BoxStream},
};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};

use crate::{cli::ManglingRule, protocols::Credential};

/// Maximum bytes in a physical line, excluding LF but including CR.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

pub type CredentialStream = BoxStream<'static, Result<Credential, WordlistError>>;
type WordStream = BoxStream<'static, Result<String, WordlistError>>;

#[derive(Debug, Error)]
pub enum WordlistError {
    #[error("Cannot read wordlist: {0}")]
    Io(#[from] io::Error),
    #[error("Wordlist line {line} exceeds the {MAX_LINE_BYTES}-byte limit")]
    LineTooLong { line: u64 },
    #[error("Wordlist line {line} is not valid UTF-8")]
    InvalidUtf8 { line: u64 },
    #[error("Wordlist sources must be regular files; pipe other sources through stdin")]
    NotRegularFile,
    #[error("Username and password lists cannot both read stdin")]
    SharedStdin,
    #[error("Supply a password source or at least one mangling rule")]
    MissingPasswords,
    #[error("Combo rows require a nonempty username followed by ':' and a password")]
    InvalidCombo,
    #[error(transparent)]
    Mutation(#[from] crate::engine::mutations::MutationError),
}

/// A line reader that preserves partially read lines across cancellation.
pub struct Wordlist<R> {
    reader: R,
    buffer: Vec<u8>,
    line: u64,
    done: bool,
}

impl<R: AsyncBufRead + Unpin> Wordlist<R> {
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::with_capacity(MAX_LINE_BYTES),
            line: 1,
            done: false,
        }
    }

    /// Read the next nonempty, trimmed UTF-8 line. Errors are terminal.
    ///
    /// # Errors
    /// Returns I/O, invalid UTF-8, or line-length errors without exposing input text.
    pub async fn next_word(&mut self) -> Result<Option<String>, WordlistError> {
        while !self.done {
            loop {
                let chunk = match self.reader.fill_buf().await {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        self.done = true;
                        return Err(error.into());
                    }
                };
                if chunk.is_empty() {
                    self.done = true;
                    break;
                }
                let newline = chunk.iter().position(|byte| *byte == b'\n');
                let count = newline.unwrap_or(chunk.len());
                if count > MAX_LINE_BYTES - self.buffer.len() {
                    self.done = true;
                    return Err(WordlistError::LineTooLong { line: self.line });
                }
                self.buffer.extend_from_slice(&chunk[..count]);
                self.reader.consume(count + usize::from(newline.is_some()));
                if newline.is_some() {
                    break;
                }
            }
            let Ok(word) = std::str::from_utf8(&self.buffer) else {
                self.done = true;
                return Err(WordlistError::InvalidUtf8 { line: self.line });
            };
            let trimmed = word.trim();
            self.line = self.line.saturating_add(1);
            if trimmed.is_empty() {
                self.buffer.clear();
                continue;
            }
            // Avoid a second allocation when the line needs no trimming.
            let owned = if trimmed.len() == word.len() {
                String::from_utf8(std::mem::take(&mut self.buffer)).map_err(|_| {
                    self.done = true;
                    WordlistError::InvalidUtf8 {
                        line: self.line.saturating_sub(1),
                    }
                })?
            } else {
                let owned = trimmed.to_owned();
                self.buffer.clear();
                owned
            };
            return Ok(Some(owned));
        }
        Ok(None)
    }

    /// Turn this reader into a stream with no background producer.
    pub fn into_stream(self) -> BoxStream<'static, Result<String, WordlistError>>
    where
        R: Send + 'static,
    {
        terminal(
            stream::try_unfold(self, |mut reader| async move {
                Ok(reader.next_word().await?.map(|word| (word, reader)))
            })
            .boxed(),
        )
    }
}

#[derive(Clone)]
pub enum InputSource {
    Single(String),
    File(PathBuf),
    Stdin,
}

impl InputSource {
    /// Interpret the CLI path `-` as stdin.
    #[must_use]
    pub fn from_path(path: PathBuf) -> Self {
        if path.as_os_str() == "-" {
            Self::Stdin
        } else {
            Self::File(path)
        }
    }

    fn words(self) -> WordStream {
        match self {
            Self::Single(word) => stream::once(async move {
                if word.len() > MAX_LINE_BYTES {
                    Err(WordlistError::LineTooLong { line: 1 })
                } else {
                    Ok(word)
                }
            })
            .boxed(),
            Self::File(path) => stream::once(async move {
                // Reject non-replayable sources before opening a FIFO can block.
                if !tokio::fs::metadata(&path).await?.is_file() {
                    return Err(WordlistError::NotRegularFile);
                }
                let file = tokio::fs::File::open(path).await?;
                Ok(Wordlist::new(BufReader::new(file)).into_stream())
            })
            .try_flatten()
            .boxed(),
            Self::Stdin => Wordlist::new(BufReader::new(tokio::io::stdin())).into_stream(),
        }
    }
}

pub enum CredentialInput {
    Product {
        users: InputSource,
        passwords: Option<InputSource>,
    },
    Combos(InputSource),
}

/// Configuration for wordlist mutations, rules, and mangling.
#[derive(Debug, Clone, Default)]
pub struct MutationConfig<'a> {
    pub mangling: &'a [ManglingRule],
    pub rule_set: Option<&'a crate::engine::mutations::RuleSet>,
    pub rule_year: Option<i32>,
}

/// Generate credentials in the order defined by SPEC section 7.4.
///
/// Files are opened lazily and may be reopened. They must not change during a run.
/// When passwords come from stdin, rules precede password-major combinations.
///
/// # Errors
/// Rejects two stdin sources or a product with neither passwords nor rules.
/// Input errors arrive as stream items; after the first error the stream ends.
pub fn credentials(
    input: CredentialInput,
    rules: &[ManglingRule],
) -> Result<CredentialStream, WordlistError> {
    credentials_with_mutations(
        input,
        &MutationConfig {
            mangling: rules,
            rule_set: None,
            rule_year: None,
        },
    )
}

/// Generate credentials with full mutation and rule-file interpreter support.
///
/// # Errors
/// Rejects two stdin sources or a product with neither passwords nor rules.
pub fn credentials_with_mutations(
    input: CredentialInput,
    config: &MutationConfig<'_>,
) -> Result<CredentialStream, WordlistError> {
    let rules = normalized_rules(config.mangling);
    let rule_year = config.rule_year;
    let rule_set = config.rule_set.cloned();

    let candidates = match input {
        CredentialInput::Combos(source) => source
            .words()
            .map_ok(move |line| {
                let parsed = parse_combo(&line);
                match parsed {
                    Ok(credential) => mangled(&credential.username, rules, rule_year)
                        .chain(stream::once(async move { Ok(credential) }))
                        .boxed(),
                    Err(error) => stream::once(async move { Err(error) }).boxed(),
                }
            })
            .try_flatten()
            .boxed(),
        CredentialInput::Product {
            users: InputSource::Stdin,
            passwords: Some(InputSource::Stdin),
        } => return Err(WordlistError::SharedStdin),
        CredentialInput::Product {
            users,
            passwords: Some(InputSource::Stdin),
        } => {
            // Rules need a single user pass before passwords consume stdin.
            let prelude = if rules.iter().any(Option::is_some) {
                users
                    .clone()
                    .words()
                    .map_ok(move |user| mangled(&user, rules, rule_year))
                    .try_flatten()
                    .boxed()
            } else {
                stream::empty().boxed()
            };
            let product = InputSource::Stdin
                .words()
                .map_ok(move |base_password| {
                    let candidates: Vec<String> = if let Some(ref rs) = rule_set {
                        rs.apply_to(&base_password).collect()
                    } else {
                        vec![base_password]
                    };
                    let users = users.clone();
                    stream::iter(candidates.into_iter().map(move |password| {
                        let users = users.clone();
                        users.words().map_ok(move |username| Credential {
                            username,
                            password: Some(password.clone()),
                        })
                    }))
                    .flatten()
                })
                .try_flatten();
            prelude.chain(product).boxed()
        }
        CredentialInput::Product { users, passwords } => {
            if passwords.is_none() && rules.iter().all(Option::is_none) {
                return Err(WordlistError::MissingPasswords);
            }
            users
                .words()
                .map_ok(move |user| {
                    let extra = mangled(&user, rules, rule_year);
                    let rule_set = rule_set.clone();
                    let supplied = passwords.clone().map_or_else(
                        || stream::empty().boxed(),
                        move |source| {
                            let user = user.clone();
                            source
                                .words()
                                .map_ok(move |base_password| {
                                    let user = user.clone();
                                    let candidates: Vec<String> = if let Some(ref rs) = rule_set {
                                        rs.apply_to(&base_password).collect()
                                    } else {
                                        vec![base_password]
                                    };
                                    stream::iter(candidates.into_iter().map(move |password| {
                                        Ok(Credential {
                                            username: user.clone(),
                                            password: Some(password),
                                        })
                                    }))
                                })
                                .try_flatten()
                                .boxed()
                        },
                    );
                    extra.chain(supplied).boxed()
                })
                .try_flatten()
                .boxed()
        }
    };
    Ok(terminal(candidates))
}

pub(crate) const MANGLING_ORDER: [ManglingRule; 7] = [
    ManglingRule::Empty,
    ManglingRule::Same,
    ManglingRule::Reverse,
    ManglingRule::Capitalize,
    ManglingRule::Leet,
    ManglingRule::Year,
    ManglingRule::Season,
];

pub(crate) fn normalized_rules(rules: &[ManglingRule]) -> [Option<ManglingRule>; 7] {
    MANGLING_ORDER.map(|rule| rules.contains(&rule).then_some(rule))
}

pub(crate) fn mangled(
    user: &str,
    rules: [Option<ManglingRule>; 7],
    rule_year: Option<i32>,
) -> CredentialStream {
    let user = user.to_owned();
    let base_year = crate::engine::mutations::resolve_rule_year(rule_year);
    let mut out: Vec<String> = Vec::new();

    for rule in rules.into_iter().flatten() {
        match rule {
            ManglingRule::Empty => {
                out.push(String::new());
            }
            ManglingRule::Same => {
                out.push(user.clone());
            }
            ManglingRule::Reverse => {
                out.push(user.chars().rev().collect());
            }
            ManglingRule::Capitalize => {
                out.push(crate::engine::mutations::capitalize_first_only(&user));
            }
            ManglingRule::Leet => {
                out.extend(crate::engine::mutations::generate_leet_candidates(&user));
            }
            ManglingRule::Year => {
                out.extend(crate::engine::mutations::generate_year_candidates(
                    &user, base_year,
                ));
            }
            ManglingRule::Season => {
                out.extend(crate::engine::mutations::generate_season_candidates(
                    base_year,
                ));
            }
        }
    }

    stream::iter(out.into_iter().map(move |pwd| {
        Ok(Credential {
            username: user.clone(),
            password: Some(pwd),
        })
    }))
    .boxed()
}

fn parse_combo(line: &str) -> Result<Credential, WordlistError> {
    let (username, password) = line.split_once(':').ok_or(WordlistError::InvalidCombo)?;
    if username.trim().is_empty() {
        return Err(WordlistError::InvalidCombo);
    }
    Ok(Credential {
        username: username.trim().into(),
        password: Some(password.trim().into()),
    })
}

fn terminal<T: Send + 'static>(
    candidates: BoxStream<'static, Result<T, WordlistError>>,
) -> BoxStream<'static, Result<T, WordlistError>> {
    stream::unfold(Some(candidates), |state| async move {
        let mut candidates = state?;
        let item = candidates.next().await?;
        let state = item.is_ok().then_some(candidates);
        Some((item, state))
    })
    .fuse()
    .boxed()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::*;

    fn literal(value: &str) -> InputSource {
        InputSource::Single(value.into())
    }

    fn expected(pairs: &[(&str, &str)]) -> Vec<Credential> {
        pairs
            .iter()
            .map(|(user, password)| Credential {
                username: (*user).into(),
                password: Some((*password).into()),
            })
            .collect()
    }

    async fn file(dir: &std::path::Path, name: &str, text: &str) -> InputSource {
        let path = dir.join(name);
        tokio::fs::write(&path, text).await.unwrap();
        InputSource::File(path)
    }

    async fn collect(input: CredentialInput, rules: &[ManglingRule]) -> Vec<Credential> {
        credentials(input, rules)
            .unwrap()
            .try_collect()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn reader_trims_crlf_unicode_whitespace_and_accepts_final_line() {
        let input = "  alice \r\n\r\n\u{2003}bob\t\ncarol".as_bytes();
        let reader = Wordlist::new(BufReader::with_capacity(1, input));
        assert_eq!(
            reader.into_stream().try_collect::<Vec<_>>().await.unwrap(),
            ["alice", "bob", "carol"]
        );
    }

    #[tokio::test]
    async fn reader_decodes_utf8_split_across_buffers() {
        let reader = Wordlist::new(BufReader::with_capacity(1, "äö東京\n".as_bytes()));
        assert_eq!(
            reader.into_stream().try_collect::<Vec<_>>().await.unwrap(),
            ["äö東京"]
        );
    }

    #[tokio::test]
    async fn empty_input_and_blank_lines_end_cleanly() {
        for input in ["", "\r\n \n\t"] {
            let mut reader = Wordlist::new(input.as_bytes());
            assert_eq!(reader.next_word().await.unwrap(), None);
            assert_eq!(reader.next_word().await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn malformed_utf8_reports_physical_line_without_input_data() {
        let mut reader = Wordlist::new(&b"\nvalid\nsecret\xff\n"[..]);
        assert_eq!(reader.next_word().await.unwrap().as_deref(), Some("valid"));
        let error = reader.next_word().await.unwrap_err();
        assert!(matches!(error, WordlistError::InvalidUtf8 { line: 3 }));
        assert!(!error.to_string().contains("secret"));
        assert_eq!(reader.next_word().await.unwrap(), None);
    }

    #[tokio::test]
    async fn line_limit_is_checked_before_buffer_growth() {
        for newline in [false, true] {
            let mut input = vec![b'x'; MAX_LINE_BYTES];
            if newline {
                input.push(b'\n');
            }
            let mut reader = Wordlist::new(input.as_slice());
            assert_eq!(
                reader.next_word().await.unwrap().unwrap().len(),
                MAX_LINE_BYTES
            );
        }
        let input = vec![b'x'; MAX_LINE_BYTES + 1];
        let mut reader = Wordlist::new(BufReader::with_capacity(1024, input.as_slice()));
        assert!(matches!(
            reader.next_word().await,
            Err(WordlistError::LineTooLong { line: 1 })
        ));
        assert_eq!(reader.buffer.capacity(), MAX_LINE_BYTES);
        assert!(reader.buffer.len() <= MAX_LINE_BYTES);
        assert_eq!(reader.next_word().await.unwrap(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_read_preserves_partial_line() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let mut reader = Wordlist::new(BufReader::new(reader));
        writer.write_all(b"sec").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), reader.next_word())
                .await
                .is_err()
        );
        writer.write_all(b"ret\n").await.unwrap();
        assert_eq!(reader.next_word().await.unwrap().as_deref(), Some("secret"));
    }

    #[tokio::test]
    async fn io_errors_terminate_reader() {
        let input = tokio_test::io::Builder::new()
            .read(b"valid\n")
            .read_error(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
            .build();
        let mut reader = Wordlist::new(BufReader::new(input));
        assert_eq!(reader.next_word().await.unwrap().as_deref(), Some("valid"));
        assert!(matches!(
            reader.next_word().await,
            Err(WordlistError::Io(_))
        ));
        assert_eq!(reader.next_word().await.unwrap(), None);
    }

    #[tokio::test]
    async fn single_credentials_preserve_literal_whitespace_and_empty_password() {
        for password in ["", " pass "] {
            let actual = collect(
                CredentialInput::Product {
                    users: literal(" user "),
                    passwords: Some(literal(password)),
                },
                &[],
            )
            .await;
            assert_eq!(actual, expected(&[(" user ", password)]));
        }
    }

    #[tokio::test]
    async fn single_user_and_password_list_keep_file_order() {
        let dir = tempfile::tempdir().unwrap();
        let passwords = file(dir.path(), "passwords", "one\ntwo\n").await;
        let actual = collect(
            CredentialInput::Product {
                users: literal("alice"),
                passwords: Some(passwords),
            },
            &[],
        )
        .await;
        assert_eq!(actual, expected(&[("alice", "one"), ("alice", "two")]));
    }

    #[tokio::test]
    async fn user_list_and_single_password_keep_file_order() {
        let dir = tempfile::tempdir().unwrap();
        let users = file(dir.path(), "users", "alice\nbob\n").await;
        let actual = collect(
            CredentialInput::Product {
                users,
                passwords: Some(literal("one")),
            },
            &[],
        )
        .await;
        assert_eq!(actual, expected(&[("alice", "one"), ("bob", "one")]));
    }

    #[tokio::test]
    async fn cartesian_product_replays_password_file_per_user() {
        let dir = tempfile::tempdir().unwrap();
        let users = file(dir.path(), "users", "alice\nbob\n").await;
        let passwords = file(dir.path(), "passwords", "one\ntwo\n").await;
        let actual = collect(
            CredentialInput::Product {
                users,
                passwords: Some(passwords),
            },
            &[],
        )
        .await;
        assert_eq!(
            actual,
            expected(&[
                ("alice", "one"),
                ("alice", "two"),
                ("bob", "one"),
                ("bob", "two")
            ])
        );
    }

    #[tokio::test]
    async fn mangling_precedes_passwords_once_per_user_in_canonical_order() {
        let dir = tempfile::tempdir().unwrap();
        let users = file(dir.path(), "users", "ab\näx\n").await;
        let actual = collect(
            CredentialInput::Product {
                users,
                passwords: Some(literal("base")),
            },
            &[
                ManglingRule::Reverse,
                ManglingRule::Empty,
                ManglingRule::Same,
                ManglingRule::Empty,
            ],
        )
        .await;
        assert_eq!(
            actual,
            expected(&[
                ("ab", ""),
                ("ab", "ab"),
                ("ab", "ba"),
                ("ab", "base"),
                ("äx", ""),
                ("äx", "äx"),
                ("äx", "xä"),
                ("äx", "base")
            ])
        );
    }

    #[tokio::test]
    async fn rules_can_supply_all_password_candidates() {
        let actual = collect(
            CredentialInput::Product {
                users: literal("ab"),
                passwords: None,
            },
            &[ManglingRule::Reverse],
        )
        .await;
        assert_eq!(actual, expected(&[("ab", "ba")]));
    }

    #[tokio::test]
    async fn combos_preserve_password_colons_and_empty_passwords() {
        let dir = tempfile::tempdir().unwrap();
        let source = file(dir.path(), "combos", " alice : pa:ss \r\nbob:\nbob:\n").await;
        let actual = collect(CredentialInput::Combos(source), &[ManglingRule::Empty]).await;
        assert_eq!(
            actual,
            expected(&[
                ("alice", ""),
                ("alice", "pa:ss"),
                ("bob", ""),
                ("bob", ""),
                ("bob", ""),
                ("bob", "")
            ])
        );
    }

    #[tokio::test]
    async fn invalid_combo_stops_before_later_valid_rows() {
        let dir = tempfile::tempdir().unwrap();
        for invalid in ["missing-colon", ":password", "  :password"] {
            let source = file(dir.path(), "combos", &format!("{invalid}\nuser:valid\n")).await;
            let mut stream = credentials(CredentialInput::Combos(source), &[]).unwrap();
            assert!(matches!(
                stream.next().await,
                Some(Err(WordlistError::InvalidCombo))
            ));
            assert!(stream.next().await.is_none());
            assert!(stream.next().await.is_none());
        }
    }

    #[tokio::test]
    async fn files_open_only_when_polled_and_errors_are_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late-file");
        let mut stream = credentials(
            CredentialInput::Product {
                users: literal("user"),
                passwords: Some(InputSource::File(path.clone())),
            },
            &[],
        )
        .unwrap();
        tokio::fs::write(&path, "password\n").await.unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap(),
            expected(&[("user", "password")]).remove(0)
        );
        let mut missing = credentials(
            CredentialInput::Combos(InputSource::File(dir.path().join("missing"))),
            &[],
        )
        .unwrap();
        assert!(matches!(
            missing.next().await,
            Some(Err(WordlistError::Io(_)))
        ));
        assert!(missing.next().await.is_none());
        let mut directory = credentials(
            CredentialInput::Combos(InputSource::File(dir.path().into())),
            &[],
        )
        .unwrap();
        assert!(matches!(
            directory.next().await,
            Some(Err(WordlistError::NotRegularFile))
        ));
    }

    #[tokio::test]
    async fn empty_user_list_does_not_open_password_source() {
        let dir = tempfile::tempdir().unwrap();
        let users = file(dir.path(), "users", "\n").await;
        let actual = collect(
            CredentialInput::Product {
                users,
                passwords: Some(InputSource::File(dir.path().join("missing"))),
            },
            &[],
        )
        .await;
        assert!(actual.is_empty());
    }

    #[test]
    fn rejects_shared_stdin_and_missing_password_source() {
        assert!(matches!(
            credentials(
                CredentialInput::Product {
                    users: InputSource::Stdin,
                    passwords: Some(InputSource::Stdin)
                },
                &[]
            ),
            Err(WordlistError::SharedStdin)
        ));
        assert!(matches!(
            credentials(
                CredentialInput::Product {
                    users: literal("user"),
                    passwords: None
                },
                &[]
            ),
            Err(WordlistError::MissingPasswords)
        ));
        assert!(matches!(
            InputSource::from_path("-".into()),
            InputSource::Stdin
        ));
    }

    #[tokio::test]
    async fn seasonal_and_year_mangling_generates_candidates() {
        let config = MutationConfig {
            mangling: &[
                ManglingRule::Capitalize,
                ManglingRule::Leet,
                ManglingRule::Year,
                ManglingRule::Season,
            ],
            rule_set: None,
            rule_year: Some(2026),
        };
        let mut stream = credentials_with_mutations(
            CredentialInput::Product {
                users: literal("admin"),
                passwords: None,
            },
            &config,
        )
        .expect("valid stream");

        let mut passwords = Vec::new();
        while let Some(item) = stream.next().await {
            passwords.push(item.expect("valid").password.unwrap_or_default());
        }

        assert!(passwords.contains(&"Admin".to_string()));
        assert!(passwords.contains(&"@dm1n".to_string()));
        assert!(passwords.contains(&"admin2026!".to_string()));
        assert!(passwords.contains(&"Winter2026!".to_string()));
        assert!(passwords.contains(&"Sommer2026#".to_string()));
    }

    #[tokio::test]
    async fn mutates_password_stream_lazily_with_ruleset() {
        let rules_content = "
            c
            $!
            u
        ";
        let rule_set: crate::engine::mutations::RuleSet =
            rules_content.parse().expect("valid rules");
        let config = MutationConfig {
            mangling: &[],
            rule_set: Some(&rule_set),
            rule_year: None,
        };

        let mut stream = credentials_with_mutations(
            CredentialInput::Product {
                users: literal("alice"),
                passwords: Some(literal("summer")),
            },
            &config,
        )
        .expect("valid stream");

        let mut passwords = Vec::new();
        while let Some(item) = stream.next().await {
            passwords.push(item.expect("valid").password.unwrap_or_default());
        }

        assert_eq!(
            passwords,
            vec![
                "Summer".to_string(),
                "summer!".to_string(),
                "SUMMER".to_string()
            ]
        );
    }
}
