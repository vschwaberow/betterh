// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 by Volker Schwaberow <volker@schwaberow.de>

//! Wordlist mutation rules and candidate generation engine ($O(1)$ memory).
//!
//! Provides a streaming Hashcat-compatible rule interpreter (`:` `c` `l` `u` `$X` `^X` `sXY` `<N` `>N`)
//! and deterministic seasonal and year password pattern generators.

use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MutationError {
    #[error("Rule I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid rule syntax on line {line}: {reason}")]
    InvalidRule { line: usize, reason: String },
}

/// A discrete mutation operator applied to a candidate string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOp {
    /// No operation (identity).
    Noop,
    /// Convert all characters to lowercase.
    Lowercase,
    /// Convert all characters to uppercase.
    Uppercase,
    /// Capitalize first character, lowercase remainder.
    Capitalize,
    /// Invert capitalization: lowercase first character, uppercase remainder.
    InvertCapitalize,
    /// Toggle case of all characters.
    ToggleCase,
    /// Reverse the string.
    Reverse,
    /// Duplicate word (`pass` -> `passpass`).
    Duplicate,
    /// Reflect / mirror word (`pass` -> `passssap`).
    Reflect,
    /// Append a character (`$X`).
    Append(char),
    /// Prepend a character (`^X`).
    Prepend(char),
    /// Delete first character (`[`).
    TruncateLeft,
    /// Delete last character (`]`).
    TruncateRight,
    /// Rotate string left (`{`).
    RotateLeft,
    /// Rotate string right (`}`).
    RotateRight,
    /// Substitute all occurrences of target char with replacement char (`sXY`).
    Substitute(char, char),
    /// Reject candidate if length is less than $N$ (`<N`).
    RejectShorter(usize),
    /// Reject candidate if length is greater than $N$ (`>N`).
    RejectLonger(usize),
}

/// A sequence of mutation operations applied to a word.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    ops: Vec<RuleOp>,
}

impl Rule {
    /// Create a new rule with the given operators.
    #[must_use]
    pub fn new(ops: Vec<RuleOp>) -> Self {
        Self { ops }
    }

    /// Parse a single line from a Hashcat-compatible rule file.
    ///
    /// Empty lines and `#` comments return `Ok(None)`.
    ///
    /// # Errors
    /// Returns [`MutationError::InvalidRule`] on malformed rule operators.
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustive character-by-character Hashcat rule parser"
    )]
    pub fn parse(line: &str, line_num: usize) -> Result<Option<Self>, MutationError> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Ok(None);
        }

        let mut ops = Vec::new();
        let chars: Vec<char> = trimmed.chars().collect();
        let mut idx = 0;

        while idx < chars.len() {
            let ch = chars[idx];
            if ch.is_whitespace() {
                idx += 1;
                continue;
            }

            match ch {
                ':' => {
                    ops.push(RuleOp::Noop);
                    idx += 1;
                }
                'l' => {
                    ops.push(RuleOp::Lowercase);
                    idx += 1;
                }
                'u' => {
                    ops.push(RuleOp::Uppercase);
                    idx += 1;
                }
                'c' => {
                    ops.push(RuleOp::Capitalize);
                    idx += 1;
                }
                'C' => {
                    ops.push(RuleOp::InvertCapitalize);
                    idx += 1;
                }
                't' => {
                    ops.push(RuleOp::ToggleCase);
                    idx += 1;
                }
                'r' => {
                    ops.push(RuleOp::Reverse);
                    idx += 1;
                }
                'd' => {
                    ops.push(RuleOp::Duplicate);
                    idx += 1;
                }
                'f' => {
                    ops.push(RuleOp::Reflect);
                    idx += 1;
                }
                '[' => {
                    ops.push(RuleOp::TruncateLeft);
                    idx += 1;
                }
                ']' => {
                    ops.push(RuleOp::TruncateRight);
                    idx += 1;
                }
                '{' => {
                    ops.push(RuleOp::RotateLeft);
                    idx += 1;
                }
                '}' => {
                    ops.push(RuleOp::RotateRight);
                    idx += 1;
                }
                '$' => {
                    idx += 1;
                    if idx >= chars.len() {
                        return Err(MutationError::InvalidRule {
                            line: line_num,
                            reason: "Operator '$' requires an append character".into(),
                        });
                    }
                    ops.push(RuleOp::Append(chars[idx]));
                    idx += 1;
                }
                '^' => {
                    idx += 1;
                    if idx >= chars.len() {
                        return Err(MutationError::InvalidRule {
                            line: line_num,
                            reason: "Operator '^' requires a prepend character".into(),
                        });
                    }
                    ops.push(RuleOp::Prepend(chars[idx]));
                    idx += 1;
                }
                's' => {
                    idx += 1;
                    if idx + 1 >= chars.len() {
                        return Err(MutationError::InvalidRule {
                            line: line_num,
                            reason: "Operator 's' requires two characters: target and replacement"
                                .into(),
                        });
                    }
                    let target = chars[idx];
                    let replacement = chars[idx + 1];
                    ops.push(RuleOp::Substitute(target, replacement));
                    idx += 2;
                }
                '<' | '>' => {
                    let is_shorter = ch == '<';
                    idx += 1;
                    let num_start = idx;
                    while idx < chars.len() && chars[idx].is_ascii_digit() {
                        idx += 1;
                    }
                    if num_start == idx {
                        return Err(MutationError::InvalidRule {
                            line: line_num,
                            reason: format!("Operator '{ch}' requires an integer length threshold"),
                        });
                    }
                    let num_str: String = chars[num_start..idx].iter().collect();
                    let n = num_str
                        .parse::<usize>()
                        .map_err(|_| MutationError::InvalidRule {
                            line: line_num,
                            reason: format!("Invalid length threshold '{num_str}'"),
                        })?;
                    if is_shorter {
                        ops.push(RuleOp::RejectShorter(n));
                    } else {
                        ops.push(RuleOp::RejectLonger(n));
                    }
                }
                other => {
                    return Err(MutationError::InvalidRule {
                        line: line_num,
                        reason: format!("Unknown rule operator '{other}'"),
                    });
                }
            }
        }

        Ok(Some(Self { ops }))
    }

    /// Apply the rule operators sequentially to the given input string.
    ///
    /// Returns `None` if a length constraint (`<N` or `>N`) rejects the candidate.
    #[must_use]
    pub fn apply(&self, input: &str) -> Option<String> {
        let mut cur = input.to_owned();

        for op in &self.ops {
            match *op {
                RuleOp::Noop => {}
                RuleOp::Lowercase => {
                    cur = cur.to_lowercase();
                }
                RuleOp::Uppercase => {
                    cur = cur.to_uppercase();
                }
                RuleOp::Capitalize => {
                    cur = capitalize_word(&cur);
                }
                RuleOp::InvertCapitalize => {
                    cur = invert_capitalize_word(&cur);
                }
                RuleOp::ToggleCase => {
                    cur = cur
                        .chars()
                        .map(|c| {
                            if c.is_lowercase() {
                                c.to_uppercase().collect::<String>()
                            } else {
                                c.to_lowercase().collect::<String>()
                            }
                        })
                        .collect();
                }
                RuleOp::Reverse => {
                    cur = cur.chars().rev().collect();
                }
                RuleOp::Duplicate => {
                    let dup = cur.clone();
                    cur.push_str(&dup);
                }
                RuleOp::Reflect => {
                    let rev: String = cur.chars().rev().collect();
                    cur.push_str(&rev);
                }
                RuleOp::Append(ch) => {
                    cur.push(ch);
                }
                RuleOp::Prepend(ch) => {
                    let mut next = String::with_capacity(cur.len() + ch.len_utf8());
                    next.push(ch);
                    next.push_str(&cur);
                    cur = next;
                }
                RuleOp::TruncateLeft => {
                    let mut chars = cur.chars();
                    chars.next();
                    cur = chars.collect();
                }
                RuleOp::TruncateRight => {
                    let mut chars: Vec<char> = cur.chars().collect();
                    if !chars.is_empty() {
                        chars.pop();
                        cur = chars.into_iter().collect();
                    }
                }
                RuleOp::RotateLeft => {
                    let mut chars: Vec<char> = cur.chars().collect();
                    if chars.len() > 1 {
                        let first = chars.remove(0);
                        chars.push(first);
                        cur = chars.into_iter().collect();
                    }
                }
                RuleOp::RotateRight => {
                    let mut chars: Vec<char> = cur.chars().collect();
                    if chars.len() > 1 {
                        let last = chars.remove(chars.len() - 1);
                        chars.insert(0, last);
                        cur = chars.into_iter().collect();
                    }
                }
                RuleOp::Substitute(target, replacement) => {
                    cur = cur
                        .chars()
                        .map(|c| if c == target { replacement } else { c })
                        .collect();
                }
                RuleOp::RejectShorter(min_len) => {
                    if cur.chars().count() < min_len {
                        return None;
                    }
                }
                RuleOp::RejectLonger(max_len) => {
                    if cur.chars().count() > max_len {
                        return None;
                    }
                }
            }
        }

        Some(cur)
    }
}

/// A parsed collection of mutation rules loaded from a rule file or built-in profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl std::str::FromStr for RuleSet {
    type Err = MutationError;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let mut rules = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            if let Some(rule) = Rule::parse(line, idx + 1)? {
                rules.push(rule);
            }
        }
        Ok(Self { rules })
    }
}

impl RuleSet {
    /// Create an empty rule set.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Number of rules in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the rule set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Slice of parsed rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Load and parse a rule file from the filesystem.
    ///
    /// # Errors
    /// Returns [`MutationError::Io`] on read failure or [`MutationError::InvalidRule`] on syntax error.
    pub fn from_file(path: &Path) -> Result<Self, MutationError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut rules = Vec::new();

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            if let Some(rule) = Rule::parse(&line, idx + 1)? {
                rules.push(rule);
            }
        }

        Ok(Self { rules })
    }

    /// Apply all rules in the set to the given input string, yielding only un-rejected outputs.
    ///
    /// If the rule set is empty, yields the original input string once.
    #[must_use]
    pub fn apply_to<'a>(&'a self, input: &'a str) -> Box<dyn Iterator<Item = String> + 'a> {
        if self.rules.is_empty() {
            Box::new(std::iter::once(input.to_owned()))
        } else {
            Box::new(self.rules.iter().filter_map(move |rule| rule.apply(input)))
        }
    }
}

/// Capitalize first character of string, lowercase the rest.
#[must_use]
pub fn capitalize_word(word: &str) -> String {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = first.to_uppercase().collect::<String>();
    out.push_str(&chars.as_str().to_lowercase());
    out
}

/// Capitalize only the first character, preserving the case of the remainder.
#[must_use]
pub fn capitalize_first_only(word: &str) -> String {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = first.to_uppercase().collect::<String>();
    out.push_str(chars.as_str());
    out
}

/// Invert capitalize: lowercase first character, uppercase remainder.
#[must_use]
pub fn invert_capitalize_word(word: &str) -> String {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = first.to_lowercase().collect::<String>();
    out.push_str(&chars.as_str().to_uppercase());
    out
}

/// Generate year-based password candidate variants for a given base word (`-e y`).
#[must_use]
pub fn generate_year_candidates(base: &str, current_year: i32) -> Vec<String> {
    let prev_year = current_year.saturating_sub(1);
    let cap = capitalize_first_only(base);

    let mut out = Vec::with_capacity(16);
    // base2026, base2025
    out.push(format!("{base}{current_year}"));
    out.push(format!("{base}{prev_year}"));
    // base2026!, base2025!
    out.push(format!("{base}{current_year}!"));
    out.push(format!("{base}{prev_year}!"));
    // base2026@, base2026#
    out.push(format!("{base}{current_year}@"));
    out.push(format!("{base}{current_year}#"));
    // Base2026!, Base2025!
    if cap != base {
        out.push(format!("{cap}{current_year}"));
        out.push(format!("{cap}{current_year}!"));
        out.push(format!("{cap}{prev_year}!"));
    }
    // base123, base123!
    out.push(format!("{base}123"));
    out.push(format!("{base}123!"));

    out
}

/// Generate seasonal quarterly password candidate variants (`-e c`).
#[must_use]
pub fn generate_season_candidates(current_year: i32) -> Vec<String> {
    let prev_year = current_year.saturating_sub(1);
    let seasons = [
        "Winter",
        "Spring",
        "Summer",
        "Autumn",
        "Fall",
        // German variants
        "Fruehling",
        "Frühling",
        "Sommer",
        "Herbst",
    ];

    let mut out = Vec::with_capacity(seasons.len() * 4);
    for season in seasons {
        // Season2026!
        out.push(format!("{season}{current_year}!"));
        // Season2026#
        out.push(format!("{season}{current_year}#"));
        // Season2026
        out.push(format!("{season}{current_year}"));
        // Season2025!
        out.push(format!("{season}{prev_year}!"));
    }

    out
}

/// Generate common leet-speak substitutions for a base string (`-e l`).
#[must_use]
pub fn generate_leet_candidates(base: &str) -> Vec<String> {
    let mut out = Vec::new();

    // Vowel-focused leet: a->@, o->0, i/l->1, e->3 (keeps consonants intact, e.g. "p@ssw0rd")
    let v_vowels: String = base
        .chars()
        .map(|c| match c {
            'a' | 'A' => '@',
            'o' | 'O' => '0',
            'i' | 'I' | 'l' | 'L' => '1',
            'e' | 'E' => '3',
            other => other,
        })
        .collect();

    if v_vowels != base {
        out.push(v_vowels);
    }

    // Full symbol leet: a->@, o->0, i/l->1, e->3, s->$ (e.g. "p@$$w0rd")
    let v_full: String = base
        .chars()
        .map(|c| match c {
            'a' | 'A' => '@',
            'o' | 'O' => '0',
            'i' | 'I' | 'l' | 'L' => '1',
            'e' | 'E' => '3',
            's' | 'S' => '$',
            other => other,
        })
        .collect();

    if v_full != base && !out.contains(&v_full) {
        out.push(v_full);
    }

    // Numeric leet: a->4, e->3, i->1, o->0, s->5 (e.g. "p455w0rd")
    let v_num: String = base
        .chars()
        .map(|c| match c {
            'a' | 'A' => '4',
            'e' | 'E' => '3',
            'i' | 'I' | 'l' | 'L' => '1',
            'o' | 'O' => '0',
            's' | 'S' => '5',
            other => other,
        })
        .collect();

    if v_num != base && !out.contains(&v_num) {
        out.push(v_num);
    }

    // Exclamation leet: i/l->!, s->5
    let v_excl: String = base
        .chars()
        .map(|c| match c {
            'i' | 'I' | 'l' | 'L' => '!',
            's' | 'S' => '$',
            'a' | 'A' => '@',
            'o' | 'O' => '0',
            'e' | 'E' => '3',
            other => other,
        })
        .collect();

    if v_excl != base && !out.contains(&v_excl) {
        out.push(v_excl);
    }

    out
}

/// Resolve the base year for year and seasonal password generation.
///
/// Uses `override_year` if provided; otherwise determines current UTC year from system time.
#[must_use]
pub fn resolve_rule_year(override_year: Option<i32>) -> i32 {
    if let Some(year) = override_year {
        return year;
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let Ok(days_i64) = i64::try_from(secs / 86400) else {
        return 2026;
    };
    let days = days_i64 + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let Ok(doe) = u32::try_from(days - era * 146_097) else {
        return 2026;
    };
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    i32::try_from(y).unwrap_or(2026)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_system_and_override_rule_year() {
        assert_eq!(resolve_rule_year(Some(2030)), 2030);
        let current = resolve_rule_year(None);
        assert!(current >= 2026);
    }

    #[test]
    fn parses_and_executes_hashcat_rule_ops() {
        let rule = Rule::parse("c $! $1", 1)
            .expect("valid rule")
            .expect("some");
        assert_eq!(rule.apply("password"), Some("Password!1".into()));

        let lower = Rule::parse("l", 2).expect("valid").expect("some");
        assert_eq!(lower.apply("PASSword"), Some("password".into()));

        let upper = Rule::parse("u", 3).expect("valid").expect("some");
        assert_eq!(upper.apply("pass"), Some("PASS".into()));

        let rev = Rule::parse("r", 4).expect("valid").expect("some");
        assert_eq!(rev.apply("admin"), Some("nimda".into()));

        let dup = Rule::parse("d", 5).expect("valid").expect("some");
        assert_eq!(dup.apply("pass"), Some("passpass".into()));

        let ref_op = Rule::parse("f", 6).expect("valid").expect("some");
        assert_eq!(ref_op.apply("abc"), Some("abccba".into()));

        let prepend = Rule::parse("^!", 7).expect("valid").expect("some");
        assert_eq!(prepend.apply("secret"), Some("!secret".into()));

        let subst = Rule::parse("sa@", 8).expect("valid").expect("some");
        assert_eq!(subst.apply("banana"), Some("b@n@n@".into()));

        let trunc = Rule::parse("[ ]", 9).expect("valid").expect("some");
        assert_eq!(trunc.apply("hello"), Some("ell".into()));

        let rot = Rule::parse("{", 10).expect("valid").expect("some");
        assert_eq!(rot.apply("abcd"), Some("bcda".into()));

        let rot_r = Rule::parse("}", 11).expect("valid").expect("some");
        assert_eq!(rot_r.apply("abcd"), Some("dabc".into()));
    }

    #[test]
    fn enforces_length_filters() {
        let rule_min = Rule::parse("<8", 1).expect("valid").expect("some");
        assert_eq!(rule_min.apply("short"), None);
        assert_eq!(rule_min.apply("longenough"), Some("longenough".into()));

        let rule_max = Rule::parse(">10", 2).expect("valid").expect("some");
        assert_eq!(rule_max.apply("toolongfortarget"), None);
        assert_eq!(rule_max.apply("short"), Some("short".into()));
    }

    #[test]
    fn parses_multi_line_ruleset() {
        let content = "
            # Comment line
            :
            c $!
            u
            ^1 $!
        ";
        let ruleset: RuleSet = content.parse().expect("valid ruleset");
        assert_eq!(ruleset.len(), 4);

        let results: Vec<String> = ruleset.apply_to("admin").collect();
        assert_eq!(results, vec!["admin", "Admin!", "ADMIN", "1admin!",]);
    }

    #[test]
    fn generates_seasonal_candidates() {
        let seasons = generate_season_candidates(2026);
        assert!(seasons.contains(&"Winter2026!".to_string()));
        assert!(seasons.contains(&"Spring2026!".to_string()));
        assert!(seasons.contains(&"Sommer2026!".to_string()));
        assert!(seasons.contains(&"Winter2025!".to_string()));
    }

    #[test]
    fn generates_year_candidates() {
        let years = generate_year_candidates("admin", 2026);
        assert!(years.contains(&"admin2026!".to_string()));
        assert!(years.contains(&"admin2025!".to_string()));
        assert!(years.contains(&"Admin2026!".to_string()));
        assert!(years.contains(&"admin123".to_string()));
    }

    #[test]
    fn generates_leet_candidates() {
        let leet = generate_leet_candidates("password");
        assert!(leet.contains(&"p@ssw0rd".to_string()));

        let admin_leet = generate_leet_candidates("admin");
        assert!(admin_leet.contains(&"@dm1n".to_string()));
    }

    #[test]
    fn rejects_malformed_syntax() {
        assert!(Rule::parse("$", 1).is_err());
        assert!(Rule::parse("^", 2).is_err());
        assert!(Rule::parse("sa", 3).is_err());
        assert!(Rule::parse("<", 4).is_err());
        assert!(Rule::parse("unknown", 5).is_err());
    }
}
