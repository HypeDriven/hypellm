//! Violation records and the report that carries them.
//!
//! Specification 4 makes the dependency policy a *build* property, not a
//! convention: the release profile "fails if crates.io dependencies, build
//! scripts, procedural macros, dynamic loading, or generated network fetches
//! are present". A finding is therefore an error, never a warning — the report
//! decides the process exit status and nothing downgrades it.

use std::fmt;
use std::path::{Path, PathBuf};

/// A single policy violation, anchored to the file that caused it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Finding {
    /// Stable rule identifier, e.g. `no-registry-dependencies`.
    pub(crate) rule: &'static str,
    /// Repository-relative path of the offending file.
    pub(crate) path: PathBuf,
    /// 1-indexed line, when the rule can attribute one.
    pub(crate) line: Option<usize>,
    /// Human-readable explanation, including the specification reference.
    pub(crate) detail: String,
}

impl Finding {
    /// A finding attributed to a whole file.
    pub(crate) fn file(rule: &'static str, path: impl Into<PathBuf>, detail: impl Into<String>) -> Self {
        Self { rule, path: path.into(), line: None, detail: detail.into() }
    }

    /// A finding attributed to a specific line.
    pub(crate) fn at(
        rule: &'static str,
        path: impl Into<PathBuf>,
        line: usize,
        detail: impl Into<String>,
    ) -> Self {
        Self { rule, path: path.into(), line: Some(line), detail: detail.into() }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(n) => write!(f, "{}:{}: [{}] {}", self.path.display(), n, self.rule, self.detail),
            None => write!(f, "{}: [{}] {}", self.path.display(), self.rule, self.detail),
        }
    }
}

/// The outcome of a scan: which rules ran, and what they found.
#[derive(Debug, Default)]
pub(crate) struct Report {
    findings: Vec<Finding>,
    rules_run: Vec<&'static str>,
    files_examined: usize,
}

impl Report {
    /// An empty report.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record that a rule executed. Rules are listed even when they find
    /// nothing, so the report distinguishes "clean" from "never checked".
    pub(crate) fn ran(&mut self, rule: &'static str) {
        if !self.rules_run.contains(&rule) {
            self.rules_run.push(rule);
        }
    }

    /// Add a violation.
    pub(crate) fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Note that `n` more files were read.
    pub(crate) fn examined(&mut self, n: usize) {
        self.files_examined = self.files_examined.saturating_add(n);
    }

    /// Whether the repository satisfies the policy.
    #[must_use]
    pub(crate) fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// The recorded violations, ordered by rule then path.
    #[must_use]
    pub(crate) fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// The rules that executed.
    #[must_use]
    pub(crate) fn rules_run(&self) -> &[&'static str] {
        &self.rules_run
    }

    /// How many files were read.
    #[must_use]
    pub(crate) fn files_examined(&self) -> usize {
        self.files_examined
    }

    /// Sort findings into a stable order so output is diffable across runs.
    pub(crate) fn sort(&mut self) {
        self.findings.sort();
    }

    /// Merge another report into this one.
    pub(crate) fn absorb(&mut self, other: Report) {
        for rule in other.rules_run {
            self.ran(rule);
        }
        self.files_examined = self.files_examined.saturating_add(other.files_examined);
        self.findings.extend(other.findings);
    }
}

/// Render a path relative to the repository root for display.
pub(crate) fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_report_is_clean() {
        let report = Report::new();
        assert!(report.is_clean());
        assert_eq!(report.findings().len(), 0);
    }

    #[test]
    fn a_report_with_a_finding_is_not_clean() {
        let mut report = Report::new();
        report.push(Finding::file("rule", "a.rs", "detail"));
        assert!(!report.is_clean());
    }

    #[test]
    fn rules_are_recorded_once_even_when_they_find_nothing() {
        let mut report = Report::new();
        report.ran("rule-a");
        report.ran("rule-a");
        report.ran("rule-b");
        assert_eq!(report.rules_run(), &["rule-a", "rule-b"]);
        assert!(report.is_clean());
    }

    #[test]
    fn findings_render_with_and_without_a_line() {
        let with_line = Finding::at("r", "a.rs", 12, "boom");
        let without = Finding::file("r", "a.rs", "boom");
        assert_eq!(with_line.to_string(), "a.rs:12: [r] boom");
        assert_eq!(without.to_string(), "a.rs: [r] boom");
    }

    #[test]
    fn sorting_is_stable_and_groups_by_rule() {
        let mut report = Report::new();
        report.push(Finding::file("z-rule", "a.rs", "d"));
        report.push(Finding::file("a-rule", "b.rs", "d"));
        report.sort();
        assert_eq!(report.findings()[0].rule, "a-rule");
    }

    #[test]
    fn absorbing_merges_findings_rules_and_counts() {
        let mut a = Report::new();
        a.ran("rule-a");
        a.examined(2);
        let mut b = Report::new();
        b.ran("rule-b");
        b.examined(3);
        b.push(Finding::file("rule-b", "x.rs", "d"));
        a.absorb(b);
        assert_eq!(a.rules_run(), &["rule-a", "rule-b"]);
        assert_eq!(a.files_examined(), 5);
        assert!(!a.is_clean());
    }

    #[test]
    fn relative_strips_the_repository_root() {
        let root = Path::new("/repo");
        assert_eq!(relative(root, Path::new("/repo/crates/a.rs")), Path::new("crates/a.rs"));
        assert_eq!(relative(root, Path::new("/elsewhere/a.rs")), Path::new("/elsewhere/a.rs"));
    }
}
