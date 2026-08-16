//! Policy rules over the Rust workspace.
//!
//! Specification 4: the production router "MUST NOT download, resolve, or
//! execute third-party packages… The release profile builds with --offline
//! against the repository and fails if crates.io dependencies, build scripts,
//! procedural macros, dynamic loading, or generated network fetches are
//! present."
//!
//! Specification 4.1 adds the per-module obligations: an owner, threat notes,
//! public API, unsafe-code declaration, fuzz targets, and resource limits, plus
//! "No build.rs, proc macros, dlopen/LoadLibrary, shell execution,
//! environment-variable interpolation in configuration, or implicit file
//! discovery."
//!
//! Each rule below names the clause it enforces.

use crate::findings::{Finding, Report, relative};
use crate::manifest::{self, DepSpec, Manifest};
use crate::walk;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Source constructs specification 4.1 forbids outright.
///
/// The match is textual, over source with line comments removed. A textual
/// match is the right conservatism here: this is a gate, and a construct that
/// appears in a string literal still deserves a human explanation.
const FORBIDDEN: &[(&str, &str)] = &[
    ("dlopen", "dynamic library loading"),
    ("dlsym", "dynamic symbol resolution"),
    ("LoadLibrary", "dynamic library loading"),
    ("libloading", "dynamic library loading"),
    ("process::Command", "shell or subprocess execution"),
    ("std::process::exit", "process exit outside the startup path"),
];

/// The one file exempt from [`FORBIDDEN`], because it *is* the list.
///
/// A scanner cannot contain the patterns it searches for without matching
/// itself. The exemption is a single named file rather than a directory or a
/// magic comment, so it cannot silently widen; `the_self_exemption_is_exactly_one_file`
/// asserts that below.
const FORBIDDEN_SELF_EXEMPT: &[&str] = &["crates/hypellm-devtools/src/rust_scan.rs"];

/// Run every Rust-side rule against the repository rooted at `root`.
pub(crate) fn scan(root: &Path) -> std::io::Result<Report> {
    let mut report = Report::new();

    let workspace_text = walk::read_text(&root.join("Cargo.toml"))?;
    let workspace = manifest::parse(&root.join("Cargo.toml"), &workspace_text);

    let members = member_manifests(root, &workspace, &mut report);
    check_manifests(root, &workspace, &members, &mut report);
    check_workspace_membership(root, &workspace, &mut report);
    check_build_scripts(root, &workspace, &mut report);
    check_module_documentation(root, &workspace, &mut report);
    check_dependencies_are_used(root, &members, &mut report)?;
    check_test_scaffolding_gated(root, &workspace, &members, &mut report)?;
    check_lint_escalation_scoped(root, &workspace, &mut report)?;
    check_sources(root, &mut report)?;

    Ok(report)
}

/// Read every member manifest.
///
/// A manifest that cannot be read is reported rather than skipped: silently
/// dropping it would let an unreadable — or deliberately unreadable — crate
/// pass the scan by being invisible to it.
fn member_manifests(root: &Path, workspace: &Manifest, report: &mut Report) -> Vec<Manifest> {
    report.ran("manifest-readable");
    let mut out = Vec::new();
    for member in &workspace.workspace_members {
        let path = root.join(member).join("Cargo.toml");
        match walk::read_text(&path) {
            Ok(text) => out.push(manifest::parse(&path, &text)),
            Err(error) => report.push(Finding::file(
                "manifest-readable",
                relative(root, &path),
                format!(
                    "declared workspace member could not be read ({error}); an unreadable \
                     manifest cannot be certified"
                ),
            )),
        }
    }
    out
}

/// Rule `no-registry-dependencies`, `no-proc-macros`, `manifest-understood`.
/// Every `[dependencies]` entry must be referenced by that crate's `src`.
///
/// Specification 4.1 requires each module to declare its dependencies
/// accurately, and an overstated declaration is not a supply-chain risk — every
/// dependency here is workspace-local — but it makes the dependency graph a
/// worse guide to what a change can affect, which is the graph a reviewer uses
/// to decide how far to look.
///
/// Only `[dependencies]` is checked. A `[dev-dependencies]` entry is used by
/// `tests/` and `benches/`, which this scan does not read, and a
/// `[build-dependencies]` entry cannot exist at all (specification 4.1 forbids
/// build scripts, enforced by `no-build-scripts`).
///
/// The reference test is textual — `name::`, `use name`, or `extern crate name`
/// with the hyphens of the package name replaced by underscores. That can be
/// fooled by a mention inside a comment or a string, which is the safe
/// direction to be wrong in: it under-reports rather than failing a build over
/// a dependency that is genuinely used in a form this does not recognise.
fn check_dependencies_are_used(
    root: &Path,
    members: &[Manifest],
    report: &mut Report,
) -> std::io::Result<()> {
    report.ran("dependencies-are-used");

    for manifest in members {
        let Some(dir) = manifest.path.parent() else {
            continue;
        };
        let src = dir.join("src");
        if !src.is_dir() {
            continue;
        }

        let mut sources = String::new();
        for file in walk::files(&src)? {
            if !walk::has_extension(&file, "rs") {
                continue;
            }
            sources.push_str(&walk::read_text(&file)?);
            sources.push('\n');
        }

        for dependency in &manifest.dependencies {
            if dependency.section != "dependencies" {
                continue;
            }
            let ident = dependency.name.replace('-', "_");
            let referenced = sources.contains(&format!("{ident}::"))
                || sources.contains(&format!("use {ident}"))
                || sources.contains(&format!("extern crate {ident}"));
            if !referenced {
                report.push(Finding::at(
                    "dependencies-are-used",
                    relative(root, &manifest.path),
                    dependency.line,
                    format!(
                        "`{}` is declared but never referenced from this crate's src; drop it, \
                         or move it to [dev-dependencies] if only tests use it",
                        dependency.name
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Test scaffolding must sit behind the `test-harness` feature.
///
/// Specification 18.2 permits `unwrap`/`expect` in tests and nowhere else, and
/// specification 4.1 requires a module to declare its public surface. A `pub mod
/// testing` with no gate puts fixture builders, fake upstreams, and a
/// hard-coded store MAC key into the library every other crate links — which is
/// how `expect` and a fixed key end up one `use` away from production code.
///
/// The check is deliberately narrow and syntactic: any `pub mod` whose name
/// says it is scaffolding must be preceded by a `cfg` naming `test-harness`.
/// It cannot tell whether the *contents* are scaffolding, so it governs the
/// names that unambiguously are.
fn check_test_scaffolding_gated(
    root: &Path,
    workspace: &Manifest,
    members: &[Manifest],
    report: &mut Report,
) -> std::io::Result<()> {
    report.ran("test-scaffolding-gated");
    const SCAFFOLDING: &[&str] = &["testing", "tempdir", "harness", "fixtures"];

    // A crate nothing depends on outside `[dev-dependencies]` cannot reach a
    // production build at all, so gating its scaffolding would be ceremony.
    // Computed rather than listed, because an exemption list is a place for
    // things to hide: the day someone adds a real dependency on the corpus
    // crate, this rule starts governing it without anyone remembering to.
    let reachable_from_production: Vec<&str> = members
        .iter()
        .flat_map(|m| m.dependencies.iter())
        .filter(|d| d.section == "dependencies")
        .map(|d| d.name.as_str())
        .collect();

    for member in &workspace.workspace_members {
        let package = members
            .iter()
            .find(|m| m.path.parent().is_some_and(|p| p.ends_with(member)))
            .and_then(|m| m.package_name.as_deref());
        if let Some(name) = package {
            if !reachable_from_production.contains(&name) {
                continue;
            }
        }
        let lib = root.join(member).join("src").join("lib.rs");
        if !lib.is_file() {
            continue;
        }
        let text = walk::read_text(&lib)?;
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("pub mod ") else {
                continue;
            };
            let name = rest.trim_end_matches(';').trim();
            if !SCAFFOLDING.contains(&name) {
                continue;
            }
            let gated = index
                .checked_sub(1)
                .and_then(|prev| lines.get(prev))
                .is_some_and(|prev| prev.contains("cfg(") && prev.contains("test-harness"));
            if !gated {
                report.push(Finding::at(
                    "test-scaffolding-gated",
                    relative(root, &lib),
                    index.saturating_add(1),
                    format!(
                        "`pub mod {name}` is test scaffolding and must be preceded by \
                         `#[cfg(any(test, feature = \"test-harness\"))]`, or it ships in \
                         the library every other crate links"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// A crate-root clippy escalation must exempt `cfg(test)`, one way or another.
///
/// Specification 18.2 forbids `unwrap`/`expect`/unchecked indexing "outside
/// startup invariants and **tests**", so `cfg(test)` is precisely the code the
/// escalation should not govern. An escalation that also governs assertions —
/// where a panic *is* the mechanism — made the documented
/// `cargo clippy --all-targets` gate fail on 66 test assertions. A gate that
/// always fails is a gate nobody runs, so the escalation achieved the opposite
/// of its intent.
///
/// Two spellings satisfy this and both are accepted, because they differ in
/// what they leave behind in the test build:
///
/// - `#![cfg_attr(not(test), deny(L))]` — the lint is off entirely in tests.
/// - `#![deny(L)]` plus `#![cfg_attr(test, warn(L))]` or `allow(L)` — `warn`
///   keeps the signal visible in tests, which is strictly nicer where the test
///   code can reasonably avoid the construct.
///
/// What is not accepted is a denied lint with no `cfg(test)` relaxation at all,
/// **or a relaxation that has drifted out of sync with the deny list** — three
/// lints denied and two relaxed silently reintroduces the failure for the
/// third. That drift is the reason this is mechanical rather than a note: it is
/// invisible in review, and the stricter-looking spelling is the broken one.
fn check_lint_escalation_scoped(
    root: &Path,
    workspace: &Manifest,
    report: &mut Report,
) -> std::io::Result<()> {
    report.ran("lint-escalation-scoped");

    for member in &workspace.workspace_members {
        for entry in ["lib.rs", "main.rs"] {
            let file = root.join(member).join("src").join(entry);
            if !file.is_file() {
                continue;
            }
            let text = walk::read_text(&file)?;
            let denied = clippy_lints_in(&text, "#![deny(");
            if denied.is_empty() {
                continue;
            }
            // Everything the file relaxes under `cfg(test)`, by either
            // spelling. `deny` inside a `cfg_attr(not(test), ...)` is not a
            // bare deny and never reaches `denied` in the first place, because
            // the scan keys on the `#![deny(` opener.
            let relaxed = clippy_lints_in(&text, "#![cfg_attr(");

            for (line, lint) in denied {
                if relaxed.iter().any(|(_, r)| *r == lint) {
                    continue;
                }
                report.push(Finding::at(
                    "lint-escalation-scoped",
                    relative(root, &file),
                    line,
                    format!(
                        "`{lint}` is denied at the crate root with no `cfg(test)` \
                         relaxation — specification 18.2 permits these constructs in \
                         tests, so this fails `cargo clippy --all-targets` on assertions. \
                         Write `#![cfg_attr(not(test), deny(...))]`, or add the lint to a \
                         `#![cfg_attr(test, warn(...))]` beside the deny"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Clippy lint names appearing in the attribute that starts with `opener`.
///
/// Deliberately syntactic: it reads the inner attribute that begins with
/// `opener` and collects every `clippy::name` token until the attribute's
/// closing line, so it handles both the one-line and the multi-line spelling
/// without a parser. The line number reported is the lint's own line, which is
/// what a reader needs to fix it.
fn clippy_lints_in(text: &str, opener: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut depth = 0usize;

    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if depth == 0 && !trimmed.starts_with(opener) {
            continue;
        }
        if depth == 0 {
            depth = 1;
        }
        for token in trimmed.split(|c: char| !c.is_alphanumeric() && c != ':' && c != '_') {
            if let Some(name) = token.strip_prefix("clippy::") {
                if !name.is_empty() {
                    found.push((index.saturating_add(1), name.to_owned()));
                }
            }
        }
        // The attribute ends on the line whose brackets balance back to zero.
        // Counting both is what lets a nested `cfg_attr(test, warn(...))` close
        // correctly rather than swallowing the rest of the file.
        let opens = trimmed.matches('(').count();
        let closes = trimmed.matches(')').count();
        depth = depth.saturating_add(opens).saturating_sub(closes);
        if trimmed.ends_with(")]") && depth <= 1 {
            depth = 0;
        }
    }
    found
}

fn check_manifests(root: &Path, workspace: &Manifest, members: &[Manifest], report: &mut Report) {
    report.ran("no-registry-dependencies");
    report.ran("no-proc-macros");
    report.ran("manifest-understood");
    report.ran("no-source-rewrites");

    for manifest in std::iter::once(workspace).chain(members.iter()) {
        let shown = relative(root, &manifest.path);

        for (line, name) in &manifest.source_rewrites {
            report.push(Finding::at(
                "no-source-rewrites",
                &shown,
                *line,
                format!(
                    "`[{name}]` redirects dependency resolution without appearing in any \
                     dependency table; specification 4 admits only workspace-local paths"
                ),
            ));
        }

        for (line, text) in &manifest.unparsed {
            report.push(Finding::at(
                "manifest-understood",
                &shown,
                *line,
                format!(
                    "the dependency scanner could not classify this line, so the manifest \
                     cannot be certified: {text}"
                ),
            ));
        }

        for dep in &manifest.dependencies {
            match &dep.spec {
                DepSpec::Path(p) => {
                    let target = manifest
                        .path
                        .parent()
                        .map(|d| d.join(p))
                        .unwrap_or_else(|| PathBuf::from(p));
                    if !target.join("Cargo.toml").is_file() {
                        report.push(Finding::at(
                            "no-registry-dependencies",
                            &shown,
                            dep.line,
                            format!(
                                "`{}` has path `{p}`, but no manifest exists there; a path that \
                                 does not resolve can fall back to a registry",
                                dep.name
                            ),
                        ));
                        continue;
                    }
                    if !target.starts_with(root) {
                        report.push(Finding::at(
                            "no-registry-dependencies",
                            &shown,
                            dep.line,
                            format!(
                                "`{}` resolves to {}, which is outside the repository \
                                 (specification 4: workspace crates stored in the repository)",
                                dep.name,
                                target.display()
                            ),
                        ));
                    }
                }
                DepSpec::Unrecognized(why) => {
                    report.push(Finding::at(
                        "no-registry-dependencies",
                        &shown,
                        dep.line,
                        format!(
                            "`{}` in [{}] is not a workspace-local path dependency ({why}); \
                             specification 4 forbids registry dependencies",
                            dep.name, dep.section
                        ),
                    ));
                }
            }
        }

        if let Some(line) = manifest.proc_macro {
            report.push(Finding::at(
                "no-proc-macros",
                &shown,
                line,
                "procedural macros are forbidden by specification 4.1",
            ));
        }
    }
}

/// Rule `workspace-members-complete`: every crate directory is a declared
/// member. An undeclared crate is not built, not linted, and not scanned.
fn check_workspace_membership(root: &Path, workspace: &Manifest, report: &mut Report) {
    report.ran("workspace-members-complete");

    let declared: BTreeSet<&str> = workspace.workspace_members.iter().map(String::as_str).collect();
    let crates_dir = root.join("crates");
    let Ok(entries) = std::fs::read_dir(&crates_dir) else {
        return;
    };

    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if entry.path().join("Cargo.toml").is_file() {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();

    for name in names {
        let expected = format!("crates/{name}");
        if !declared.contains(expected.as_str()) {
            report.push(Finding::file(
                "workspace-members-complete",
                "Cargo.toml",
                format!(
                    "`{expected}` contains a manifest but is not a workspace member, so it is \
                     never built, linted, or scanned"
                ),
            ));
        }
    }
}

/// Rule `no-build-scripts`.
///
/// Only a `build.rs` at a package root is a Cargo build script. A module named
/// `build.rs` inside `src/` is ordinary source — `hypellm-config/src/build.rs`
/// builds a validated configuration snapshot and is not a build script. The
/// rule must not confuse the two.
fn check_build_scripts(root: &Path, workspace: &Manifest, report: &mut Report) {
    report.ran("no-build-scripts");

    let roots = std::iter::once(String::new()).chain(workspace.workspace_members.iter().cloned());
    for member in roots {
        let dir = if member.is_empty() { root.to_path_buf() } else { root.join(&member) };
        let script = dir.join("build.rs");
        if script.is_file() {
            report.push(Finding::file(
                "no-build-scripts",
                relative(root, &script),
                "build scripts are forbidden by specification 4.1; they execute arbitrary code \
                 at build time",
            ));
        }

        let manifest_path = dir.join("Cargo.toml");
        if let Ok(text) = walk::read_text(&manifest_path) {
            let parsed = manifest::parse(&manifest_path, &text);
            if let Some(line) = parsed.build_key {
                report.push(Finding::at(
                    "no-build-scripts",
                    relative(root, &manifest_path),
                    line,
                    "an explicit `build` key names a build script, forbidden by specification 4.1",
                ));
            }
        }
    }
}

/// Whether a `MODULE.md` *declares* a field, rather than merely mentioning it.
///
/// Two forms are in use and both are legitimate: a row in the summary table at
/// the top (`| Owner | … |`) and a section heading (`## Threat notes`). What is
/// not accepted is the word appearing in prose — this rule used to be a bare
/// `contains`, which meant a file discussing its "Limits" in a sentence
/// satisfied the requirement to declare them, and the check for that field
/// could never fail.
fn declares(text: &str, field: &str) -> bool {
    text.lines().any(|line| {
        let trimmed = line.trim();
        // `## Field`, at any heading depth.
        let heading = trimmed
            .trim_start_matches('#')
            .trim_start()
            .eq_ignore_ascii_case(field);
        let is_heading = trimmed.starts_with('#') && heading;
        // `| Field | value |`, the summary-table form.
        let is_row = trimmed.starts_with('|')
            && trimmed
                .split('|')
                .nth(1)
                .is_some_and(|cell| cell.trim().eq_ignore_ascii_case(field));
        is_heading || is_row
    })
}

/// Rule `module-documentation`: specification 4.1 requires every in-repository
/// module to declare owner, threat notes, public API, unsafe-code status, fuzz
/// targets, and limits.
fn check_module_documentation(root: &Path, workspace: &Manifest, report: &mut Report) {
    report.ran("module-documentation");

    // All six specification 4.1 names, not a subset. This rule used to check
    // three of them while its own failure message quoted all six — so a new
    // crate could ship with no threat notes, no declared public API, and no
    // resource limits, and the gate would pass it. Every existing module
    // already carries the other three; enforcing them costs nothing now and
    // stops the next crate from being the exception.
    const REQUIRED_HEADINGS: &[&str] = &[
        "Owner",
        "Threat notes",
        "Public API",
        "Unsafe code",
        "Fuzz targets",
        "Limits",
    ];

    for member in &workspace.workspace_members {
        let doc = root.join(member).join("MODULE.md");
        if !doc.is_file() {
            report.push(Finding::file(
                "module-documentation",
                format!("{member}/MODULE.md"),
                "specification 4.1 requires each module to declare an owner, threat notes, \
                 public API, unsafe-code status, fuzz targets, and resource limits",
            ));
            continue;
        }
        if let Ok(text) = walk::read_text(&doc) {
            for heading in REQUIRED_HEADINGS {
                if !declares(&text, heading) {
                    report.push(Finding::file(
                        "module-documentation",
                        format!("{member}/MODULE.md"),
                        format!("does not declare `{heading}` (specification 4.1)"),
                    ));
                }
            }
        }
    }
}

/// The crate whose sources may not read the environment.
///
/// Specification 4.1 forbids environment-variable interpolation *in
/// configuration*; elsewhere reading the environment is ordinary, so the rule
/// is scoped rather than global. Named here so the scope is checked against the
/// tree in one place — see `check_sources`.
const CONFIG_CRATE: &str = "crates/hypellm-config";

/// Rules `unsafe-forbidden`, `forbidden-api`, `no-config-env-interpolation`.
fn check_sources(root: &Path, report: &mut Report) -> std::io::Result<()> {
    report.ran("unsafe-forbidden");
    report.ran("forbidden-api");
    report.ran("no-config-env-interpolation");

    let files = walk::files(&root.join("crates"))?;
    let rust: Vec<&PathBuf> = files.iter().filter(|p| walk::has_extension(p, "rs")).collect();
    report.examined(rust.len());

    // `no-config-env-interpolation` is scoped to one crate by a path literal,
    // which fails **open**: rename or move that crate and the rule silently
    // stops applying to anything, while `depscan` still reports it as run. A
    // whole-workspace rename is exactly when that happens and exactly when
    // nobody is looking at this line.
    //
    // So the literal is checked against the tree before it is used. If it
    // matches no file, that is a bug in this scanner, reported as a finding
    // rather than as silence.
    if !rust
        .iter()
        .any(|path| relative(root, path).to_string_lossy().starts_with(CONFIG_CRATE))
    {
        report.push(Finding::file(
            "no-config-env-interpolation",
            "crates/hypellm-devtools/src/rust_scan.rs",
            format!(
                "this rule is scoped to `{CONFIG_CRATE}`, which matches no source file — \
                 the crate was renamed or moved and the rule is now checking nothing. \
                 Update `CONFIG_CRATE`."
            ),
        ));
    }

    for path in rust {
        let shown = relative(root, path);
        let text = walk::read_text(path)?;

        if is_crate_root(path) && !text.contains("#![forbid(unsafe_code)]") {
            report.push(Finding::file(
                "unsafe-forbidden",
                &shown,
                "crate root does not declare `#![forbid(unsafe_code)]` (specification 18.2)",
            ));
        }

        let exempt = FORBIDDEN_SELF_EXEMPT.iter().any(|e| shown == Path::new(e));

        for (index, raw) in text.lines().enumerate() {
            let line_no = index.saturating_add(1);
            let code = strip_line_comment(raw);

            if !exempt {
                for (pattern, reason) in FORBIDDEN {
                    if code.contains(pattern) {
                        report.push(Finding::at(
                            "forbidden-api",
                            &shown,
                            line_no,
                            format!("`{pattern}` is {reason}, forbidden by specification 4.1"),
                        ));
                    }
                }
            }

            // Specification 4.1 forbids environment-variable interpolation in
            // configuration specifically; elsewhere reading the environment is
            // ordinary (the test suite uses `temp_dir`).
            if shown.starts_with(CONFIG_CRATE) && code.contains("env::var") {
                report.push(Finding::at(
                    "no-config-env-interpolation",
                    &shown,
                    line_no,
                    "configuration must not interpolate environment variables \
                     (specification 4.1, 11.1)",
                ));
            }
        }
    }

    Ok(())
}

fn is_crate_root(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if !matches!(name, "lib.rs" | "main.rs") {
        return false;
    }
    path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()) == Some("src")
}

/// Remove a `//` line comment. Block comments are left alone: a forbidden
/// construct hidden in one still deserves review.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => line.get(..i).unwrap_or(line),
        None => line,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lint_extraction_handles_both_attribute_spellings() {
        // The rule compares a deny list against a `cfg(test)` relaxation list,
        // so both have to be read correctly out of one- and multi-line
        // attributes — the multi-line one is what the workspace actually uses.
        let one_line = "#![deny(clippy::panic, clippy::unwrap_used)]\n";
        assert_eq!(
            clippy_lints_in(one_line, "#![deny(")
                .into_iter()
                .map(|(_, l)| l)
                .collect::<Vec<_>>(),
            vec!["panic", "unwrap_used"]
        );

        let multi = "#![deny(\n    clippy::panic,\n    clippy::indexing_slicing\n)]\n";
        let found = clippy_lints_in(multi, "#![deny(");
        assert_eq!(
            found.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(),
            vec!["panic", "indexing_slicing"]
        );
        // The line reported is the lint's own, not the attribute's, because
        // that is the line someone has to edit.
        assert_eq!(found.first().map(|(n, _)| *n), Some(2));
        assert_eq!(found.get(1).map(|(n, _)| *n), Some(3));
    }

    #[test]
    fn a_nested_cfg_attr_closes_rather_than_swallowing_the_file() {
        // `#![cfg_attr(test, warn(...))]` nests one paren level deeper than a
        // plain deny. If the depth tracking got that wrong the scan would run
        // on past the attribute and collect lint names from the rest of the
        // crate, which would make every deny look relaxed — the rule failing
        // open, and silently.
        let text = "#![cfg_attr(\n    test,\n    warn(\n        clippy::panic\n    )\n)]\n\
                    fn later() { let _ = \"clippy::indexing_slicing\"; }\n";
        let found = clippy_lints_in(text, "#![cfg_attr(");
        assert_eq!(
            found.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(),
            vec!["panic"],
            "the scan ran past the end of the attribute"
        );
    }

    #[test]
    fn the_self_exemption_is_exactly_one_file() {
        // The exemption exists so the pattern table does not match itself. If
        // it ever grows, that is a policy change and must be reviewed, not a
        // convenience.
        assert_eq!(FORBIDDEN_SELF_EXEMPT.len(), 1);
        assert_eq!(FORBIDDEN_SELF_EXEMPT[0], "crates/hypellm-devtools/src/rust_scan.rs");
    }

    #[test]
    fn a_source_module_named_build_rs_is_not_a_build_script() {
        // `crates/hypellm-config/src/build.rs` is ordinary source. Only a
        // `build.rs` at the package root is a Cargo build script.
        assert!(!is_crate_root(Path::new("crates/hypellm-config/src/build.rs")));
        let dir = Path::new("crates/hypellm-config");
        assert_eq!(dir.join("build.rs"), Path::new("crates/hypellm-config/build.rs"));
    }

    #[test]
    fn crate_roots_are_identified_precisely() {
        assert!(is_crate_root(Path::new("crates/x/src/lib.rs")));
        assert!(is_crate_root(Path::new("crates/x/src/main.rs")));
        assert!(!is_crate_root(Path::new("crates/x/src/inner/lib.rs")));
        assert!(!is_crate_root(Path::new("crates/x/tests/lib.rs")));
        assert!(!is_crate_root(Path::new("crates/x/src/other.rs")));
    }

    #[test]
    fn line_comments_are_stripped_before_matching() {
        assert_eq!(strip_line_comment("let x = 1; // dlopen"), "let x = 1; ");
        assert_eq!(strip_line_comment("let x = 1;"), "let x = 1;");
    }

    #[test]
    fn the_forbidden_table_covers_the_constructs_named_by_the_specification() {
        let reasons: Vec<&str> = FORBIDDEN.iter().map(|(_, r)| *r).collect();
        assert!(reasons.iter().any(|r| r.contains("dynamic library")));
        assert!(reasons.iter().any(|r| r.contains("subprocess")));
    }

    #[test]
    fn scanning_this_repository_is_clean() {
        // The scanner is meaningless if it does not pass on the tree it
        // governs. This is the regression test for the policy itself.
        let root = repo_root();
        let report = scan(&root).expect("scan the repository");
        assert!(
            report.is_clean(),
            "dependency scan found violations:\n{}",
            report
                .findings()
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(report.files_examined() > 0);
    }

    fn repo_root() -> PathBuf {
        // CARGO_MANIFEST_DIR is crates/hypellm-devtools.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repository root")
            .to_path_buf()
    }
}
