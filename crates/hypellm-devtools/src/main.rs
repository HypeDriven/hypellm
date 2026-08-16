//! `depscan` — the supply-chain policy gate for the HypeLLM Router repository.
//!
//! Specification 4 states the rule this tool enforces: the production router
//! "MUST NOT download, resolve, or execute third-party packages. Cargo.lock
//! alone is insufficient because it still admits external source into the
//! trusted computing base. The release profile builds with --offline against
//! the repository and fails if crates.io dependencies, build scripts,
//! procedural macros, dynamic loading, or generated network fetches are
//! present."
//!
//! Appendix C makes the scan part of the definition of done: "Strict dependency
//! scan reports only workspace-owned Rust and static web sources."
//!
//! # Usage
//!
//! ```text
//! depscan [--root DIR]        # enforce the policy; exit 1 on any violation
//! depscan --manifest [--root DIR]   # emit the content-addressed build manifest
//! depscan --list-rules
//! ```
//!
//! The default mode prints one line per violation and exits non-zero. It is a
//! gate, not an advisory: there is no severity, no warning level, and no way to
//! suppress a finding from the command line. A construct that must be allowed
//! is allowed by changing the rule, in a reviewed commit.

#![forbid(unsafe_code)]
// Specification 18.2: all integer conversions are checked. `depscan` is a build
// gate rather than a data-plane component, but the same escalation applies to
// the code that reads repository files. Only `as_conversions` is escalated:
// the other 18.2 lints (`indexing_slicing`, `panic`) have no sites in this
// crate, and a deny for a lint that never fires would be noise.
#![cfg_attr(not(test), deny(clippy::as_conversions))]

mod findings;
mod manifest;
mod rust_scan;
mod sbom;
mod walk;
mod web_scan;

use findings::Report;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut root = PathBuf::from(".");
    let mut mode = Mode::Enforce;

    let mut i = 0usize;
    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            "--root" => match args.get(i.saturating_add(1)) {
                Some(value) => {
                    root = PathBuf::from(value);
                    i = i.saturating_add(1);
                }
                None => return fail("--root requires a directory"),
            },
            "--manifest" => mode = Mode::Manifest,
            "--list-rules" => mode = Mode::ListRules,
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unrecognised argument `{other}`")),
        }
        i = i.saturating_add(1);
    }

    let root = match root.canonicalize() {
        Ok(path) => path,
        Err(error) => return fail(&format!("cannot read {}: {error}", root.display())),
    };

    match mode {
        Mode::ListRules => {
            for rule in RULES {
                println!("{rule}");
            }
            ExitCode::SUCCESS
        }
        Mode::Manifest => match sbom::build(&root) {
            Ok(manifest) => {
                print!("{}", manifest.render());
                ExitCode::SUCCESS
            }
            Err(error) => fail(&format!("cannot build the manifest: {error}")),
        },
        Mode::Enforce => match run(&root) {
            Ok(report) => {
                print_report(&report);
                if report.is_clean() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
            }
            Err(error) => fail(&format!("scan failed: {error}")),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Enforce,
    Manifest,
    ListRules,
}

const USAGE: &str = "\
depscan — HypeLLM Router supply-chain policy gate (specification 4, 4.1)

    depscan [--root DIR]        enforce the policy; exit 1 on any violation
    depscan --manifest          emit the content-addressed build manifest
    depscan --list-rules        list the rules this build enforces
    depscan --help

There is no way to suppress a finding from the command line. A construct that
must be permitted is permitted by changing the rule, in a reviewed commit.
";

/// Every rule, with the clause it enforces. Printed by `--list-rules` so the
/// enforced set is auditable without reading the source.
const RULES: &[&str] = &[
    "no-registry-dependencies    §4    every dependency is a workspace-local path dependency",
    "no-source-rewrites          §4    no [patch] or [replace] table redirects resolution",
    "manifest-understood         §4    every manifest line is classified; unknown forms fail",
    "manifest-readable           §4    every declared workspace member manifest can be read",
    "no-build-scripts            §4.1  no build.rs at a package root, no `build` key",
    "no-proc-macros              §4.1  no procedural macro crates",
    "forbidden-api               §4.1  no dynamic loading, shell execution, or process exit",
    "no-config-env-interpolation §4.1  configuration does not read the environment",
    "unsafe-forbidden            §18.2 every crate root declares #![forbid(unsafe_code)]",
    "workspace-members-complete  §18.1 every crate directory is a declared workspace member",
    "module-documentation        §4.1  every module declares owner, unsafe status, fuzz targets",
    "dependencies-are-used       §4.1  every declared [dependencies] entry is referenced by src",
    "test-scaffolding-gated      §18.2 test fixtures are behind the test-harness feature",
    "lint-escalation-scoped      §18.2 crate-root clippy denies are scoped to not(test)",
    "web-first-party-only        §15   no vendor directory, no remote origins, known asset types",
    "web-no-code-from-strings    §15   no eval, Function, innerHTML, service worker, WebAssembly",
    "web-no-inline-handlers      §15.1 no inline event handler attributes",
    "web-no-inline-script        §15.1 script elements are external and empty",
    "web-references-resolve      §15.1 every referenced module and asset exists in the tree",
    "web-labelled-controls       C     every named form control has an accessible name",
];

fn run(root: &Path) -> std::io::Result<Report> {
    let mut report = rust_scan::scan(root)?;
    report.absorb(web_scan::scan(root, &root.join("web"))?);
    report.sort();
    Ok(report)
}

fn print_report(report: &Report) {
    for finding in report.findings() {
        println!("{finding}");
    }

    if report.is_clean() {
        println!(
            "depscan: clean — {} rules, {} files; only workspace-owned Rust and static web sources",
            report.rules_run().len(),
            report.files_examined()
        );
    } else {
        println!(
            "depscan: {} violation(s) across {} rules, {} files examined",
            report.findings().len(),
            report.rules_run().len(),
            report.files_examined()
        );
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("depscan: {message}");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repository root")
            .to_path_buf()
    }

    #[test]
    fn every_rule_that_runs_is_documented_in_the_rule_list() {
        // `--list-rules` is the auditable statement of what the gate enforces.
        // If a rule runs but is undocumented, the statement is incomplete.
        let root = repo_root();
        let report = run(&root).expect("scan");
        for rule in report.rules_run() {
            assert!(
                RULES.iter().any(|line| line.starts_with(rule)),
                "rule `{rule}` runs but is not listed in --list-rules"
            );
        }
    }

    #[test]
    fn every_documented_rule_actually_runs() {
        let root = repo_root();
        let report = run(&root).expect("scan");
        for line in RULES {
            let name = line.split_whitespace().next().unwrap_or_default();
            assert!(
                report.rules_run().contains(&name),
                "rule `{name}` is documented but never ran"
            );
        }
    }
}
