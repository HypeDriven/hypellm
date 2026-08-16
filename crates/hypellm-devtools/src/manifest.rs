//! A deliberately small Cargo manifest reader.
//!
//! This is **not** a TOML parser, and it must not become one. It recognises
//! exactly the constructs the HypeLLM manifests are allowed to contain and
//! reports everything else as unrecognised. That direction of failure is the
//! important one: a full parser that silently accepts an unfamiliar dependency
//! form would let external source into the trusted computing base, which is the
//! single thing specification 4 exists to prevent.
//!
//! Every ambiguity therefore resolves to [`DepSpec::Unrecognized`], which the
//! caller reports as a violation.

use std::path::{Path, PathBuf};

/// How a dependency was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DepSpec {
    /// A path dependency: `{ path = "../other-crate" }`.
    Path(String),
    /// Anything this reader does not positively recognise as workspace-local,
    /// including registry versions, git sources, and unfamiliar keys. The
    /// string explains what was seen.
    Unrecognized(String),
}

/// One dependency entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dependency {
    /// Crate name as written on the left of `=`.
    pub(crate) name: String,
    /// Manifest section it appeared in, e.g. `dependencies`.
    pub(crate) section: String,
    /// 1-indexed line.
    pub(crate) line: usize,
    /// How it was declared.
    pub(crate) spec: DepSpec,
}

/// The subset of a Cargo manifest the policy cares about.
#[derive(Debug, Clone, Default)]
pub(crate) struct Manifest {
    /// Path to the manifest.
    pub(crate) path: PathBuf,
    /// `name` under `[package]`.
    pub(crate) package_name: Option<String>,
    /// Line of an explicit `build = "…"` key, which specification 4.1 forbids.
    pub(crate) build_key: Option<usize>,
    /// Line of `proc-macro = true`, which specification 4.1 forbids.
    pub(crate) proc_macro: Option<usize>,
    /// Every dependency in every dependency section.
    pub(crate) dependencies: Vec<Dependency>,
    /// `members` under `[workspace]`.
    pub(crate) workspace_members: Vec<String>,
    /// Lines of any `[patch…]` or `[replace]` section header.
    ///
    /// These redirect a dependency to a different source without appearing in
    /// any dependency table, so a manifest can look clean while resolving to
    /// something else entirely.
    pub(crate) source_rewrites: Vec<(usize, String)>,
    /// Lines the reader could not classify at all.
    pub(crate) unparsed: Vec<(usize, String)>,
}

/// Parse the manifest at `path`.
pub(crate) fn parse(path: &Path, text: &str) -> Manifest {
    let mut manifest = Manifest { path: path.to_path_buf(), ..Manifest::default() };
    let mut section = String::new();
    let mut pending: Option<(usize, String, String)> = None; // multi-line array

    for (index, raw) in text.lines().enumerate() {
        let line_no = index.saturating_add(1);

        // Continue a multi-line array such as `members = [ … ]`.
        if let Some((start, key, mut acc)) = pending.take() {
            acc.push(' ');
            acc.push_str(strip_comment(raw).trim());
            if acc.contains(']') {
                absorb_array(&mut manifest, &section, start, &key, &acc);
            } else {
                pending = Some((start, key, acc));
            }
            continue;
        }

        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(name) = section_header(line) {
            // `[patch.crates-io]`, `[patch."https://…"]` and `[replace]`
            // redirect resolution without naming a dependency.
            if name == "replace" || name == "patch" || name.starts_with("patch.") {
                manifest.source_rewrites.push((line_no, name.clone()));
            }
            section = name;
            continue;
        }

        let Some((key, value)) = split_key_value(line) else {
            manifest.unparsed.push((line_no, line.to_string()));
            continue;
        };

        if value.starts_with('[') && !value.contains(']') {
            pending = Some((line_no, key, value));
            continue;
        }
        if value.starts_with('[') {
            absorb_array(&mut manifest, &section, line_no, &key, &value);
            continue;
        }

        absorb_pair(&mut manifest, &section, line_no, &key, &value);
    }

    if let Some((line_no, key, acc)) = pending {
        manifest.unparsed.push((line_no, format!("unterminated array for key `{key}`: {acc}")));
    }

    manifest
}

fn absorb_pair(manifest: &mut Manifest, section: &str, line: usize, key: &str, value: &str) {
    if is_dependency_section(section) {
        manifest.dependencies.push(Dependency {
            name: key.to_string(),
            section: section.to_string(),
            line,
            spec: classify(value),
        });
        return;
    }

    match (section, key) {
        ("package", "name") => manifest.package_name = unquote(value),
        ("package", "build") => manifest.build_key = Some(line),
        ("lib", "proc-macro" | "proc_macro") if value.trim() == "true" => {
            manifest.proc_macro = Some(line);
        }
        _ => {}
    }
}

fn absorb_array(manifest: &mut Manifest, section: &str, line: usize, key: &str, value: &str) {
    if section == "workspace" && key == "members" {
        manifest.workspace_members = array_strings(value);
        return;
    }
    if is_dependency_section(section) {
        // An array-valued dependency is not a form we accept.
        manifest.dependencies.push(Dependency {
            name: key.to_string(),
            section: section.to_string(),
            line,
            spec: DepSpec::Unrecognized(format!("array-valued dependency: {value}")),
        });
    }
}

/// Any section whose final component is a dependency table, including
/// `[target.'cfg(unix)'.dependencies]`.
fn is_dependency_section(section: &str) -> bool {
    matches!(
        section.rsplit('.').next(),
        Some("dependencies" | "dev-dependencies" | "build-dependencies")
    )
}

/// Decide whether a dependency value is a workspace-local path dependency.
///
/// Fails closed: only an inline table carrying `path` and no source-selecting
/// key is accepted.
fn classify(value: &str) -> DepSpec {
    let trimmed = value.trim();

    if trimmed.starts_with('"') {
        return DepSpec::Unrecognized(format!("registry version requirement {trimmed}"));
    }

    let Some(inner) = trimmed.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return DepSpec::Unrecognized(format!("unrecognised dependency form {trimmed}"));
    };

    let mut path = None;
    for entry in split_top_level(inner) {
        let Some((key, val)) = split_key_value(entry.trim()) else {
            if entry.trim().is_empty() {
                continue;
            }
            return DepSpec::Unrecognized(format!("unrecognised dependency key {entry}"));
        };
        match key.as_str() {
            "path" => path = unquote(&val),
            // Any of these select a source outside the workspace.
            "version" | "git" | "registry" | "registry-index" | "branch" | "tag" | "rev" => {
                return DepSpec::Unrecognized(format!("external source key `{key}`"));
            }
            "features" | "default-features" | "optional" | "package" => {}
            other => return DepSpec::Unrecognized(format!("unrecognised dependency key `{other}`")),
        }
    }

    match path {
        Some(p) => DepSpec::Path(p),
        None => DepSpec::Unrecognized("dependency has no `path` key".to_string()),
    }
}

/// `[a.b]` → `a.b`
fn section_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    // `[[bin]]` arrives here as `[bin]` after one strip; normalise it.
    let inner = inner.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(inner);
    Some(inner.trim().to_string())
}

fn split_key_value(line: &str) -> Option<(String, String)> {
    let eq = find_top_level_eq(line)?;
    let key = line.get(..eq)?.trim().trim_matches('"').to_string();
    let value = line.get(eq.saturating_add(1)..)?.trim().to_string();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

/// Find the `=` that separates key from value, ignoring any inside quotes.
fn find_top_level_eq(line: &str) -> Option<usize> {
    let mut in_quotes = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '=' if !in_quotes => return Some(i),
            _ => {}
        }
    }
    None
}

/// Split an inline table body on commas that are not inside quotes.
fn split_top_level(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut start = 0usize;
    for (i, ch) in inner.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                if let Some(piece) = inner.get(start..i) {
                    out.push(piece);
                }
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    if let Some(piece) = inner.get(start..) {
        out.push(piece);
    }
    out
}

fn array_strings(value: &str) -> Vec<String> {
    let inner = value.trim().trim_start_matches('[').trim_end_matches(']');
    split_top_level(inner).iter().filter_map(|s| unquote(s.trim())).collect()
}

fn unquote(value: &str) -> Option<String> {
    let t = value.trim();
    t.strip_prefix('"').and_then(|s| s.strip_suffix('"')).map(str::to_string)
}

/// Remove a trailing `#` comment that is not inside a quoted string.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return line.get(..i).unwrap_or(line),
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(text: &str) -> Manifest {
        parse(Path::new("Cargo.toml"), text)
    }

    #[test]
    fn a_path_dependency_is_recognised() {
        let manifest = m("[dependencies]\nhypellm-core = { path = \"../hypellm-core\" }\n");
        assert_eq!(manifest.dependencies.len(), 1);
        assert_eq!(manifest.dependencies[0].spec, DepSpec::Path("../hypellm-core".to_string()));
    }

    #[test]
    fn a_registry_version_is_not_recognised() {
        let manifest = m("[dependencies]\nserde = \"1.0\"\n");
        assert!(matches!(manifest.dependencies[0].spec, DepSpec::Unrecognized(_)));
    }

    #[test]
    fn a_path_dependency_that_also_names_a_version_is_rejected() {
        // This is the dangerous form: it looks local but resolves from the
        // registry when published or when the path is absent.
        let manifest = m("[dependencies]\nx = { path = \"../x\", version = \"1.0\" }\n");
        assert!(matches!(manifest.dependencies[0].spec, DepSpec::Unrecognized(_)));
    }

    #[test]
    fn a_git_dependency_is_rejected() {
        let manifest = m("[dependencies]\nx = { git = \"https://example.invalid/x\" }\n");
        assert!(matches!(manifest.dependencies[0].spec, DepSpec::Unrecognized(_)));
    }

    #[test]
    fn an_unfamiliar_dependency_key_is_rejected_rather_than_ignored() {
        let manifest = m("[dependencies]\nx = { path = \"../x\", artifact = \"bin\" }\n");
        assert!(matches!(manifest.dependencies[0].spec, DepSpec::Unrecognized(_)));
    }

    #[test]
    fn dev_and_build_dependency_sections_are_scanned_too() {
        let manifest = m("[dev-dependencies]\na = \"1\"\n[build-dependencies]\nb = \"1\"\n");
        assert_eq!(manifest.dependencies.len(), 2);
        assert!(manifest.dependencies.iter().all(|d| matches!(d.spec, DepSpec::Unrecognized(_))));
    }

    #[test]
    fn target_specific_dependency_sections_are_scanned() {
        let manifest = m("[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n");
        assert_eq!(manifest.dependencies.len(), 1);
        assert!(matches!(manifest.dependencies[0].spec, DepSpec::Unrecognized(_)));
    }

    #[test]
    fn a_build_script_key_is_located() {
        let manifest = m("[package]\nname = \"x\"\nbuild = \"build.rs\"\n");
        assert_eq!(manifest.build_key, Some(3));
        assert_eq!(manifest.package_name, Some("x".to_string()));
    }

    #[test]
    fn a_proc_macro_lib_is_located() {
        let manifest = m("[lib]\nproc-macro = true\n");
        assert_eq!(manifest.proc_macro, Some(2));
    }

    #[test]
    fn workspace_members_are_collected_across_lines() {
        let manifest = m("[workspace]\nmembers = [\n  \"crates/a\",\n  \"crates/b\",\n]\n");
        assert_eq!(manifest.workspace_members, vec!["crates/a", "crates/b"]);
    }

    #[test]
    fn workspace_members_on_one_line_are_collected() {
        let manifest = m("[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n");
        assert_eq!(manifest.workspace_members, vec!["crates/a", "crates/b"]);
    }

    #[test]
    fn comments_are_stripped_but_not_inside_strings() {
        let manifest = m("[package]\nname = \"a#b\" # trailing\n");
        assert_eq!(manifest.package_name, Some("a#b".to_string()));
    }

    #[test]
    fn a_double_bracket_section_is_normalised() {
        // `[[bin]]` must not be read as a section named `[bin]`.
        let manifest = m("[[bin]]\nname = \"depscan\"\n[dependencies]\nx = { path = \"../x\" }\n");
        assert_eq!(manifest.dependencies.len(), 1);
    }

    #[test]
    fn workspace_inherited_keys_do_not_become_dependencies() {
        let manifest = m("[package]\nversion.workspace = true\n[lints]\nworkspace = true\n");
        assert!(manifest.dependencies.is_empty());
        assert_eq!(manifest.build_key, None);
    }

    #[test]
    fn patch_and_replace_tables_are_located() {
        // These redirect resolution without naming a dependency, so a manifest
        // carrying one looks clean to a dependency-table scan.
        for text in [
            "[patch.crates-io]\nserde = { path = \"../vendor/serde\" }\n",
            "[patch.\"https://example.invalid\"]\nx = { path = \"../x\" }\n",
            "[replace]\n\"serde:1.0.0\" = { path = \"../serde\" }\n",
        ] {
            let manifest = m(text);
            assert!(!manifest.source_rewrites.is_empty(), "missed a rewrite in: {text}");
        }
    }

    #[test]
    fn an_ordinary_manifest_declares_no_source_rewrites() {
        let manifest = m("[package]\nname = \"x\"\n[dependencies]\ny = { path = \"../y\" }\n");
        assert!(manifest.source_rewrites.is_empty());
    }

    #[test]
    fn an_unterminated_array_is_reported_rather_than_dropped() {
        let manifest = m("[workspace]\nmembers = [\n  \"crates/a\",\n");
        assert!(!manifest.unparsed.is_empty());
    }
}
