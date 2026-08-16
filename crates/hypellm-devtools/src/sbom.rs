//! The internal build manifest.
//!
//! Specification 4.1: "Release inputs are content-addressed; builds produce an
//! SBOM-like internal manifest even when no external packages exist."
//!
//! The manifest is the answer to "what source produced this binary" for a
//! project that has no package list to point at. It records a SHA-256 over
//! every release input and a single root digest over the sorted set, so two
//! builds can be compared by one hex string.
//!
//! The root digest covers the *paths as well as* the contents. Hashing only
//! contents would let a file be renamed, or two files swapped, without changing
//! the root.

use hypellm_crypto::{Sha256, hex, sha256};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use crate::walk;

/// One release input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Entry {
    /// Repository-relative path.
    pub(crate) path: PathBuf,
    /// Size in bytes.
    pub(crate) bytes: u64,
    /// Lowercase hex SHA-256 of the file contents.
    pub(crate) digest: String,
}

/// The manifest as a whole.
#[derive(Debug, Clone)]
pub(crate) struct Sbom {
    /// Every release input, sorted by path.
    pub(crate) entries: Vec<Entry>,
    /// Root digest over the sorted `path\0digest\n` records.
    pub(crate) root: String,
}

/// Directories and files that constitute release inputs.
///
/// Deliberately explicit: a glob over the repository would silently start
/// covering new top-level directories, and the point of the manifest is that
/// its scope is a reviewed decision.
const INPUT_ROOTS: &[&str] = &["crates", "web"];

/// Individual files at the repository root that affect the build.
const INPUT_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", ".cargo/config.toml"];

/// Build the manifest for the repository at `root`.
pub(crate) fn build(root: &Path) -> io::Result<Sbom> {
    let mut paths: Vec<PathBuf> = Vec::new();

    for dir in INPUT_ROOTS {
        let full = root.join(dir);
        if full.is_dir() {
            paths.extend(walk::files(&full)?);
        }
    }
    for file in INPUT_FILES {
        let full = root.join(file);
        if full.is_file() {
            paths.push(full);
        }
    }
    paths.sort();
    paths.dedup();

    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(&path)?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        // Checked rather than `as`: on every supported target `usize` is at
        // most 64 bits so this cannot fail, but the failure is reported as an
        // I/O error rather than silently truncating a recorded size.
        let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::other(format!("file size does not fit in u64: {}", path.display()))
        })?;
        entries.push(Entry {
            path: relative,
            bytes: bytes_len,
            digest: hex::encode(&sha256(&bytes)),
        });
    }
    entries.sort();

    Ok(Sbom { root: root_digest(&entries), entries })
}

/// Digest over the sorted `path\0digest\n` records.
fn root_digest(entries: &[Entry]) -> String {
    let mut hasher = Sha256::new();
    for entry in entries {
        hasher.update(entry.path.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(entry.digest.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(&hasher.finalize())
}

impl Sbom {
    /// Render the manifest in the repository's line-oriented style: one
    /// `input` record per file, then a `root` record.
    ///
    /// The format matches the configuration grammar of specification 11.1
    /// (`type key=value`) so the same reader conventions apply.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HypeLLM Router internal build manifest (specification 4.1).\n");
        out.push_str("# Content-addressed release inputs; no external packages exist.\n");
        for entry in &self.entries {
            let _ = writeln!(
                out,
                "input path={} bytes={} sha256={}",
                entry.path.display(),
                entry.bytes,
                entry.digest
            );
        }
        let _ = writeln!(out, "root count={} sha256={}", self.entries.len(), self.root);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hypellm-devtools-sbom-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("crates")).expect("create scratch dir");
        dir
    }

    #[test]
    fn the_manifest_is_deterministic() {
        let dir = scratch("deterministic");
        std::fs::write(dir.join("crates/a.rs"), "fn a() {}").expect("write");
        std::fs::write(dir.join("crates/b.rs"), "fn b() {}").expect("write");

        let first = build(&dir).expect("build");
        let second = build(&dir).expect("build");
        assert_eq!(first.root, second.root);
        assert_eq!(first.entries.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changing_a_byte_changes_the_root() {
        let dir = scratch("content");
        std::fs::write(dir.join("crates/a.rs"), "fn a() {}").expect("write");
        let before = build(&dir).expect("build").root;
        std::fs::write(dir.join("crates/a.rs"), "fn a() { }").expect("write");
        let after = build(&dir).expect("build").root;
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn renaming_a_file_changes_the_root_even_though_contents_are_identical() {
        // A root over contents alone would miss this.
        let dir = scratch("rename");
        std::fs::write(dir.join("crates/a.rs"), "same").expect("write");
        let before = build(&dir).expect("build").root;
        std::fs::remove_file(dir.join("crates/a.rs")).expect("remove");
        std::fs::write(dir.join("crates/b.rs"), "same").expect("write");
        let after = build(&dir).expect("build").root;
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn swapping_two_files_changes_the_root() {
        let dir = scratch("swap");
        std::fs::write(dir.join("crates/a.rs"), "one").expect("write");
        std::fs::write(dir.join("crates/b.rs"), "two").expect("write");
        let before = build(&dir).expect("build").root;
        std::fs::write(dir.join("crates/a.rs"), "two").expect("write");
        std::fs::write(dir.join("crates/b.rs"), "one").expect("write");
        let after = build(&dir).expect("build").root;
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_rendered_manifest_carries_every_entry_and_the_root() {
        let dir = scratch("render");
        std::fs::write(dir.join("crates/a.rs"), "x").expect("write");
        let sbom = build(&dir).expect("build");
        let text = sbom.render();
        assert!(text.contains("input path=crates/a.rs"));
        assert!(text.contains(&format!("root count=1 sha256={}", sbom.root)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_repository_manifest_is_non_empty() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repository root")
            .to_path_buf();
        let sbom = build(&root).expect("build the repository manifest");
        assert!(sbom.entries.len() > 50, "expected the whole workspace, got {}", sbom.entries.len());
        assert_eq!(sbom.root.len(), 64);
    }
}
