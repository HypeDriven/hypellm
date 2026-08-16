//! Bounded, deterministic directory traversal.
//!
//! The scan must produce the same answer on every machine, so entries are
//! sorted rather than taken in directory order. Traversal is depth-bounded and
//! refuses to follow symbolic links: a scan that could be redirected out of the
//! repository by a symlink would not be evidence of anything.

use std::io;
use std::path::{Path, PathBuf};

/// Directories never descended into. `target` and `dist` are build output,
/// `run` is local scratch state, `.git` is history.
pub(crate) const SKIP_DIRS: &[&str] = &["target", "dist", "run", ".git", "node_modules"];

/// Maximum directory nesting. The repository is nowhere near this deep; the
/// bound exists so a symlink loop or a pathological tree cannot hang the scan.
const MAX_DEPTH: usize = 32;

/// Collect every regular file under `root`, sorted, skipping [`SKIP_DIRS`].
///
/// Symbolic links are not followed and are reported as an error, because the
/// dependency scan is a security control: silently skipping a link would let a
/// linked-in source tree escape review.
pub(crate) fn files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    descend(root, 0, &mut out)?;
    out.sort();
    Ok(out)
}

fn descend(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if depth > MAX_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("directory nesting exceeds {MAX_DEPTH} at {}", dir.display()),
        ));
    }

    let mut entries: Vec<PathBuf> =
        std::fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?.iter().map(|e| e.path()).collect();
    entries.sort();

    for path in entries {
        // `symlink_metadata` does not traverse the link, so a link to a
        // directory is seen as a link rather than silently walked.
        let meta = std::fs::symlink_metadata(&path)?;
        let file_type = meta.file_type();

        if file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("symbolic link in scanned tree: {}", path.display()),
            ));
        }

        if file_type.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if SKIP_DIRS.contains(&name) {
                continue;
            }
            descend(&path, depth.saturating_add(1), out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }

    Ok(())
}

/// Whether `path` has the given extension.
#[must_use]
pub(crate) fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| e == ext)
}

/// Read a file as UTF-8, refusing anything that is not valid text.
///
/// A source file that is not UTF-8 cannot be reviewed by the rules below, so it
/// is an error rather than a skip.
pub(crate) fn read_text(path: &Path) -> io::Result<String> {
    let bytes = std::fs::read(path)?;
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("not valid UTF-8: {}", path.display()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hypellm-devtools-walk-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    #[test]
    fn files_are_returned_sorted_and_recursively() {
        let dir = scratch("sorted");
        std::fs::create_dir_all(dir.join("b")).expect("mkdir");
        std::fs::write(dir.join("z.rs"), "").expect("write");
        std::fs::write(dir.join("a.rs"), "").expect("write");
        std::fs::write(dir.join("b/m.rs"), "").expect("write");

        let found = files(&dir).expect("walk");
        let names: Vec<_> =
            found.iter().filter_map(|p| p.strip_prefix(&dir).ok()).map(|p| p.to_path_buf()).collect();
        assert_eq!(
            names,
            vec![PathBuf::from("a.rs"), PathBuf::from("b/m.rs"), PathBuf::from("z.rs")]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_output_directories_are_skipped() {
        let dir = scratch("skip");
        std::fs::create_dir_all(dir.join("target")).expect("mkdir");
        std::fs::write(dir.join("target/huge.rs"), "").expect("write");
        std::fs::write(dir.join("kept.rs"), "").expect("write");

        let found = files(&dir).expect("walk");
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("kept.rs"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extensions_are_matched_exactly() {
        assert!(has_extension(Path::new("a/b.rs"), "rs"));
        assert!(!has_extension(Path::new("a/b.rss"), "rs"));
        assert!(!has_extension(Path::new("a/brs"), "rs"));
    }

    #[test]
    fn non_utf8_files_are_an_error_not_a_skip() {
        let dir = scratch("utf8");
        let path = dir.join("bad.rs");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).expect("write");
        assert!(read_text(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
