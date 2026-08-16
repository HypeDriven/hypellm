# Module: hypellm-devtools

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` is declared in `src/main.rs` and inherited from the workspace lint table. |
| External dependencies | None. Rust standard library plus one workspace path dependency: `hypellm-crypto` (SHA-256 and hex for the build manifest). |
| Fuzz targets | **None for this crate yet.** Required targets are listed under [Fuzz targets](#fuzz-targets). |

## Scope: a gate, not a guarantee

This crate builds one binary, `depscan`. It is **build and CI tooling**. Nothing
here is linked into `hypellm-router`; no other crate depends on it. It is a
workspace member so that it is itself subject to every rule it enforces — its own
`MODULE.md` requirement included — and so that
`rust_scan::tests::scanning_this_repository_is_clean` turns the policy into a
regression test that fails the build when the tree drifts.

It enforces two specification clauses mechanically:

| Concern | Reference | What `depscan` does |
|---|---|---|
| No third-party packages | §4 | Every dependency in every workspace manifest must be a workspace-local `path` dependency that resolves inside the repository |
| No build scripts, proc macros, dynamic loading, shell execution, env interpolation in config | §4.1 | Textual and manifest-level rules over `crates/` |
| Per-module declarations | §4.1 | Every workspace member has a `MODULE.md` naming `Owner`, `Unsafe code`, `Fuzz targets` |
| `#![forbid(unsafe_code)]` at every crate root | §18.2 | Checked at `src/lib.rs` and `src/main.rs` of each crate |
| Panic-adjacent lint escalations exempt `cfg(test)` | §18.2 | A crate-root `#![deny(clippy::…)]` must be scoped `cfg_attr(not(test), …)` or paired with a `cfg_attr(test, warn/allow(…))` covering **every** denied lint. §18.2 permits these constructs "outside startup invariants and tests"; an escalation that also governs assertions makes `cargo clippy --all-targets` fail, and a gate that always fails is a gate nobody runs |
| First-party static web app only | §15, §15.1 | No `vendor/`, no remote origins, no `eval`/`Function`/`innerHTML`/service worker/WebAssembly, no inline handlers, no inline script bodies, every referenced module resolves |
| Accessible form controls | Appendix C | Every named `el('input'\|'select'\|'textarea')` reaches `field`/`inlineField`, carries `aria-label`, or is paired with a `<label for>` naming its own id. Appendix C requires the SPA to pass accessibility tests and there were none; the application was already correct, so this prevents regression rather than fixing a defect. Colour contrast, focus order, and whether a label reads meaningfully are outside what a static rule can judge |
| Content-addressed release inputs | §4.1 | `--manifest` emits the SBOM-like internal manifest |
| Definition of done | Appendix C | "Strict dependency scan reports only workspace-owned Rust and static web sources" |

The enforced set is printed by `--list-rules`, and two tests
(`every_rule_that_runs_is_documented_in_the_rule_list`,
`every_documented_rule_actually_runs`) keep that statement and the executed set
in agreement, so the auditable claim cannot silently diverge from behaviour.

### What this module deliberately does not do

The single most important boundary here is that **`depscan` is not a compiler,
and it is not a defence against a hostile author with commit access.** It detects
accident and drift. The control against deliberate evasion is two-person review
of auth, parser, adapter-credential, policy-activation, and storage changes
(§21.1); `depscan` narrows what such a review must look for, it does not replace
it. Reading a clean scan as "this tree is safe" is a misuse of the tool.

Concretely, it is not:

- **A TOML parser, and it must not become one.** `manifest.rs` recognises exactly
  the constructs the HypeLLM manifests are permitted to contain and classifies
  everything else as `DepSpec::Unrecognized` or `Manifest::unparsed`, both of
  which are reported as violations. A general parser that silently accepted an
  unfamiliar dependency form would defeat the one thing §4 exists to prevent, so
  the reader fails closed on ambiguity by construction.
- **A JavaScript, HTML, or CSS parser.** `web_scan.rs` strips comments per file
  type and then matches text. It reasons about tokens no further than that.
- **A linter or a formatter.** Style, complexity, and correctness are `clippy`'s
  and review's business.
- **Suppressible.** There is no severity, no warning level, no allowlist file,
  and no command-line escape. A construct that must be permitted is permitted by
  editing the rule in a reviewed commit. The one exemption in the source —
  `FORBIDDEN_SELF_EXEMPT` — names exactly one file and a test asserts that it
  stays one file.
- **A signer.** The build manifest is a plain SHA-256 tree digest. §4.1 puts
  signing and provenance retention outside this repository, and they stay there.
- **Networked or process-spawning.** `depscan` reads files. It opens no sockets,
  spawns no processes, and reads no environment variables to decide anything.

## Threat notes

`depscan` reads a working tree that may contain content nobody has reviewed yet —
a contributor branch, a merge in flight. Its inputs are therefore untrusted, and
its output is a security claim that other people rely on. Both directions matter:
a crash on malformed input is an availability problem, but a *false clean* is the
real hazard.

**Fail-closed behaviour that holds.** Any I/O or decoding error aborts the scan
and exits non-zero (`main::run` → `fail`); a scan never partially succeeds.
Symbolic links anywhere in the walked tree are a hard error rather than a skip,
because a link could otherwise redirect the scan out of the repository or hide a
linked-in source tree (`walk::descend`). Non-UTF-8 source is an error, not a
skip, because a file the rules cannot read is a file the rules cannot certify
(`walk::read_text`). Manifest ambiguity resolves to a violation, never to
acceptance (`manifest::classify`). Traversal is depth-bounded and order-stable,
so the result is the same on every machine.

**Known blind spots in the manifest reader.** These are the differentials between
what `depscan` inspects and what Cargo actually resolves, and each is a way a
registry source could enter without a finding:

- `[patch.*]` and `[replace]` tables are not inspected.
  `manifest::is_dependency_section` matches only sections whose last component is
  `dependencies`, `dev-dependencies`, or `build-dependencies`, so
  `[patch.crates-io] x = { git = "…" }` parses cleanly and is silently ignored.
- `.cargo/config.toml` is hashed into the build manifest but never
  policy-parsed. A `[source.crates-io] replace-with = …` entry, an added
  `[registries]` table, or the removal of the `[net] offline = true` line that
  currently backs the whole policy would all pass the scan.
- `Cargo.lock` is likewise hashed but not read. §4 says the lockfile is
  insufficient evidence; `depscan` does not use it as evidence either, in either
  direction.
- Member manifests that cannot be read are skipped without a finding.
  `rust_scan::member_manifests`, `check_build_scripts`, and
  `check_module_documentation` all use `if let Ok(text) = walk::read_text(…)`, so
  a member whose `Cargo.toml` or `MODULE.md` is unreadable or not UTF-8 is
  quietly uncertified rather than reported. Note the asymmetry: the same
  condition on a `.rs` file under `crates/` *is* a hard error, because
  `check_sources` propagates it.
- Members declared in the workspace but absent from disk produce no finding, and
  `check_workspace_membership` only inspects `crates/`; a crate directory
  elsewhere in the tree is neither required to be a member nor scanned.

**Evasion surface in the textual rules.** `rust_scan::FORBIDDEN` matches
substrings on lines with `//` comments removed; block comments are left in
deliberately, so a forbidden construct hidden in one still gets flagged.
Rewriting a call to avoid the literal pattern defeats it trivially — that is
accepted, given the boundary stated above. Two related notes: `rust_scan.rs` is
exempt from its own pattern table (it contains the table), which makes it the one
file where a forbidden API could land unnoticed and is a reason changes to it
belong in the two-person-review set; and the `no-config-env-interpolation` rule
is scoped by path prefix to `crates/hypellm-config`, so configuration logic that
migrates out of that crate leaves the rule's coverage with it.

**Skipped directories are unexamined, not proven absent.** `walk::SKIP_DIRS`
covers `target`, `dist`, `run`, `.git`, and `node_modules`. The last is the sharp
edge: §15 forbids npm packages outright, and a `web/vendor/` directory *is*
reported, but a `web/node_modules/` directory is silently walked past. The
asymmetry is worth closing.

**Gaps in the web rules.**

- `check_inline_script` reports a `<script>` element with a non-empty body, but
  despite its doc comment it does not verify that a `src` attribute is present,
  and an unterminated `<script>` with no matching `</script>` produces no finding
  at all — the search simply advances past it.
- `FORBIDDEN_JS` is applied only to files with a `.js` extension. `innerHTML`
  inside an `.svg` file, or an `eval(` inside an HTML inline script body, is
  caught only indirectly, by the inline-script rule.
- The remote-origin rule matches scheme prefixes with a fixed allowlist of XML
  namespace URIs (`NAMESPACE_URIS`). A protocol-relative `//cdn.example/x.js`
  reference carries no scheme and is not matched.
- `web_scan::resolve` proves containment *lexically* — it normalises `..` and
  `.` without touching the filesystem and then checks `starts_with(web_root)`.
  That is sound only because `walk::files` has already rejected every symbolic
  link in the tree. If the no-symlink rule is ever relaxed, this containment
  check stops proving containment and must be replaced with a canonicalising one.

**Build manifest integrity.** `sbom::root_digest` hashes `path\0digest\n` per
entry over a sorted list, so a rename or a swap of two identical-content files
changes the root — hashing contents alone would miss both, and there are tests
for each. Two limits on what that root proves. First, paths are folded through
`Path::to_string_lossy`, so two distinct filenames containing invalid UTF-8 map
to the same replacement-character string and could collide in the root digest;
this is a latent weakness even though no such path exists in the tree today.
Second, the manifest is an unkeyed digest, not a signature: it detects drift when
compared against a value retained elsewhere, and detects nothing at all against
someone who can edit the tree and re-run `depscan --manifest`. Its scope is also
narrower than §4.1's "release inputs" — `INPUT_ROOTS` and `INPUT_FILES` cover
`crates/`, `web/`, `Cargo.toml`, `Cargo.lock`, and `.cargo/config.toml`, but
nothing pins the compiler and linker versions that §4.1 also requires to be
reproducible. That scope is deliberately an explicit list rather than a glob, so
widening it is a reviewed decision.

**Resource exhaustion.** The tool is memory-bounded only by the tree it is
pointed at. See the limits table: file sizes, file counts, and finding counts are
all unbounded. A repository containing one enormous file will make `depscan`
allocate it whole. This is tolerable because the input is a checked-out
repository under review and `depscan` runs in CI rather than on the data plane —
but it means `depscan` must never be exposed as a service or pointed at an
arbitrary path on request.

**Panic safety.** All slicing goes through `str::get`/`Path` APIs, all arithmetic
on offsets uses `saturating_add`, and directory recursion is depth-bounded, so
malformed input produces findings or errors rather than panics. `unwrap`/`expect`
appear only in `#[cfg(test)]` code, consistent with §18.2.

## Limits

Enforced today:

| Input / resource | Limit | Enforced by |
|---|---|---|
| Directory nesting depth | 32; exceeding it is an error that aborts the scan | `walk::MAX_DEPTH`, checked in `walk::descend` |
| Symbolic links in the scanned tree | Zero permitted; any link is an error | `walk::descend` via `symlink_metadata` |
| Directories traversed | `target`, `dist`, `run`, `.git`, `node_modules` are never descended into | `walk::SKIP_DIRS` |
| Source encoding | UTF-8 only; anything else is an error, not a skip | `walk::read_text` |
| Self-exemption from the forbidden-API table | Exactly one file, asserted by test | `rust_scan::FORBIDDEN_SELF_EXEMPT`, `the_self_exemption_is_exactly_one_file` |
| Remote-origin excerpt in a finding | 60 characters | `web_scan::check_remote_origins` (`chars().take(60)`) |
| Build-manifest scope | `crates/`, `web/`, `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml` — an explicit list, not a glob | `sbom::INPUT_ROOTS`, `sbom::INPUT_FILES` |
| Command-line arguments | Fixed set; an unrecognised argument exits non-zero without scanning | `main::main` |

Not enforced — stated plainly so no one reads a bound into this table that the
code does not provide:

| Input / resource | Status |
|---|---|
| Individual file size | **Unbounded.** `walk::read_text` and `sbom::build` read whole files into memory via `std::fs::read`; `strip_js_comments` allocates a second copy. |
| Total files or total bytes scanned | **Unbounded.** `walk::files` accumulates every path in the tree into one `Vec`. |
| Number of findings, and finding length | **Unbounded.** `findings::Report` grows without a cap, and `manifest-understood` findings embed the offending manifest line verbatim. |
| Wall-clock deadline | **None.** Termination rests on the depth bound and the no-symlink rule; there is no timeout or cancellation path. §18.2's deadline requirement governs the data plane, and `depscan` is not on it. |
| Line length and per-line scan cost | **Unbounded**, and `check_inline_handler` scans each HTML line once per entry in an 87-name event-attribute table. |

## Public API

There is no library target and no `lib.rs`. Every module is `pub(crate)`; the
only surface is the `depscan` binary:

```text
depscan [--root DIR]        enforce the policy; exit 1 on any violation
depscan --manifest [--root DIR]   emit the content-addressed build manifest
depscan --list-rules        list the rules this build enforces
depscan --help
```

The contract callers may depend on is the exit status — `0` clean, non-zero for
any violation, malformed argument, or I/O failure — plus the stability of the
rule identifiers in `main::RULES`. Finding text is human-readable and not a
machine interface. Adding a rule is a policy change; removing or renaming one
breaks anything keyed on the identifier and belongs in a reviewed commit.

## Fuzz targets

The workspace has no `fuzz/` directory and no libFuzzer harness — specification
4 admits no such dependency. Fuzzing is a seeded, deterministic mutation engine
in `hypellm-test-corpus::fuzz`, driven from ordinary `tests/fuzz.rs` targets so
that `cargo test` runs it and a failing seed is reproducible by number rather
than by corpus file. All seven areas specification 21 names have a suite; see
`docs/deferred-issues.md`, `DI-002`, for the table. `hypellm-core` carries the
property layer in `tests/properties.rs`.

None cover this crate yet. The following are required by §21 (Fuzz: configuration, management API) and §18.2
("configuration and protocol parsers are fuzzed"), because each of these
functions is a hand-written recogniser over untrusted text where a false-accept
is a policy bypass:

| Target | Entry point | Property |
|---|---|---|
| `manifest_parse` | `manifest::parse` | Required, not yet implemented. No panic on arbitrary bytes; every dependency entry is either `DepSpec::Path` or reported, never silently dropped. |
| `manifest_classify` | `manifest::classify` | Required, not yet implemented. Any value carrying `version`, `git`, `registry`, `branch`, `tag`, or `rev` classifies as `Unrecognized`. |
| `js_comment_strip` | `web_scan::strip_js_comments` | Required, not yet implemented. Line count is preserved; no substring inside a string literal is ever removed. |
| `web_reference_resolve` | `web_scan::resolve` | Required, not yet implemented. Every `Some(path)` result is lexically contained in `web_root`. |
| `inline_script_scan` | `web_scan::check_inline_script` | Required, not yet implemented. Terminates on arbitrary markup, including unbalanced tags. |

Until these land, the corresponding assurance rests on the unit tests in each
module and on review.
