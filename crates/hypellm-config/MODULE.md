# Module: hypellm-config

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` declared in `lib.rs` and inherited from the workspace. |
| External dependencies | None. Workspace path dependencies only: `hypellm-core`, `hypellm-crypto`, `hypellm-fleet`. Rust standard library otherwise. |
| Fuzz targets | `tests/fuzz.rs` — 8 targets over the grammar, driven by `hypellm-test-corpus::fuzz`. See [Fuzz targets](#fuzz-targets). |

## Scope and the "no evaluation step" rule

This module owns the whole path from configuration *text* to a validated,
activatable `ValidatedConfig` — parse, schema check, typed field extraction,
reference resolution, invariant verification, canonicalisation, and digest. It
ends there. `hypellm-store` performs the durable commit and the pointer swap;
`hypellm-router` binds listeners; adapters resolve credentials.

Specification 11.1 fixes the grammar: `type key=value …`, JSON-style quoted
escapes, `#` comments outside strings, unknown fields are errors, and
"includes, environment expansion, anchors, expressions, and executable
templates are forbidden". The forbidden list is the load-bearing half. Every
item on it is a way for a configuration file to *compute* something at load
time, and each has been a real vulnerability class: `!!python/object` in YAML,
`${ENV}` leaking a secret into a log line, an `!include` reading `/etc/shadow`,
a billion-laughs anchor expansion.

The defence is structural rather than a blocklist: **this module has no
evaluation step at all.** There is no code path in `parse.rs` that opens a file,
reads an environment variable, expands a reference, or re-enters the parser on
derived text. `${SECRET}`, `*anchor`, `{{ 1 + 1 }}` and `!!python/object` are
all simply literal string values, and unit tests pin that behaviour precisely so
that a future "convenience" that expands one of them fails the suite instead of
shipping an exfiltration primitive.

What this module deliberately does **not** do:

| Not done here | Where it belongs |
|---|---|
| Read files, resolve paths, or discover configuration implicitly | `hypellm-router` startup; specification 4.1 forbids implicit discovery |
| Durably commit, activate, or swap a snapshot | `hypellm-store` (specification 11, 11.2) |
| Hold, decrypt, or validate secret values | Adapter boundary; `credential` records carry metadata and an opaque `CredentialRef` only (specification 10) |
| Resolve DNS, pin addresses, or enforce egress at connect time | `hypellm-core::netaddr` plus the connect-time egress guard; this module classifies only what is statically knowable |
| Make routing decisions | `hypellm-core::PolicySnapshot::route` (specification 18.3) |
| Authorise the caller submitting a draft | `hypellm-admin-api` / `hypellm-auth` |

One further boundary worth stating: the digest computed here is an **unkeyed**
SHA-256 over the canonical text (`hypellm_crypto::digest`). It detects drift and
lets nodes compare "which configuration am I running" (specification 11.2), and
it is *not* a tamper seal. Authenticity of an activated configuration comes from
the store's protected frames and the audit chain.

## Threat notes

- **Model selectors fail closed.** `parse_model_selector` distinguishes an
  omitted selector (the explicit wildcard default) from an empty or malformed
  identifier. Invalid `binding model=` and `grant model=` values produce
  `invalid_identifier` rather than widening to every alias.
- **Error messages echo raw field values.** `Fields::bool_field`,
  `u64_field`/`i64_field`, `parsed`/`opt_parsed`, and most `build_*` helpers
  format the offending value into `ConfigError::message` (up to
  `max_value_bytes`, 8 KiB), and those messages are surfaced by the validation
  endpoint and written to logs. The type's doc comment asserts no field here
  holds key material — that holds only while the grammar keeps credentials as
  references. Any future record type carrying a secret *value* must suppress the
  value in its error text first. Note also that `unknown_field` prints only the
  key, so a secret pasted into a misspelled field is not echoed; a secret pasted
  into a *known* field with the wrong type is.
- **Parser differentials against the canonical emitter.** The digest is only
  meaningful if `parse ∘ to_canonical_string` is the identity on meaning.
  Two mechanisms protect that: `quote_if_needed` escapes `"`, `\`, `#`,
  whitespace and every control character, so no value can forge a record
  boundary or a comment; and because every emitted value ends in either a bare
  token character or a closing quote, canonical output can never end a line in a
  bare backslash, which the reader would take as a continuation. Both properties
  are currently defended by unit tests only — this is exactly what the
  round-trip fuzz target below exists to attack.
- **Continuation joining precedes tokenisation.** A trailing `\` is consumed as
  a line continuation before any string state is considered, so a quoted string
  may span lines and a value's final backslash cannot be written as a line-final
  character. The failure mode is a hard `InvalidEscape`, not a misread value, but
  it means the continuation rule is lexically outside the string grammar and
  must be fuzzed as such.
- **Resource amplification in the tokeniser.** `parse_logical_line` materialises
  the entire logical line as a `Vec<char>` — four bytes per character — so peak
  transient allocation is roughly 4× the largest logical line, and a 4 MiB
  single-line document costs about 16 MiB. Bounded, but not proportional to
  input; do not lower `max_bytes` expectations on that basis.
- **Superlinear validation in `build`.** The reachability check is `for each
  target { for each alias { permitted_targets.contains(…) } }` — a linear scan
  inside a nested loop. At the record ceiling that is on the order of 10⁴ × 10⁴
  identifier comparisons. Configuration is administrator-supplied and validated
  off the request path (specification 11), so this is a management-plane CPU
  cost, not a data-plane one; it still needs an authenticated, rate-limited
  validation endpoint in front of it.
- **Unbounded error accumulation.** `build` deliberately collects every error
  rather than stopping at the first, so an operator sees the whole list. There is
  no cap on the error vector and no truncation of individual messages. The bound
  is indirect — one error per bad record plus one per unreachable target, each
  embedding values up to 8 KiB — which permits a pathological 4 MiB document to
  produce tens of thousands of formatted strings in one response. An explicit cap
  belongs here.
- **SSRF surface is split, by necessity.** `validate_endpoint` rejects at load
  time what is statically decidable: cleartext `http` to anything but a loopback
  literal or the name `localhost`; an IP literal whose class the declared egress
  profile does not permit; the cloud metadata address under *every* profile; a
  relative `unix` socket path. A DNS name cannot be classified at load time, so
  it is syntax-checked here and must be classified and pinned at connect time
  (specification 10). Weakening either half silently re-opens the other.
- **Silent clamping on numeric fields.** `cost` is clamped with `cost.min(9)`
  rather than rejected out of range, and preference `rank` saturates at
  `u16::MAX`. Neither can currently be reached maliciously (the 8 KiB value limit
  caps a preference list well below 65 535 entries), but clamping is a weaker
  contract than the rest of the module and should not be extended to new fields.
- **Prompts are not an input here.** Nothing in this crate is reachable from
  request data. That is what makes "prompts are inert data — never interpreted
  as configuration" (specification 10.1) enforceable by construction, and it is
  an invariant to preserve: no request-derived string may ever be fed to `parse`.

## Limits

Enforced by `ParseLimits::DEFAULT` (`parse.rs`), which `load` always uses:

| Input | Limit | Enforced by |
|---|---|---|
| Total document size | 4 MiB | `ParseLimits::max_bytes`, checked before any scanning |
| Records per document | 20 000 | `ParseLimits::max_records` |
| Fields per record | 64 | `ParseLimits::max_fields_per_record` |
| Single value length | 8 KiB | `ParseLimits::max_value_bytes`, checked per quoted segment and per assembled token |
| Continuation lines per logical record | 32 | `ParseLimits::max_continuations` |
| Record type / field name | 64 bytes, `[a-z][a-z0-9_]*` | `parse::is_identifier` |
| Identifier values (`id`, `provider`, `targets`, pins, scopes) | 128 bytes, `[A-Za-z0-9._:-]` | `hypellm_core::ids::MAX_ID_LEN` via `Id::new` |
| Endpoint host | 253 bytes total, labels ≤ 63 | `hypellm_core::netaddr::is_valid_host` |
| Endpoint port | 0–65 535 | `u16::try_from`, `invalid_port` |
| Integer fields | 32- or 64-bit range, checked conversion | `Fields::u32_field` / `i32_field`, `integer_out_of_range` |
| Record types accepted | 13, closed set | `schema::SCHEMAS`; anything else is `unknown_record_type` |
| Field names accepted | Closed per record type | `schema::validate_record`; anything else is `unknown_field` |

Limits and validations that are **not** enforced here, and must not be assumed:

| Gap | Consequence |
|---|---|
| `provider base_path` is stored verbatim — no absoluteness, traversal, or length check beyond `max_value_bytes` | Path composition safety is entirely the adapter's responsibility |
| `settings` string fields (`inference_listen`, `admin_listen`, `metrics_listen`, `cors_origins`, `state_dir`, `tls_helper_socket`, `oidc_*`, `control_socket`) are accepted as free-form strings | A malformed listen address or CORS origin fails at bind/compare time, not at load; specification 15.2 exact-origin matching is enforced elsewhere |
| `residency` tokens are free-form and lowercased, never checked against a known set or cross-checked between tenant and target | A typo makes a target permanently ineligible and surfaces as `no_eligible_target` at request time rather than as a config error (fail-closed, but silent) |
| No cap on the number or total size of accumulated `ConfigError`s | See threat notes |
| No limit on lines, blank lines, or comments independent of `max_bytes` | Bounded only transitively by document size |

## Fuzz targets

`tests/fuzz.rs` — eight targets, run by `cargo test -p hypellm-config`. The
engine is `hypellm-test-corpus::fuzz`; there is no `fuzz/` directory and no
libFuzzer harness, because specification 4 admits no such dependency.

Configuration is not attacker-controlled the way a request body is, so the
threat these assert against is not memory corruption but a **fail-open**: a
malformed record silently ignored, or a field quietly defaulting to something
permissive, widens access with no error. That is not hypothetical here — this
suite found exactly that defect, an explicitly empty `model=` in a `grant`
widening it from one alias to every alias.

| Target | Property under attack |
|---|---|
| `no_mutation_of_a_configuration_panics_the_loader` | Every input either loads or reports errors; nothing is half-applied |
| `a_loaded_configuration_never_grants_more_than_its_text_says` | No silent widening: a grant naming one alias never becomes a grant over all |
| `an_unknown_field_is_always_an_error` | Specification 11.1's "unknown fields are errors", against mutations that rename one |
| `the_loader_is_deterministic` | Two loads of one text agree on digest, or on error codes |
| `a_very_long_line_is_refused_rather_than_consuming_the_process` | The line-oriented grammar's natural unbounded input |
| `deeply_repeated_records_are_bounded` | The many-records shape of the same |
| `random_text_is_rejected_without_panicking` | Unstructured input over the grammar's delimiters |
| `no_mutated_verifier_ever_accepts_a_password_it_was_not_built_from` | The fail-open specific to `local_user`: a corrupted verifier must refuse, never default into a guessable credential |

Still outstanding (§21, §18.2):

| Target | Property under attack |
|---|---|
| `config_parse` | Arbitrary bytes into `parse(text, &ParseLimits::DEFAULT)` never panics, never exceeds a declared limit, and always terminates |
| `config_canonical_roundtrip` | For any document that parses, `parse(to_canonical_string(d)) == d` and `to_canonical_string` is idempotent — the parser-differential and digest-stability property |
| `config_build` | `build` on any parseable document never panics, and error count and total message size stay within a stated bound |
| `config_endpoint_guard` | Generated `(scheme, host, port, egress)` tuples never yield an accepted endpoint that is non-loopback cleartext, of a class the profile forbids, or the metadata address |
| `config_limits` | Randomised `ParseLimits` are respected exactly — no off-by-one admits `max_records + 1` records or an oversized value |

## Public API

See `lib.rs`. Three layers, deliberately separable so that the management API
can report a parse failure differently from a validation failure:

- `parse::{parse, ParseLimits, Document, Record, ParseError, quote_if_needed,
  split_list}` — text to records, no semantics.
- `schema::{SCHEMAS, validate_record, Fields, ConfigError}` — the closed record
  set and strict typed field access. Booleans accept only `true`/`false`; `yes`,
  `on`, and `1` are errors, so `enabled=yse` cannot silently read as false.
- `build::{build, ValidatedConfig, Settings, …}` — reference resolution,
  invariants, canonical text, digest.

`load(text, version)` composes all three. The surface is intentionally narrow:
no partial builds, no lenient mode, no merge or overlay of documents, and no
way to construct a `ValidatedConfig` that skipped validation.
