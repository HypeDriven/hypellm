# Module: hypellm-crypto

Specification 4.1 requires every in-repository module to declare an owner, threat
notes, public API, unsafe-code declaration, fuzz targets, and maximum
input/resource limits.

| Field | Value |
|---|---|
| Owner | Security (primary), Platform (secondary) |
| Unsafe code | None. `#![forbid(unsafe_code)]` inherited from the workspace. |
| External dependencies | None. Rust standard library only. |
| Fuzz targets | **None for this crate yet.** Required: `sha256_stream`, `base64_roundtrip`, `hex_roundtrip` (§21). The workspace engine is `hypellm-test-corpus::fuzz`; five other crates use it. |

## Scope and the "no novel cryptography" rule

Specification 4 (`TLS reality`) and 9.1 (`OIDC dependency boundary`) forbid
writing novel signature or TLS code to satisfy the dependency policy. This module
does **not** implement TLS, asymmetric signatures, key agreement, JWT signature
verification, or any AEAD. Those remain delegated to the platform boundary
(`hypellm-net::helper`, types `TlsHelper` and `VerifierClient`) or to the
audited-exception profile.

What this module *does* implement is the set of fully-specified, deterministic,
test-vector-verifiable primitives the router cannot function without:

| Primitive | Reference | Why the router needs it |
|---|---|---|
| SHA-256 | FIPS 180-4 | Configuration digests, audit hash chain, credential/session digests |
| HMAC-SHA-256 | RFC 2104 / FIPS 198-1 | Keyed API-key digests, protected store frames, CSRF binding, pseudonyms |
| CRC-32 (IEEE 802.3) | ITU-T V.42 | Cheap non-protected store frame checksums (corruption, not tampering) |
| Base64 / Base64url | RFC 4648 | Key material encoding, OIDC PKCE/state, cookie values |
| Hex | RFC 4648 §8 | Digest display in audit records and config digests |
| Constant-time compare | — | Digest comparison without timing oracle |

Every primitive is validated against published vectors in the unit tests. A
divergence from the reference is a build failure, not a runtime surprise.

## Threat notes

- **Timing side channels.** All secret-vs-candidate comparisons must go through
  `ct::eq`. Comparing `Digest` values with `==` is safe because `PartialEq` for
  `Digest` is itself implemented in constant time.
- **Secret material in memory.** `Secret<N>` zeroes its bytes on drop and
  redacts `Debug`. This is best-effort: the specification (7.1) says "zeroed on
  release where the platform permits". Rust gives no guarantee against compiler
  copies; do not treat this as a hard boundary.
- **Randomness failure.** `random::fill` reads `/dev/urandom` and returns an
  error rather than falling back to a weaker source. Callers on the security
  path must fail closed. There is no user-space PRNG in this module by design.
- **Length-extension.** Raw SHA-256 is length-extendable. Never authenticate a
  message with `sha256(secret || message)`; use `hmac_sha256`.

## Limits

| Input | Limit |
|---|---|
| SHA-256 message length | 2^61 - 1 bytes (FIPS bound); enforced by `u64` bit counter saturation check |
| HMAC key length | Unbounded input, hashed down to 32 bytes when > 64 |
| Base64 decode input | Caller-supplied `max_output` (bytes), default callers use 8 KiB |
| Hex decode input | Caller-supplied buffer size |

## Public API

See `lib.rs`. The surface is intentionally narrow: no streaming HMAC, no
configurable digest sizes, no algorithm negotiation.
