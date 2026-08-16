//! The HypeLLM Router gateway.
//!
//! Specification 18.1: "hypellm-router — Binary, startup validation, listener
//! orchestration, privilege drop, shutdown."
//!
//! A library plus a thin binary, so the request pipeline is testable without
//! spawning a process.
//!
//! ```text
//!  client bytes
//!       │
//!  server.rs      accept, bound connections, parse the head strictly
//!       │
//!  routes.rs      dispatch by exact path
//!       │
//!  protocol/      parse into CanonicalRequest, render events back out
//!       │
//!  pipeline.rs    route once, then reserve → attempt → meter → audit
//!       │
//!  dispatch.rs    one attempt: encode, connect, stream, classify
//!       │
//!  hypellm-net      egress guard, pinning, pooling, TLS boundary
//! ```

#![forbid(unsafe_code)]
// Specification 18.2: "no panics on data-plane input", "all integer
// conversions checked". This crate is the data plane — listener, request
// pipeline, protocol translation — so the workspace-level `warn` is escalated
// to `deny` here. A new unchecked index or silent `as` is a compile error, not
// one more line in a warning list. Individual exceptions carry a `#[allow]` on
// the smallest enclosing item together with the reason it cannot fail.
//
// Scoped to `not(test)`: specification 18.2 forbids these "outside startup
// invariants and tests", and `cfg(test)` is exactly the set of code that is not
// the data plane. Escalating there too made `cargo clippy --all-targets` fail
// on assertions — which does not make the data plane safer, it just means
// nobody runs the wider lint. The per-test-module `#[allow]`s below are now
// redundant and kept as a second line of defence.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        clippy::panic,
        clippy::expect_used
    )
)]

pub mod admin;
pub mod dispatch;
pub mod hardening;
pub mod pipeline;
pub mod protocol;
pub mod routes;
pub mod server;
pub mod startup;
pub mod state;
#[cfg(any(test, feature = "test-harness"))]
pub mod testing;
