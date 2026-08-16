//! Client protocol translation.
//!
//! Specification 8: compatibility is behavioural, not path-level. Each module
//! here owns one client dialect end to end — parsing a request into the
//! canonical model and rendering canonical events back out — so that a
//! dialect's quirks stay in one file and cannot leak into routing.
//!
//! | Module | Endpoints |
//! |---|---|
//! | [`openai`] | `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/models` |
//! | [`anthropic`] | `/v1/messages` |

pub mod anthropic;
pub mod openai;

pub use openai::ParseContext;
