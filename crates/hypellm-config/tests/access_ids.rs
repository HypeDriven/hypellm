//! The optional `id` on `grant` and `quota`.
//!
//! It exists so `POST /admin/v1/policies:edit` can address one record. It must
//! decide nothing at runtime — a grant with an id authorizes exactly what the
//! same grant without one does — and two records sharing one would make an
//! edit ambiguous, so a duplicate is an error rather than "the first wins".

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_config::load;
use hypellm_core::ids::{AliasId, PrincipalId, TenantId};
use hypellm_core::policy::RoutingContext;

const BASE: &str = "tenant id=acme
provider id=p family=llamacpp scheme=http host=127.0.0.1 port=8000
target id=p:m provider=p model=m capabilities=chat context=8192 max_output=1024
alias id=code targets=p:m
alias id=chat targets=p:m
binding id=default scope=tenant:acme prefer=*
grant scope=tenant:acme model=* allow=true
";

fn codes(extra: &str) -> Vec<String> {
    match load(&format!("{BASE}{extra}\n"), 1) {
        Ok(_) => Vec::new(),
        Err(errors) => errors.iter().map(|e| e.code.to_owned()).collect(),
    }
}

#[test]
fn a_grant_or_quota_id_must_be_unique_and_well_formed() {
    let twice = "grant id=g scope=principal:user:1 model=code allow=false\n\
                 grant id=g scope=principal:user:2 model=code allow=false";
    assert!(codes(twice).contains(&"duplicate_id".to_owned()));
    let quotas = "quota id=q scope=principal:user:1 class=batch\nquota id=q scope=principal:user:2 class=batch";
    assert!(codes(quotas).contains(&"duplicate_id".to_owned()));
    assert!(codes("grant id=\"a b\" scope=principal:user:1 allow=false").contains(&"invalid_identifier".to_owned()));
    // A grant and a quota may share one: each kind is addressed separately.
    assert!(codes("grant id=x scope=principal:user:1 allow=false\nquota id=x scope=principal:user:1 class=batch").is_empty());
}

#[test]
fn an_id_changes_nothing_a_grant_decides() {
    let principal = PrincipalId::new("user:1").unwrap();
    let tenant = TenantId::new("acme").unwrap();
    let ctx = RoutingContext { principal: &principal, groups: &[], tenant: &tenant, attempted: &[], now_millis: 0, key: None };
    let code = AliasId::new("code").unwrap();
    let chat = AliasId::new("chat").unwrap();
    for deny in [
        "grant scope=principal:user:1 model=code allow=false",
        "grant id=pg-1 scope=principal:user:1 model=code allow=false",
    ] {
        let config = load(&format!("{BASE}{deny}\n"), 1).expect("loads");
        let op = hypellm_core::canonical::Operation::Chat;
        assert!(!config.snapshot.authorizes(&ctx, &code, op), "{deny}");
        assert!(config.snapshot.authorizes(&ctx, &chat, op), "{deny}");
    }
}

#[test]
fn a_second_quota_for_one_scope_is_refused_rather_than_replacing_the_first() {
    // The fail-open: a class-only quota added after a limited one would have
    // replaced its limits with none.
    let pair = "quota scope=principal:user:1 concurrency=2\nquota id=q scope=principal:user:1 class=batch";
    assert!(codes(pair).contains(&"duplicate_quota".to_owned()), "{:?}", codes(pair));
    // Different operations on one alias are different scopes.
    assert!(codes("quota scope=alias:code operation=chat rps=1\nquota scope=alias:code operation=embeddings rps=1").is_empty());
}
