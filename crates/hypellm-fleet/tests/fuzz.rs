//! Seeded, deterministic fuzzing of the fleet's untrusted surfaces.
//!
//! There is no `fuzz/` directory and no libFuzzer: specification 4 admits no
//! such dependency. The engine is the shared mutator in
//! `hypellm_test_corpus::fuzz`, driven from ordinary `#[test]` functions so
//! that `cargo test` runs it and a failure is reproducible by seed number.
//!
//! # Each target asserts a property
//!
//! A target that only asserts "does not panic" is close to worthless here. The
//! three below assert things the code could plausibly get wrong:
//!
//! - **`agent_inventory`** — no identifier the configuration does not declare
//!   is ever adopted, no numeric field escapes its range, and a refused payload
//!   yields nothing at all rather than a partial belief.
//! - **`agent_replies`** — no malformed reply advances the activation state
//!   machine, no sanitised token escapes the identifier alphabet, and a reply
//!   is never read against a verb that did not provoke it.
//! - **`plan_execution`** — no interleaving of acquire, transition, release,
//!   and expiry leaks a lease or drives a host's slot count out of step with
//!   the leases actually held.
//!
//! # What this is not
//!
//! Not coverage-guided, and it does not shrink. It finds what its seeds and
//! mutation strategies reach, and a failing case prints at whatever size it was
//! generated.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::ids::{
    AcceleratorId, AgentId, ArtifactId, DeploymentId, HostId, LeaseId, PoolId, TargetId,
};
use hypellm_fleet::activation::{
    ActivationLedger, ActivationOutcome, ActivationRecord, ActivationState, LeaseRelease,
};
use hypellm_fleet::model::{
    Accelerator, AcceleratorKind, Arch, Deployment, FleetAgent, FleetConfig, Host, HostState,
    Readiness,
};
use hypellm_fleet::plan::{Plan, PlanStep, PlanTrace};
use hypellm_fleet::protocol::{
    AgentReply, AgentRequest, MAX_CODE_LEN, MAX_LINE, parse_reply, sanitize_token,
};
use hypellm_fleet::state::{Lease, LeaseOperation, MAX_INVENTORY_BYTES, parse_inventory};
use hypellm_test_corpus::fuzz::{Rng, mutate};

/// The fleet every inventory case is parsed against.
///
/// Small on purpose: what matters is which identifiers it declares, because
/// that is the whole allowlist a mutated payload has to get past.
fn fleet() -> FleetConfig {
    let mut fleet = FleetConfig::empty();
    fleet.enabled = true;
    fleet.agents.insert(
        AgentId::new("local").unwrap(),
        FleetAgent {
            id: AgentId::new("local").unwrap(),
            socket: "/run/hypellm/fleet.sock".to_owned(),
            observation_interval_ms: 5_000,
            observation_max_age_ms: 30_000,
            request_timeout_ms: 5_000,
        },
    );
    fleet.hosts.insert(
        HostId::new("spark").unwrap(),
        Host {
            id: HostId::new("spark").unwrap(),
            agent: AgentId::new("local").unwrap(),
            arch: Arch::Aarch64,
            state: HostState::Enabled,
            reserved_memory_bytes: 0,
            max_concurrent_activations: 1,
        },
    );
    fleet.accelerators.insert(
        AcceleratorId::new("gb10").unwrap(),
        Accelerator {
            id: AcceleratorId::new("gb10").unwrap(),
            host: HostId::new("spark").unwrap(),
            kind: AcceleratorKind::Unified,
            memory_bytes: 140 * 1024 * 1024 * 1024,
            pool: PoolId::new("spark-unified").unwrap(),
        },
    );
    fleet.deployments.insert(
        DeploymentId::new("spark-music3").unwrap(),
        Deployment {
            id: DeploymentId::new("spark-music3").unwrap(),
            target: TargetId::new("spark:music3").unwrap(),
            accelerator: AcceleratorId::new("gb10").unwrap(),
            artifact: Some(ArtifactId::new("music3").unwrap()),
            memory_bytes: 64 * 1024 * 1024 * 1024,
            start_ms: 180_000,
            stop_ms: 15_000,
            drain_ms: 30_000,
            probe_ms: 10_000,
            readiness: Readiness::HttpOk,
            min_resident_ms: 600_000,
            evictable: true,
            pinned: false,
            autostart: true,
            retention_weight: 0,
            max_drainable_inflight: 0,
            force_stop: false,
        },
    );
    fleet.artifacts.insert(
        ArtifactId::new("music3").unwrap(),
        hypellm_fleet::model::Artifact {
            id: ArtifactId::new("music3").unwrap(),
            kind: hypellm_fleet::model::ArtifactKind::Image,
            arch: Arch::Aarch64,
            size_bytes: 20 * 1024 * 1024 * 1024,
            digest: format!("sha256:{}", "0".repeat(64)),
            source: "mirror".to_owned(),
        },
    );
    fleet
}

const INVENTORY_SEEDS: &[&[u8]] = &[
    br#"{"deployments":[{"id":"spark-music3","state":"ready","memory_bytes":1,"inflight":0}]}"#,
    br#"{"deployments":[{"id":"spark-music3","state":"starting","state_age_ms":100}]}"#,
    br#"{"accelerators":[{"id":"gb10","used_memory_bytes":10,"total_memory_bytes":100}]}"#,
    br#"{"hosts":[{"id":"spark","reachable":true,"free_disk_bytes":1024,"arch":"aarch64"}]}"#,
    br#"{"artifacts":[{"id":"music3","host":"spark","present":true,"verified":true}]}"#,
    br#"{"deployments":[],"hosts":[],"accelerators":[],"artifacts":[]}"#,
    br#"{}"#,
];

#[test]
fn agent_inventory_never_adopts_an_undeclared_identifier() {
    let fleet = fleet();
    let mut rng = Rng::new(0x1_0001);
    let mut accepted = 0u32;

    for _ in 0..4_000 {
        let seed = rng.pick(INVENTORY_SEEDS).copied().unwrap_or(b"{}");
        let case = mutate(seed, &mut rng);
        let Ok(inventory) = parse_inventory(&case, &fleet) else {
            continue;
        };
        accepted += 1;

        for id in inventory.deployments.keys() {
            assert!(
                fleet.deployments.contains_key(id),
                "adopted deployment {id} that the configuration does not declare"
            );
        }
        for id in inventory.hosts.keys() {
            assert!(fleet.hosts.contains_key(id), "adopted host {id}");
        }
        for id in inventory.accelerators.keys() {
            assert!(
                fleet.accelerators.contains_key(id),
                "adopted accelerator {id}"
            );
        }
        for (artifact, host) in inventory.artifacts.keys() {
            assert!(fleet.artifacts.contains_key(artifact), "adopted artifact");
            assert!(fleet.hosts.contains_key(host), "adopted host by artifact");
        }
        for observation in inventory.accelerators.values() {
            assert!(
                observation.total_memory_bytes == 0
                    || observation.used_memory_bytes <= observation.total_memory_bytes,
                "a device reported using more than it has"
            );
        }
        assert!(
            inventory.deployments.len() <= fleet.deployments.len(),
            "more deployments were adopted than exist"
        );
    }

    assert!(
        accepted > 100,
        "only {accepted} payloads parsed; the mutator is not reaching the parser"
    );
}

#[test]
fn an_inventory_that_is_refused_leaves_nothing_behind() {
    // A half-applied observation means planning against a mixture of two
    // moments. The parser must produce a whole inventory or none.
    let fleet = fleet();
    let mut rng = Rng::new(0x1_0002);
    let mut refused = 0u32;
    for _ in 0..4_000 {
        let seed = rng.pick(INVENTORY_SEEDS).copied().unwrap_or(b"{}");
        let case = mutate(seed, &mut rng);
        match parse_inventory(&case, &fleet) {
            Ok(_) => {}
            Err(error) => {
                refused += 1;
                // The error itself must be one of the closed set, so a caller
                // can act on it rather than on a string.
                assert!(
                    !error.code().is_empty(),
                    "a refusal must carry a stable code"
                );
            }
        }
    }
    assert!(refused > 10, "only {refused} payloads were refused");
}

#[test]
fn an_oversized_inventory_is_refused_before_it_is_parsed() {
    let fleet = fleet();
    let payload = vec![b' '; MAX_INVENTORY_BYTES + 1];
    assert!(parse_inventory(&payload, &fleet).is_err());
}

const REPLY_SEEDS: &[&[u8]] = &[
    b"OK sim-1 sha256deadbeef\n",
    b"OK 4096\n",
    b"ACCEPTED act-7\n",
    b"OK ready done 1000\n",
    b"OK starting loading 500\n",
    b"ERR unknown_deployment\n",
    b"OK\n",
    b"\n",
];

fn requests() -> Vec<AgentRequest> {
    vec![
        AgentRequest::Hello {
            nonce: "abcd".to_owned(),
            fleet_digest: "sha256deadbeef".to_owned(),
            hmac: "00".to_owned(),
        },
        AgentRequest::Observe,
        AgentRequest::Activate {
            deployment: DeploymentId::new("spark-music3").unwrap(),
            lease: LeaseId::new("l-1").unwrap(),
            deadline_ms: 1_000,
        },
        AgentRequest::Status {
            activation: hypellm_core::ids::ActivationId::new("act-7").unwrap(),
        },
        AgentRequest::Cancel {
            activation: hypellm_core::ids::ActivationId::new("act-7").unwrap(),
        },
    ]
}

#[test]
fn no_malformed_agent_reply_advances_the_activation_state_machine() {
    let mut rng = Rng::new(0x2_0001);
    let ledger = ActivationLedger::new();
    let lease = LeaseId::new("l-1").unwrap();
    let plan = Plan {
        deployment: DeploymentId::new("spark-music3").unwrap(),
        host: HostId::new("spark").unwrap(),
        steps: vec![PlanStep::Activate(
            DeploymentId::new("spark-music3").unwrap(),
        )],
        eta_ms: 1_000,
        trace: PlanTrace::default(),
    };
    let record = ActivationRecord::from_plan(
        &plan,
        Lease {
            id: lease.clone(),
            deployment: DeploymentId::new("spark-music3").unwrap(),
            operation: LeaseOperation::Activate,
            issued_ms: 0,
            expires_ms: u64::MAX,
            decision_id: String::new(),
        },
        0,
    );
    assert!(ledger.acquire(record, 1));
    assert!(ledger.transition(&lease, ActivationState::LeaseHeld));
    assert!(ledger.transition(&lease, ActivationState::Starting));

    let verbs = requests();
    let mut parsed = 0u32;
    for _ in 0..8_000 {
        let seed = rng.pick(REPLY_SEEDS).copied().unwrap_or(b"\n");
        let case = mutate(seed, &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };
        let request = rng.pick(&verbs).cloned().unwrap_or(AgentRequest::Observe);

        match parse_reply(&request, text) {
            Err(_) => {
                // A reply the router could not understand must leave the
                // machine where it was. The state below is checked after every
                // case, so a transition on a malformed reply shows up here.
            }
            Ok(reply) => {
                parsed += 1;
                match reply {
                    AgentReply::Error { code } | AgentReply::Hello { agent_version: code, .. } => {
                        assert!(code.len() <= MAX_CODE_LEN);
                        assert!(
                            code.chars()
                                .all(|c| c.is_ascii_alphanumeric()
                                    || c == '_'
                                    || c == '-'
                                    || c == '.'),
                            "a sanitised token escaped the identifier alphabet: {code:?}"
                        );
                    }
                    AgentReply::Status {
                        progress_permille, ..
                    } => assert!(progress_permille <= 1_000),
                    AgentReply::InventoryPending { length } => {
                        assert!(length <= MAX_INVENTORY_BYTES);
                    }
                    AgentReply::Accepted { .. } | AgentReply::Ok => {}
                }
            }
        }
        assert_eq!(
            ledger.state_of(&lease),
            Some(ActivationState::Starting),
            "parsing a reply moved the activation state machine"
        );
    }
    assert!(parsed > 100, "only {parsed} replies parsed");
}

#[test]
fn a_reply_is_never_parsed_against_a_verb_that_did_not_provoke_it() {
    // `OK 4096` is an inventory length after OBSERVE and nonsense elsewhere. A
    // parser that accepted it everywhere would let a confused agent answer one
    // verb with another's reply.
    let mut rng = Rng::new(0x2_0002);
    let verbs = requests();
    for _ in 0..4_000 {
        let seed = rng.pick(REPLY_SEEDS).copied().unwrap_or(b"\n");
        let case = mutate(seed, &mut rng);
        let Ok(text) = core::str::from_utf8(&case) else {
            continue;
        };
        for request in &verbs {
            let Ok(reply) = parse_reply(request, text) else {
                continue;
            };
            let permitted = match (request, &reply) {
                (_, AgentReply::Error { .. }) => true,
                (AgentRequest::Hello { .. }, AgentReply::Hello { .. })
                | (AgentRequest::Observe, AgentReply::InventoryPending { .. })
                | (AgentRequest::Activate { .. }, AgentReply::Accepted { .. })
                | (AgentRequest::Deactivate { .. }, AgentReply::Accepted { .. })
                | (AgentRequest::Fetch { .. }, AgentReply::Accepted { .. })
                | (AgentRequest::Status { .. }, AgentReply::Status { .. })
                | (AgentRequest::Cancel { .. }, AgentReply::Ok) => true,
                _ => false,
            };
            assert!(
                permitted,
                "{} accepted a {reply:?}",
                request.verb()
            );
        }
    }
}

#[test]
fn a_sanitised_token_never_escapes_the_identifier_alphabet() {
    let mut rng = Rng::new(0x2_0003);
    for _ in 0..8_000 {
        let case = mutate(b"code_with-dots.and\x1b[2Jescapes\n\"quotes\"", &mut rng);
        let text = String::from_utf8_lossy(&case);
        let token = sanitize_token(&text);
        assert!(token.len() <= MAX_CODE_LEN);
        assert!(
            token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'),
            "escaped: {token:?}"
        );
    }
}

#[test]
fn an_over_long_reply_line_is_refused_rather_than_read() {
    let line = "OK ".to_owned() + &"a".repeat(MAX_LINE);
    assert!(parse_reply(&AgentRequest::Observe, &line).is_err());
}

#[test]
fn no_interleaving_of_lease_operations_leaks_a_lease() {
    let mut rng = Rng::new(0x3_0001);
    for round in 0..200u64 {
        let ledger = ActivationLedger::new();
        let host = HostId::new("spark").unwrap();
        let mut live: Vec<LeaseId> = Vec::new();
        let concurrency = 1 + u32::try_from(rng.below(4)).unwrap_or(0);

        for step in 0..64u64 {
            let now = step.saturating_mul(1_000);
            match rng.below(5) {
                0 | 1 => {
                    let id = LeaseId::new(format!("l-{round}-{step}")).unwrap();
                    let plan = Plan {
                        deployment: DeploymentId::new("spark-music3").unwrap(),
                        host: host.clone(),
                        steps: vec![PlanStep::Activate(
                            DeploymentId::new("spark-music3").unwrap(),
                        )],
                        eta_ms: 1_000,
                        trace: PlanTrace::default(),
                    };
                    let lease = Lease {
                        id: id.clone(),
                        deployment: DeploymentId::new("spark-music3").unwrap(),
                        operation: LeaseOperation::Activate,
                        issued_ms: now,
                        expires_ms: now.saturating_add(10_000),
                        decision_id: String::new(),
                    };
                    if ledger.acquire(ActivationRecord::from_plan(&plan, lease, now), concurrency)
                    {
                        live.push(id);
                    }
                }
                2 => {
                    if let Some(id) = live.pop() {
                        assert_eq!(
                            ledger.release(&id, ActivationOutcome::Succeeded, "ready", now),
                            LeaseRelease::Released
                        );
                    }
                }
                3 => {
                    // Expiry, which releases without the caller knowing.
                    for id in ledger.expired(now) {
                        if ledger.release(&id, ActivationOutcome::Cancelled, "expired", now)
                            == LeaseRelease::Released
                        {
                            live.retain(|held| held != &id);
                        }
                    }
                }
                _ => {
                    // A spurious release of a lease that may already be gone.
                    let id = LeaseId::new(format!("l-{round}-{}", rng.below(64))).unwrap();
                    let before = ledger.slots_held(&host);
                    let outcome =
                        ledger.release(&id, ActivationOutcome::Failed, "spurious", now);
                    if outcome != LeaseRelease::Released {
                        assert_eq!(
                            ledger.slots_held(&host),
                            before,
                            "a refused release must not return a slot"
                        );
                    } else {
                        live.retain(|held| held != &id);
                    }
                }
            }

            assert_eq!(
                ledger.slots_held(&host),
                u32::try_from(live.len()).unwrap_or(u32::MAX),
                "round {round}, step {step}: slots and live leases diverged"
            );
            assert!(
                ledger.slots_held(&host) <= concurrency,
                "round {round}: more slots held than the host permits"
            );
        }

        let (acquired, released) = ledger.accounting();
        assert_eq!(
            acquired,
            released.saturating_add(u64::try_from(live.len()).unwrap_or(0)),
            "round {round}: leases leaked"
        );
    }
}
