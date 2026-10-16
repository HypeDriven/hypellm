//! The liveness probe runs on one thread, however many rounds it does.
//!
//! In a binary of its own because it counts the process's threads: any other
//! test running beside it would start and stop threads of its own and make the
//! count meaningless. Specification 3.2: no unbounded thread may originate from
//! the probe's work, so the count while it runs must be flat.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(target_os = "linux")]

use hypellm_router::probe;
use hypellm_router::testing::{CannedResponse, FakeUpstream, router_with_config};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const OK_BODY: &str = r#"{"status":"ok"}"#;

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

#[test]
fn many_probe_rounds_start_no_thread_and_the_loop_is_one() {
    let slave = FakeUpstream::start(CannedResponse::json(200, OK_BODY));
    let port = slave.address.port();
    let text = format!(
        "\
settings state_dir=/tmp/hypellm-test target_probe_interval_ms=1000 target_probe_timeout_ms=500
tenant id=acme
provider id=a family=llamacpp scheme=http host=127.0.0.1 port={port} base_path=/v1 egress=local
provider id=b family=semif scheme=http host=127.0.0.1 port={port} egress=local
target id=a:m provider=a model=m local=true operations=chat context=1000 max_output=100
target id=b:m provider=b model=m local=true capabilities=rerank operations=rerank context=1000 max_output=1
alias id=chat targets=a:m
alias id=decide capability=rerank targets=b:m
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=*
"
    );
    let router = router_with_config(&slave, &text);

    // Rounds on this thread: each probe dials, answers and closes; nothing is
    // left running.
    let before = threads();
    for _ in 0..100 {
        assert_eq!(probe::run_round(&router.state, Duration::from_millis(500), &|| false), 2);
    }
    assert_eq!(threads(), before, "a probe round left a thread behind");

    // The loop itself: one thread for its whole life, sampled across rounds.
    let stop = Arc::new(AtomicBool::new(false));
    let thread = {
        let state = Arc::clone(&router.state);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || probe::probe_loop(&state, &|| stop.load(Ordering::SeqCst)))
    };
    let running = before + 1;
    let until = Instant::now() + Duration::from_millis(2_500);
    while Instant::now() < until {
        assert_eq!(threads(), running, "the probe loop's thread count moved");
        std::thread::sleep(Duration::from_millis(100));
    }
    stop.store(true, Ordering::SeqCst);
    thread.join().unwrap();
    assert!(slave.served() > 200, "the loop must actually have probed");
}
