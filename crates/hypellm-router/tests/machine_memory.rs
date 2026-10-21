//! Machine memory, end to end (specification 12.4): a real router and job
//! workers, two simulated shims for two targets on one machine, and jobs
//! submitted over a socket.
//!
//! The machine holds 100 units and each target's job 60, so the two can never
//! run at once. The properties: a job waits — without reaching its shim —
//! while another target's job holds the memory; and when memory comes back,
//! a waiting job of a higher class goes before a lower-class one that became
//! eligible at the same moment.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "specification 18.2 permits these in tests"
)]

use hypellm_core::time::Clock;
use hypellm_router::routes::InferenceHandler;
use hypellm_router::server::{Server, ServerConfig};
use hypellm_router::testing::{
    CannedResponse, FakeUpstream, ShimPart, ShimScript, SimulatedShim, TestRouter, router_with_config,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wire_json::{Limits, Value, parse};

fn config(video: u16, song: u16) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=60000 retry_budget_ms=60000 \\
         max_attempts=1 job_retention_ms=60000 job_poll_ms=250
tenant id=acme
credential id=cred_shim
machine id=spark memory_bytes=100
provider id=video family=job scheme=http host=127.0.0.1 port={video} egress=local \\
         credential=cred_shim machine=spark
target id=video:h3 provider=video model=h3 local=true operations=job \\
       capabilities=audio-to-video concurrency=1 run_memory_bytes=60 class=batch
provider id=song family=job scheme=http host=127.0.0.1 port={song} egress=local \\
         credential=cred_shim machine=spark
target id=song:yue2 provider=song model=yue2 local=true operations=job \\
       capabilities=text-to-music concurrency=1 run_memory_bytes=60 class=standard
alias id=h3 capability=audio-to-video targets=video:h3
alias id=yue2 capability=text-to-music targets=song:yue2
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=*
"
    )
}

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    workers: Vec<std::thread::JoinHandle<()>>,
    router: TestRouter,
    video: SimulatedShim,
    song: SimulatedShim,
    _upstream: FakeUpstream,
}

impl Harness {
    fn start(video: ShimScript, song: ShimScript) -> Self {
        let video = SimulatedShim::start(video);
        let song = SimulatedShim::start(song);
        let upstream = FakeUpstream::start(CannedResponse::json(200, "{}"));
        let router = router_with_config(&upstream, &config(video.address.port(), song.address.port()));
        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let server = Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = server.shutdown_handle();
        let handler = Arc::new(InferenceHandler::new(Arc::clone(&router.state)));
        let thread = std::thread::spawn(move || {
            let _ = server.serve(handler);
        });
        let workers = (0..4)
            .map(|_| {
                let state = Arc::clone(&router.state);
                std::thread::spawn(move || hypellm_router::jobs::worker_loop(&state))
            })
            .collect();
        Self {
            address,
            shutdown,
            thread: Some(thread),
            workers,
            router,
            video,
            song,
            _upstream: upstream,
        }
    }

    fn call(&self, method: &str, path: &str, body: &str) -> (u16, Vec<u8>) {
        request(self.address, &self.router.api_key, method, path, body)
    }

    fn submit(&self, body: &str) -> String {
        let (status, bytes) = self.call("POST", "/v1/jobs", body);
        assert_eq!(status, 202, "{}", String::from_utf8_lossy(&bytes));
        json(&bytes).get("job_id").and_then(Value::as_str).unwrap().to_owned()
    }

    fn state_of(&self, job: &str) -> String {
        let (_, bytes) = self.call("GET", &format!("/v1/jobs/{job}"), "");
        json(&bytes).get("state").and_then(Value::as_str).unwrap_or_default().to_owned()
    }

    fn wait_terminal(&self, job: &str) -> String {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let state = self.state_of(job);
            if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
                return state;
            }
            assert!(Instant::now() < until, "job stuck in {state}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_until(&self, what: &str, done: impl Fn() -> bool) {
        let until = Instant::now() + Duration::from_secs(15);
        while !done() {
            assert!(Instant::now() < until, "timed out waiting until {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(jobs) = self.router.state.jobs() {
            jobs.shutdown();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        self.shutdown.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn json(bytes: &[u8]) -> Value {
    parse(bytes, &Limits::DEFAULT)
        .unwrap_or_else(|_| panic!("not JSON: {}", String::from_utf8_lossy(bytes)))
}

fn request(address: SocketAddr, key: &str, method: &str, path: &str, body: &str) -> (u16, Vec<u8>) {
    let raw = format!(
        "{method} {path} HTTP/1.1\r\nHost: router.test\r\nContent-Type: application/json\r\n\
         Connection: close\r\nAuthorization: Bearer {key}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    let _ = stream.read_to_end(&mut bytes);
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").expect("a response head");
    let head = String::from_utf8_lossy(&bytes[..split]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, bytes[split + 4..].to_vec())
}

fn video_job() -> &'static str {
    r#"{"model":"h3","verb":"audio-to-video","prompt":"a lighthouse at dusk",
        "inputs":[{"name":"audio","media_type":"audio/wav","data":"UklGRg=="}]}"#
}

fn song_job() -> &'static str {
    r#"{"model":"yue2","verb":"text-to-music","prompt":"a lullaby"}"#
}

/// A shim whose first job runs for `polls` status polls, and every later one
/// finishes at once.
fn running_for(polls: u32, part: &str, media_type: &str) -> ShimScript {
    let mut script = ShimScript::succeeding(vec![ShimPart::honest(part, media_type, b"bytes")]);
    script.polls_before_done = polls;
    script
}

#[test]
fn a_job_waits_without_reaching_its_shim_while_another_target_holds_the_memory() {
    let h = Harness::start(running_for(8, "video", "video/mp4"), running_for(0, "audio", "audio/flac"));
    let video = h.submit(video_job());
    h.wait_until("the video job runs", || {
        h.video.log().iter().any(|l| l.starts_with("GET /job/v1/jobs/sim_0001 "))
    });
    let song = h.submit(song_job());
    // Several job-queue ticks pass with the video job still holding 60 of 100.
    let until = Instant::now() + Duration::from_millis(750);
    while Instant::now() < until {
        assert_eq!(h.state_of(&video), "running");
        assert!(h.song.submits().is_empty(), "the song job reached its shim beside the video job");
        assert_eq!(h.state_of(&song), "queued");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(h.wait_terminal(&video), "succeeded");
    assert_eq!(h.wait_terminal(&song), "succeeded");
    assert_eq!(h.song.submits().len(), 1);
    let views = h.router.state.admission.machine_views();
    assert_eq!(views[0].1.held_bytes, 0, "memory was not returned");
    assert!(views[0].1.waiting.is_empty(), "a claim outlived its job");
}

#[test]
fn a_waiting_higher_class_job_goes_before_a_lower_class_one() {
    let h = Harness::start(running_for(8, "video", "video/mp4"), running_for(0, "audio", "audio/flac"));
    let first = h.submit(video_job());
    h.wait_until("the first video job runs", || {
        h.video.log().iter().any(|l| l.starts_with("GET /job/v1/jobs/sim_0001 "))
    });
    // Both wait: the second video job for its target's slot, the song for the
    // memory. When the first ends both become eligible, and the song (standard)
    // must take the machine ahead of the second video job (batch).
    let second = h.submit(video_job());
    let song = h.submit(song_job());
    h.wait_until("the song or the second video job reaches its shim", || {
        !h.song.submits().is_empty() || h.video.submits().len() > 1
    });
    assert_eq!(h.song.submits().len(), 1, "the batch job took the machine first");
    assert_eq!(h.video.submits().len(), 1, "both ran on the machine at once");
    for job in [&first, &second, &song] {
        assert_eq!(h.wait_terminal(job), "succeeded");
    }
}
