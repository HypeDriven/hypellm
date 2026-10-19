//! Artifact jobs through a job shim, end to end (orchestration §11.3–§11.5):
//! a real router and job workers, `POST /v1/jobs` over a socket, and a
//! simulated shim speaking the protocol on another.
//!
//! Each test names the property it would catch the absence of. The shim is
//! scripted to be adversarial where the property is about what a shim can do
//! to the router: a part longer than it said, a type other than it said.

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
    FakeUpstream, CannedResponse, ShimPart, ShimScript, SimulatedShim, TestRouter, router_with_config,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wire_json::{Limits, Value, parse};

const PNG: &str = "iVBORw0KGgo=";

fn config(shim: u16) -> String {
    format!(
        "\
settings state_dir=/tmp/hypellm-test default_deadline_ms=60000 retry_budget_ms=60000 \\
         max_attempts=1 job_retention_ms=60000
tenant id=acme
credential id=cred_shim
provider id=trellis family=job scheme=http host=127.0.0.1 port={shim} egress=local credential=cred_shim
target id=trellis:img3d provider=trellis model=trellis local=true operations=job \\
       capabilities=image-to-3d concurrency=1
alias id=mesh capability=image-to-3d targets=trellis:img3d
grant scope=tenant:acme model=* allow=true
binding id=default scope=tenant:acme model=* prefer=trellis:img3d
"
    )
}

struct Harness {
    address: SocketAddr,
    shutdown: hypellm_router::server::ShutdownHandle,
    thread: Option<std::thread::JoinHandle<()>>,
    workers: Vec<std::thread::JoinHandle<()>>,
    router: TestRouter,
    shim: SimulatedShim,
    _upstream: FakeUpstream,
}

impl Harness {
    fn start(script: ShimScript) -> Self {
        let shim = SimulatedShim::start(script);
        let upstream = FakeUpstream::start(CannedResponse::json(200, "{}"));
        let router = router_with_config(&upstream, &config(shim.address.port()));
        let clock: Arc<dyn Clock> = Arc::clone(&router.state.clock);
        let server = Server::bind("127.0.0.1:0", ServerConfig::inference(), clock).unwrap();
        let address = server.local_addr().unwrap();
        let shutdown = server.shutdown_handle();
        let handler = Arc::new(InferenceHandler::new(Arc::clone(&router.state)));
        let thread = std::thread::spawn(move || {
            let _ = server.serve(handler);
        });
        let workers = (0..2)
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
            shim,
            _upstream: upstream,
        }
    }

    fn call(&self, method: &str, path: &str, body: &str) -> Response {
        request(self.address, &self.router.api_key, method, path, body)
    }

    fn submit(&self, body: &str) -> String {
        let response = self.call("POST", "/v1/jobs", body);
        assert_eq!(response.status, 202, "{}", response.text());
        response.json().get("job_id").and_then(Value::as_str).unwrap().to_owned()
    }

    fn wait_terminal(&self, job: &str) -> Value {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let view = self.call("GET", &format!("/v1/jobs/{job}"), "").json();
            let state = view.get("state").and_then(Value::as_str).unwrap_or_default().to_owned();
            if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
                return view;
            }
            assert!(Instant::now() < until, "job stuck in {state}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn spool_dir(&self, job: &str) -> std::path::PathBuf {
        self.router.dir.path().join("jobs").join(job)
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

struct Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        parse(&self.body, &Limits::DEFAULT).unwrap_or_else(|_| panic!("not JSON: {}", self.text()))
    }

    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }
}

fn request(address: SocketAddr, key: &str, method: &str, path: &str, body: &str) -> Response {
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
    Response {
        status,
        head,
        body: bytes[split + 4..].to_vec(),
    }
}

fn mesh_job() -> String {
    format!(
        r#"{{"model":"mesh","verb":"image-to-3d","prompt":"a chair",
            "params":{{"seed":7}},
            "inputs":[{{"name":"image","media_type":"image/png","data":"{PNG}"}}]}}"#
    )
}

#[test]
fn an_artifact_job_reaches_its_shim_and_its_parts_are_served_as_attachments() {
    let glb = b"glTF-binary-mesh-bytes".to_vec();
    let ply = vec![7_u8; 4096];
    let h = Harness::start(ShimScript::succeeding(vec![
        ShimPart::honest("mesh", "model/gltf-binary", &glb),
        ShimPart::honest("points", "application/octet-stream", &ply),
    ]));
    let job = h.submit(&mesh_job());
    let view = h.wait_terminal(&job);
    assert_eq!(view.get("state").and_then(Value::as_str), Some("succeeded"), "{view:?}");
    let parts = view.get("parts").and_then(Value::as_array).expect("parts listed");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].get("name").and_then(Value::as_str), Some("mesh"));
    assert_eq!(
        parts[0].get("sha256").and_then(Value::as_str).map(str::to_owned),
        Some(hypellm_crypto::hex::encode(&hypellm_crypto::sha256::sha256(&glb)))
    );

    // The first part is the result, served as an attachment that cannot be
    // sniffed into a page.
    let result = h.call("GET", &format!("/v1/jobs/{job}/result"), "");
    assert_eq!(result.status, 200);
    assert_eq!(result.body, glb);
    assert_eq!(result.header("content-type").as_deref(), Some("model/gltf-binary"));
    assert_eq!(result.header("x-content-type-options").as_deref(), Some("nosniff"));
    assert!(result.header("content-disposition").unwrap_or_default().starts_with("attachment"));
    let points = h.call("GET", &format!("/v1/jobs/{job}/result/points"), "");
    assert_eq!(points.body, ply);
    assert_eq!(h.call("GET", &format!("/v1/jobs/{job}/result/nothing"), "").status, 404);

    // Every request to the shim carried the router's credential, and the
    // input travelled inline.
    let log = h.shim.log();
    assert!(!log.is_empty() && log.iter().all(|line| line.ends_with(" auth")), "{log:?}");
    let submit = parse(&h.shim.submits()[0], &Limits::DEFAULT).unwrap();
    assert_eq!(submit.get("verb").and_then(Value::as_str), Some("image-to-3d"));
    let inputs = submit.get("inputs").and_then(Value::as_array).unwrap();
    assert_eq!(inputs[0].get("data").and_then(Value::as_str), Some(PNG));
}

#[test]
fn a_part_longer_than_its_declared_length_fails_the_job_and_leaves_no_spool_file() {
    // Orchestration §11.8: the shim declares 8 bytes and serves 9 — for the
    // second part, after the first was spooled honestly, so the cleanup has
    // a file to remove.
    let mut liar = ShimPart::honest("points", "application/octet-stream", b"123456789");
    liar.declared_bytes = 8;
    let h = Harness::start(ShimScript::succeeding(vec![
        ShimPart::honest("mesh", "model/gltf-binary", b"honest"),
        liar,
    ]));
    let job = h.submit(&mesh_job());
    let view = h.wait_terminal(&job);
    assert_eq!(view.get("state").and_then(Value::as_str), Some("failed"), "{view:?}");
    assert!(!h.spool_dir(&job).exists(), "a spool file outlived a failed fetch");
    assert_eq!(h.call("GET", &format!("/v1/jobs/{job}/result"), "").status, 404);
}

#[test]
fn a_part_whose_type_differs_from_its_status_is_never_spooled_or_served() {
    // Declared a mesh, served a page: the head check refuses it before a byte
    // is kept, and nothing scriptable reaches a browser.
    let mut page = ShimPart::honest("mesh", "model/gltf-binary", b"<script>1</script>");
    page.served_type = "text/html".to_owned();
    let h = Harness::start(ShimScript::succeeding(vec![page]));
    let job = h.submit(&mesh_job());
    let view = h.wait_terminal(&job);
    assert_eq!(view.get("state").and_then(Value::as_str), Some("failed"), "{view:?}");
    assert!(!h.spool_dir(&job).exists());
}

#[test]
fn a_shim_that_has_not_loaded_its_model_makes_the_job_wait_rather_than_fail() {
    let mut script = ShimScript::succeeding(vec![ShimPart::honest("mesh", "model/gltf-binary", b"m")]);
    script.submit_refusals = vec![(503, "not_ready")];
    let h = Harness::start(script);
    let job = h.submit(&mesh_job());
    let view = h.wait_terminal(&job);
    assert_eq!(view.get("state").and_then(Value::as_str), Some("succeeded"), "{view:?}");
    assert_eq!(h.shim.submits().len(), 2, "the job was not tried again");
}

#[test]
fn an_input_the_service_refuses_ends_the_job_with_that_reason() {
    let mut script = ShimScript::succeeding(Vec::new());
    script.fail_with = Some("invalid_input");
    let h = Harness::start(script);
    let job = h.submit(&mesh_job());
    let view = h.wait_terminal(&job);
    assert_eq!(view.get("state").and_then(Value::as_str), Some("failed"));
    assert_eq!(h.shim.submits().len(), 1, "an invalid input was retried");
}

#[test]
fn a_verb_the_alias_does_not_serve_is_refused_at_submission() {
    let h = Harness::start(ShimScript::succeeding(Vec::new()));
    let response = h.call(
        "POST",
        "/v1/jobs",
        r#"{"model":"mesh","verb":"text-to-music","prompt":"a song"}"#,
    );
    assert_eq!(response.status, 400, "{}", response.text());
    assert!(h.shim.submits().is_empty());
}

#[test]
fn a_cancelled_job_tells_its_shim_and_fetches_nothing() {
    let mut script = ShimScript::succeeding(vec![ShimPart::honest("mesh", "model/gltf-binary", b"m")]);
    script.polls_before_done = 1_000;
    let h = Harness::start(script);
    let job = h.submit(&mesh_job());
    let until = Instant::now() + Duration::from_secs(10);
    while !h.shim.log().iter().any(|l| l.starts_with("GET /job/v1/jobs/sim_0001 ")) {
        assert!(Instant::now() < until, "the job never reached its shim");
        std::thread::sleep(Duration::from_millis(10));
    }
    let cancelled = h.call("DELETE", &format!("/v1/jobs/{job}"), "");
    assert_eq!(cancelled.status, 200, "{}", cancelled.text());
    let view = h.wait_terminal(&job);
    assert_eq!(view.get("state").and_then(Value::as_str), Some("cancelled"));
    let until = Instant::now() + Duration::from_secs(10);
    while !h.shim.log().iter().any(|l| l.starts_with("DELETE /job/v1/jobs/sim_0001 ")) {
        assert!(Instant::now() < until, "the shim was never told: {:?}", h.shim.log());
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!h.shim.log().iter().any(|l| l.contains("/parts/")), "a cancelled job fetched parts");
}
