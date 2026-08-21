//! The `hypellm-router` binary.
//!
//! Specification 18.1: "Binary, startup validation, listener orchestration,
//! privilege drop, shutdown."
//!
//! ```text
//! hypellm-router --config <path> --secrets <dir> [--static <dir>] [--log <level>]
//! hypellm-router --check --config <path>
//! hypellm-router --generate-secrets <dir>
//! hypellm-router --version
//! ```
//!
//! # Shutdown
//!
//! The router stops when its control socket receives `shutdown`. Signal
//! handling would need `unsafe` FFI to `sigaction`, which specification 18.2
//! forbids workspace-wide; the control socket is the dependency-free
//! equivalent and is documented in `docs/deployment.md`. A supervisor that can
//! only send `SIGTERM` should be configured with a `KillSignal` shim that
//! writes to the socket, or accept that termination is not graceful.

#![forbid(unsafe_code)]
// Specification 18.2, as in `lib.rs`: unchecked indexing and silent `as`
// conversions are compile errors in the router, not warnings.
#![cfg_attr(not(test), deny(clippy::indexing_slicing, clippy::as_conversions, clippy::panic))]

use hypellm_router::startup::{Router, Secrets, StartupError, check_config};
use hypellm_telemetry::Severity;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Exit codes, so a supervisor can distinguish the failure.
mod exit {
    /// Configuration did not validate, or arguments were wrong.
    pub(crate) const CONFIGURATION: u8 = 2;
    /// The state directory could not be opened, or its integrity failed.
    pub(crate) const STATE: u8 = 3;
    /// A listener could not be bound.
    pub(crate) const LISTENER: u8 = 4;
    /// A required secret was missing.
    pub(crate) const SECRETS: u8 = 5;
}

#[derive(Debug, Default)]
struct Arguments {
    config: Option<PathBuf>,
    secrets: Option<PathBuf>,
    static_root: Option<PathBuf>,
    log_level: Option<Severity>,
    check: bool,
    generate_secrets: Option<PathBuf>,
    control: Option<&'static str>,
    adopt_config: Option<String>,
    version: bool,
    help: bool,
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut arguments = Arguments::default();
    let mut argv = std::env::args().skip(1);

    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--config" | "-c" => {
                arguments.config = Some(PathBuf::from(
                    argv.next().ok_or("--config requires a path")?,
                ));
            }
            "--secrets" => {
                arguments.secrets = Some(PathBuf::from(
                    argv.next().ok_or("--secrets requires a directory")?,
                ));
            }
            "--static" => {
                arguments.static_root = Some(PathBuf::from(
                    argv.next().ok_or("--static requires a directory")?,
                ));
            }
            "--log" => {
                let level = argv.next().ok_or("--log requires a level")?;
                arguments.log_level = Some(
                    Severity::parse(&level)
                        .ok_or_else(|| format!("unknown log level '{level}'"))?,
                );
            }
            "--check" => arguments.check = true,
            "--adopt-config" => {
                arguments.adopt_config = Some(
                    argv.next()
                        .ok_or("--adopt-config requires a reason, which is recorded")?,
                );
            }
            // Sending the command through the binary rather than by hand keeps
            // the control token out of shell history and out of the process
            // list: it is read from the secrets directory here, never passed as
            // an argument.
            "--shutdown" => arguments.control = Some("shutdown"),
            "--ping" => arguments.control = Some("ping"),
            "--generate-secrets" => {
                arguments.generate_secrets = Some(PathBuf::from(
                    argv.next().ok_or("--generate-secrets requires a directory")?,
                ));
            }
            "--version" | "-V" => arguments.version = true,
            "--help" | "-h" => arguments.help = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(arguments)
}

const USAGE: &str = "\
hypellm-router — secure, high-performance LLM routing gateway

USAGE:
    hypellm-router --config <path> --secrets <dir> [--static <dir>] [--log <level>]
    hypellm-router --check --config <path>
    hypellm-router --generate-secrets <dir>
    hypellm-router --adopt-config REASON --config <path> --secrets <dir>
    hypellm-router --shutdown --config <path> --secrets <dir>
    hypellm-router --ping --config <path> --secrets <dir>

OPTIONS:
    -c, --config <path>        the configuration file
        --secrets <dir>        directory holding the platform secret files
        --static <dir>         serve the admin application from this directory
        --log <level>          debug | info | warn | error | critical
        --check                validate the configuration and exit
        --generate-secrets <d> write a fresh secret bundle and exit
        --adopt-config <why>   start from the configuration file, overriding any
                               published policy; the reason is audited
        --shutdown             ask a running router to drain and stop
        --ping                 check that a running router answers
    -V, --version              print the version
    -h, --help                 print this message

EXIT CODES:
    0  clean shutdown
    2  configuration or arguments invalid
    3  state directory unusable or integrity failure
    4  a listener could not be bound
    5  a required secret was missing
";

/// Send one authenticated command to a running router and print its reply.
///
/// The token comes from the secrets directory rather than from an argument, so
/// it never appears in the process list or in shell history — the same reason
/// specification 10 keeps the router's own keys in files rather than in the
/// environment.
fn send_control_command(config_path: &std::path::Path, control_key: &[u8], command: &str) -> ExitCode {
    let config = match check_config(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("hypellm-router: {e}");
            return ExitCode::from(exit::CONFIGURATION);
        }
    };
    let path = match hypellm_router::startup::control_socket_path(&config) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("hypellm-router: {message}");
            return ExitCode::from(exit::CONFIGURATION);
        }
    };

    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&path) else {
        eprintln!(
            "hypellm-router: no router is listening at {}",
            path.display()
        );
        return ExitCode::from(exit::STATE);
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));

    let line = format!("{} {command}\n", hypellm_crypto::hex::encode(control_key));
    if stream.write_all(line.as_bytes()).is_err() {
        eprintln!("hypellm-router: the control socket closed before the command was sent");
        return ExitCode::from(exit::STATE);
    }

    let mut reply = String::new();
    let _ = BufReader::new(stream).read_line(&mut reply);
    let reply = reply.trim();
    println!("{reply}");
    if reply == "unauthenticated" {
        eprintln!(
            "hypellm-router: the running router refused this control.key — \
             it was started with a different secrets directory"
        );
        return ExitCode::from(exit::SECRETS);
    }
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let arguments = match parse_arguments() {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("hypellm-router: {message}\n\n{USAGE}");
            return ExitCode::from(exit::CONFIGURATION);
        }
    };

    if arguments.help {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if arguments.version {
        println!("hypellm-router {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    if let Some(dir) = arguments.generate_secrets {
        let generated = Secrets::generate()
            .map_err(|e| format!("cannot generate secrets: {e}"))
            .and_then(|secrets| {
                secrets
                    .write_to(&dir)
                    .map_err(|e| format!("cannot write to {}: {e}", dir.display()))
            });
        return match generated {
            Ok(()) => {
                println!("wrote a secret bundle to {}", dir.display());
                println!(
                    "these files are the router's root of trust: \
                     protect them as you would a private key"
                );
                println!(
                    "control.key authenticates `--shutdown` and `--ping`; \
                     anyone who can read it can stop this router"
                );
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("hypellm-router: {message}");
                ExitCode::from(exit::SECRETS)
            }
        };
    }

    let Some(config_path) = arguments.config else {
        eprintln!("hypellm-router: --config is required\n\n{USAGE}");
        return ExitCode::from(exit::CONFIGURATION);
    };

    if arguments.check {
        return match check_config(&config_path) {
            Ok(config) => {
                println!(
                    "configuration is valid: {} providers, {} targets, {} aliases",
                    config.snapshot.providers.len(),
                    config.snapshot.targets.len(),
                    config.snapshot.aliases.len()
                );
                println!("digest {}", config.digest);
                // The fleet digest is printed separately and only when a fleet
                // is declared, because it is a *different* agreement: the
                // configuration digest says what this router activated, and
                // this says what it and its agents must both believe the fleet
                // is. An operator compares it against
                // `fleet-agent --print-digest` before enabling orchestration,
                // and the router refuses every mutating verb while the two
                // disagree.
                if !config.fleet.deployments.is_empty() {
                    println!(
                        "fleet: {} hosts, {} accelerators, {} deployments, {} artifacts \
                         ({})",
                        config.fleet.hosts.len(),
                        config.fleet.accelerators.len(),
                        config.fleet.deployments.len(),
                        config.fleet.artifacts.len(),
                        if config.settings.fleet_enabled {
                            "enabled"
                        } else {
                            "declared but not enabled"
                        }
                    );
                    println!("fleet digest {}", config.fleet.digest());
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("hypellm-router: {e}");
                ExitCode::from(exit::CONFIGURATION)
            }
        };
    }

    let Some(secrets_dir) = arguments.secrets else {
        eprintln!("hypellm-router: --secrets is required\n\n{USAGE}");
        return ExitCode::from(exit::CONFIGURATION);
    };
    let secrets = match Secrets::from_dir(&secrets_dir) {
        Ok(secrets) => secrets,
        Err(e) => {
            eprintln!("hypellm-router: {e}");
            eprintln!("run `hypellm-router --generate-secrets {}` to create one", secrets_dir.display());
            return ExitCode::from(exit::SECRETS);
        }
    };
    if let Some(command) = arguments.control {
        return send_control_command(&config_path, &secrets.control, command);
    }

    let oidc_key = secrets.oidc.clone();
    // Kept before `secrets` is moved into the router. The control socket needs
    // it to authenticate commands (specification 20.1 authorises graceful
    // shutdown, not an unauthenticated trigger for it).
    let control_key = secrets.control.clone();

    let log_level = arguments.log_level.unwrap_or(Severity::Info);
    // A reason is required rather than optional. This overrides a policy that
    // went through drafting, review, and approval; whoever reads the audit
    // record afterwards needs to know why, and an operator typing it is being
    // asked to have a reason.
    if let Some(reason) = arguments.adopt_config.as_deref() {
        if reason.trim().len() < 8 {
            eprintln!(
                "hypellm-router: --adopt-config needs a reason of at least 8 characters; \
                 it is recorded in the audit chain"
            );
            return ExitCode::from(exit::CONFIGURATION);
        }
    }
    let router = match Router::assemble_with(
        &config_path,
        secrets,
        log_level,
        arguments.adopt_config.as_deref(),
    ) {
        Ok(router) => router,
        Err(e) => {
            eprintln!("hypellm-router: {e}");
            return ExitCode::from(match e {
                StartupError::Store(_) => exit::STATE,
                StartupError::Listener { .. } => exit::LISTENER,
                StartupError::MissingSecret(_) => exit::SECRETS,
                _ => exit::CONFIGURATION,
            });
        }
    };

    let config = router.state.config();
    let cors = hypellm_admin_api::CorsPolicy::with_origins(config.settings.cors_origins.clone());

    eprintln!(
        "hypellm-router listening: inference {} management {}",
        router
            .inference
            .local_addr()
            .map_or_else(|_| "?".to_owned(), |a| a.to_string()),
        router
            .management
            .local_addr()
            .map_or_else(|_| "?".to_owned(), |a| a.to_string())
    );

    // The control socket is the shutdown mechanism. See the module comment for
    // why it is not a signal handler.
    let (inference_shutdown, management_shutdown) = router.shutdown_handles();
    let control_path = match hypellm_router::startup::control_socket_path(&config) {
        Ok(path) => path,
        Err(message) => {
            eprintln!("hypellm-router: {message}");
            return ExitCode::from(exit::CONFIGURATION);
        }
    };
    let _ = std::fs::remove_file(&control_path);
    match UnixListener::bind(&control_path) {
        Ok(listener) => {
            // Two controls, because either alone is one mistake from failing
            // open. The mode narrows who can *open* the socket; the token
            // decides whether an opener may act. A deployment that gets the
            // directory mode wrong still cannot be stopped by a local account
            // that has not read the secrets directory.
            if let Err(e) = hypellm_router::state::restrict_to_owner(&control_path) {
                eprintln!(
                    "hypellm-router: cannot restrict the control socket at {}: {e}",
                    control_path.display()
                );
                return ExitCode::from(exit::STATE);
            }

            let inference_shutdown = inference_shutdown.clone();
            let management_shutdown = management_shutdown.clone();
            let thread_path = control_path.clone();
            // Hex, so the token is a single whitespace-free word an operator
            // can paste, and so the comparison is over a fixed-width string
            // rather than over whatever the caller sent.
            let expected_hex = hypellm_crypto::hex::encode(&control_key).into_bytes();
            let spawned = std::thread::Builder::new()
                .name("hypellm-control".to_owned())
                .spawn(move || {
                    for stream in listener.incoming() {
                        let Ok(stream) = stream else { break };
                        let mut reply = match stream.try_clone() {
                            Ok(handle) => handle,
                            Err(_) => continue,
                        };
                        let mut line = String::new();
                        if BufReader::new(stream).read_line(&mut line).is_err() {
                            continue;
                        }
                        let Some(command) = hypellm_router::startup::authenticated_control_command(
                            &line,
                            &expected_hex,
                        ) else {
                            let _ = reply.write_all(b"unauthenticated\n");
                            eprintln!("hypellm-router: refused an unauthenticated control command");
                            continue;
                        };

                        match command {
                            "shutdown" | "drain" => {
                                let _ = reply.write_all(b"shutting down\n");
                                inference_shutdown.shutdown();
                                management_shutdown.shutdown();
                                break;
                            }
                            "ping" => {
                                let _ = reply.write_all(b"pong\n");
                            }
                            other => {
                                let _ = reply
                                    .write_all(format!("unknown command '{other}'\n").as_bytes());
                            }
                        }
                    }
                    let _ = std::fs::remove_file(&thread_path);
                });
            if spawned.is_err() {
                eprintln!("hypellm-router: the control socket thread could not be started");
            } else {
                eprintln!(
                    "hypellm-router: control socket at {} \
                     (run `hypellm-router --shutdown --config <path> --secrets <dir>` to stop; \
                     commands must present the token in <secrets>/control.key)",
                    control_path.display()
                );
            }
        }
        Err(e) => {
            // Without it there is no graceful shutdown, which specification
            // 20.1 requires. Refusing to start is better than running a router
            // that cannot be drained.
            eprintln!(
                "hypellm-router: cannot bind the control socket at {}: {e}",
                control_path.display()
            );
            eprintln!(
                "hypellm-router: without a control socket the router cannot be shut down \
                 gracefully; set `control_socket` in the settings record"
            );
            return ExitCode::from(exit::LISTENER);
        }
    }

    let verifier: Option<Arc<dyn hypellm_auth::oidc::TokenVerifier>> = config
        .settings
        .oidc_verifier_socket
        .as_ref()
        .map(|path| {
            let client: Arc<dyn hypellm_auth::oidc::TokenVerifier> =
                Arc::new(hypellm_net::VerifierClient::new(
                    path.clone(),
                    std::time::Duration::from_secs(5),
                ));
            client
        });

    let oidc_config = config.settings.oidc_issuer.as_ref().and_then(|issuer| {
        Some(hypellm_auth::oidc::OidcConfig {
            issuer: issuer.clone(),
            client_id: config.settings.oidc_client_id.clone()?,
            authorization_endpoint: config.settings.oidc_authorization_endpoint.clone()?,
            token_endpoint: config.settings.oidc_token_endpoint.clone()?,
            redirect_uri: config.settings.oidc_redirect_uri.clone()?,
            hosted_domains: config.settings.oidc_hosted_domains.clone(),
            clock_skew_millis: 60_000,
        })
    });

    match router.serve(cors, oidc_config, verifier, oidc_key, arguments.static_root) {
        Ok(()) => {
            eprintln!("hypellm-router: shutdown complete");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hypellm-router: listener error: {e}");
            ExitCode::from(exit::LISTENER)
        }
    }
}
