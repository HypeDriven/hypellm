# HypeLLM Router — local workflow on the fleet k3s cluster (namespace hypellm).
#
#   just bootstrap  first run: secrets, router, and a key to call it with
#   just up         build the image, start the router, print its endpoints
#   just key        mint another API key
#   just down       delete the namespace; the router drains on SIGTERM
#   just logs       follow the router's structured log
#   just status     is it up, and what is it serving
#   just tailnet    the tailnet node: address, routes, who can reach it
#   just oidc       write the OAuth secret from .env, start the verifier
#
# `just --list` prints the rest. The manifests are in k8s/; kstack and the
# cluster conventions are described in ~/system/docs/k3s.md.

set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := false

config := justfile_directory() / "docker" / "hypellm.conf"

ns      := "hypellm"
image   := "hypellm-router:local"
kubectl := "kubectl --context " + env("KUBE_CONTEXT", "fleet") + " -n " + ns

# Everything printed and probed below is read back out of that file rather than
# restated here. Two copies of a port number drift, and this is the copy every
# health check and printed URL uses — a stale one sends the reader to an
# address nothing is listening on. k8s/publish.yaml publishes each listener to
# the same port on 127.0.0.1, so the configured ports are also the host's.
inference_port := `sed -n 's/.*inference_listen=[^:]*:\([0-9]*\).*/\1/p' docker/hypellm.conf | head -1`
admin_port     := `sed -n 's/.*admin_listen=[^:]*:\([0-9]*\).*/\1/p' docker/hypellm.conf | head -1`
metrics_port   := `sed -n 's/.*metrics_listen=[^:]*:\([0-9]*\).*/\1/p' docker/hypellm.conf | head -1`

# Bind-mount roots. Covered by .gitignore's /run rule; nothing here is
# committable, and run/secrets is the router's root of trust.
state_dir     := justfile_directory() / "run" / "state"
secrets_dir   := justfile_directory() / "run" / "secrets"
tailscale_dir := justfile_directory() / "run" / "tailscale"
# Nightly backups (k8s/backup.yaml): `current` is the router's backup_dir, `archive` the dated copies.
backups_dir   := justfile_directory() / "run" / "backups"

# The identity verifier's two directories, created empty and used only by the
# verifier `just oidc` starts (see spec/components/identity-verifier.html). `verify` is the socket
# the router reaches it on and is mounted into both pods; `verifier` holds
# verifier.json and the OAuth client secret, so it is 0700 and never committed.
verify_dir    := justfile_directory() / "run" / "verify"
verifier_dir  := justfile_directory() / "run" / "verifier"

# The one-shot tools below (`check`, `password`, `shell`, secret generation)
# run as the invoking user so the bind-mounted files stay readable from the
# host without sudo. The pod runs as uid/gid 1000 for the same reason.
# The LAN publisher in k8s/publish.yaml binds this address; keep the two in step.
lan_addr := "192.168.8.121"
lan_net  := "192.168.8.0/24"

uid := `id -u`
gid := `id -g`

_default:
    @just --list --unsorted

# Build the image, start the router, and print where it is listening.
#
# The router and its tailnet node are two containers in one pod, so the
# network namespace belongs to the pod and survives a restart of either. The
# Compose-era failure where a restarted sidecar stranded the router in a dead
# namespace cannot happen here.
[doc('Build the image, start the router, and print where it is listening')]
up: _ports _dirs build _secrets _authkey
    kstack load {{image}}
    kstack apply {{ns}}
    kstack roll {{ns}} {{image}}
    @just _tailnet_up
    kstack wait {{ns}} --timeout 120
    @just _wait
    @just _drift
    @just endpoints

# --- API keys --------------------------------------------------------------
#
# Everything here goes through break-glass, because with no OIDC provider
# configured it is the only credential that carries `manage_keys` — the shipped
# `admin` password account reaches every other screen and not this one. Three
# consequences worth knowing before reaching for these:
#
#   * The token is printed once by `--generate-secrets` and stored nowhere —
#     the router keeps a verifier it cannot invert. `bootstrap` is the only
#     recipe that ever learns it without being told.
#   * Every sign-in emits a `critical` log event and an audit record. That is
#     the emergency path working, not noise to suppress.
#   * Minting, listing and revoking all need `manage_keys`, which specification
#     9.1 marks as requiring recent authentication — five minutes. So each of
#     these signs in fresh rather than caching a session that would usually be
#     stale before it was reused.
#
# No secret is ever passed as a command-line argument: /proc/<pid>/cmdline is
# readable by every account on the host, and a pipe and an environment are not.
# Secrets reach curl through `-K -` or `--data-binary @-` on stdin, and the
# break-glass token reaches a child `just` through the environment.

# From nothing to a key something can actually call the router with.
#
# The gap this closes: `just up` leaves a router that answers /health and
# refuses everything else, and the first key needs a token that scrolled past
# during setup. Here that token is captured from the generator's stdout, spent
# on the sign-in, and printed at the end to be stored offline.
[doc('Generate secrets, start the router, and mint the first API key')]
bootstrap principal="agent":
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f "{{secrets_dir}}/store_mac.key" ]; then
        printf '\n\033[1;31m  A secret bundle already exists in run/secrets.\033[0m\n' >&2
        printf '  %s\n' "Generating another would rewrite store_mac.key, and run/state is" >&2
        printf '  %s\n' "authenticated under the current one — the router would refuse to open" >&2
        printf '  %s\n' "its own log rather than start with history it cannot verify." >&2
        printf '\n  %s\n' "still have the break-glass token:      just key {{principal}}" >&2
        printf '  %s\n\n'  "lost it, and run/state is expendable:  just bootstrap-fresh" >&2
        exit 1
    fi
    just _dirs
    just build
    echo "→ generating the secret bundle in run/secrets"
    # Captured, not printed. This is the only moment the token exists anywhere:
    # `--generate-secrets` writes the verifier and drops the token, so one that
    # is not read here leaves a break-glass path nothing can satisfy — which is
    # the state this recipe exists to avoid.
    generated=$(docker run --rm --network none \
        -u "{{uid}}:{{gid}}" \
        -v "{{secrets_dir}}:/etc/hypellm/secrets" \
        {{image}} --generate-secrets /etc/hypellm/secrets)
    token=$(sed -n 's/^break-glass token: //p' <<<"$generated" | head -1)
    if [ -z "$token" ]; then
        printf '%s\n' "$generated" >&2
        echo "hypellm: no break-glass token in that output; refusing to continue" >&2
        exit 1
    fi
    just up
    # Exported rather than passed as an argument, and written to no file.
    export HYPELLM_BREAK_GLASS_TOKEN="$token"
    just key {{principal}}
    printf '\033[1m  Break-glass token\033[0m  \033[2m%s\033[0m\n' "save this offline now"
    printf '    \033[33m%s\033[0m\n\n' "$token"
    printf '  \033[2m%s\033[0m\n' "Stored nowhere and unrecoverable. Without it the management plane has no"
    printf '  \033[2m%s\033[0m\n' "credential at all until Google OIDC is configured, and the only way back"
    printf '  \033[2m%s\033[0m\n\n' "is just bootstrap-fresh, which discards run/state."

# Discard the router's key bundle and the state it authenticates, then
# bootstrap again.
#
# For one situation: the break-glass token is lost, so the management plane is
# unreachable and no key can be minted. Everything in run/state authenticates
# under the store MAC key, so a new bundle without a new state directory is a
# router that will not start — the two go together or not at all.
#
# Deliberately narrower than `rm -rf run/secrets`: provider credentials there
# are the operator's, not the router's, and a missing one that the
# configuration declares is a startup failure rather than a warning.
[doc('Discard the router keys and run/state, then bootstrap from scratch')]
bootstrap-fresh principal="agent":
    #!/usr/bin/env bash
    set -euo pipefail
    printf '\n\033[1;31m  This discards the root of trust and everything it authenticates.\033[0m\n'
    printf '  %s\n' "run/secrets   the eight router keys, including the store MAC key"
    printf '  %s\n' "run/state     API keys, sessions, activations, the audit chain"
    printf '\n  %s\n' "Kept: run/secrets/credentials, so provider credentials survive, and"
    printf '  %s\n\n'  "run/tailscale, so the node keeps its tailnet identity."
    if [ "${HYPELLM_ASSUME_YES:-}" != "1" ]; then
        if [ ! -r /dev/tty ]; then
            echo "hypellm: no terminal to confirm on; set HYPELLM_ASSUME_YES=1 to proceed" >&2
            exit 1
        fi
        printf '  Type \033[1mdiscard\033[0m to continue: '
        read -r reply < /dev/tty
        if [ "$reply" != "discard" ]; then
            echo "  nothing was changed"
            exit 1
        fi
    fi
    just down
    for f in store_mac.key key_verifier.key session.key pseudonym.key oidc.key \
             control.key fleet.key break_glass.verifier; do
        rm -f "{{secrets_dir}}/$f"
    done
    rm -rf "{{state_dir}}"
    just bootstrap {{principal}}

# Mint an API key and print it once.
#
# Scopes are comma separated and default to what a coding harness needs. Ask
# for fewer where fewer will do: a key without `embeddings` gets a 403 from
# /v1/embeddings rather than a routing decision, which is the point of them.
[doc('Mint an API key: just key <principal> [scopes]')]
key principal="agent" scopes="inference,models,embeddings,tokenize":
    #!/usr/bin/env bash
    set -euo pipefail
    read -r cookie csrf < <(just _session "minting an API key for {{principal}}")
    # The request body carries no secret and can go in a file; the session
    # cookie carries a full management session and goes in a pipe.
    body=$(mktemp)
    trap 'rm -f "$body"' EXIT
    jq -nc --arg p "{{principal}}" --arg s "{{scopes}}" \
       '{principal:$p, scopes:($s|split(",")), description:"minted by just key"}' >"$body"
    response=$(curl -sS -K - <<CFG
    url = "http://127.0.0.1:{{admin_port}}/admin/v1/keys"
    request = "POST"
    header = "Cookie: __Host-hypellm_session=$cookie"
    header = "X-Hypellm-Csrf: $csrf"
    header = "Content-Type: application/json"
    data-binary = "@$body"
    CFG
    )
    secret=$(jq -r '.secret // empty' <<<"$response" 2>/dev/null || true)
    if [ -z "$secret" ]; then
        echo "hypellm: the key was not created" >&2
        jq . <<<"$response" >&2 2>/dev/null || printf '%s\n' "$response" >&2
        exit 1
    fi
    id=$(jq -r '.id' <<<"$response")
    base="http://127.0.0.1:{{inference_port}}/v1"
    echo
    printf '\033[1m  API key\033[0m  \033[2m%s · %s · shown once\033[0m\n' "$id" "{{scopes}}"
    printf '    \033[32m%s\033[0m\n\n' "$secret"
    printf '  \033[2m%s\033[0m\n' "for an OpenAI-compatible client:"
    printf '    export OPENAI_BASE_URL=%s\n' "$base"
    printf '    export OPENAI_API_KEY=%s\n\n' "$secret"
    printf '  \033[2m%s\033[0m\n' "try it     curl -H \"Authorization: Bearer \$OPENAI_API_KEY\" $base/models"
    printf '  \033[2m%s\033[0m\n\n' "revoke it  just revoke $id"

# The keys this tenant holds. No secrets here — the router kept verifiers.
[doc('List API keys')]
keys:
    #!/usr/bin/env bash
    set -euo pipefail
    read -r cookie csrf < <(just _session "listing API keys")
    curl -sS -K - <<CFG | jq '.items // .'
    url = "http://127.0.0.1:{{admin_port}}/admin/v1/keys"
    header = "Cookie: __Host-hypellm_session=$cookie"
    CFG

# Revoke a key. Immediate, monotonic, and not subject to publication delay:
# this is the operation that runs during a compromise.
[doc('Revoke an API key by id')]
revoke id:
    #!/usr/bin/env bash
    set -euo pipefail
    read -r cookie csrf < <(just _session "revoking API key {{id}}")
    code=$(curl -sS -o /dev/null -w '%{http_code}' -K - <<CFG
    url = "http://127.0.0.1:{{admin_port}}/admin/v1/keys/{{id}}"
    request = "DELETE"
    header = "Cookie: __Host-hypellm_session=$cookie"
    header = "X-Hypellm-Csrf: $csrf"
    CFG
    )
    case "$code" in
        2*) echo "revoked {{id}}" ;;
        *)  echo "hypellm: revoking {{id}} failed with HTTP $code" >&2; exit 1 ;;
    esac

# Sign in over break-glass and echo "<session cookie> <csrf token>".
#
# The token comes from HYPELLM_BREAK_GLASS_TOKEN when set — which is how
# `bootstrap` hands it over, and how a non-interactive caller supplies it — and
# otherwise from a hidden prompt on the terminal. It goes to curl on stdin, so
# it appears in no process list and in no file.
_session reason:
    #!/usr/bin/env bash
    set -euo pipefail
    token="${HYPELLM_BREAK_GLASS_TOKEN:-}"
    if [ -z "$token" ]; then
        if [ ! -r /dev/tty ]; then
            echo "hypellm: set HYPELLM_BREAK_GLASS_TOKEN; there is no terminal to prompt on" >&2
            exit 1
        fi
        printf 'break-glass token (hidden): ' >&2
        read -rs token < /dev/tty
        printf '\n' >&2
    fi
    if [ -z "$token" ]; then
        echo "hypellm: no break-glass token given" >&2
        exit 1
    fi
    headers=$(mktemp)
    trap 'rm -f "$headers"' EXIT
    # printf is a shell builtin, so the payload never becomes another process's
    # argv on its way to curl's stdin.
    payload=$(jq -nc --arg t "$token" --arg r "{{reason}}" '{token:$t, reason:$r}')
    body=$(printf '%s' "$payload" | curl -sS -D "$headers" -X POST \
        -H 'Content-Type: application/json' --data-binary @- \
        "http://127.0.0.1:{{admin_port}}/admin/v1/auth/break-glass") \
        || { echo "hypellm: nothing answered on :{{admin_port}} — is the router up?" >&2; exit 1; }
    csrf=$(jq -r '.csrf_token // empty' <<<"$body" 2>/dev/null || true)
    if [ -z "$csrf" ]; then
        printf '\033[1;31mbreak-glass sign-in failed\033[0m\n' >&2
        jq -r '.error.message // .' <<<"$body" >&2 2>/dev/null || printf '%s\n' "$body" >&2
        printf '\033[2m%s\033[0m\n' "the token is the one --generate-secrets printed once. If it is lost," >&2
        printf '\033[2m%s\033[0m\n' "just bootstrap-fresh is the only way back, and it discards run/state." >&2
        exit 1
    fi
    cookie=$(sed -n 's/.*__Host-hypellm_session=\([^;]*\).*/\1/p' "$headers" | tr -d '\r' | head -1)
    if [ -z "$cookie" ]; then
        echo "hypellm: the sign-in returned no session cookie" >&2
        exit 1
    fi
    printf '%s %s\n' "$cookie" "$csrf"

# Build the image. Runs depscan and the release build inside the container.
build:
    docker build -f docker/Dockerfile -t {{image}} .

# Validate docker/hypellm.conf without starting anything. Prints the
# configuration digest, and the fleet digest when a fleet is declared.
[doc('Validate docker/hypellm.conf and print its digest')]
check: build
    @docker run --rm --network none \
        -v "{{config}}:/etc/hypellm/hypellm.conf:ro" \
        {{image}} --check --config /etc/hypellm/hypellm.conf

# The identity verifier's two test layers.
#
# `--selftest` is the JOSE logic in-process — algorithm confusion, key
# selection, tampering, bounds — and needs only openssl. `acceptance` stands the
# real process up behind a local TLS key-set server and drives it twice: once
# over a re-derived copy of the router's framing, once through the router's own
# `VerifierClient`. Neither reaches the network.
#
# The client half lives in `crates/hypellm-net/tests/verifier_acceptance.rs` and
# is `#[ignore]`d, because starting a process is what specification 4.1 forbids
# the router from doing — so the harness starts it and the tests only connect.
# `cargo test --workspace` therefore stays hermetic and skips them.
# Derive a password verifier for a `local_user` record.
#
# The password is read from stdin, never from an argument: `/proc/<pid>/cmdline`
# is readable by every account on this host. `read -rs` keeps it out of shell
# history too, which a `just password the-secret` could not.
[doc('Derive a local_user password verifier, reading the password from stdin')]
password:
    #!/usr/bin/env bash
    set -euo pipefail
    printf 'password: ' >&2
    read -rs value
    printf '\n' >&2
    [ -n "$value" ] || { echo "empty password" >&2; exit 1; }
    printf '%s' "$value" | docker run --rm -i --network none \
        --entrypoint /usr/local/bin/hypellm-router {{image}} --hash-password

[doc('Run the identity verifier self-test and end-to-end acceptance')]
verifier-acceptance:
    @verifier/hypellm-verifier --selftest
    @echo
    @verifier/acceptance

# Bring up Google sign-in: the OAuth client secret, then the verifier process.
#
# The secret comes from `.env` (see `.env.example`) and lands in
# `run/verifier/client_secret`. Everything else the verifier needs is in
# `run/verifier/verifier.json`, which is copied and edited by hand because two
# of its fields — `client_id` and `redirect_uri` — have to match the router's
# configuration and the Google console byte for byte, and a recipe that
# generated them would be a third place for them to disagree.
#
# `--check` before `up`: it loads the configuration, asserts the secret file is
# present and non-empty, and prints what it resolved without starting a socket.
# It prints "loaded" for the secret, never the secret.
[doc('Write the OAuth client secret from .env and start the identity verifier')]
oidc: _dirs _verifier_secret
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -f "{{verifier_dir}}/verifier.json" ]; then
        echo "hypellm: run/verifier/verifier.json does not exist" >&2
        echo >&2
        echo "  cp verifier/verifier.example.json run/verifier/verifier.json" >&2
        echo >&2
        echo "  then set client_id and redirect_uri to match oidc_client_id and" >&2
        echo "  oidc_redirect_uri in {{config}}, and the authorized redirect URI" >&2
        echo "  on the OAuth client. See spec/components/identity-verifier.html." >&2
        exit 1
    fi
    # A one-shot container with the verifier pod's mounts, as the same user.
    docker run --rm --network none -u "{{uid}}:{{gid}}" \
        -v "{{justfile_directory()}}/verifier:/opt/hypellm-verifier:ro" \
        -v "{{verifier_dir}}:/etc/hypellm/verifier:ro" \
        python:3.13-slim python3 /opt/hypellm-verifier/hypellm-verifier \
        --config /etc/hypellm/verifier/verifier.json --check
    # Restarted after the apply, not just applied: its script arrives over a
    # hostPath, so an unchanged manifest would leave the old process running
    # the old script.
    kstack apply {{ns}} --dir k8s/oidc
    {{kubectl}} rollout restart deploy/verifier >/dev/null

    # It has no health check, so without this an immediate exit is silent and
    # the next thing the operator sees is a sign-in that says the verifier is
    # not configured.
    if ! {{kubectl}} rollout status deploy/verifier --timeout=60s; then
        echo "hypellm: the verifier did not start; its log follows" >&2
        {{kubectl}} logs deploy/verifier --tail 20 >&2 || true
        exit 1
    fi
    echo
    echo "  The verifier is up. The router reads its socket only when"
    echo "  oidc_verifier_socket is set in {{config}}; add the oidc_* settings"
    echo "  there and \`just restart\` if you have not already."

# Delete the namespace. The pod gets SIGTERM, which supervisor/hypellm-init
# turns into `shutdown` over the authenticated control socket: admission stops
# and in-flight requests drain. terminationGracePeriodSeconds is 45 s, above
# the inference listener's 30 s drain deadline, so the drain is never cut off
# by SIGKILL. run/ is a hostPath and is untouched.
[doc('Delete the namespace; the router drains on SIGTERM')]
down:
    kstack down {{ns}}

# Graceful stop and start, picking up an edited docker/hypellm.conf.
restart: down up

# Once any policy has been published through the management API, the router
# resumes the last published version on every start and ignores this file —
# a reviewed policy must not vanish on a restart (spec/deployment.html,
# "Startup"). This makes docker/hypellm.conf the active configuration again:
# one start with `--adopt-config`, whose reason goes into the audit chain, then
# the normal arguments back. Anything published since that is not also in the
# file is replaced, so copy it into the file first.
[doc('Make docker/hypellm.conf the active configuration again, with a recorded reason')]
adopt reason:
    #!/usr/bin/env bash
    set -euo pipefail
    [ -n "{{reason}}" ] || { echo "a reason is required; it is recorded" >&2; exit 1; }
    kstack apply {{ns}} >/dev/null
    index=$({{kubectl}} get deploy/hypellm -o json | jq '[.spec.template.spec.containers[].name] | index("router")')
    jq -nc --arg reason "{{reason}}" --argjson i "$index" \
        '[{op:"add", path:"/spec/template/spec/containers/\($i)/args/-", value:"--adopt-config"},
          {op:"add", path:"/spec/template/spec/containers/\($i)/args/-", value:$reason}]' \
        | {{kubectl}} patch deploy/hypellm --type=json --patch-file=/dev/stdin >/dev/null
    {{kubectl}} rollout status deploy/hypellm --timeout=180s
    {{kubectl}} logs deploy/hypellm -c router | grep -m1 '"config.adopted_from_file"' \
        || { echo "the router did not report adopting the file" >&2; exit 1; }
    # Back to the manifest's arguments; this start resumes the adopted version.
    kstack apply {{ns}} >/dev/null
    {{kubectl}} rollout status deploy/hypellm --timeout=180s
    just _wait

# The router's log is line-delimited JSON; pipe through jq to read it:
# `just logs | jq -c`. `just logs tailscale` follows the tailnet node instead,
# which is where a login URL or a routing problem shows up; `just logs
# verifier` follows the identity verifier.
[doc("Follow a container's log: router (default), tailscale or verifier")]
logs service="router":
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{service}}" in
        verifier) exec {{kubectl}} logs -f deploy/verifier ;;
        *)        exec {{kubectl}} logs -f deploy/hypellm -c "{{service}}" ;;
    esac

# Is it running, and does it answer?
status:
    @kstack status {{ns}}
    @echo
    @printf 'live:   '; curl -fsS --max-time 2 http://127.0.0.1:{{inference_port}}/health/live  && echo || echo 'unreachable'
    @printf 'ready:  '; curl -fsS --max-time 2 http://127.0.0.1:{{inference_port}}/health/ready && echo || echo 'unreachable'
    @printf 'tailnet: '; just _ts_addr

# The current metrics exposition.
metrics:
    @curl -fsS http://127.0.0.1:{{metrics_port}}/metrics

# A throwaway container from the same image, sharing the state directory and
# the configuration read-only. The running router is left alone.
[doc('Open a shell in a throwaway container from the same image')]
shell:
    @docker run --rm -it --entrypoint /bin/bash \
        -u "{{uid}}:{{gid}}" \
        -v "{{state_dir}}:/var/lib/hypellm:ro" \
        -v "{{config}}:/etc/hypellm/hypellm.conf:ro" \
        {{image}}

# Print the endpoint map for a running router.
endpoints:
    #!/usr/bin/env bash
    set -euo pipefail
    ts_addr=$(just _ts_addr)
    case "$ts_addr" in
        *.*.*.*) tailnet="http://${ts_addr}:{{inference_port}}" ;;
        *)       tailnet="" ;;
    esac
    admin="http://127.0.0.1:{{admin_port}}"
    ts_name=$(just _ts_name)
    case "$ts_name" in
        *.ts.net) admin_tailnet="https://${ts_name}/" ;;
        *)        admin_tailnet="" ;;
    esac
    metrics="http://127.0.0.1:{{metrics_port}}"

    rule() { printf '\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────────────"; }
    head() { printf '\n\033[1m%s\033[0m  \033[2m%s\033[0m\n' "$1" "$2"; }
    row()  { printf '  \033[36m%-6s\033[0m %-26s \033[2m%s\033[0m\n' "$1" "$2" "$3"; }

    rule
    printf '\033[1;32m  HypeLLM Router is up\033[0m\n'
    rule

    if [ -n "$tailnet" ]; then
        head "Inference — tailnet" "$tailnet · $(just _ts_name)"
    else
        head "Inference — tailnet" "not logged in; this host only for now"
    fi
    row POST "/v1/chat/completions"  "OpenAI chat, streaming"
    row POST "/v1/responses"         "OpenAI responses"
    row POST "/v1/embeddings"        "OpenAI embeddings"
    row POST "/v1/messages"          "Anthropic messages"
    row POST "/v1/tokenize"          "token count for a request"
    row GET  "/v1/models"            "aliases this key may use"
    row GET  "/health/live"          "unauthenticated"
    row GET  "/health/ready"         "unauthenticated"
    printf '  \033[2m%s\033[0m\n' "also on http://127.0.0.1:{{inference_port}} from this host"
    printf '  \033[2m%s\033[0m\n' "and on http://{{lan_addr}}:{{inference_port}} from {{lan_net}} (plain HTTP; \`just lan-firewall\` once)"
    printf '  \033[2m%s\033[0m\n' "a router API key is required; tailnet reachability is not authentication"

    head "Management" "$admin — session cookie + CSRF"
    row GET  "/"                     "admin SPA"
    row POST "/admin/v1/auth/password"    "sign in as a local_user"
    row POST "/admin/v1/auth/break-glass" "sign in (no OIDC configured)"
    row GET  "/admin/v1/overview"    "fleet, targets, breakers"
    row GET  "/admin/v1/keys"        "API keys (POST to mint one)"
    row GET  "/admin/v1/policies"    "drafts, simulate, activate"
    row GET  "/admin/v1/usage"       "usage and cost estimates"
    row GET  "/admin/v1/audit"       "audit chain (export at /audit/export)"
    if [ -n "$admin_tailnet" ]; then
        printf '  \033[2m%s\033[0m\n' "on the tailnet as $admin_tailnet (HTTPS, proxied by the sidecar; /metrics withheld)"
    else
        printf '  \033[2m%s\033[0m\n' "not logged in to the tailnet; this host only for now"
    fi

    head "Metrics — this host only" "$metrics"
    row GET  "/metrics"              "also on $admin/metrics"
    row GET  "/health/live"          "supervisor probe"

    head "Upstream" "the router dials these; nothing here starts them"
    just _upstreams
    printf '  \033[2m%s\033[0m\n' "a LAN slave needs a subnet route on the tailnet — just tailnet"

    echo
    printf '  \033[2m%s\033[0m\n' "config  docker/hypellm.conf   ·   state  run/state   ·   secrets  run/secrets   ·   k8s/"
    printf '  \033[2m%s\033[0m\n' "just key · just keys · just logs · just status · just tailnet · just down"
    echo

# The tailnet node: its address, what it accepts, and which routes it has
# learned. The routes matter — without one to the slaves' network, the
# providers in docker/hypellm.conf have no path.
[doc('Show the tailnet node, its address and its learned routes')]
tailnet:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! {{kubectl}} get deploy/hypellm >/dev/null 2>&1; then
        echo "the router pod is not running — try \`just up\`" >&2
        exit 1
    fi
    ts() { {{kubectl}} exec deploy/hypellm -c tailscale -- tailscale "$@" 2>/dev/null; }
    echo "node"
    ts status --peers=false --json | jq -r '
        "  name    \(.Self.DNSName // "(not logged in)" | rtrimstr("."))",
        "  address \(.Self.TailscaleIPs // ["(none)"] | join(", "))",
        "  online  \(.Self.Online // false)"'
    echo
    echo "reachable on the tailnet"
    echo "  inference   :{{inference_port}}   (bound 0.0.0.0)"
    name=$(ts status --peers=false --json | jq -r '.Self.DNSName // "" | rtrimstr(".")')
    echo "  management  https://${name:-<node name>}/   (sidecar HTTPS proxy; :{{admin_port}} itself is bound to the pod IP)"
    echo "  metrics     no          (bound to the pod IP; 127.0.0.1 on this host only)"
    echo
    echo "learned subnet routes — the only path to a LAN slave"
    routes=$(ts debug prefs 2>/dev/null | jq -r '.RouteAll // false')
    echo "  accept-routes: ${routes}"
    ts status --json | jq -r '
        (([.Peer[]? | select((.PrimaryRoutes // []) | length > 0)]) as $r
         | if ($r | length) == 0
           then "  none advertised on this tailnet — LAN slaves are unreachable"
           else ($r[] | "  \(.DNSName | rtrimstr(".")) advertises \((.PrimaryRoutes // []) | join(", "))")
           end)'

# WSL's mirrored mode puts the LAN address on this distro, but the Hyper-V
# firewall in front of it blocks inbound by default. One rule, inference only,
# from the LAN only — the same shape as the k3s rules lan-stage1.ps1 adds.
# Changes the Windows host, so it asks for elevation (a UAC prompt).
[doc('Allow LAN peers through the Hyper-V firewall to the inference port')]
lan-firewall:
    #!/usr/bin/env bash
    set -euo pipefail
    name="HypeLLM-Inference-TCP-{{inference_port}}"
    ps="if (-not (Get-NetFirewallHyperVRule -Name '$name' -ErrorAction SilentlyContinue)) { New-NetFirewallHyperVRule -Name '$name' -DisplayName '$name' -Direction Inbound -VMCreatorId '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -Protocol TCP -LocalPorts {{inference_port}} -RemoteAddresses '{{lan_net}}' -Action Allow | Out-Null }"
    enc=$(printf '%s' "$ps" | iconv -t UTF-16LE | base64 -w0)
    powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-EncodedCommand','$enc'"
    powershell.exe -NoProfile -Command "Get-NetFirewallHyperVRule -Name '$name' | Format-Table Name,Direction,Action,LocalPorts" | tr -d '\r'

# --- internals -------------------------------------------------------------

# Warn when docker/hypellm.conf is not what the router is running.
#
# After any publication through the management API the router resumes the
# last published version on every start and ignores the file, so an edit here
# that `just up` appears to deploy may be doing nothing. The configuration
# names no pod address, so the file's digest and the running one are directly
# comparable. A warning, not a failure: a policy published through the API on
# purpose is exactly this state too.
_drift:
    #!/usr/bin/env bash
    set -euo pipefail
    file=$(docker run --rm --network none -v "{{config}}:/etc/hypellm/hypellm.conf:ro" \
        {{image}} --check --config /etc/hypellm/hypellm.conf 2>/dev/null | sed -n 's/^digest //p')
    running=$({{kubectl}} logs deploy/hypellm -c router 2>/dev/null \
        | sed -n 's/.*"event":"router.started","config_digest":"\([0-9a-f]*\)".*/\1/p' | tail -1)
    if [ -z "$file" ] || [ -z "$running" ]; then exit 0; fi
    case "$file" in
        "$running"*) ;;
        *)
            printf '\n\033[1;33m  %s\033[0m\n' "docker/hypellm.conf is not the active configuration (file ${file:0:12}, running ${running})."
            printf '  \033[2m%s\033[0m\n' "A policy published through the management API wins on every start; to deploy the file anyway:"
            printf '  \033[2m%s\033[0m\n\n' "just adopt \"<why the file should replace what was published>\""
            ;;
    esac

# A port already taken on this host leaves the publisher pod crash-looping on
# its bind with nothing saying which listener wanted it. Say both, and say
# where to change it.
_ports:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$({{kubectl}} get pods -l app=publish -o name 2>/dev/null)" ]; then exit 0; fi
    clash=0
    for entry in "inference:{{inference_port}}" "management:{{admin_port}}" "metrics:{{metrics_port}}"; do
        name=${entry%%:*}; port=${entry##*:}
        if ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then
            echo "port $port ($name) is already in use on this host" >&2
            clash=1
        fi
    done
    if [ "$clash" = 1 ]; then
        echo >&2
        echo "Change the listen addresses in {{config}} and the matching" >&2
        echo "listeners in k8s/publish.yaml; just reads the ports back from" >&2
        echo "the configuration, so those two files are the only ones to edit." >&2
        exit 1
    fi

# hostPath volumes are declared `type: Directory`, so they have to exist, owned
# by the invoking user, before the pod starts.
_dirs:
    @mkdir -p "{{state_dir}}" "{{secrets_dir}}" "{{tailscale_dir}}" "{{verify_dir}}" "{{verifier_dir}}" "{{backups_dir}}/current"
    @chmod 0700 "{{secrets_dir}}" "{{tailscale_dir}}" "{{verifier_dir}}" "{{backups_dir}}" "{{backups_dir}}/current"

# Generate the secret bundle once. A missing key is a startup failure by
# design (exit 5) and is never silently regenerated: a router that invents its
# own store MAC key cannot detect tampering across a restart.
_secrets:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f "{{secrets_dir}}/store_mac.key" ]; then exit 0; fi
    echo "→ generating the secret bundle in run/secrets"
    # A throwaway container, not the pod: `--network none` because this needs
    # no network at all — the keys come from the OS entropy source.
    docker run --rm --network none \
        -u "{{uid}}:{{gid}}" \
        -v "{{secrets_dir}}:/etc/hypellm/secrets" \
        {{image}} --generate-secrets /etc/hypellm/secrets
    echo
    echo "  The break-glass token above is printed once and stored nowhere."
    echo "  Save it now: with no OIDC configured it is the only way into the"
    echo "  management plane, and therefore the only way to mint the API key"
    echo "  that inference requires. See spec/using-the-router.html."

# Tailscale authenticates once and persists its node identity in
# run/tailscale. A key is needed only for that first login; after it, the file
# can be deleted. Absent, the node prints a login URL instead and `just up`
# surfaces it — which is the better path for a machine someone is sitting at.
#
# Read from a file rather than taken from the ambient environment so it cannot
# arrive by accident. It reaches the tailscale container as TS_AUTHKEY through
# the `tailscale-authkey` Secret, which exists only while the file does.
_authkey:
    #!/usr/bin/env bash
    set -euo pipefail
    key_file="{{secrets_dir}}/tailscale.authkey"
    {{kubectl}} create namespace {{ns}} --dry-run=client -o yaml | {{kubectl}} apply -f - >/dev/null
    if [ -f "$key_file" ]; then
        {{kubectl}} create secret generic tailscale-authkey --from-file=authkey="$key_file" \
            --dry-run=client -o yaml | {{kubectl}} apply -f - >/dev/null
    else
        {{kubectl}} delete secret tailscale-authkey --ignore-not-found >/dev/null
    fi

# Materialise the OAuth client secret from `.env` into the one file the verifier
# reads, and nowhere else.
#
# Why a file when `.env` is right there and a Secret would happily pass it as an
# environment variable: `kubectl get pod -o yaml` prints a container's whole
# environment to anyone who can read the namespace, and `/proc/<pid>/environ`
# does the same for the process uid. A 0600 file is readable by the verifier's
# user alone. So `dotenv-load` stays false at the top of this file and nothing
# here exports anything — `.env` is a host-side convenience for typing the
# secret once, not a channel into a container.
#
# Parsed, not sourced, for the same reason no secret here is ever an argv entry:
# `source .env` executes it, which turns a text file holding one secret into
# arbitrary code running as the invoking user.
#
# Absent `.env` is not an error when the secret file already exists — that is
# the operator who wrote it by hand, as spec/components/identity-verifier.html describes, and
# overwriting or complaining would both be wrong.
_verifier_secret:
    #!/usr/bin/env bash
    set -euo pipefail
    env_file="{{justfile_directory()}}/.env"
    target="{{verifier_dir}}/client_secret"
    if [ ! -f "$env_file" ]; then
        if [ -f "$target" ]; then exit 0; fi
        echo "hypellm: no .env, and run/verifier/client_secret does not exist" >&2
        echo "  cp .env.example .env    then put the OAuth client secret in it" >&2
        exit 1
    fi
    secret=$(sed -n 's/^[[:space:]]*HYPELLM_OIDC_CLIENT_SECRET=//p' "$env_file" | head -1)
    # A CRLF `.env` is likely on this host — the repository already carries two
    # spellings of the Windows Zone.Identifier rule — and a trailing carriage
    # return would be sent to Google as part of the secret. Stripped before the
    # quotes, so a quoted value ending in CR loses both.
    secret=${secret%$'\r'}
    case "$secret" in
        \"*\") secret=${secret#\"}; secret=${secret%\"} ;;
        \'*\') secret=${secret#\'}; secret=${secret%\'} ;;
    esac
    if [ -z "$secret" ]; then
        echo "hypellm: HYPELLM_OIDC_CLIENT_SECRET is unset or empty in .env" >&2
        exit 1
    fi
    # umask first, so the file is never briefly world-readable between the
    # write and the chmod.
    umask 077
    printf '%s' "$secret" > "$target"
    chmod 600 "$target"
    # The length, not the value. Enough to catch an empty or truncated paste
    # without putting the secret in a terminal scrollback or a CI log.
    echo "→ wrote run/verifier/client_secret from .env (${#secret} bytes)"

# Every provider endpoint the configuration declares, for the endpoint map.
_upstreams:
    #!/usr/bin/env bash
    set -euo pipefail
    awk '/^provider /{
        id=""; h=""; p=""; f=""
        for(i=1;i<=NF;i++){
            if($i~/^id=/)     id=substr($i,4)
            if($i~/^host=/)   h=substr($i,6)
            if($i~/^port=/)   p=substr($i,6)
            if($i~/^family=/) f=substr($i,8)
        }
        if(h!="") printf "  \033[36m%-6s\033[0m %-26s \033[2m%s\033[0m\n", "", id, "http://" h ":" p "  (" f ")"
    }' docker/hypellm.conf

# The node's tailnet address, or a word saying why there is not one. Used by
# `status` and by the endpoint map, both of which must not fail when the node
# has not logged in yet.
_ts_addr:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! {{kubectl}} get deploy/hypellm >/dev/null 2>&1; then echo "pod not running"; exit 0; fi
    addr=$({{kubectl}} exec deploy/hypellm -c tailscale -- tailscale ip -4 2>/dev/null | tr -d '\r' | head -1 || true)
    if [ -n "${addr:-}" ]; then echo "$addr"; else echo "not logged in"; fi

# The node's MagicDNS name, when it has one.
_ts_name:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! {{kubectl}} get deploy/hypellm >/dev/null 2>&1; then echo "pod not running"; exit 0; fi
    {{kubectl}} exec deploy/hypellm -c tailscale -- tailscale status --peers=false --json 2>/dev/null \
        | jq -r '.Self.DNSName // "" | rtrimstr(".")' | grep . || echo "no MagicDNS name"

# Can the pod reach every configured provider address?
#
# Under Docker Desktop this repaired a routing collision: a compose network on
# 192.168.0.0/20 contains the Sparks' 192.168.8.0/24 and swallowed their
# packets. Pods are on 10.42.0.0/16, which collides with nothing on the LAN, so
# there is nothing to repair; what is left is the check, run from inside the
# router's namespace, which is the vantage point that matters.
[doc('Check the provider addresses are reachable from the router pod')]
lanroutes:
    #!/usr/bin/env bash
    set -uo pipefail
    awk '/^provider /{h="";p=""; for(i=1;i<=NF;i++){ if($i~/^host=/) h=substr($i,6); if($i~/^port=/) p=substr($i,6) } if(h!="") print h, p}' {{config}} \
        | sort -u | while read -r host port; do
            if {{kubectl}} exec deploy/hypellm -c tailscale -- nc -z -w 3 "$host" "$port" >/dev/null 2>&1; then
                echo "  reachable    $host:$port"
            else
                echo "  UNREACHABLE  $host:$port" >&2
            fi
        done

# Wait until the tailnet node is logged in, surfacing the login URL when there
# is no key. containerboot gives up on an interactive login after about a
# minute and the container restarts with a fresh URL, so the URL shown is
# always the newest one.
_tailnet_up:
    #!/usr/bin/env bash
    set -euo pipefail
    shown=""
    for _ in $(seq 1 240); do
        if {{kubectl}} exec deploy/hypellm -c tailscale -- tailscale status --peers=false >/dev/null 2>&1; then
            [ -n "$shown" ] && printf '\033[1;32m  authenticated\033[0m\n'
            exit 0
        fi
        url=$({{kubectl}} logs deploy/hypellm -c tailscale 2>/dev/null \
              | grep -oE 'https://login\.tailscale\.com/a/[0-9a-f]+' | tail -1 || true)
        if [ -n "${url:-}" ] && [ "$url" != "$shown" ]; then
            printf '\n\033[1;33m  This node is not on the tailnet yet.\033[0m\n'
            printf '  Authenticate it now: \033[4m%s\033[0m\n' "$url"
            printf '  \033[2m%s\033[0m\n' "the pod is not ready until this completes; the URL changes about once a minute"
            printf '  \033[2m%s\033[0m\n\n' "to skip this next time, put a key in run/secrets/tailscale.authkey"
            shown=$url
        fi
        sleep 1
    done
    printf '\n\033[1;31m  %s\033[0m\n' "The tailnet node did not authenticate within four minutes." >&2
    {{kubectl}} logs deploy/hypellm -c tailscale --tail 15 >&2 || true
    exit 1

# Poll liveness until the router answers or the deadline passes. The image
# carries no curl, so the probe runs from the host against the published port.
_wait:
    #!/usr/bin/env bash
    set -euo pipefail
    for _ in $(seq 1 60); do
        if curl -fsS --max-time 1 "http://127.0.0.1:{{inference_port}}/health/live" >/dev/null 2>&1; then
            exit 0
        fi
        sleep 0.5
    done
    echo "the router did not answer /health/live within 30s:" >&2
    {{kubectl}} logs deploy/hypellm -c router --tail 40 >&2 || true
    exit 1
