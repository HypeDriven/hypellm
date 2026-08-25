# HypeLLM Router — local container workflow.
#
#   just bootstrap  first run: secrets, router, and a key to call it with
#   just up         build the image, start the router, print its endpoints
#   just key        mint another API key
#   just down       graceful shutdown over the control socket, then remove
#   just logs       follow the router's structured log
#   just status     is it up, and what is it serving
#   just tailnet    the tailnet node: address, routes, who can reach it
#
# `just --list` prints the rest.

set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load := false

config := justfile_directory() / "docker" / "hypellm.conf"

# Everything printed and probed below is read back out of that file rather than
# restated here. Two copies of a port number drift, and this is the copy every
# health check and printed URL uses — a stale one sends the reader to an
# address nothing is listening on. compose.yaml publishes each listener to the
# same port on 127.0.0.1, so the configured ports are also the host's.
inference_port := `sed -n 's/.*inference_listen=[^:]*:\([0-9]*\).*/\1/p' docker/hypellm.conf | head -1`
admin_port     := `sed -n 's/.*admin_listen=[^:]*:\([0-9]*\).*/\1/p' docker/hypellm.conf | head -1`
metrics_port   := `sed -n 's/.*metrics_listen=[^:]*:\([0-9]*\).*/\1/p' docker/hypellm.conf | head -1`

# The bind address of the management and metrics listeners: the compose bridge
# address, not loopback and not the tailnet. Read back for the same reason the
# ports are — so the printed URLs cannot disagree with what is bound.
admin_bind := `sed -n 's/.*admin_listen=\([^: ]*\):.*/\1/p' docker/hypellm.conf | head -1`

# Bind-mount roots. Covered by .gitignore's /run rule; nothing here is
# committable, and run/secrets is the router's root of trust.
state_dir     := justfile_directory() / "run" / "state"
secrets_dir   := justfile_directory() / "run" / "secrets"
tailscale_dir := justfile_directory() / "run" / "tailscale"

# Tailscale authenticates once and persists its node identity in
# run/tailscale. A key is needed only for that first login; after it, the file
# can be deleted. Absent, the node prints a login URL instead and `just up`
# surfaces it — which is the better path for a machine someone is sitting at.
#
# Read from a file rather than taken from the ambient environment so it cannot
# arrive by accident, and so `just` is the only thing that puts it in the
# container's environment.
export HYPELLM_TS_AUTHKEY := \
    if path_exists(justfile_directory() / "run" / "secrets" / "tailscale.authkey") == "true" \
    { trim(`cat run/secrets/tailscale.authkey 2>/dev/null || true`) } else { "" }

# The container runs as the invoking user so the bind mounts stay readable
# from the host without sudo.
export HYPELLM_UID := `id -u`
export HYPELLM_GID := `id -g`

compose := "docker compose"

_default:
    @just --list --unsorted

# Build the image, start the router, and print where it is listening.
up: _ports _dirs _lock build _secrets _lanroutes _tailnet_up
    @{{compose}} up -d --no-build router
    @just _wait
    @just endpoints

# --- API keys --------------------------------------------------------------
#
# Everything here goes through break-glass, because with no OIDC provider
# configured it is the only credential the management plane accepts. Three
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
        -u "$HYPELLM_UID:$HYPELLM_GID" \
        -v "{{secrets_dir}}:/etc/hypellm/secrets" \
        hypellm-router:local --generate-secrets /etc/hypellm/secrets)
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
    @{{compose}} build router

# Validate docker/hypellm.conf without starting anything. Prints the
# configuration digest, and the fleet digest when a fleet is declared.
[doc('Validate docker/hypellm.conf and print its digest')]
check: build
    @docker run --rm --network none \
        -v "{{config}}:/etc/hypellm/hypellm.conf:ro" \
        hypellm-router:local --check --config /etc/hypellm/hypellm.conf

# Stop the router the way it is meant to be stopped: `shutdown` over the
# authenticated control socket, which stops admission and drains in-flight
# requests. Falls back to compose's SIGTERM/SIGKILL if the socket is gone.
[doc('Drain over the control socket, then remove the container')]
down:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$({{compose}} ps -q router 2>/dev/null)" ]; then
        echo "→ draining (control socket)"
        if {{compose}} exec -T router /usr/local/bin/hypellm-router --shutdown \
                --config /etc/hypellm/hypellm.conf --secrets /etc/hypellm/secrets; then
            # Wait for the process to exit on its own. Tearing the container
            # down here instead would SIGKILL the router mid-drain, which drops
            # the streams the drain exists to finish — and leaves the state
            # lock behind, because the lock is removed on `Drop`.
            for _ in $(seq 1 60); do
                [ -z "$({{compose}} ps -q router 2>/dev/null)" ] && break
                state=$(docker inspect -f '{{{{.State.Status}}}}' hypellm-router 2>/dev/null || echo gone)
                [ "$state" != "running" ] && break
                sleep 0.5
            done
        else
            echo "  control socket unavailable; compose will signal instead"
        fi
    fi
    {{compose}} down --remove-orphans

# Graceful stop and start, picking up an edited docker/hypellm.conf.
restart: down up

# The router's log is line-delimited JSON; pipe through jq to read it:
# `just logs | jq -c`. `just logs tailscale` follows the sidecar instead, which
# is where a login URL or a routing problem shows up.
[doc("Follow a service's log: router (default) or tailscale")]
logs service="router":
    @{{compose}} logs -f {{service}}

# Is it running, and does it answer?
status:
    @{{compose}} ps
    @echo
    @printf 'live:   '; curl -fsS --max-time 2 http://127.0.0.1:{{inference_port}}/health/live  && echo || echo 'unreachable'
    @printf 'ready:  '; curl -fsS --max-time 2 http://127.0.0.1:{{inference_port}}/health/ready && echo || echo 'unreachable'
    @printf 'tailnet: '; just _ts_addr
    @just _stranded

# The current metrics exposition.
metrics:
    @curl -fsS http://127.0.0.1:{{metrics_port}}/metrics

# A throwaway container from the same image, sharing the state directory and
# the configuration read-only. The running router is left alone.
[doc('Open a shell in a throwaway container from the same image')]
shell:
    @docker run --rm -it --entrypoint /bin/bash \
        -u "$HYPELLM_UID:$HYPELLM_GID" \
        -v "{{state_dir}}:/var/lib/hypellm:ro" \
        -v "{{justfile_directory()}}/docker/hypellm.conf:/etc/hypellm/hypellm.conf:ro" \
        hypellm-router:local

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
    printf '  \033[2m%s\033[0m\n' "a router API key is required; tailnet reachability is not authentication"

    head "Management — this host only" "$admin — session cookie + CSRF"
    row GET  "/"                     "admin SPA"
    row POST "/admin/v1/auth/break-glass" "sign in (no OIDC configured)"
    row GET  "/admin/v1/overview"    "fleet, targets, breakers"
    row GET  "/admin/v1/keys"        "API keys (POST to mint one)"
    row GET  "/admin/v1/policies"    "drafts, simulate, activate"
    row GET  "/admin/v1/usage"       "usage and cost estimates"
    row GET  "/admin/v1/audit"       "audit chain (export at /audit/export)"
    printf '  \033[2m%s\033[0m\n' "bound {{admin_bind}}, so no tailnet peer can reach it"

    head "Metrics — this host only" "$metrics"
    row GET  "/metrics"              "also on $admin/metrics"
    row GET  "/health/live"          "supervisor probe"

    head "Upstream" "the router dials these; nothing here starts them"
    just _upstreams
    printf '  \033[2m%s\033[0m\n' "a LAN slave needs a subnet route on the tailnet — just tailnet"

    echo
    printf '  \033[2m%s\033[0m\n' "config  docker/hypellm.conf   ·   state  run/state   ·   secrets  run/secrets"
    printf '  \033[2m%s\033[0m\n' "just key · just keys · just logs · just status · just tailnet · just down"
    echo

# The tailnet node: its address, what it accepts, and which routes it has
# learned. The routes matter — without one to the slaves' network, the
# providers in docker/hypellm.conf have no path.
[doc('Show the tailnet node, its address and its learned routes')]
tailnet:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "$({{compose}} ps -q tailscale 2>/dev/null)" ]; then
        echo "the tailscale sidecar is not running — try \`just up\`" >&2
        exit 1
    fi
    ts() { {{compose}} exec -T tailscale tailscale "$@" 2>/dev/null; }
    echo "node"
    ts status --peers=false --json | jq -r '
        "  name    \(.Self.DNSName // "(not logged in)" | rtrimstr("."))",
        "  address \(.Self.TailscaleIPs // ["(none)"] | join(", "))",
        "  online  \(.Self.Online // false)"'
    echo
    echo "reachable on the tailnet"
    echo "  inference   :{{inference_port}}   (bound 0.0.0.0)"
    echo "  management  no          (bound {{admin_bind}}, host loopback only)"
    echo "  metrics     no          (bound {{admin_bind}}, host loopback only)"
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

# --- internals -------------------------------------------------------------

# The store's single-writer lock is a PID file, and inside a PID namespace the
# router is pid 1 — which always looks alive. A container that was killed
# rather than drained therefore leaves a lock that no later start can reclaim,
# and the refusal is permanent. Sweeping it is safe only once no router is
# running, which is why this checks for a container before touching the file.
# docs/deferred-issues.md records the limitation.
_lock:
    #!/usr/bin/env bash
    set -euo pipefail
    lock="{{state_dir}}/lock"
    if [ ! -f "$lock" ]; then exit 0; fi
    if [ -n "$({{compose}} ps -q router 2>/dev/null)" ]; then exit 0; fi
    echo "→ clearing a stale state lock (pid $(cat "$lock" 2>/dev/null || echo '?'), no router container running)"
    rm -f "$lock"

# A port already published on this host makes `docker compose up` fail with a
# message about the port and nothing about which listener wanted it. Say both,
# and say where to change it.
_ports:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$({{compose}} ps -q router 2>/dev/null)" ]; then exit 0; fi
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
        echo "\`ports:\` entries in compose.yaml; just reads the ports back from" >&2
        echo "the configuration, so those two files are the only ones to edit." >&2
        exit 1
    fi

# Bind-mount targets have to exist and be owned by the invoking user before
# Docker creates them itself as root.
_dirs:
    @mkdir -p "{{state_dir}}" "{{secrets_dir}}" "{{tailscale_dir}}"
    @chmod 0700 "{{secrets_dir}}" "{{tailscale_dir}}"

# Generate the secret bundle once. A missing key is a startup failure by
# design (exit 5) and is never silently regenerated: a router that invents its
# own store MAC key cannot detect tampering across a restart.
_secrets:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f "{{secrets_dir}}/store_mac.key" ]; then exit 0; fi
    echo "→ generating the secret bundle in run/secrets"
    # Plain `docker run`, not `compose run`: the router service shares the
    # sidecar's network namespace, so compose would start a tailnet node just
    # to write eight files. `--network none` because this needs no network at
    # all — the keys come from the OS entropy source.
    docker run --rm --network none \
        -u "$HYPELLM_UID:$HYPELLM_GID" \
        -v "{{secrets_dir}}:/etc/hypellm/secrets" \
        hypellm-router:local --generate-secrets /etc/hypellm/secrets
    echo
    echo "  The break-glass token above is printed once and stored nowhere."
    echo "  Save it now: with no OIDC configured it is the only way into the"
    echo "  management plane, and therefore the only way to mint the API key"
    echo "  that inference requires. See docs/using-the-router.md."

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

# The router has no network namespace of its own. If the sidecar is gone and
# the router is not, the router is reachable by nothing while still reporting
# `Up` — a state worth naming rather than leaving someone to discover.
_stranded:
    #!/usr/bin/env bash
    set -euo pipefail
    router=$({{compose}} ps -q router 2>/dev/null || true)
    sidecar=$({{compose}} ps -q tailscale 2>/dev/null || true)
    if [ -n "$router" ] && [ -z "$sidecar" ]; then
        printf '\n\033[1;31m  %s\033[0m\n' "The router is running without its network namespace."
        printf '  %s\n' "The tailscale sidecar owns it and has exited, so the router reaches"
        printf '  %s\n' "nothing and nothing reaches it. Run \`just restart\`."
    fi

# The node's tailnet address, or a word saying why there is not one. Used by
# `status` and by the endpoint map, both of which must not fail when the node
# has not logged in yet.
_ts_addr:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "$({{compose}} ps -q tailscale 2>/dev/null)" ]; then echo "sidecar not running"; exit 0; fi
    addr=$({{compose}} exec -T tailscale tailscale ip -4 2>/dev/null | tr -d '\r' | head -1 || true)
    if [ -n "${addr:-}" ]; then echo "$addr"; else echo "not logged in"; fi

# The node's MagicDNS name, when it has one.
_ts_name:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -z "$({{compose}} ps -q tailscale 2>/dev/null)" ]; then echo "sidecar not running"; exit 0; fi
    {{compose}} exec -T tailscale tailscale status --peers=false --json 2>/dev/null \
        | jq -r '.Self.DNSName // "" | rtrimstr(".")' | grep . || echo "no MagicDNS name"

# Make the configured provider addresses reachable from inside a container.
#
# Docker allocates bridge subnets from a built-in pool that ends with
# 192.168.0.0/16 in /20 chunks, and it reaches that fallback once 172.17-172.31
# are used up — which a machine with a dozen compose projects manages easily.
# On this host that produced a network on 192.168.0.0/20, which *contains* the
# Sparks' 192.168.8.0/24, so the Docker VM routes every packet for a slave onto
# a local bridge instead of out to the LAN:
#
#     ip route get 192.168.8.105
#     192.168.8.105 dev br-814c33bb4ef9  src 192.168.0.1
#
# The host itself is unaffected, which is what makes it easy to miss: `curl`
# from a terminal works and the identical `curl` in a container times out.
#
# This adds a /32 for each configured provider via the VM's real gateway, which
# is more specific than the bridge route and wins. It is a workaround, not a
# fix — the fix is to stop the other project occupying that range — and it is
# re-applied here because the VM's routing table does not survive a Docker
# Desktop restart, so without it the router silently loses its upstreams and
# reports `deadline_exceeded` with no hint why.
#
# It does nothing when the addresses are already reachable, which is the normal
# case on a machine without the collision.
[doc('Ensure the provider addresses are reachable from inside a container')]
lanroutes: _lanroutes

_lanroutes:
    #!/usr/bin/env bash
    set -uo pipefail
    hosts=$(awk '/^provider /{for(i=1;i<=NF;i++) if($i~/^host=/) print substr($i,6)}' {{config}} \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u | tr '\n' ' ')
    if [ -z "${hosts// /}" ]; then exit 0; fi

    for ip in $hosts; do
        # Can a container reach it? That is the question that matters; the
        # host's own answer is different and is checked separately below.
        if docker run --rm --network bridge busybox:1.37 \
               nc -z -w 3 "$ip" 8000 >/dev/null 2>&1; then
            continue
        fi
        if ! curl -sS -o /dev/null -m 4 "http://$ip:8000/health" >/dev/null 2>&1; then
            echo "  $ip is unreachable from this host too — not a routing collision," >&2
            echo "  so check the slave itself rather than Docker." >&2
            continue
        fi
        # Reachable from the host, not from a container: something local is
        # claiming the address. Name it, because the fix is to stop it doing so.
        docker network ls -q | xargs -r docker network inspect 2>/dev/null | HYPELLM_IP="$ip" python3 -c "import ipaddress,json,os,sys; a=ipaddress.ip_address(os.environ['HYPELLM_IP']); [print('  %s is inside docker network %r (%s) — that is why a container cannot reach it' % (a, n['Name'], c['Subnet'])) for n in json.load(sys.stdin) for c in ((n.get('IPAM') or {}).get('Config') or []) if c.get('Subnet') and a in ipaddress.ip_network(c['Subnet'])]" 2>/dev/null || true
        if docker run --rm --network host --cap-add NET_ADMIN busybox:1.37 \
               ip route replace "$ip/32" via 192.168.65.1 dev eth0 >/dev/null 2>&1; then
            echo "  added a /32 route for $ip via the Docker VM gateway"
        else
            echo "  could not add a route for $ip — containers will not reach it" >&2
        fi
    done

# Bring the tailnet node up and wait until it is logged in, because the router
# runs inside its network namespace and must not attach to one that is about to
# disappear. containerboot exits when an interactive login is not completed
# inside its own deadline; if the router had already attached, it would keep
# running with a dead namespace, reachable by nothing and still reported `Up`.
#
# Without a key in run/secrets/tailscale.authkey the node prints a login URL
# and waits, which is unhelpful if nobody is reading the log — so pull it out
# and put it in front of the operator as soon as it appears.
_tailnet_up:
    #!/usr/bin/env bash
    set -euo pipefail
    {{compose}} up -d tailscale >/dev/null
    shown=0
    for _ in $(seq 1 240); do
        if {{compose}} exec -T tailscale tailscale status --peers=false >/dev/null 2>&1; then
            [ "$shown" = 1 ] && printf '\033[1;32m  authenticated\033[0m\n'
            exit 0
        fi
        if [ -z "$({{compose}} ps -q tailscale 2>/dev/null)" ]; then
            printf '\n\033[1;31m  The tailnet node exited before authenticating.\033[0m\n' >&2
            printf '  %s\n' "It gives up on an interactive login after about a minute." >&2
            printf '  %s\n' "Put a key in run/secrets/tailscale.authkey and run just up again," >&2
            printf '  %s\n\n' "or re-run just up and open the URL promptly." >&2
            {{compose}} logs --tail 15 tailscale >&2
            exit 1
        fi
        if [ "$shown" = 0 ]; then
            url=$({{compose}} logs tailscale 2>/dev/null \
                  | grep -oE 'https://login\.tailscale\.com/a/[0-9a-f]+' | tail -1 || true)
            if [ -n "${url:-}" ]; then
                printf '\n\033[1;33m  This node is not on the tailnet yet.\033[0m\n'
                printf '  Authenticate it now: \033[4m%s\033[0m\n' "$url"
                printf '  \033[2m%s\033[0m\n' "the router starts once this completes — it runs inside this node's namespace"
                printf '  \033[2m%s\033[0m\n' "you have 15 minutes; this waits 4 and can be re-run with just up"
                printf '  \033[2m%s\033[0m\n\n' "to skip this next time, put a key in run/secrets/tailscale.authkey"
                shown=1
            fi
        fi
        sleep 1
    done
    printf '\n\033[1;31m  %s\033[0m\n' "The tailnet node did not authenticate within four minutes." >&2
    {{compose}} logs --tail 15 tailscale >&2
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
        if [ -z "$({{compose}} ps -q router 2>/dev/null)" ]; then
            echo "the router container exited during startup:" >&2
            {{compose}} logs --tail 40 router >&2
            exit 1
        fi
        sleep 0.5
    done
    echo "the router did not answer /health/live within 30s:" >&2
    {{compose}} logs --tail 40 router >&2
    exit 1
