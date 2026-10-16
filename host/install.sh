#!/bin/sh
# HypeLLM host kit: enroll this machine as a fleet slave (specification 26.8).
#
#   curl -fsSL https://<router>/fleet/v1/install.sh | \
#     sh -s -- --router https://<router> --token <token> --version <version>
#
# What it does, in order, and nothing before you agree:
#
#   1. Checks that what a slave needs is already here (docker without sudo,
#      sshd and its Ed25519 host key, curl, openssl, awk). It installs no
#      package, starts no service, and never uses sudo.
#   2. Asks the router which host this will be and which key to trust.
#   3. Asks where containers should be deployed and keep their state
#      (default ~/.hypellm).
#   4. Shows every change it will make and asks you to approve.
#   5. Creates the data directory, a device key, and a forced-command shim;
#      adds ONE line to ~/.ssh/authorized_keys; registers with the router.
#
# Registering does not make this machine a fleet member. An administrator
# approves it in the dashboard, a second person publishes the result, and
# only then does the fleet agent add it — pinned to the SSH host key printed
# at the end of this script.
#
# The agent's key can run only the shim, and the shim runs only `df`,
# `nvidia-smi`, a short list of `docker` subcommands, `mkdir` under the data
# directory, and `curl` to this machine's loopback. Everything else is refused.
# `docker create` is held to a fixed flag vocabulary: no --privileged, no host
# network or PID namespace, no capability or device beyond the GPUs, and no
# mount except a container's own state directory under the data directory.
#
# Upgrading: re-run the command an administrator mints. The data directory,
# the device key and the registration are kept; the shim is replaced.

set -eu

HOST_KIT_VERSION="1.1.0"

ROUTER=""
TOKEN=""
VERSION=""
DATA_DIR=""
ADDRESS=""
RUN_AS=""
ASSUME_YES=0
DRY_RUN=0
SSH_HOST_KEY="/etc/ssh/ssh_host_ed25519_key.pub"

say() { printf '%s\n' "$*"; }
fail() { printf 'hypellm-install: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Usage: install.sh --router https://ROUTER --token TOKEN [options]

  --router URL        the router's https origin (from the dashboard command)
  --token TOKEN       the one-time enrollment token
  --version V         refuse to run unless this script is host kit V
  --data-dir PATH     where containers live (skips the prompt)
  --address IP        the LAN address the fleet agent should use
  --user NAME         when run as root: the account to set up instead
  --ssh-host-key FILE the sshd Ed25519 public host key to register
  --yes               do not ask; approve the plan as shown
  --dry-run           check and show the plan, change nothing
USAGE
}

need() { [ "$2" -ge 2 ] || fail "$1 needs a value"; }
while [ $# -gt 0 ]; do
    case $1 in
        --router) need "$1" $#; ROUTER=$2; shift 2 ;;
        --token) need "$1" $#; TOKEN=$2; shift 2 ;;
        --version) need "$1" $#; VERSION=$2; shift 2 ;;
        --data-dir) need "$1" $#; DATA_DIR=$2; shift 2 ;;
        --address) need "$1" $#; ADDRESS=$2; shift 2 ;;
        --user) need "$1" $#; RUN_AS=$2; shift 2 ;;
        --ssh-host-key) need "$1" $#; SSH_HOST_KEY=$2; shift 2 ;;
        --yes) ASSUME_YES=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; fail "unknown argument: $1" ;;
    esac
done

# -- Arguments ---------------------------------------------------------------

if [ -n "$VERSION" ] && [ "$VERSION" != "$HOST_KIT_VERSION" ]; then
    fail "this router serves host kit $HOST_KIT_VERSION, but --version $VERSION was asked for; \
ask an administrator for a fresh command"
fi
case $ROUTER in
    https://*) ;;
    *) fail "--router must be the router's https origin" ;;
esac
# An origin and nothing else: it is joined with paths below.
if printf '%s' "${ROUTER#https://}" | grep -q '[^A-Za-z0-9.:-]'; then
    fail "--router must be an origin such as https://router.example.ts.net"
fi
if [ "${#TOKEN}" -ne 64 ] || printf '%s' "$TOKEN" | grep -q '[^0-9a-f]'; then
    fail "--token must be the 64-character token from the dashboard"
fi

# -- Who this is for ---------------------------------------------------------

if [ "$(id -u)" -eq 0 ]; then
    [ -n "$RUN_AS" ] || fail "do not run this as root; run it as the account that will own the \
data directory and accept the fleet agent's key (or pass --user NAME as root)"
    if printf '%s' "$RUN_AS" | grep -q '[^a-z0-9_.-]'; then
        fail "--user must be a plain account name"
    fi
    ACCOUNT=$RUN_AS
    ACCOUNT_HOME=$(getent passwd "$ACCOUNT" 2>/dev/null | cut -d: -f6) || true
    [ -n "$ACCOUNT_HOME" ] || fail "no such account: $ACCOUNT"
else
    [ -z "$RUN_AS" ] || fail "--user is only for running as root"
    ACCOUNT=$(id -un)
    ACCOUNT_HOME=$HOME
fi
case $ACCOUNT in
    -*|"") fail "the account name '$ACCOUNT' cannot be used as an SSH login" ;;
esac
if printf '%s' "$ACCOUNT" | grep -q '[^a-z0-9_.-]'; then
    fail "the account name '$ACCOUNT' cannot be used as an SSH login"
fi

as_account() {
    # Only fixed command strings reach here.
    if [ -n "$RUN_AS" ]; then su -s /bin/sh "$RUN_AS" -c "$1"; else sh -c "$1"; fi
}

# -- 1. Preflight: everything first, all problems at once --------------------

problems=""
problem() { problems="$problems
  - $*"; }

for tool in curl openssl awk sed grep uname id; do
    command -v "$tool" >/dev/null 2>&1 || problem "$tool is not installed"
done
if ! command -v docker >/dev/null 2>&1; then
    problem "docker is not installed"
elif ! as_account 'docker info >/dev/null 2>&1'; then
    problem "docker is installed but $ACCOUNT cannot use it without sudo (add $ACCOUNT to the \
docker group, then log in again)"
fi
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    problem "sshd is not installed; the fleet agent reaches this machine over SSH"
fi
if [ ! -r "$SSH_HOST_KEY" ]; then
    problem "the SSH host key $SSH_HOST_KEY is not readable"
elif ! grep -q '^ssh-ed25519 ' "$SSH_HOST_KEY"; then
    problem "$SSH_HOST_KEY is not an Ed25519 host key"
fi
GPU_LINES=""
if command -v nvidia-smi >/dev/null 2>&1; then
    GPU_LINES=$(nvidia-smi --query-gpu=index,name,memory.total --format=csv,noheader,nounits \
        2>/dev/null) || GPU_LINES=""
fi

if [ -n "$problems" ]; then
    printf 'hypellm-install: this machine is not ready:%s\n' "$problems" >&2
    exit 1
fi

# -- Facts -------------------------------------------------------------------

case $(uname -m) in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
esac
MEMORY_BYTES=$(awk '/^MemTotal:/ { printf "%.0f", $2 * 1024 }' /proc/meminfo 2>/dev/null) || true
[ -n "$MEMORY_BYTES" ] || fail "could not read the machine's memory from /proc/meminfo"
HOSTNAME_SHOWN=$(printf '%s' "$(uname -n)" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-64)
if [ -z "$ADDRESS" ] && command -v ip >/dev/null 2>&1; then
    # The source address the kernel would use for the LAN; no packet is sent.
    ADDRESS=$(ip -4 route get 192.0.2.1 2>/dev/null \
        | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }') || true
fi
[ -n "$ADDRESS" ] || fail "could not work out this machine's LAN address; pass --address IP"
if printf '%s' "$ADDRESS" | grep -q '[^0-9A-Fa-f.:]'; then
    fail "--address must be an IP address"
fi
HOST_KEY_LINE=$(awk '$1 == "ssh-ed25519" { print $1 " " $2; exit }' "$SSH_HOST_KEY")

# GPUs as JSON. Names are narrowed to a plain alphabet before they are quoted.
GPUS_JSON=$(printf '%s\n' "$GPU_LINES" | awk -F', *' '
    NF >= 3 && $1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
        name = $2; gsub(/[^A-Za-z0-9 ._()-]/, "_", name)
        printf "%s{\"index\":%d,\"name\":\"%s\",\"memory_bytes\":%.0f}", sep, $1, substr(name, 1, 64), $3 * 1048576
        sep = ","
    }')
GPU_SUMMARY=$(printf '%s\n' "$GPU_LINES" | awk -F', *' 'NF >= 3 { n++ } END { print n + 0 }')

# -- 2. Ask the router who this will be ----------------------------------------

post() {
    # The body goes on stdin, so the token is not in curl's argument list.
    printf '%s' "$2" | curl -sS --proto '=https' --tlsv1.2 --max-time 30 -X POST \
        -H 'Content-Type: application/json' --data-binary @- \
        -w '\n%{http_code}' "$ROUTER$1"
}
json_field() {
    printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" \
        | head -n 1
}
reply_of() { printf '%s\n' "$1" | sed '$d'; }
status_of() { printf '%s\n' "$1" | tail -n 1; }

BEGIN=$(post /fleet/v1/enroll:begin "{\"token\":\"$TOKEN\"}") \
    || fail "could not reach $ROUTER"
if [ "$(status_of "$BEGIN")" != 200 ]; then
    fail "the router refused the token: $(json_field "$(reply_of "$BEGIN")" message)"
fi
HOST_ID=$(json_field "$(reply_of "$BEGIN")" host)
AGENT_KEY=$(json_field "$(reply_of "$BEGIN")" agent_ssh_key)
if [ -z "$HOST_ID" ] || printf '%s' "$HOST_ID" | grep -q '[^A-Za-z0-9._:-]'; then
    fail "the router sent an unusable host identifier"
fi
case $AGENT_KEY in
    "ssh-ed25519 "*) ;;
    *) fail "the router sent no usable agent key" ;;
esac
if printf '%s' "${AGENT_KEY#ssh-ed25519 }" | grep -q '[^A-Za-z0-9+/=]'; then
    fail "the router sent no usable agent key"
fi

# -- 3. Where containers live ------------------------------------------------

ask() {
    # stdin is this script when it arrives through a pipe, so answers come
    # from the terminal.
    if ! (: < /dev/tty) 2>/dev/null; then
        fail "no terminal to ask on; pass --data-dir and --yes"
    fi
    printf '%s' "$1" > /dev/tty
    IFS= read -r REPLY < /dev/tty || REPLY=""
}

if [ -z "$DATA_DIR" ]; then
    if [ "$ASSUME_YES" -eq 1 ]; then
        DATA_DIR="$ACCOUNT_HOME/.hypellm"
    else
        ask "Where should containers be deployed and keep their state? [$ACCOUNT_HOME/.hypellm] "
        DATA_DIR=${REPLY:-$ACCOUNT_HOME/.hypellm}
    fi
fi
case $DATA_DIR in
    "~") DATA_DIR=$ACCOUNT_HOME ;;
    "~/"*) DATA_DIR="$ACCOUNT_HOME/${DATA_DIR#\~/}" ;;
esac
DATA_DIR=${DATA_DIR%/}
case $DATA_DIR in
    /*) ;;
    *) fail "the data directory must be an absolute path" ;;
esac
case /$DATA_DIR/ in
    */../*) fail "the data directory may not contain '..'" ;;
esac
if printf '%s' "$DATA_DIR" | grep -q '[^A-Za-z0-9/._-]'; then
    fail "the data directory may contain only letters, digits, '/', '.', '_' and '-'"
fi
[ "${#DATA_DIR}" -le 256 ] || fail "the data directory path is too long"

SHIM="$DATA_DIR/bin/hypellm-host-shim"
AUTH_KEYS="$ACCOUNT_HOME/.ssh/authorized_keys"
AUTH_LINE="restrict,command=\"$SHIM\" $AGENT_KEY hypellm-agent"

# -- 4. The plan ---------------------------------------------------------------

say ""
say "HypeLLM host kit $HOST_KIT_VERSION will enroll this machine as host '$HOST_ID'."
say ""
say "It will:"
say "  1. create $DATA_DIR (mode 0700) with bin/, containers/ and state/"
if [ -f "$DATA_DIR/device.key" ]; then
    say "  2. keep the existing device key $DATA_DIR/device.key"
else
    say "  2. generate an Ed25519 device key at $DATA_DIR/device.key (mode 0600)"
fi
say "  3. install the forced-command shim at $SHIM"
say "  4. add one line to $AUTH_KEYS (replacing any earlier 'hypellm-agent' line):"
say "       $AUTH_LINE"
say "  5. register with $ROUTER:"
say "       address $ADDRESS, $ARCH, $GPU_SUMMARY GPU(s), $MEMORY_BYTES bytes of memory,"
say "       data directory, SSH host key, and the device public key"
say ""
say "It installs no package, starts no service, and does not use sudo."
say "The machine joins the fleet only after an administrator approves it."
say ""

if [ "$DRY_RUN" -eq 1 ]; then
    say "Dry run: nothing was changed."
    exit 0
fi
if [ "$ASSUME_YES" -ne 1 ]; then
    ask "Proceed? [y/N] "
    case $REPLY in
        y|Y|yes|YES) ;;
        *) say "Nothing was changed."; exit 1 ;;
    esac
fi

# -- 5. Do it ------------------------------------------------------------------

umask 077
mkdir -p "$DATA_DIR/bin" "$DATA_DIR/containers" "$DATA_DIR/state"
chmod 0700 "$DATA_DIR"
if [ ! -f "$DATA_DIR/device.key" ]; then
    openssl genpkey -algorithm ed25519 -out "$DATA_DIR/device.key" 2>/dev/null \
        || fail "openssl could not generate an Ed25519 key"
fi
chmod 0600 "$DATA_DIR/device.key"
DEVICE_PEM=$(openssl pkey -in "$DATA_DIR/device.key" -pubout 2>/dev/null) \
    || fail "openssl could not read the device key"

cat > "$SHIM.tmp" <<'SHIM'
#!/bin/sh
# hypellm-host-shim: the only thing the fleet agent's SSH key may run.
#
# sshd puts the requested command in SSH_ORIGINAL_COMMAND. The agent builds it
# with Python's shlex.join, so it is words that are either bare-safe or
# single-quoted (with '"'"' for a quote). It is split here by that grammar
# alone — never by eval or a shell — and then checked against a fixed list.
set -u
refuse() { echo "hypellm-host-shim: refused" >&2; exit 126; }

cmd=${SSH_ORIGINAL_COMMAND-}
[ -n "$cmd" ] || refuse
nl='
'
case $cmd in *"$nl"*) refuse ;; esac
cr=$(printf '\r')
case $cmd in *"$cr"*) refuse ;; esac

words=$(printf '%s' "$cmd" | awk '
    BEGIN { safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@%+=:,./_-" }
    {
        line = $0; n = length(line); word = ""; inword = 0; i = 1
        while (i <= n) {
            c = substr(line, i, 1)
            if (c == " ") {
                if (!inword) exit 1
                print word; word = ""; inword = 0; i++
                continue
            }
            inword = 1
            if (c == "\047") {
                j = index(substr(line, i + 1), "\047")
                if (j == 0) exit 1
                word = word substr(line, i + 1, j - 1)
                i += j + 1
            } else if (c == "\"") {
                if (substr(line, i, 3) != "\"\047\"") exit 1
                word = word "\047"; i += 3
            } else if (index(safe, c) > 0) {
                word = word c; i++
            } else {
                exit 1
            }
        }
        if (!inword || word == "") exit 1
        print word
    }') || refuse
[ -n "$words" ] || refuse

set --
while IFS= read -r word; do
    [ -n "$word" ] || refuse
    set -- "$@" "$word"
done <<EOF
$words
EOF

is_name() { case $1 in ""|-*|*[!A-Za-z0-9_.-]*) return 1 ;; esac; return 0; }
is_ref() { case $1 in ""|-*|*[!A-Za-z0-9_./:@-]*) return 1 ;; esac; return 0; }
is_path() { case $1 in /*) case $1 in *[!A-Za-z0-9_./-]*|*..*) return 1 ;; esac; return 0 ;; esac; return 1; }
is_int() { case $1 in ""|*[!0-9]*) return 1 ;; esac; [ "${#1}" -le 6 ]; }
is_format() { case $1 in *"$nl"*) return 1 ;; esac; return 0; }

# The data directory is where this shim lives: <data>/bin/hypellm-host-shim.
# Taken from the path sshd ran, never from the environment or the command.
DATA=""
case $0 in */bin/hypellm-host-shim) DATA=${0%/bin/hypellm-host-shim} ;; esac
case $DATA in /*) ;; *) DATA="" ;; esac
case $DATA in *[!A-Za-z0-9/._-]*|*..*) DATA="" ;; esac

# A container's state directory: <data>/containers/<name>, nothing else.
is_state_dir() {
    [ -n "$DATA" ] || return 1
    case $1 in "$DATA"/containers/*) ;; *) return 1 ;; esac
    seg=${1#"$DATA"/containers/}
    case $seg in .*|*/*) return 1 ;; esac
    is_name "$seg"
}
# -v <data>/containers/<name>:<absolute container path>, no options.
is_state_mount() {
    case $1 in *:*:*) return 1 ;; *:/*) ;; *) return 1 ;; esac
    is_state_dir "${1%%:*}" && is_path "${1#*:}"
}
is_port() {
    case $1 in ""|*[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
# -p <IPv4>:<host port>:<container port>, the bind address explicit.
is_port_map() {
    case $1 in *[!0-9.:]*) return 1 ;; esac
    ip=${1%%:*}; rest=${1#*:}; hp=${rest%%:*}; cp=${rest#*:}
    case $ip in ""|*[!0-9.]*) return 1 ;; esac
    [ "$rest" = "$hp:$cp" ] && is_port "$hp" && is_port "$cp"
}
is_env() {
    key=${1%%=*}
    [ "$key" != "$1" ] || return 1
    case $key in ""|[!A-Za-z_]*|*[!A-Za-z0-9_]*) return 1 ;; esac
    return 0
}
is_label() {
    case $1 in hypellm.template=*) ;; *) return 1 ;; esac
    h=${1#hypellm.template=}
    [ "${#h}" -eq 64 ] || return 1
    case $h in *[!0-9a-f]*) return 1 ;; esac
    return 0
}
is_gpus() {
    case $1 in device=*) ;; *) return 1 ;; esac
    case ${1#device=} in ""|*[!0-9,]*|,*|*,|*,,*) return 1 ;; esac
    return 0
}

case $1 in
mkdir)
    [ $# -eq 3 ] && [ "$2" = -p ] && is_state_dir "$3" || refuse
    ;;
df)
    [ $# -eq 4 ] && [ "$2" = -B1 ] && [ "$3" = --output=avail ] && is_path "$4" || refuse
    ;;
nvidia-smi)
    [ $# -eq 3 ] || refuse
    case $2 in --query-gpu=*) ;; *) refuse ;; esac
    case $3 in --format=csv,noheader,nounits) ;; *) refuse ;; esac
    case $2 in *[!A-Za-z0-9=,._-]*) refuse ;; esac
    ;;
docker)
    [ $# -ge 2 ] || refuse
    case $2 in
    ps)
        [ $# -eq 2 ] || { [ $# -eq 4 ] && [ "$3" = --format ] && is_format "$4"; } || refuse ;;
    start)
        [ $# -eq 3 ] && is_name "$3" || refuse ;;
    stop)
        if [ $# -eq 3 ]; then is_name "$3" || refuse
        elif [ $# -eq 5 ]; then
            case $3 in --timeout|-t) ;; *) refuse ;; esac
            is_int "$4" && is_name "$5" || refuse
        else refuse; fi ;;
    inspect)
        [ $# -eq 5 ] && [ "$3" = --format ] && is_format "$4" && is_ref "$5" || refuse ;;
    image)
        [ $# -eq 6 ] && [ "$3" = inspect ] && [ "$4" = --format ] && is_format "$5" \
            && is_ref "$6" || refuse ;;
    pull|save)
        [ $# -eq 3 ] && is_ref "$3" || refuse ;;
    load)
        [ $# -eq 2 ] || { [ $# -eq 3 ] && [ "$3" = -q ]; } || refuse ;;
    rm)
        [ $# -eq 3 ] && is_name "$3" || refuse ;;
    create)
        # Options up to the image are held to a fixed vocabulary; what follows
        # the image is the container's own command line and runs inside it.
        want=""; named=0; image=""; i=0
        for arg do
            i=$((i + 1))
            [ $i -le 2 ] && continue
            [ -z "$image" ] || continue
            case $want in
            name) is_name "$arg" || refuse; named=1; want=""; continue ;;
            label) is_label "$arg" || refuse; want=""; continue ;;
            gpus) is_gpus "$arg" || refuse; want=""; continue ;;
            port) is_port_map "$arg" || refuse; want=""; continue ;;
            mount) is_state_mount "$arg" || refuse; want=""; continue ;;
            env) is_env "$arg" || refuse; want=""; continue ;;
            restart) [ "$arg" = no ] || refuse; want=""; continue ;;
            esac
            case $arg in
            --name) want=name ;;
            --label) want=label ;;
            --gpus) want=gpus ;;
            -p) want=port ;;
            -v) want=mount ;;
            -e) want=env ;;
            --restart) want=restart ;;
            -*) refuse ;;
            *) is_ref "$arg" || refuse; image=$arg ;;
            esac
        done
        [ -z "$want" ] && [ "$named" -eq 1 ] && [ -n "$image" ] || refuse ;;
    *) refuse ;;
    esac
    ;;
curl)
    shift
    url=""
    while [ $# -gt 0 ]; do
        case $1 in
        -f|-s|-S|-fs|-sS|-fsS|--fail|--silent|--show-error) shift ;;
        --max-time|-m) [ $# -ge 2 ] && is_int "$2" || refuse; shift 2 ;;
        http://127.0.0.1:*|http://localhost:*)
            [ -z "$url" ] || refuse
            case $1 in *[!A-Za-z0-9:/._~?=\&%-]*) refuse ;; esac
            case ${1#http://*:} in ""|[!0-9]*) refuse ;; esac
            url=$1; shift ;;
        *) refuse ;;
        esac
    done
    [ -n "$url" ] || refuse
    exec curl --proto =http --max-redirs 0 -fsS --max-time 10 "$url"
    ;;
*)
    refuse
    ;;
esac
exec "$@"
SHIM
chmod 0755 "$SHIM.tmp"
mv "$SHIM.tmp" "$SHIM"

mkdir -p "$ACCOUNT_HOME/.ssh"
chmod 0700 "$ACCOUNT_HOME/.ssh"
touch "$AUTH_KEYS"
# Replace, never duplicate: re-running the kit leaves exactly one line.
grep -v ' hypellm-agent$' "$AUTH_KEYS" > "$AUTH_KEYS.hypellm-tmp" || true
printf '%s\n' "$AUTH_LINE" >> "$AUTH_KEYS.hypellm-tmp"
chmod 0600 "$AUTH_KEYS.hypellm-tmp"
mv "$AUTH_KEYS.hypellm-tmp" "$AUTH_KEYS"

if [ -n "$RUN_AS" ]; then
    chown -R "$ACCOUNT" "$DATA_DIR" "$ACCOUNT_HOME/.ssh"
fi

DEVICE_JSON=$(printf '%s\n' "$DEVICE_PEM" | awk '{ printf "%s\\n", $0 }')
REPORT="{\"token\":\"$TOKEN\",\"address\":\"$ADDRESS\",\"arch\":\"$ARCH\",\
\"hostname\":\"$HOSTNAME_SHOWN\",\"ssh_user\":\"$ACCOUNT\",\"data_dir\":\"$DATA_DIR\",\
\"memory_bytes\":$MEMORY_BYTES,\"gpus\":[$GPUS_JSON],\"ssh_host_key\":\"$HOST_KEY_LINE\",\
\"device_key\":\"$DEVICE_JSON\",\"kit_version\":\"$HOST_KIT_VERSION\"}"

DONE=$(post /fleet/v1/enroll:complete "$REPORT") || fail "could not reach $ROUTER to register"
if [ "$(status_of "$DONE")" != 201 ]; then
    fail "the router refused the registration: $(json_field "$(reply_of "$DONE")" message)"
fi

say ""
say "Registered as host '$HOST_ID'. It stays unavailable until an administrator approves it."
say "Compare these with what the dashboard shows before approving:"
say "  SSH host key: $(json_field "$(reply_of "$DONE")" ssh_host_key_fingerprint)"
say "  Device key:   $(json_field "$(reply_of "$DONE")" device_key_fingerprint)"
