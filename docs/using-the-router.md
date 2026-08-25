# Using HypeLLM Router

How to point a project at a running router and send inference through it. For
standing one up, see [deployment](deployment.md); for what it does internally,
[the specification](../secure_llm_router_specification.md).

Written to be followed literally, by a person or by an agent. Every request and
response below was run against a live router.

Contents: [What you need](#what-you-need) · [Getting an API
key](#getting-an-api-key) · [Base URL](#base-url) · [OpenAI-compatible
clients](#openai-compatible-clients) · [Anthropic-compatible
clients](#anthropic-compatible-clients) · [Endpoints](#endpoints) ·
[Discovering aliases](#discovering-aliases) · [Sending an
image](#sending-an-image) · [Streaming](#streaming) · [Errors](#errors) ·
[Router extensions](#router-extensions) · [Limits](#limits) · [When something
is wrong](#when-something-is-wrong)

---

## What you need

1. **The base URL** of the inference listener.
2. **An API key**, which is not the same thing as network access — reaching the
   router authenticates nothing.
3. **A model alias** the key is permitted to use. You ask for an *alias*, not a
   provider's model name; the router picks the target.

---

## Getting an API key

Keys are minted through the management API, which needs an operator session.
There is no bootstrap key and no way to mint one from the inference listener.

If you already have a key, skip to [base URL](#base-url). It looks like
`hypellmk_<id>_<secret>` and is shown exactly once when created.

### The short way

For the containerised setup in this repository, `just` does all of it:

```bash
just bootstrap          # first run: secret bundle, router, and the first key
just key agent          # any key after that
just keys               # what is outstanding
just revoke <id>        # immediately
```

`bootstrap` is the only one that does not need the break-glass token: it
captures the token from `--generate-secrets`, spends it on the sign-in, and
prints it at the end to be stored offline. The others prompt for it, or read
`HYPELLM_BREAK_GLASS_TOKEN`. No secret is passed as a command-line argument.

If the token is already lost, `just bootstrap-fresh` discards the router's key
bundle and `run/state` and starts over. It keeps `run/secrets/credentials`,
because provider credentials are the operator's rather than the router's.

The rest of this section is what those recipes do, for a deployment without
them.

### 1. Sign in

With Google OIDC configured, sign in through the admin SPA and read the CSRF
token from `GET /admin/v1/session`. Without it — the local and air-gapped
profiles — use break-glass, whose token was printed once by
`--generate-secrets`:

```bash
curl -sS -D headers.txt -X POST http://127.0.0.1:18001/admin/v1/auth/break-glass \
  -H 'Content-Type: application/json' \
  -d '{"token":"<break-glass token>","reason":"minting the first API key"}'
```

```json
{"csrf_token":"EXAMPLEcsrf0000000000000000000000000000000d","expires_in_seconds":3600}
```

The session cookie is in the response headers. Two things about it:

- Every break-glass sign-in emits a `critical` log event and an audit record.
  It is an emergency path used deliberately, not a login.
- The cookie is `__Host-hypellm_session` with `Secure`, so a browser will not
  store it over plain HTTP except on `localhost`. `curl` does not care.

```bash
SESSION=$(grep -i '^set-cookie' headers.txt \
          | sed 's/.*__Host-hypellm_session=\([^;]*\).*/\1/' | tr -d '\r')
```

### 2. Mint the key

The CSRF token goes in `X-Hypellm-Csrf` — not `X-CSRF-Token`. Every mutating
management request needs it.

```bash
curl -sS -X POST http://127.0.0.1:18001/admin/v1/keys \
  -H "Cookie: __Host-hypellm_session=$SESSION" \
  -H "X-Hypellm-Csrf: <csrf_token>" \
  -H 'Content-Type: application/json' \
  -d '{
        "principal": "agent",
        "scopes": ["inference", "models", "embeddings", "tokenize"],
        "description": "project agent"
      }'
```

```json
{
  "id": "e75e4806c274423b",
  "principal": "agent",
  "secret": "hypellmk_e75e4806c274423b_EXAMPLEsecret000000000000000000000000000000",
  "notice": "this secret is shown once and cannot be retrieved again"
}
```

Scopes are `inference` (chat and responses), `embeddings`, `models`,
`tokenize`, `management:read`, `management:write`. Ask for the ones the project
uses and no more — a key without `embeddings` gets `403` from
`/v1/embeddings` rather than a routing decision.

Optional fields: `expires_at` (epoch milliseconds) and a source restriction.
A source-restricted key fails closed where the peer address is unknown, which
includes every caller arriving over a Unix-socket listener.

---

## Base URL

The inference listener. Everything in this document is relative to it.

```
http://<host>:18000
```

Its address depends on the deployment. For the containerised setup in this
repository, `just up` prints it; the management and metrics listeners are
deliberately somewhere else and are not part of this document.

Confirm it before configuring anything — both of these answer without a key:

```bash
curl -sS http://<host>:18000/health/live     # {"status":"ok"}
curl -sS http://<host>:18000/health/ready    # {"status":"ready"}
```

`not_ready` means the router is up but will refuse requests.

---

## OpenAI-compatible clients

Set the base URL to `http://<host>:18000/v1` and the API key to the router key.
Nothing else changes. The `model` is an **alias**, from `GET /v1/models`.

```python
from openai import OpenAI

client = OpenAI(base_url="http://<host>:18000/v1", api_key="hypellmk_...")

response = client.chat.completions.create(
    model="chat-standard",
    messages=[{"role": "user", "content": "ping"}],
)
```

Environment-variable form, which most coding tools accept:

```bash
export OPENAI_BASE_URL="http://<host>:18000/v1"
export OPENAI_API_KEY="hypellmk_..."
```

Do not point a client at the provider's model name
(`qwen3.8-27b-obliterated-q5-k-m`, `gpt-4o`). Aliases are what policy is
written against; a native model name is not routable and returns
`model_not_found`.

## Anthropic-compatible clients

`POST /v1/messages` speaks the Anthropic dialect, including `x-api-key`:

```bash
curl -sS -X POST http://<host>:18000/v1/messages \
  -H "x-api-key: hypellmk_..." \
  -H 'Content-Type: application/json' \
  -d '{"model":"chat-standard","max_tokens":64,
       "messages":[{"role":"user","content":"ping"}]}'
```

```json
{
  "id": "msg_4ac5df86ac95d65f8080935c25dbec03",
  "type": "message",
  "role": "assistant",
  "model": "chat-standard",
  "content": [{"type": "text", "text": "pong"}],
  "stop_reason": "end_turn",
  "usage": {"input_tokens": 9, "output_tokens": 6}
}
```

`Authorization: Bearer` works here too. The router accepts either header on
every endpoint.

---

## Endpoints

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/v1/models` | `models` | Aliases this key may use |
| `POST` | `/v1/chat/completions` | `inference` | OpenAI Chat Completions |
| `POST` | `/v1/responses` | `inference` | OpenAI Responses |
| `POST` | `/v1/embeddings` | `embeddings` | OpenAI embeddings |
| `POST` | `/v1/messages` | `inference` | Anthropic Messages |
| `POST` | `/v1/tokenize` | `tokenize` | Token count for a request |
| `GET` | `/health/live` | — | Process is up |
| `GET` | `/health/ready` | — | Will accept requests |

The path set is exact and undecoded. There is no prefix matching: anything else
is `404`, including `/v1/chat/completions/`.

### Discovering aliases

```bash
curl -sS -H "Authorization: Bearer $KEY" http://<host>:18000/v1/models
```

```json
{
  "object": "list",
  "data": [
    {"id": "chat-standard",   "object": "model", "owned_by": "hypellm", "description": "the default chat model"},
    {"id": "qwen-any",        "object": "model", "owned_by": "hypellm", "description": "text or images, routed by modality"},
    {"id": "qwen3.8-27b",     "object": "model", "owned_by": "hypellm", "description": "Qwen3.8 27B, whichever Spark is warm"},
    {"id": "vision-standard", "object": "model", "owned_by": "hypellm", "description": "images"}
  ]
}
```

This lists what *this key's tenant and permissions* allow, not everything
configured. An alias missing here is a policy fact, not a bug.

Which one to send:

| Alias | Use it for |
|---|---|
| `chat-standard` | The default. Text chat; pick this unless you have a reason not to. |
| `qwen3.8-27b` | The same models, named after the weights rather than the role. |
| `vision-standard` | Images. Declares the `vision` verb explicitly. |
| `qwen-any` | Text or images through one name, sorted out by what you send. |

All four currently resolve to the same pair of DGX Sparks; the router picks
whichever ranks higher, and `hypellm.native_model` in the response says which
answered. They are separate names because policy is written against them — an
operator can point `vision-standard` somewhere else without touching a client.

### Sending an image

Both Sparks load the vision projector, so images work on any alias declaring
the `image` modality. Standard OpenAI content parts — a `data:` URI or an
`https://` URL:

```bash
curl -sS -X POST http://<host>:18000/v1/chat/completions \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
        "model": "vision-standard",
        "max_tokens": 300,
        "messages": [{"role": "user", "content": [
          {"type": "text", "text": "What colour fills this image? One word."},
          {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KG..."}}
        ]}]
      }'
```

```json
{"choices": [{"message": {"role": "assistant", "content": "Red"}}],
 "hypellm": {"native_model": "qwen3.8-27b-obliterated-q5-k-m"}}
```

Two things this will not do:

- **Documents are refused.** A `file` / `input_file` part returns
  `no_eligible_target`, and the decision trace says `modality_unsupported` on
  every target. That is deliberate — a document is forwarded opaquely and these
  servers have no path for one, so the request is refused before anything is
  dialled rather than failing at the provider.
- **Budget tokens for thinking.** One Spark runs a reasoning build and emits
  `reasoning_content` before its answer. `"max_tokens": 40` can be consumed
  entirely by reasoning and return empty `content` with `finish_reason: "stop"`
  — which looks like a broken model and is not one. Give it a few hundred.

### Streaming

Set `"stream": true`. Server-sent events, `data:` per line, terminated by
`data: [DONE]`.

```
data: {"id":"chatcmpl-ce24...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

data: {"id":"chatcmpl-ce24...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"pong"},"finish_reason":null}]}

data: {"id":"chatcmpl-ce24...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: {"id":"chatcmpl-ce24...","object":"chat.completion.chunk","choices":[{"index":0,"delta":{}}],"usage":{"prompt_tokens":9,"completion_tokens":6,"total_tokens":15}}

data: [DONE]
```

Two things worth knowing:

- **A stream can fail mid-flight, and it will not be retried.** The router fails
  over freely before a provider has been committed to and never after the first
  content or tool delta has reached you — splicing a second provider's output
  into a half-delivered answer would be worse than an error. After that point a
  failure is a normalized error event and a closed connection.
- **Backpressure is real.** A client that stops reading blocks the router's
  connection worker, which stops it reading from the provider. Consume the
  stream.

Comment lines (`: keepalive`) may appear at intervals to keep an idle
connection open. Ignore them; every SSE client already does.

### Counting tokens

`POST /v1/tokenize` takes a request body of the same shape and returns a count
without running inference. Admission uses a conservative byte-based estimate
rather than this number, so a request may still be rejected as too large after
`/v1/tokenize` said it fit.

---

## Errors

One shape everywhere, OpenAI-compatible, plus a `request_id`:

```json
{
  "error": {
    "message": "the requested model is not available",
    "type": "invalid_request_error",
    "code": "model_not_found",
    "param": "model"
  },
  "request_id": "d5f7600c2372debef33a97b291ca6fe2"
}
```

`/v1/messages` returns the Anthropic error shape instead. Every response — good
or bad — carries `x-request-id`, which is the same value.

| Status | `code` | What it means | What to do |
|---|---|---|---|
| 400 | `invalid_request` | Malformed body, bad field, unknown value | Fix the request; `param` names the field |
| 401 | `unauthenticated` | Missing, malformed, revoked or expired key | Check the key; do not retry |
| 403 | `permission_denied` | Key lacks the scope, or policy denies the alias | Ask for the scope or the grant |
| 404 | `model_not_found` | No such alias, or not visible to this key | `GET /v1/models` |
| 404 | `not_found` | No such endpoint | Check the path |
| 413 | — | Body over the configured maximum | Send less |
| 429 | `rate_limited` | Concurrency, queue, request-rate or token-rate limit | Honour `Retry-After`; back off |
| 503 | `no_eligible_target` | No target passed policy, health and capability filters | See below |
| 504 | `deadline_exceeded` | Deadline passed | Retry idempotent work only |

`no_eligible_target` is the one that needs interpreting. It means every target
was excluded, and the reason is per-target: policy denial, residency, a
capability the request needed and no target declared, an open circuit breaker,
or a target that simply is not running. **Ask an operator for the decision
trace** — `GET /admin/v1/decisions/<request_id>` names every excluded target
and why:

```json
{
  "request_id": "696cf77f92f86fd51a9058c5710bb9a2",
  "explanation": "policy a388be7bf84d; candidates=0; excluded=1; chosen=none",
  "candidates": [],
  "exclusions": [{"target": "spark2:qwen38-q5", "reason": "modality_unsupported"}]
}
```

That is faster than guessing, and it is why `request_id` is on every response.

### Retrying

Retry `429`, `503` and `504`. Do not retry `400`, `401`, `403` or `404` — they
are deterministic and will fail identically.

The router already fails over between eligible targets, applies its own
deadlines and runs circuit breakers. A client that retries aggressively on top
of that adds load to a router that is already shedding it. Exponential backoff,
and honour `Retry-After` when present.

---

## Router extensions

Standard clients need none of this and can ignore the section. All of it is
additive: the request bodies stay valid OpenAI and Anthropic documents.

### Response metadata

Responses carry a `hypellm` object naming the target actually reached — the
router may have chosen a different provider than a previous identical request.

```json
"hypellm": {"native_model": "qwen3-27b", "upstream_id": "chatcmpl-verify"}
```

`usage` carries `"hypellm": {"usage_source": "provider_reported"}` or
`"router_estimated"`. Do not bill from an estimate.

### Asking for a reasoning tier

`reasoning_effort` (`minimal`, `low`, `medium`, `high`), or `reasoning.effort`
in the Responses dialect. An unrecognised value is an error rather than a
silent downgrade.

This is an **eligibility filter, not a hint**: a tier no target declares yields
`no_eligible_target` rather than a quietly cheaper answer.

### Asking for a quality floor

`min_quality`, an integer. Targets below it are excluded. Policy may already
impose a floor; the higher of the two applies, so this can narrow the candidate
set and never widens it.

### Routing hints

An optional `hypellm_routing` object, honoured only if the key is permitted to
send hints — otherwise silently ignored, by design.

```json
{
  "model": "chat-standard",
  "messages": [{"role": "user", "content": "ping"}],
  "hypellm_routing": {
    "prefer_target": "spark:qwen38-q5",
    "require_local": true,
    "idempotency_key": "..."
  }
}
```

- `prefer_target` reorders eligible targets within a bounded slice of the
  score. It cannot make an ineligible target eligible, beat a warmer one, or
  outrank a policy binding. Express hard preference through aliases and
  bindings instead.
- `require_local` excludes targets not marked local — inference that would
  leave the deployment.
- `idempotency_key` marks the request safe to fail over after a provider has
  accepted it.

Prompt content is never configuration. Nothing written in a message can change
a destination, a credential, or a routing decision.

---

## Limits

| Limit | Default |
|---|---|
| Request body | 16 MiB |
| Request head | 32 KiB |
| Request headers | 100 |
| Concurrent connections | 4096 |
| Requests per connection | 1000 |
| Read/write timeout | 30 s |
| Keep-alive idle | 75 s |

Per-tenant and per-key concurrency, queue depth, request rate, token rate, byte
rate and spend are configured separately and surface as `429`. Ask your
operator what applies to your key rather than discovering it under load.

HTTP/1.1 only. There is no HTTP/2 and no inbound TLS — a production deployment
puts a TLS edge in front, so the URL you are given may well be `https://` even
though the router itself speaks cleartext.

Long generations are ordinary synchronous requests held open for their
deadline. There is no jobs API and no polling endpoint.

---

## When something is wrong

Work down this list; each step rules out the one above it.

1. **`curl http://<host>:18000/health/live`.** No answer means a network or
   address problem, not a router problem. On the containerised setup, `just
   status` says whether it is running and `just tailnet` whether it is
   reachable.
2. **`curl -H "Authorization: Bearer $KEY" .../v1/models`.** `401` means the key
   is wrong, revoked or expired. `200` with fewer aliases than expected is a
   policy fact — the endpoint shows only what this key's tenant may use.
3. **Check you are asking for an alias**, not a provider's model name.
4. **On `no_eligible_target`, get the decision trace** for the `request_id`.
   Guessing at which filter excluded which target is slower than reading it.
5. **On `429`, back off** and ask which quota you are hitting.
6. **Keep the `request_id`.** Every operator-side record — audit entries, decision
   traces, metrics correlation — is keyed by it, and prompts are not logged by
   default, so it is often the only thread back to what happened.
