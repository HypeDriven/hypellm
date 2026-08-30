# The HypeLLM identity verifier

This directory holds the reference **identity verifier**: the process that
checks OpenID Connect identity token signatures and redeems authorization
codes.

It is deliberately outside the Rust workspace. It is not a workspace member, not
built by `cargo build --workspace`, and not scanned by `depscan` as router
source — the same arrangement as `agent/`, for the same reason.

## Why it is a separate process

Specification 4 and 9.1 draw the line:

> **OIDC dependency boundary:** JWT signature verification and HTTPS are
> cryptographic security functions. Strict profile delegates them to an approved
> local identity/TLS verifier service over a narrow authenticated local
> interface. … Never write novel signature or TLS code merely to satisfy "no
> dependencies."

The router therefore ships a *client* — `crates/hypellm-net/src/helper.rs` — and
no verifier. Without one, `settings oidc_verifier_socket` points at nothing,
`oidc_callback` answers `the identity verifier is not configured`, and Google
sign-in cannot complete. This is that service.

**This is an honest cost, not a free win.** The verifier holds the OAuth client
secret and decides which tokens are authentic. It is in the trusted computing
base and should be reviewed as such.

## What it does, and what it deliberately does not

It performs **no cryptography of its own**:

- The RSA signature check is `openssl dgst -verify`, invoked with an argument
  vector. OpenSSL is the platform's audited implementation.
- HTTPS to the key set and the token endpoint is the standard library's `ssl`
  module against the system trust store, with verification asserted rather than
  assumed.

What remains here is the JOSE envelope — splitting the token, pinning the
algorithm, selecting the key by `kid`, and encoding a public key into a form
OpenSSL will read. That is structure, not cryptography, but it is also where JWT
verifiers historically fail, so each decision is stated in the file and each has
a case in `--selftest`.

It also **does not validate claims**. `iss`, `aud`, `azp`, `exp`, `iat`,
`nonce`, `email_verified` and `hd` are checked by
`hypellm_auth::oidc::validate_claims`, in exactly one place, so a check cannot
be skipped on one of two paths. An expired token verifies here and is refused by
the router — `--selftest` asserts exactly that, because a verifier that helpfully
checked `exp` too would create the second path this design exists to avoid.

## What the router may tell it

Two verbs, framed as `VERB <length>\n<payload>`:

```text
→ VERIFY <length>\n<id token>
← OK <length>\n<claims JSON>
← ERR <code>\n

→ EXCHANGE <length>\n{"code":…,"code_verifier":…,"redirect_uri":…,"client_id":…,"token_endpoint":…}
← OK <length>\n<claims JSON>
← ERR <code>\n
```

`EXCHANGE` carries a `token_endpoint`, a `client_id` and a `redirect_uri`, and
**none of them is used as given**. Each is compared against this verifier's own
configuration and a mismatch is refused with `endpoint_mismatch`. A fully
compromised router can ask this process to redeem a code against the endpoint it
was configured with, and nowhere else — it cannot make it spend the client secret
at an attacker's host. Same rule as the fleet agent's, same reason.

## Obligations

These are normative. A verifier that does not keep them is not this verifier.

- **Runs as its own unprivileged user**, separate from the router. The process
  refuses to start as root.
- **Holds the OAuth client secret; the router never sees one.** It is read from
  a file, never from a command-line argument, and never logged.
- **Pins the algorithm before selecting a key.** `none` and every MAC algorithm
  are refused, so a caller cannot present a token signed with the public key the
  verifier is about to look up.
- **Never treats a router-supplied value as a destination.**
- **Caches issuer keys for a bounded lifetime, and rate-limits the refetch an
  unknown `kid` triggers.** Otherwise an unauthenticated caller decides how often
  this process talks to the issuer.
- **Bounds everything**: token size, key-set size, response size, and every
  timeout.
- **Logs no token, no claim, no email address, and no secret.**

## Setting it up

### 1. An OAuth client

In the Google Cloud console, create an **OAuth 2.0 Client ID** of type *Web
application*. Add the router's callback as an authorized redirect URI:

```text
https://admin.example/admin/v1/auth/google/callback
```

It must match `oidc_redirect_uri` in the router's configuration and
`redirect_uri` here, byte for byte. Google compares it exactly.

### 2. Configure the verifier

```bash
cp verifier/verifier.example.json /etc/hypellm/verifier/verifier.json
$EDITOR /etc/hypellm/verifier/verifier.json
printf '%s' 'the-client-secret' > /etc/hypellm/verifier/client_secret
chmod 600 /etc/hypellm/verifier/client_secret
verifier/hypellm-verifier --config /etc/hypellm/verifier/verifier.json --check
```

An unknown field is an error rather than a warning, for the reason the router's
own grammar takes that position (specification 11.1): a misspelled
`client_secret_file` would otherwise deploy a verifier with no secret.

Under the compose stack the paths are `run/verifier/` on the host, and `just
oidc` does the last three lines for you — it writes `client_secret` from
`HYPELLM_OIDC_CLIENT_SECRET` in a git-ignored `.env` (see `.env.example`), runs
`--check`, and starts the service under the `oidc` profile:

```bash
cp .env.example .env                 # then put the client secret in it
cp verifier/verifier.example.json run/verifier/verifier.json
$EDITOR run/verifier/verifier.json   # client_id and redirect_uri
just oidc
```

`.env` is read by `just` on the host and is never loaded into a container
environment — `docker inspect` prints a container's environment to anyone in the
`docker` group, whereas the 0600 file is readable by the verifier's user alone.
`verifier.json` is still edited by hand: `client_id` and `redirect_uri` have to
agree with the router's configuration and the Google console byte for byte, and
generating them here would add a third place for them to disagree.

### 3. Run it

```bash
verifier/hypellm-verifier \
    --config /etc/hypellm/verifier/verifier.json \
    --socket /run/hypellm/verify.sock
```

The socket is created `0660`. The router's user needs a group in common with the
verifier's, and the containing directory's permissions are the real access
control — anything that can open this socket can ask it to verify tokens. The
router does not set either; that is the deployment's job.

### 4. Point the router at it

```text
settings oidc_issuer=https://accounts.google.com \
         oidc_client_id=REPLACE.apps.googleusercontent.com \
         oidc_authorization_endpoint=https://accounts.google.com/o/oauth2/v2/auth \
         oidc_token_endpoint=https://oauth2.googleapis.com/token \
         oidc_redirect_uri=https://admin.example/admin/v1/auth/google/callback \
         oidc_verifier_socket=/run/hypellm/verify.sock \
         oidc_hosted_domains=example.com
```

`GET /admin/v1/settings` then reports `oidc.configured` and
`oidc.verifier_configured`, and the admin application's Settings screen shows
both. Both must be true before a sign-in can complete.

## Checking it works

```bash
just verifier-acceptance     # both layers
```

**`--selftest`** — twenty-eight cases over the JOSE logic in-process:
algorithm confusion in its three usual shapes, key selection, tampering after
signing, token shape, bounds, and the `EXCHANGE` pinning rules. It needs
`openssl` and **no network**, and the last case asserts that — because the
first draft of this file refetched the key set on every unknown `kid` and so
silently reached Google's live endpoint.

**`verifier/acceptance`** — the wire. It stands this process up behind a local
TLS key-set server whose certificate it is told to trust, then drives it twice:
once over a re-derived copy of the router's framing (a deliberate second
implementation, so it disagrees if the framing is wrong), and once through the
router's own `VerifierClient`. That second layer lives in
`crates/hypellm-net/tests/verifier_acceptance.rs` and is `#[ignore]`d, because
starting a process is exactly what specification 4.1 forbids the router from
doing — the harness starts it and the tests only connect. `cargo test
--workspace` therefore stays hermetic and needs neither Python nor a socket.

Add `--no-cargo` to run the wire layer alone on a machine without Rust.

The router's side of the boundary is covered separately by
`crates/hypellm-net/tests/fuzz.rs`, which asserts that no reply from a process
like this one — buggy, replaced, or mid-upgrade — can make the router invent an
identity.

## Enrolling the first administrator

A router with OIDC configured and no `identity` records has nobody who can sign
in. That fails closed correctly and is discovered at the worst moment, so do it
deliberately:

1. **Sign in once and be refused.** The refusal names the `(iss, sub)` pair your
   account presented:

   ```json
   {"error":{"code":"forbidden","message":"this identity is not bound to a principal in this deployment",
     "details":[{"code":"unknown_identity","location":"identity",
       "message":"no identity record matches issuer=https://accounts.google.com subject=104729183746152938471"}]}}
   ```

   The subject is the stable identity, not the email address: specification 9.1
   makes `(iss, sub)` the key because an email can be reassigned to a different
   person.

2. **Open a break-glass session** — the sign-in screen's *Use break-glass
   access*, or `POST /admin/v1/auth/break-glass`.

3. **Draft the records and publish them**, on the Routing policies screen or
   through `POST /admin/v1/policies`:

   ```text
   identity issuer=https://accounts.google.com subject=104729183746152938471 \
            principal=user:alice tenant=acme description="first administrator"
   role_binding subject=principal:user:alice role=operator
   ```

   Pick the narrowest role that does the job. `break_glass_admin` carries every
   permission the model defines and is not a general-purpose administrator role.

4. **Sign out of break-glass and sign in with Google.** The closing audit record
   is what gives a review the window rather than only its start.

## When it stops working

| Symptom | Cause |
|---|---|
| `the identity verifier is not configured` | `oidc_verifier_socket` is unset in the router's configuration. |
| Sign-in fails, verifier logs nothing | The router cannot open the socket. Check the group and the directory's permissions. |
| `ERR unknown_kid` for every token | The key set fetch is failing, or `jwks_uri` is wrong. Run with `--log debug`. |
| `ERR endpoint_mismatch` | The router's `oidc_token_endpoint`, `oidc_client_id` or `oidc_redirect_uri` disagrees with this verifier's configuration. They are compared exactly. |
| `ERR exchange_refused` | Google refused the code — usually a redirect URI that does not match the OAuth client, or a reused code. |
| `this identity is not bound to a principal` | Sign-in worked. There is no `identity` record. See above. |

An identity outage does not lock you out: break-glass is preprovisioned exactly
for this, and `docs/runbooks.md` §22.4 is the procedure.
