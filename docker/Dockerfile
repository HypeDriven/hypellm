# syntax=docker/dockerfile:1

# HypeLLM Router — local container image.
#
# Two stages and no package installation in either. Specification 4 forbids
# third-party packages in the router; the same reasoning applies to the image
# it ships in, so the runtime layer is a bare Debian plus one statically-linked-
# enough binary and the static admin assets. There is no shell entrypoint, no
# init wrapper, and no `curl` — a supervisor checks liveness over HTTP from
# outside.

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
# The tag is pinned rather than floating: `rust:1` would silently move the
# compiler under a security artifact between two builds of the same commit.
FROM rust:1.95-trixie AS build

WORKDIR /src

# `.cargo/config.toml` sets `net.offline = true`. Copying it first means the
# build below fails immediately if a registry dependency ever appears, rather
# than quietly fetching one — the same gate the workspace enforces locally.
COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY web ./web

# The supply-chain and static-web gate (specification 4/4.1/15). It is not
# advisory: a finding fails the image build, which is the point of running it
# here rather than only on a developer's machine.
RUN cargo run -q -p hypellm-devtools --bin depscan --offline -- --root .

# The target directory is a cache mount, so the binary has to be copied out
# inside the same layer — a cache mount is not part of the image.
RUN --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --offline -p hypellm-router \
 && cp /src/target/release/hypellm-router /usr/local/bin/hypellm-router

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

# A fixed system uid so the bind-mounted state and secret directories have a
# predictable owner. `compose.yaml` overrides it with the invoking user's uid
# so that a developer can read what the router wrote; in any other context this
# is the account the router runs as, and it owns nothing it does not write.
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin hypellm

COPY --from=build /usr/local/bin/hypellm-router /usr/local/bin/hypellm-router
COPY web /srv/hypellm/web

# A default configuration so the image is runnable on its own. `compose.yaml`
# bind-mounts the same file read-only, so editing `docker/hypellm.conf` and
# restarting is enough — there is no need to rebuild to change policy.
COPY docker/hypellm.conf /etc/hypellm/hypellm.conf

# Owned by the router account and writable, because `--generate-secrets` and
# the store both create files here on first start.
RUN mkdir -p /etc/hypellm/secrets /var/lib/hypellm \
 && chown -R hypellm:hypellm /etc/hypellm /var/lib/hypellm \
 && chmod 0700 /etc/hypellm/secrets /var/lib/hypellm

USER hypellm

# 8000 inference · 8001 management and the admin SPA · 8002 metrics.
# Documentation only: `compose.yaml` decides what is published, and publishes
# each to loopback on the host.
EXPOSE 8000 8001 8002

# `--generate-secrets` and `--check` are reached by appending arguments, which
# is why the entrypoint is the binary and not a script.
ENTRYPOINT ["/usr/local/bin/hypellm-router"]
CMD ["--config", "/etc/hypellm/hypellm.conf", \
     "--secrets", "/etc/hypellm/secrets", \
     "--static", "/srv/hypellm/web", \
     "--log", "info"]
