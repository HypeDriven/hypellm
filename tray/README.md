# HypeLLM Monitor

A dependency-free Windows 11 tray companion for the HypeLLM Router, in the
style of HypeLimits, its sibling allowance monitor: one compact floating
monitor, a gauge glyph in the tray, and a process that stays at the
bottom of every scheduler the OS has.

It shows **which models are going through the router right now** — one row per
target with requests in flight, queued, or streaming, as a bar of occupancy
against the target's concurrency limit — and **tokens per second per user and
per key**, ranked, with the fastest as the full bar.

It is the fourth reference component in this repository that lives outside
the workspace, beside `agent/`, `verifier/` and `supervisor/`, and like them it is deliberately not a workspace
member: it is C++ against the Win32 API, built with CMake, and nothing in the
router knows it exists.

## Build

From a Visual Studio Developer Command Prompt:

```bat
cmake -S tray -B tray\build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build tray\build
ctest --test-dir tray\build --output-on-failure
```

The executable is `tray\build\hypellm-monitor.exe`. It links only Windows
system libraries (`winhttp`, `user32`, `gdi32`, `comctl32`, `dwmapi`, `uxtheme`,
`advapi32`, `shell32`) and has no runtime dependency.

The portable half — the JSON reader, the rate arithmetic, and the decision of
what the monitor shows — builds and tests on any host, and a MinGW-w64
toolchain cross-compiles the whole application from Linux:

```sh
cmake -S tray -B tray/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE=<file setting CMAKE_SYSTEM_NAME=Windows and the x86_64-w64-mingw32 compilers>
cmake --build tray/build
```

## Connecting it

The monitor reads the router's management API with an ordinary router API key
that carries the `management:read` scope. Its principal must hold a role that
grants `read_summary` (every role does) and, for the per-user and per-key
figures, `read_tenant_usage` (`operator` and above). A key whose principal has
only `viewer` sees its own principal's usage and no key breakdown, and the
monitor says so in Options.

Mint one on the router's Keys screen or with `just key monitor management:read`
after adding `role_binding subject=principal:monitor role=operator` to the
configuration, then in **Options** paste the management listener's address
(`http://127.0.0.1:18001` for the shipped compose file, or the `https://`
address of the TLS edge in front of it) and the key. The key is stored in
Windows Credential Manager, never in the registry or a file, and is sent only
as a bearer header to the address you typed: the monitor uses no proxy,
follows no redirect, and takes nothing but the scheme, host, port and path
prefix from the address.

## What it shows, and what it does not

Every two seconds (configurable) the monitor calls `GET /admin/v1/traffic` and
`GET /admin/v1/usage`, plus `/session`, `/targets` and `/overview` on first
contact and occasionally after.

- **Models.** One row per target the key can see: what it is, whether it can
  serve, and what it is doing, in that order.

  *Whether it can serve* comes from `/targets` — the administrative state now
  in force, the worst circuit-breaker state across the target's operations, and
  the quarantine flag. A target that is enabled with a closed breaker is
  captioned **ready**; one that is drained, in maintenance, disabled or
  quarantined is captioned by whatever withdrew it; an open breaker reads as
  **failing** and a half-open one as **recovering**. Those rows are drawn in
  red and amber rather than dimmed, because dimming is the monitor's word for
  "quiet" and a quarantined target is not quiet. A target the listing does not
  contain is `unknown` and never `ready`: silence about a target is not
  evidence that it is fine. An administrative state this build has no word for
  is printed verbatim and treated as unavailable, so a state added later cannot
  read as ready by default.

  *What it is doing* comes from `traffic.capacity.targets`, the router's own
  admission occupancy per target: in flight, queued, streaming, and the
  concurrency limit. The bar is in-flight over the limit, coloured green
  through red as it fills. A limit that no admission scope enforces is shown
  but named as declared-only in the tooltip. A row also carries its rate when
  *requests or tokens* are moving in the rate window — requests and not only
  tokens, because a SemIf scorer answers with scores and reports no output
  tokens at all: a rerank target tested for token throughput would never appear,
  and its calls are far too short to be caught in flight by a two-second poll.

  Rows are ordered busy, then moving, then ready, then recovering, then
  unavailable, then unknown; the heading counts what is not available.
  **List every model, not only the busy ones** is on by default and can be
  turned off in Options, which narrows the list to targets with traffic —
  except that a target which is not available is listed either way, since a
  broken target has no traffic to be found by.

  Each row is labelled *machine · model*, from the target's provider and model
  name, because a model name is not an identifier here: two machines run the
  same quantisation of the same weights, and a row reading only
  `Qwen3.5-4B-Q6_K` names neither of them. The machine leads so that it is what
  survives when a narrow window ellipsises the label; the tooltip carries the
  target identifier in full.

  A router that exposes no admission controller to the management API reports
  no occupancy at all. The section then lists the targets and their
  availability with no figures and no bars, rather than disappearing.
- **Users and Keys.** The usage view holds cumulative counters, and the monitor
  differences them: the rate is the change over the sliding rate window
  (60 s by default), from the oldest sample still inside it to the newest.
  Rows appear when a rate is positive - in tokens, or in completed requests
  where the traffic generates no tokens - and disappear when the window
  empties. A section whose rows are all token-less ranks and draws its bars in
  requests per minute, and says so in the caption; it does not rank in a unit
  every row would score zero in.
  A counter that goes backwards, or a changed `since` epoch, restarts the
  series rather than producing a negative or absurd rate.
- **Tray.** The ring takes the colour of the busiest target's utilisation and
  is grey when unconfigured, red when the router is unreachable, orange when
  the key is rejected. The centre dot is lit only while something is in
  flight. The tooltip counts in-flight requests, busy models, how many targets
  are ready out of how many the key can see, and total output tokens per second
  - or, when nothing in flight is generating tokens, the completed requests per
  minute.

Three honest limits, all consequences of what the router exposes rather than of
the monitor:

- **"Ready" is not a liveness check.** The router has no readiness probe: it
  learns that a target is broken by routing to it and watching it fail. So the
  strongest thing it can say about a target nothing has been routed to lately
  is that it is enabled and nothing is known to be wrong with it, which is what
  **ready** means here and what every ready row's tooltip says. A container
  that died quietly a minute ago still reads as ready until the first request
  finds out. The converse is solid: **failing**, **draining**, **quarantined**,
  **maintenance** and **disabled** are all things the router positively knows.

- **Rates count a request's tokens when it completes.** The router does not
  publish the token position of a stream in progress, so a three-minute
  generation shows as a step at the end, not a ramp during. "Tokens per second"
  here is completed throughput smoothed over the window, and every tooltip says
  so. A row whose traffic reports no tokens is captioned in requests per minute
  instead, and its tooltip claims no token figure rather than a zero one.
- **Visibility is the key's.** The router narrows every management read to the
  caller's tenant and permissions; the monitor shows what the key may see and
  never more. A tenant whose traffic samples the router dropped is shown
  without figures rather than with confident zeros.

On first run the monitor asks once whether to start at login (**Yes** registers
it under the current user's Run key; **No** is not asked again) and then opens
Options so the address and key can be entered. The choice can be changed in
Options at any time, and a later start from a moved executable re-registers
the path without changing the choice.

A router that is unreachable keeps the last known rows on screen, dimmed under
a red status line; a rejected key tints the line orange, and clicking it opens
Options.

## Priorities

The process runs in `IDLE_PRIORITY_CLASS` with priority boost disabled, low
memory priority and EcoQoS execution-speed throttling; the UI thread is
below-normal; the refresh thread is idle priority, in background mode, with
thread-level EcoQoS. It never raises the timer resolution or asks for
foreground or multimedia scheduling. This is the same set HypeLimits applies.

## Tests

`tests/test_core.cpp` covers the JSON reader's limits and exactness, both
management views against fixtures shaped like the router's handlers, rate
arithmetic including window expiry and epoch and counter resets, the series
bound, and every branch of what the monitor shows — a quiet enabled target
listed and captioned ready, a withdrawn or failing one named by what withdrew
it and surviving a list narrowed to traffic, an unlisted target left unknown,
an unrecognised administrative state never read as ready, ready ranked above
quarantined, a router with no admission controller still listing its targets
with no figures, users ranked, keys shortened and hidden for principal-scoped
keys, stale rates dropping off, token-less rerank traffic still listed and
ranked by request rate, machines named beside their models where two rows would
otherwise read alike, and each failure state naming itself. `ctest` runs it on
Windows and on Linux.
