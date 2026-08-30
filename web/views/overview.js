/**
 * The Overview screen.
 *
 * Specification 15.3: "Request rate, latency, errors, active streams, capacity,
 * target status, configuration version."
 *
 * All seven are answered, from three endpoints. `GET /admin/v1/overview`
 * returns fleet counts and the active configuration identity; `GET
 * /admin/v1/targets` returns, per target, the breaker state, the admin state,
 * the operator quarantine flag, and three counters that are cumulative since
 * the router started; `GET /admin/v1/traffic` returns the rolling rate and
 * latency window, the active-stream gauge, and the admission limits beside
 * their occupancy.
 *
 * The distinction between the second and the third is the one to keep hold of
 * while editing this file. A cumulative counter divided by uptime is the
 * average since boot: on a router that was busy yesterday and is idle now it
 * reads as busy. `/admin/v1/traffic` measures a window instead, and it reports
 * the span it actually covered rather than the one it was asked for, because a
 * router that has been up for thirty seconds has not lived through a minute.
 * Every rate on this screen is that count divided by that span, and neither
 * half is ever presented without the other.
 *
 * Two limits on what the numbers mean, both of which the screen states rather
 * than hides:
 *
 * - **The latency figures are bucket upper bounds.** The router keeps a
 *   bucketed histogram, so a p99 of 25 ms means "at or below 25 ms". The cells
 *   are written `≤ 25 ms` for that reason, and a quantile past the largest
 *   bucket reads `> 2 min` rather than being clamped to the bound.
 *   Specification 19.1's measured distributions come from `hypellm-bench`, not
 *   from here.
 * - **Rate and latency are the caller's own tenant's.** Appendix B keeps
 *   management visibility inside the caller's tenant, and a request rate is a
 *   direct measure of how much work a tenant is doing. On a single-tenant
 *   deployment that is the whole router; on a shared one it is not, and the
 *   panel says so.
 *
 * Two further decisions worth stating:
 *
 * - **The screen is read-only.** Every control here either re-reads or
 *   navigates. Changing a target's state is `PATCH /admin/v1/targets/{id}`,
 *   which needs `operate_targets`, a reason, an `If-Match`, and a confirmation
 *   against the row being changed; that belongs on the targets screen, where
 *   the row and its ETag are in hand. Putting a one-click quarantine on a
 *   summary dashboard would be a security-sensitive mutation taken against a
 *   number rather than against a target.
 * - **The counters are cumulative and are labelled as such.** `total_requests`
 *   counts since the router started, not since some window. Presenting it as
 *   "traffic" would make an idle router that has been up for a week look busy.
 */

import {
  append,
  el,
  formatCount,
  formatDuration,
  formatTime,
  pill,
  replace,
  text,
} from '../components/dom.js';
import {
  actionButton,
  definitionList,
  emptyState,
  inlineField,
  panel,
  toolbar,
} from '../components/layout.js';
import { grid, pageHeader, stat, table } from '../components/table.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/overview',
  title: 'Overview',
  // The lede says what the numbers are, because "since the router started" is
  // the difference between reading this screen correctly and misreading it.
  lede: 'Rate, latency, capacity, target status, and the active configuration, as the router reports them now.',
  // `GET /admin/v1/overview`, `/targets` and `/traffic` all require
  // `Permission::ReadSummary` (crates/hypellm-admin-api/src/handlers.rs), which
  // every role holds. A principal who cannot read the summary cannot use this
  // screen at all, so the nav hides it rather than showing three failing panels.
  permission: 'read_summary',
};

/** The largest page the targets endpoint will serve (`Pagination::MAX_LIMIT`). */
const TARGET_PAGE_LIMIT = 500;

/**
 * Auto-refresh choices, in milliseconds.
 *
 * A fixed, short list rather than a free interval: an unbounded poll rate set
 * from the browser would be a client-controlled load on the management plane,
 * and specification 3.2's "nothing unbounded originates from a request" applies
 * to the console as much as to the data path. Off is the default because a
 * screen that refetches while unattended is a screen that keeps a session warm
 * for nobody.
 */
const REFRESH_CHOICES = [
  { value: '0', label: 'Off', millis: 0 },
  { value: '15000', label: 'Every 15 seconds', millis: 15_000 },
  { value: '60000', label: 'Every minute', millis: 60_000 },
];

/**
 * Render the screen.
 *
 * @param {HTMLElement} container Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session The `/admin/v1/session` body.
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @returns {Promise<() => void>} Cleanup, called on navigation away.
 */
export async function mount(container, ctx) {
  /** Set by cleanup. A poll that is already in flight must not paint after it. */
  let stopped = false;
  /** @type {number|null} */
  let timer = null;
  /** Guards against a manual refresh and a poll overlapping. */
  let loading = false;

  // The first load happens before anything is painted, so the shell's own
  // "Loading…" line and `aria-busy` cover it and this screen needs no loading
  // state of its own.
  let snapshot = await load(ctx.api);

  const status = el('p', {
    class: 'panel__note',
    role: 'status',
    'aria-live': 'polite',
    text: `Read at ${formatTime(Date.now())}.`,
  });

  const body = el('div');

  const refresh = actionButton('Refresh', () => runRefresh(), {
    tone: 'quiet',
    busyLabel: 'Reading…',
  });

  const interval = el(
    'select',
    {},
    REFRESH_CHOICES.map((choice) => el('option', { value: choice.value }, choice.label)),
  );
  interval.addEventListener('change', () => {
    scheduleFrom(interval.value);
  });

  const controls = toolbar(
    [
      el('div', { class: 'panel__actions' }, refresh),
      inlineField({ id: 'overview-refresh', label: 'Auto refresh', control: interval }),
    ],
    { label: 'Overview controls' },
  );

  // The header and the controls are built once and the results are painted into
  // `body`, so a refresh cannot move focus out of the control the operator is
  // using or reset the interval they just chose.
  append(container, [pageHeader(meta.title, meta.lede), controls, status, body]);
  paint(body, snapshot, ctx);

  /**
   * Re-read both endpoints and repaint.
   *
   * Not optimistic and not partial: either both responses arrive and the whole
   * body is replaced, or the previous reading stays on screen with its own
   * timestamp. A screen showing new target rows against old fleet totals would
   * be a reading that never existed.
   *
   * @returns {Promise<void>}
   */
  async function runRefresh() {
    if (loading || stopped) {
      return;
    }
    loading = true;
    status.textContent = 'Reading…';
    try {
      const next = await load(ctx.api);
      if (stopped) {
        return;
      }
      snapshot = next;
      paint(body, snapshot, ctx);
      status.textContent = `Read at ${formatTime(Date.now())}.`;
    } catch (error) {
      if (error && error.name === 'AbortError') {
        // Navigation cancelled it; the next screen owns the DOM now.
        return;
      }
      // The last good reading stays on screen, so the timestamp is what tells
      // the operator how stale it is.
      status.textContent = `The refresh failed. The figures below were read at ${formatTime(snapshot.readAt)}.`;
      throw error;
    } finally {
      loading = false;
    }
  }

  /**
   * Apply an interval choice.
   *
   * @param {string} value
   */
  function scheduleFrom(value) {
    clearTimer();
    const choice = REFRESH_CHOICES.find((candidate) => candidate.value === value);
    if (!choice || choice.millis === 0 || stopped) {
      return;
    }
    timer = window.setInterval(() => {
      runRefresh().catch((error) => {
        if (error && error.name === 'AbortError') {
          return;
        }
        // A poll that fails is stopped rather than left to retry every fifteen
        // seconds against a router that is evidently unwell: the operator is
        // told once, and asks for the next read themselves.
        clearTimer();
        interval.value = '0';
        ctx.notify('warn', `automatic refresh stopped: ${error && error.message ? error.message : 'the read failed'}`);
      });
    }, choice.millis);
  }

  function clearTimer() {
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  return () => {
    stopped = true;
    clearTimer();
  };
}

/**
 * Read all three endpoints.
 *
 * Sequentially, not concurrently: `Api.request` aborts whatever is in flight
 * before starting a non-shared request, so two overlapping `get` calls would
 * cancel each other. Doing them in order keeps all three cancellable by
 * navigation, which matters more here than the two round trips it costs.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<{overview: object, targets: object[], traffic: object, truncated: boolean, readAt: number}>}
 */
async function load(api) {
  const overview = await api.get('/overview');
  const targets = await api.get(`/targets?limit=${TARGET_PAGE_LIMIT}`);
  const traffic = await api.get('/traffic');
  const envelope = targets.data || {};
  return {
    overview: overview.data || {},
    targets: Array.isArray(envelope.data) ? envelope.data : [],
    traffic: traffic.data || {},
    truncated: Boolean(envelope.has_more),
    readAt: Date.now(),
  };
}

/**
 * Paint one reading.
 *
 * @param {HTMLElement} body
 * @param {{overview: object, targets: object[], truncated: boolean, readAt: number}} snapshot
 * @param {object} ctx
 */
function paint(body, snapshot, ctx) {
  const { overview, targets, traffic, truncated } = snapshot;
  const live = summarize(targets);

  replace(body, [
    grid(tiles(overview, live, traffic, targets.length, truncated)),
    ratePanel(traffic),
    panel({
      title: 'Target status',
      note: targetsNote(overview, targets.length, truncated),
      actions: [
        actionButton('Open targets', () => {
          ctx.navigate('/targets');
        }, { tone: 'quiet' }),
      ],
      content: targetTable(overview, targets),
    }),
    panel({
      title: 'Configuration and audit',
      note: 'The digest identifies the exact activated configuration; quote it when reporting behaviour that looks wrong.',
      content: definitionList([
        ['Configuration version', versionText(overview.config_version)],
        ['Configuration digest', mono(overview.config_digest)],
        ['Providers', formatCount(overview.providers)],
        ['Aliases', formatCount(overview.aliases)],
        ['Tenants', formatCount(overview.tenants)],
        ['Audit records', formatCount(overview.audit_records)],
        ['Audit chain head', mono(overview.audit_head)],
      ]),
    }),
  ]);
}

/**
 * The tile row.
 *
 * @param {object} overview
 * @param {{inFlight: number, requests: number, failures: number, complete: boolean}} live
 * @param {object} traffic The `/admin/v1/traffic` body.
 * @param {number} listed
 * @param {boolean} truncated
 * @returns {HTMLElement[]}
 */
function tiles(overview, live, traffic, listed, truncated) {
  // "Across the targets this screen read" rather than "across the fleet": when
  // the list is truncated the sums are a subset, and saying which subset is the
  // difference between an incomplete figure and a wrong one.
  const scope = truncated
    ? `summed across the first ${formatCount(listed)} targets`
    : `summed across ${formatCount(listed)} targets`;
  const partial = live.complete ? '' : ' The router omitted a counter on at least one target.';

  const shortest = shortestWindow(traffic);
  const streams = traffic && traffic.capacity ? traffic.capacity.active_streams : undefined;

  return [
    stat(
      'Targets healthy',
      healthText(overview),
      degradedNote(overview),
    ),
    // The one figure on this row that is a *rate* rather than a total, which is
    // why its note names the span it was measured over. Every other tile here
    // counts since the router started.
    stat('Requests per second', rateTileValue(shortest), rateTileNote(traffic, shortest)),
    stat('Active streams', formatCount(streams), streamsNote(traffic)),
    stat('Requests in flight', formatCount(live.inFlight), `${scope}.${partial}`),
    stat('Requests seen', formatCount(live.requests), 'Cumulative since the router started.'),
    stat('Failed requests', formatCount(live.failures), failureNote(live)),
    stat(
      'Configuration',
      versionText(overview.config_version),
      typeof overview.config_digest === 'string' ? overview.config_digest : 'digest not reported',
    ),
  ];
}

/**
 * The shortest measurement window the router reported, or `null`.
 *
 * "Shortest" rather than "first": the tile is meant to say what the router is
 * doing *now*, and a five-minute average hides a spike that started ninety
 * seconds ago. The panel below shows every window the router returned.
 *
 * @param {object} traffic
 * @returns {object|null}
 */
function shortestWindow(traffic) {
  if (!traffic || traffic.attributed === false || !Array.isArray(traffic.windows)) {
    return null;
  }
  let shortest = null;
  for (const window of traffic.windows) {
    if (!window || typeof window.window_millis !== 'number') {
      continue;
    }
    if (shortest === null || window.window_millis < shortest.window_millis) {
      shortest = window;
    }
  }
  return shortest;
}

/**
 * The span below which a rate is arithmetic rather than measurement.
 *
 * One request in the first fifty milliseconds of uptime divides out to twenty a
 * second. The count is real; the rate is not, so it is withheld until the
 * router has been observing for at least a second.
 */
const MINIMUM_RATE_SPAN_MILLIS = 1000;

/**
 * A per-second rate, or `null` when the covered span is too short to divide by.
 *
 * The router deliberately reports counts and a covered span rather than a rate,
 * so that there is exactly one figure per measurement and no second one to
 * disagree with it. This is the division, done once, here.
 *
 * @param {unknown} count
 * @param {unknown} coveredMillis
 * @returns {number|null}
 */
function perSecond(count, coveredMillis) {
  if (typeof count !== 'number' || !Number.isFinite(count)) {
    return null;
  }
  if (
    typeof coveredMillis !== 'number' ||
    !Number.isFinite(coveredMillis) ||
    coveredMillis < MINIMUM_RATE_SPAN_MILLIS
  ) {
    return null;
  }
  return (count * 1000) / coveredMillis;
}

/**
 * Format a rate with a precision that does not outrun the measurement.
 *
 * @param {number|null} value
 * @returns {string}
 */
function formatRate(value) {
  if (value === null) {
    return '—';
  }
  if (value === 0) {
    return '0';
  }
  if (value < 1) {
    return value.toFixed(2);
  }
  if (value < 100) {
    return value.toFixed(1);
  }
  return formatCount(Math.round(value));
}

/**
 * @param {object|null} window
 * @returns {string}
 */
function rateTileValue(window) {
  if (!window) {
    return '—';
  }
  return formatRate(perSecond(window.requests, window.covered_millis));
}

/**
 * The tile's note, which is where the honesty lives.
 *
 * @param {object} traffic
 * @param {object|null} window
 * @returns {string}
 */
function rateTileNote(traffic, window) {
  if (traffic && traffic.attributed === false) {
    return 'This tenant is not being attributed; see the panel below.';
  }
  if (!window) {
    return 'The router reported no measurement window.';
  }
  const covered = formatDuration(window.covered_millis);
  const requests = formatCount(window.requests);
  if (window.complete === false) {
    return `${requests} requests over ${covered}; the router has not been observing for a full ${formatDuration(window.window_millis)}.`;
  }
  return `${requests} requests over ${covered}, for this tenant.`;
}

/**
 * @param {object} traffic
 * @returns {string}
 */
function streamsNote(traffic) {
  const capacity = traffic ? traffic.capacity : undefined;
  if (!capacity || capacity.available === false) {
    return 'The router reported no capacity figures.';
  }
  return 'Upstream streams open right now, across the targets you can see.';
}

/**
 * The rate, latency, and capacity panel.
 *
 * Three readings, one panel, because an operator reads them together: a rate
 * that has risen, a latency that has risen with it, and a limit it is
 * approaching are one story, and on three separate screens they are three
 * unrelated facts.
 *
 * @param {object} traffic The `/admin/v1/traffic` body.
 * @returns {HTMLElement}
 */
function ratePanel(traffic) {
  const attributed = !traffic || traffic.attributed !== false;
  const windows = traffic && Array.isArray(traffic.windows) ? traffic.windows : [];

  let rateContent;
  if (!attributed) {
    // Not "no traffic": the router tracks a bounded number of tenants and this
    // one arrived after the last ring was taken, so its samples were dropped. A
    // zero here would report the busiest tenant on the router as idle.
    rateContent = emptyState(
      'This tenant’s traffic is not being attributed',
      `The router keeps a bounded set of per-tenant measurement windows, and every one of them was already in use when this tenant first appeared, so its completed requests were not recorded. The figures are missing, not zero — ${formatCount(traffic.unattributed_samples)} samples have been dropped this way across the router. The metrics exposition on the management listener still carries router-wide totals.`,
    );
  } else if (windows.length === 0) {
    rateContent = emptyState(
      'The router returned no measurement window',
      'The traffic endpoint answered without a window, which is a router-side inconsistency rather than an idle deployment. Quote the configuration digest when reporting it.',
    );
  } else {
    rateContent = rateTable(traffic, windows);
  }

  return panel({
    title: 'Rate, latency, and capacity',
    note: 'Rate and latency are measured over a rolling window for your own tenant. Latency is bucketed, so a percentile is an upper bound and is written as one.',
    content: [
      rateContent,
      el('h3', { class: 'card__title', text: 'Admission capacity' }),
      capacityContent(traffic ? traffic.capacity : undefined),
    ],
  });
}

/**
 * One row per measurement window.
 *
 * The count and the span it was measured over both appear, not just the rate
 * derived from them: a rate with no denominator cannot be checked, and this
 * screen's whole claim is that what it shows is what the router said.
 *
 * @param {object} traffic
 * @param {object[]} windows
 * @returns {HTMLElement}
 */
function rateTable(traffic, windows) {
  const largest = typeof traffic.largest_bucket_millis === 'number'
    ? traffic.largest_bucket_millis
    : null;

  return table({
    caption:
      'Completed requests and their latency, over each rolling window. Percentiles are bucket upper bounds; the router publishes the same distributions as histograms at GET /metrics on the management listener.',
    rows: windows,
    columns: [
      { label: 'Window', cell: (row) => windowCell(row) },
      {
        label: 'Requests',
        numeric: true,
        cell: (row) => formatCount(row.requests),
      },
      {
        label: 'Per second',
        numeric: true,
        cell: (row) => formatRate(perSecond(row.requests, row.covered_millis)),
      },
      { label: 'Succeeded', numeric: true, cell: (row) => formatCount(row.successes) },
      { label: 'Client errors', numeric: true, cell: (row) => errorCell(row, 'client_errors') },
      { label: 'Throttled', numeric: true, cell: (row) => errorCell(row, 'throttled') },
      { label: 'Server errors', numeric: true, cell: (row) => errorCell(row, 'server_errors') },
      {
        label: 'Router p50 / p99',
        cell: (row) => quantilePairCell(row.router_latency, largest),
      },
      {
        label: 'Upstream p50 / p99',
        cell: (row) => quantilePairCell(row.upstream_latency, largest),
      },
      {
        label: 'Output tokens/s',
        numeric: true,
        cell: (row) => formatRate(perSecond(row.output_tokens, row.covered_millis)),
      },
    ],
  });
}

/**
 * The window name, and the span actually covered when it is not the whole one.
 *
 * @param {object} row
 * @returns {Node}
 */
function windowCell(row) {
  const label = `Last ${formatDuration(row.window_millis)}`;
  if (row.complete === false) {
    return el('span', {}, [
      text(label),
      el('span', { class: 'stat__note', text: ` covering ${formatDuration(row.covered_millis)}` }),
    ]);
  }
  return text(label);
}

/**
 * An error count, tinted only when it is non-zero.
 *
 * @param {object} row
 * @param {string} field
 * @returns {Node}
 */
function errorCell(row, field) {
  const value = row[field];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return text('—');
  }
  if (value === 0) {
    return text('0');
  }
  // Throttling is a limit working as configured; a server error is an outage.
  // The tones differ because the operator's next action does.
  return pill(formatCount(value), field === 'throttled' ? 'warn' : 'danger');
}

/**
 * The median and the 99th percentile, side by side.
 *
 * @param {object} latency
 * @param {number|null} largest
 * @returns {Node}
 */
function quantilePairCell(latency, largest) {
  if (!latency || typeof latency.samples !== 'number' || latency.samples === 0) {
    return el('span', { class: 'stat__note', text: 'no samples' });
  }
  return text(
    `${quantileText(latency.p50_millis, latency, largest)} / ${quantileText(latency.p99_millis, latency, largest)}`,
  );
}

/**
 * One percentile, written as the bound it actually is.
 *
 * `≤ 25 ms` rather than `25 ms`, because the router keeps a bucketed histogram
 * and 25 is the bucket's upper edge. A percentile that fell in the overflow
 * bucket has no upper edge at all and reads `> 2 min` — the difference between
 * a slow provider and a hung one.
 *
 * @param {unknown} value
 * @param {object} latency
 * @param {number|null} largest
 * @returns {string}
 */
function quantileText(value, latency, largest) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return `≤ ${formatDuration(value)}`;
  }
  if (latency.above_largest_bucket > 0 && largest !== null) {
    return `> ${formatDuration(largest)}`;
  }
  return '—';
}

/**
 * The capacity half of the panel.
 *
 * @param {object|undefined} capacity
 * @returns {Array<Node>|Node}
 */
function capacityContent(capacity) {
  if (!capacity || capacity.available === false) {
    return emptyState(
      'The router is not reporting admission capacity',
      typeof capacity?.reason === 'string'
        ? capacity.reason
        : 'The traffic endpoint returned no capacity object.',
    );
  }

  const scopes = [capacity.global, capacity.tenant].filter((scope) => scope && typeof scope === 'object');
  const targets = Array.isArray(capacity.targets) ? capacity.targets : [];

  return [
    scopeTable(scopes),
    targets.length === 0
      ? emptyState(
          'No target is visible to you',
          'Per-target capacity is scoped the same way the target list is; an alias you hold no grant for does not appear here.',
        )
      : targetCapacityTable(targets),
  ];
}

/**
 * The admission scopes that govern the caller.
 *
 * @param {object[]} scopes
 * @returns {HTMLElement}
 */
function scopeTable(scopes) {
  return table({
    caption:
      'Admission scopes, with what is occupying them. A limit of zero means the scope imposes none. Reservations acquired and released must be equal whenever nothing is in flight.',
    rows: scopes,
    columns: [
      { label: 'Scope', cell: (row) => el('span', { class: 'mono', text: String(row.name ?? '—') }) },
      { label: 'Concurrency', cell: (row) => occupancyCell(row.in_flight, row.max_concurrency, row.exists) },
      { label: 'Queued', cell: (row) => occupancyCell(row.queued, row.max_queued, row.exists) },
      { label: 'Rate limit', cell: (row) => limitText(row.requests_per_second, '/s') },
      { label: 'Token limit', cell: (row) => limitText(row.tokens_per_minute, '/min') },
      { label: 'Reservations', cell: (row) => reservationCell(row) },
      { label: 'Budget', cell: (row) => budgetCell(row) },
    ],
  });
}

/**
 * Per-target capacity.
 *
 * @param {object[]} targets
 * @returns {HTMLElement}
 */
function targetCapacityTable(targets) {
  return table({
    caption:
      'Per-target admission. A target with no admission scope shows the concurrency its configuration declares, which nothing is currently enforcing.',
    rows: targets,
    columns: [
      { label: 'Target', cell: (row) => el('span', { class: 'mono', text: String(row.id ?? '—') }) },
      { label: 'Concurrency', cell: (row) => occupancyCell(row.in_flight, row.max_concurrency, true) },
      { label: 'Queued', cell: (row) => occupancyCell(row.queued, row.max_queued, true) },
      { label: 'Rate limit', cell: (row) => limitText(row.requests_per_second, '/s') },
      { label: 'Active streams', numeric: true, cell: (row) => formatCount(row.active_streams) },
      { label: 'Enforced', cell: (row) => enforcedCell(row.admission_scope) },
    ],
  });
}

/**
 * An occupancy against its limit, with a bar when there is a limit to draw.
 *
 * A `<meter>` rather than a styled div, for the reason the fleet screen already
 * gives: the value, the maximum, and the accessible label come from the element
 * itself, so a screen reader announces the numbers rather than "graphic".
 *
 * @param {unknown} used
 * @param {unknown} limit
 * @param {unknown} exists Whether the scope exists at all.
 * @returns {Node}
 */
function occupancyCell(used, limit, exists) {
  if (exists === false) {
    // The scope has not been created yet, so there is nothing occupying it —
    // which is not the same as an occupancy of zero that was measured.
    return el('span', { class: 'stat__note', text: 'not yet in use' });
  }
  if (typeof used !== 'number' || !Number.isFinite(used)) {
    return text('—');
  }
  if (typeof limit !== 'number' || !Number.isFinite(limit) || limit === 0) {
    return el('span', {}, [
      text(formatCount(used)),
      el('span', { class: 'stat__note', text: ' of no limit' }),
    ]);
  }
  const meter = el('meter', {
    class: 'meter',
    min: '0',
    max: String(limit),
    value: String(Math.min(used, limit)),
    'aria-label': `${formatCount(used)} of ${formatCount(limit)} in use`,
  });
  return el('div', { class: 'meter-row' }, [
    meter,
    el('span', {
      class: 'meter-row__label',
      text: `${formatCount(used)} / ${formatCount(limit)}`,
    }),
  ]);
}

/**
 * A configured limit, where zero means "none".
 *
 * @param {unknown} value
 * @param {string} suffix
 * @returns {Node}
 */
function limitText(value, suffix) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return text('—');
  }
  if (value === 0) {
    return el('span', { class: 'stat__note', text: 'no limit' });
  }
  return text(`${formatCount(value)}${suffix}`);
}

/**
 * The conservation pair from Appendix B.
 *
 * Shown because a leak is otherwise invisible until the scope stops admitting
 * anything: an idle scope whose two counters differ has lost a reservation.
 *
 * @param {object} row
 * @returns {Node}
 */
function reservationCell(row) {
  if (typeof row.acquired !== 'number' || typeof row.released !== 'number') {
    return text('—');
  }
  const outstanding = row.acquired - row.released;
  const label = `${formatCount(row.acquired)} / ${formatCount(row.released)}`;
  if (outstanding === 0) {
    return text(label);
  }
  // A non-zero difference is expected while requests are in flight, and is only
  // a defect if it persists with an idle scope — which the note says, rather
  // than the cell claiming a leak it cannot know about.
  return el('span', {}, [
    text(label),
    el('span', { class: 'stat__note', text: ` (${formatCount(outstanding)} outstanding)` }),
  ]);
}

/**
 * Spend against the budget, when one is configured.
 *
 * @param {object} row
 * @returns {Node}
 */
function budgetCell(row) {
  const limit = row.budget_minor_units;
  if (typeof limit !== 'number' || !Number.isFinite(limit) || limit === 0) {
    return el('span', { class: 'stat__note', text: 'no budget' });
  }
  const spent = typeof row.spent_minor_units === 'number' ? row.spent_minor_units : 0;
  const period = typeof row.budget_period === 'string' ? row.budget_period : 'period';
  return el('span', {}, [
    text(`${formatCount(spent)} / ${formatCount(limit)}`),
    el('span', { class: 'stat__note', text: ` per ${period}, in minor units` }),
  ]);
}

/**
 * Whether an admission scope is actually policing this target.
 *
 * @param {unknown} value
 * @returns {Node}
 */
function enforcedCell(value) {
  if (value === true) {
    return pill('enforced', 'ok');
  }
  if (value === false) {
    // The configuration declares a concurrency and nothing is admitting against
    // it. Saying "declared" rather than showing the pair unqualified is what
    // stops the number being read as a limit in force.
    return pill('declared only', 'warn');
  }
  return pill('unknown', 'neutral');
}

/**
 * Sum the per-target counters.
 *
 * A field that is missing or not a number is not counted as zero: `complete`
 * carries that fact up to the tile note instead, because a silently short sum
 * reads exactly like a quiet router.
 *
 * @param {object[]} targets
 * @returns {{inFlight: number, requests: number, failures: number, complete: boolean}}
 */
function summarize(targets) {
  const totals = { inFlight: 0, requests: 0, failures: 0, complete: true };

  /**
   * @param {object} target
   * @param {string} field
   * @returns {number}
   */
  const counter = (target, field) => {
    const value = target ? target[field] : undefined;
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }
    totals.complete = false;
    return 0;
  };

  for (const target of targets) {
    totals.inFlight += counter(target, 'in_flight');
    totals.requests += counter(target, 'total_requests');
    totals.failures += counter(target, 'total_failures');
  }

  return totals;
}

/**
 * The target table, or an empty state that says why it is empty.
 *
 * @param {object} overview
 * @param {object[]} targets
 * @returns {HTMLElement}
 */
function targetTable(overview, targets) {
  if (targets.length === 0) {
    // Two different emptinesses, and an operator needs to tell them apart: a
    // configuration with no targets is a deployment that cannot serve anything,
    // while a configuration with targets that returned none is a fault.
    if (overview.targets_total === 0) {
      return emptyState(
        'The active configuration declares no targets',
        'The router has nothing to route to and will refuse inference requests until a target is configured and the configuration is activated.',
      );
    }
    return emptyState(
      'The router reported targets but returned none',
      `The overview counts ${formatCount(overview.targets_total)} targets while the targets endpoint returned an empty page. This is a router-side inconsistency, not an empty deployment; quote the configuration digest when reporting it.`,
    );
  }

  return table({
    caption: 'Every configured target, with its administrative state, circuit breaker, and cumulative counters.',
    // The order the endpoint returned is preserved. It is the same order the
    // targets screen shows, and re-sorting by health here would mean the same
    // target sits in a different place on two screens.
    rows: targets,
    columns: [
      {
        label: 'Target',
        cell: (row) => el('span', { class: 'mono', text: String(row.id ?? '—') }),
      },
      { label: 'Provider', cell: (row) => String(row.provider ?? '—') },
      { label: 'Model', cell: (row) => el('span', { class: 'mono', text: String(row.model ?? '—') }) },
      { label: 'State', cell: (row) => stateCell(row) },
      { label: 'Breaker', cell: (row) => breakerCell(row.breaker_state) },
      { label: 'Placement', cell: (row) => placementText(row) },
      { label: 'In flight', numeric: true, cell: (row) => formatCount(row.in_flight) },
      { label: 'Requests', numeric: true, cell: (row) => formatCount(row.total_requests) },
      { label: 'Failures', numeric: true, cell: (row) => formatCount(row.total_failures) },
    ],
  });
}

/**
 * Administrative state, plus the operator quarantine when the two differ.
 *
 * `state` is the configured administrative state and `quarantined` is the live
 * override held in the health registry (specification 13: manual quarantine
 * overrides automated recovery). They are two separate facts and a target can
 * be `enabled` in configuration and quarantined right now, so collapsing them
 * into one badge would hide the reason the target is not being selected.
 *
 * @param {object} row
 * @returns {Node}
 */
function stateCell(row) {
  const state = typeof row.state === 'string' ? row.state : 'unknown';
  const badges = [pill(state, stateTone(state))];
  if (row.quarantined === true && state !== 'quarantined') {
    badges.push(text(' '), pill('quarantined', 'danger'));
  }
  return el('span', {}, badges);
}

/**
 * @param {string} state
 * @returns {'ok'|'warn'|'danger'|'neutral'}
 */
function stateTone(state) {
  // `AdminState::admits_new_requests` is true for `enabled` alone; everything
  // else is a target that will not be selected, and the tone says so.
  switch (state) {
    case 'enabled':
      return 'ok';
    case 'draining':
    case 'maintenance':
      return 'warn';
    case 'quarantined':
    case 'disabled':
      return 'danger';
    default:
      return 'neutral';
  }
}

/**
 * @param {unknown} value
 * @returns {Node}
 */
function breakerCell(value) {
  const state = typeof value === 'string' ? value : 'unknown';
  switch (state) {
    case 'closed':
      // Closed is the healthy state for a circuit breaker, which is the
      // opposite of how the word reads to anyone who has not met one before;
      // the label says "closed (passing)" so nobody has to remember.
      return pill('closed · passing', 'ok');
    case 'half_open':
      return pill('half open · probing', 'warn');
    case 'open':
      return pill('open · refusing', 'danger');
    default:
      return pill(state, 'neutral');
  }
}

/**
 * Where the target runs, which is a residency question before it is a
 * performance one (specification 6.3: residency is an eligibility filter).
 *
 * @param {object} row
 * @returns {string}
 */
function placementText(row) {
  if (typeof row.residency === 'string' && row.residency !== '') {
    return row.local === true ? `local · ${row.residency}` : row.residency;
  }
  if (row.local === true) {
    return 'local';
  }
  if (row.local === false) {
    return 'remote';
  }
  return '—';
}

/**
 * @param {object} overview
 * @returns {string}
 */
function healthText(overview) {
  const healthy = overview.targets_healthy;
  const total = overview.targets_total;
  if (typeof healthy !== 'number' || typeof total !== 'number') {
    return '—';
  }
  return `${formatCount(healthy)} / ${formatCount(total)}`;
}

/**
 * @param {object} overview
 * @returns {string}
 */
function degradedNote(overview) {
  const degraded = overview.targets_degraded;
  if (typeof degraded !== 'number') {
    return 'The router did not report a degraded count.';
  }
  if (degraded === 0) {
    return 'No target is quarantined or has an open breaker.';
  }
  return `${formatCount(degraded)} quarantined or with an open breaker.`;
}

/**
 * @param {{requests: number, failures: number}} live
 * @returns {string}
 */
function failureNote(live) {
  if (live.requests <= 0) {
    return 'No requests recorded yet, so there is no share to compute.';
  }
  // One decimal place: the counters are cumulative totals, and more precision
  // would suggest a measurement window that does not exist.
  const share = (live.failures / live.requests) * 100;
  return `${share.toFixed(1)}% of requests seen.`;
}

/**
 * @param {object} overview
 * @param {number} listed
 * @param {boolean} truncated
 * @returns {string}
 */
function targetsNote(overview, listed, truncated) {
  if (!truncated) {
    return 'Administrative state comes from the active configuration; the breaker and the counters are live.';
  }
  return `Showing the first ${formatCount(listed)} of ${formatCount(overview.targets_total)} targets. The tiles above sum only these; open the targets screen for the rest.`;
}

/**
 * @param {unknown} version
 * @returns {string}
 */
function versionText(version) {
  return typeof version === 'number' && Number.isFinite(version) ? `v${formatCount(version)}` : '—';
}

/**
 * A monospaced value, or an em dash when the router did not report one.
 *
 * @param {unknown} value
 * @returns {Node|null}
 */
function mono(value) {
  if (typeof value !== 'string' || value === '') {
    return null;
  }
  return el('span', { class: 'mono', text: value });
}
