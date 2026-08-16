/**
 * The Overview screen.
 *
 * Specification 15.3: "Request rate, latency, errors, active streams, capacity,
 * target status, configuration version."
 *
 * The management API answers four of those seven honestly and does not answer
 * the other three at all, and that gap is the main design problem this file
 * solves. `GET /admin/v1/overview` returns fleet counts and the active
 * configuration identity; `GET /admin/v1/targets` returns, per target, the
 * breaker state, the admin state, the operator quarantine flag, and three
 * cumulative counters (`in_flight`, `total_requests`, `total_failures`). None
 * of that is a rate, none of it is a latency distribution, and no endpoint
 * reports an admission limit, so nothing here can be labelled "requests per
 * second" or "p99" without inventing it. Rates and latencies live in the
 * router's Prometheus exposition, which is a different surface with a different
 * audience; this screen names that instead of approximating it. An operator has
 * to be able to trust that what the console shows is what the router said —
 * a plausible-looking number nobody measured is worse than a blank.
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

import { append, el, formatCount, formatTime, pill, replace, text } from '../components/dom.js';
import {
  actionButton,
  definitionList,
  emptyState,
  inlineField,
  notAvailable,
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
  lede: 'Fleet health, target status, and the active configuration, as the router reports them now.',
  // `GET /admin/v1/overview` and `GET /admin/v1/targets` both require
  // `Permission::ReadSummary` (crates/hypellm-admin-api/src/handlers.rs), which
  // every role holds. A principal who cannot read the summary cannot use this
  // screen at all, so the nav hides it rather than showing two failing panels.
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
 * Read both endpoints.
 *
 * Sequentially, not concurrently: `Api.request` aborts whatever is in flight
 * before starting a non-shared request, so two overlapping `get` calls would
 * cancel each other. Doing them in order keeps both cancellable by navigation,
 * which matters more here than the one round trip it costs.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<{overview: object, targets: object[], truncated: boolean, readAt: number}>}
 */
async function load(api) {
  const overview = await api.get('/overview');
  const targets = await api.get(`/targets?limit=${TARGET_PAGE_LIMIT}`);
  const envelope = targets.data || {};
  return {
    overview: overview.data || {},
    targets: Array.isArray(envelope.data) ? envelope.data : [],
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
  const { overview, targets, truncated } = snapshot;
  const live = summarize(targets);

  replace(body, [
    grid(tiles(overview, live, targets.length, truncated)),
    panel({
      title: 'Rate, latency, and capacity',
      content: notAvailable(
        'Live rate, latency, and capacity reporting',
        'The management API reports cumulative counters per target, not rates, latency distributions, or admission limits. The router publishes hypellm_requests_total, hypellm_router_overhead_milliseconds, and hypellm_upstream_latency_milliseconds at GET /metrics on the management listener; this console reads only /admin/v1 JSON and does not scrape it.',
      ),
    }),
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
 * @param {number} listed
 * @param {boolean} truncated
 * @returns {HTMLElement[]}
 */
function tiles(overview, live, listed, truncated) {
  // "Across the targets this screen read" rather than "across the fleet": when
  // the list is truncated the sums are a subset, and saying which subset is the
  // difference between an incomplete figure and a wrong one.
  const scope = truncated
    ? `summed across the first ${formatCount(listed)} targets`
    : `summed across ${formatCount(listed)} targets`;
  const partial = live.complete ? '' : ' The router omitted a counter on at least one target.';

  return [
    stat(
      'Targets healthy',
      healthText(overview),
      degradedNote(overview),
    ),
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
