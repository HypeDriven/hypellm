/**
 * The usage screen.
 *
 * Specification 15.3: "Per **authorized scope**, model/alias, operation,
 * status, cost class; **no prompt bodies by default**." The router's
 * `GET /admin/v1/usage` answers with exactly those dimensions and nothing
 * else — there is no prompt, no completion, and no per-request record to
 * render, by design (`crates/hypellm-admin-api/src/usage.rs`: the aggregate
 * counts tuples, it does not log requests).
 *
 * Four decisions in this file are worth explaining:
 *
 * - **The authorized scope is stated, never inferred.** The endpoint returns
 *   `scope: "tenant" | "principal"`, decided by whether the caller holds
 *   `read_tenant_usage`. A principal-scoped total that looked like a
 *   tenant-scoped one would be read as "the tenant spent this much", which is
 *   a wrong answer rather than a partial one, so the scope the router applied
 *   is rendered at the top of the screen and repeated in the table caption.
 * - **Provider-reported and router-estimated numbers stay distinguishable.**
 *   Specification 14 requires it, and the handler carries it through as
 *   `estimated_requests`. An estimate that reads as a bill is the failure this
 *   column exists to prevent, so it is shown per row and as a share of the
 *   total, never folded silently into the counts.
 * - **A truncated breakdown says so.** Past the aggregate's bounded series
 *   limit, rows fold into an unattributed remainder (`aggregated: true`,
 *   `principal: null`) and the envelope sets `truncated`. The totals remain
 *   correct while the breakdown stops being complete; the screen distinguishes
 *   the two, because "incomplete" and "wrong" call for different actions.
 * - **Filtering and regrouping happen here, on the rows the router returned.**
 *   The endpoint takes no query parameters, so client-side filtering is the
 *   only kind available. That makes it essential to be explicit about what the
 *   figures above the table are the sum of: the router's own scope total when
 *   nothing is filtered, and the visible subset when something is — labelled
 *   either way rather than left for the operator to guess.
 *
 * The screen is read-only: usage is a counter the data plane writes, and the
 * management API exposes no mutation for it. Nothing here needs `If-Match`,
 * a confirmation, or the non-optimistic mutation discipline of specification
 * 15.4 — the one write-shaped control, Refresh, re-reads and repaints from the
 * response rather than adjusting anything locally.
 */

import { el, formatCount, formatTime, pill, text } from '../components/dom.js';
import { banner, grid, pageHeader, render, stat, table } from '../components/table.js';
import {
  actionButton,
  definitionList,
  emptyState,
  inlineField,
  panel,
  toolbar,
} from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/usage',
  title: 'Usage',
  lede: 'Request and token totals by principal, alias, target, operation, status, and cost class. No prompt or completion content is recorded.',
  // Either permission grants the screen; which one the session holds decides
  // whether the router answers with the whole tenant or only with this
  // principal (`list_usage` in `hypellm-admin-api::handlers`).
  permission: ['read_tenant_usage', 'read_own_usage'],
};

/**
 * How many rows are drawn before the operator asks for the rest.
 *
 * The aggregate is bounded at a few thousand series, so "all of them" is
 * finite — but a four-thousand-row table is not something anyone reads, and
 * building it costs a visible pause. The top slice by request count is the
 * answer to the question the screen is usually opened with.
 */
const DEFAULT_ROW_LIMIT = 200;

/** The dimensions a usage row is broken down by, in the handler's own order. */
const DIMENSIONS = [
  { key: 'principal', label: 'Principal', identifier: true },
  { key: 'alias', label: 'Alias', identifier: true },
  { key: 'target', label: 'Target', identifier: true },
  { key: 'operation', label: 'Operation' },
  { key: 'status', label: 'Status' },
  { key: 'cost_class', label: 'Cost class', numeric: true },
];

/** The counters, in the order they are worth reading. */
const MEASURES = [
  { key: 'requests', label: 'Requests' },
  { key: 'input_tokens', label: 'Input tokens' },
  { key: 'output_tokens', label: 'Output tokens' },
  { key: 'cached_input_tokens', label: 'Cached input' },
  { key: 'reasoning_tokens', label: 'Reasoning' },
  { key: 'estimated_requests', label: 'Estimated' },
];

/** The ways the returned rows can be re-aggregated for reading. */
const BREAKDOWNS = [
  { value: 'full', label: 'Every dimension', dimensions: DIMENSIONS.map((d) => d.key) },
  { value: 'principal', label: 'Principal', dimensions: ['principal'] },
  { value: 'alias', label: 'Alias', dimensions: ['alias'] },
  { value: 'target', label: 'Target', dimensions: ['target'] },
  { value: 'operation', label: 'Operation', dimensions: ['operation'] },
  { value: 'status', label: 'Status', dimensions: ['status'] },
  { value: 'cost_class', label: 'Cost class', dimensions: ['cost_class'] },
  { value: 'alias-status', label: 'Alias and status', dimensions: ['alias', 'status'] },
  {
    value: 'principal-alias',
    label: 'Principal and alias',
    dimensions: ['principal', 'alias'],
  },
];

/**
 * Tone for an outcome class.
 *
 * The vocabulary is closed (`UsageStatus` in `hypellm-admin-api::usage`); an
 * unknown value is rendered neutrally rather than guessed at, so a status added
 * on the router side shows up as itself instead of as a colour that may be a
 * lie.
 *
 * @param {string} status
 * @returns {'ok'|'warn'|'danger'|'neutral'}
 */
function statusTone(status) {
  switch (status) {
    case 'success':
      return 'ok';
    case 'throttled':
    case 'client_error':
      return 'warn';
    case 'server_error':
      return 'danger';
    default:
      return 'neutral';
  }
}

/**
 * A counter as a number, or `null` when the router sent something else.
 *
 * The counters are `u64` on the router side. Anything that is not a finite
 * number here is a shape mismatch, and rendering it as a zero would invent a
 * fact; `null` becomes an em dash downstream.
 *
 * @param {unknown} value
 * @returns {number|null}
 */
function counter(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** @param {unknown} value @returns {Node} */
function countCell(value) {
  const number = counter(value);
  return text(number === null ? '—' : formatCount(number));
}

/** A zeroed counter set. @returns {object} */
function zeroTotals() {
  const totals = {};
  for (const measure of MEASURES) {
    totals[measure.key] = 0;
  }
  return totals;
}

/**
 * Add one row's counters into an accumulator.
 *
 * @param {object} totals
 * @param {object} row
 */
function addTotals(totals, row) {
  for (const measure of MEASURES) {
    totals[measure.key] += counter(row[measure.key]) || 0;
  }
}

/**
 * Re-aggregate the returned rows over a chosen set of dimensions.
 *
 * The router already returns the finest breakdown it holds; grouping here only
 * ever sums rows together, so no total can change as the operator switches
 * view. Ordering is by request count and then by the group key, which makes it
 * deterministic: the same response always draws the same table, and two
 * operators comparing screens are comparing the same thing.
 *
 * @param {object[]} rows
 * @param {string[]} dimensions Keys from [`DIMENSIONS`].
 * @returns {Array<{values: object, totals: object, aggregated: boolean, sort: string}>}
 */
function groupRows(rows, dimensions) {
  const groups = new Map();
  for (const row of rows) {
    const values = {};
    for (const key of dimensions) {
      const value = row[key];
      values[key] = value === undefined ? null : value;
    }
    // A NUL separator cannot occur inside an identifier the router accepts, so
    // two different tuples cannot collide into one row.
    const id = dimensions.map((key) => String(values[key])).join('\u0000');
    let group = groups.get(id);
    if (!group) {
      group = { values, totals: zeroTotals(), aggregated: false, sort: id };
      groups.set(id, group);
    }
    addTotals(group.totals, row);
    // Specification 15.3 honesty: a group that swallowed any folded remainder
    // is no longer a complete attribution, and it has to keep saying so.
    group.aggregated = group.aggregated || row.aggregated === true;
  }

  return [...groups.values()].sort((left, right) => {
    const byRequests = right.totals.requests - left.totals.requests;
    return byRequests !== 0 ? byRequests : left.sort.localeCompare(right.sort);
  });
}

/**
 * The distinct values of one dimension, for a filter control.
 *
 * Built from the response rather than from a copy of the router's vocabulary:
 * an option that matches nothing is a dead end, and a vocabulary that drifts
 * apart from the router's is a screen that silently hides rows.
 *
 * @param {object[]} rows
 * @param {string} key
 * @returns {string[]}
 */
function distinctValues(rows, key) {
  const seen = new Set();
  for (const row of rows) {
    const value = row[key];
    if (value !== null && value !== undefined) {
      seen.add(String(value));
    }
  }
  return [...seen].sort();
}

/**
 * Refill a `<select>` in place, keeping the element and its label.
 *
 * Replacing the control itself would move focus and break the `<label for>`
 * association that was set up once; replacing only the options keeps the
 * keyboard where the operator left it across a refresh.
 *
 * @param {HTMLSelectElement} select
 * @param {string[]} values
 * @param {string} allLabel
 */
function fillOptions(select, values, allLabel) {
  const previous = select.value;
  render(select, [
    el('option', { value: '' }, allLabel),
    ...values.map((value) => el('option', { value }, value)),
  ]);
  // A value that no longer occurs would filter every row away while looking
  // like a live selection; fall back to "all" instead.
  select.value = values.includes(previous) ? previous : '';
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container  Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @returns {Promise<void>}
 */
export async function mount(container, ctx) {
  // Awaited before anything is drawn, so the shell's "Loading…" line and
  // `aria-busy` cover the wait, and a failure reaches the shell error boundary
  // with the router's own message and request id rather than a half-built page.
  const first = await ctx.api.get('/usage');

  const state = {
    /** @type {object} The `/admin/v1/usage` envelope. */
    envelope: first.data || {},
    /** When the envelope was received, for an honest "as of" line. */
    fetchedAt: Date.now(),
    /** @type {string} A [`BREAKDOWNS`] value. */
    breakdown: 'full',
    /** @type {string} Operation filter, or `''` for all. */
    operation: '',
    /** @type {string} Status filter, or `''` for all. */
    status: '',
    /** @type {string} Substring match over principal, alias, and target. */
    search: '',
    /** @type {number} How many grouped rows to draw. */
    limit: DEFAULT_ROW_LIMIT,
  };

  // Controls are built once and kept; only the results below them are
  // repainted, so filtering never steals focus from the control being used.
  const breakdownSelect = el(
    'select',
    {},
    BREAKDOWNS.map((option) => el('option', { value: option.value }, option.label)),
  );
  const operationSelect = el('select', {});
  const statusSelect = el('select', {});
  const searchInput = el('input', {
    type: 'search',
    autocomplete: 'off',
    spellcheck: 'false',
    placeholder: 'principal, alias, or target',
  });

  const scopeHost = el('div');
  const filtersHost = el('div');
  const resultsHost = el('div');
  // Refreshing replaces content the operator may not be looking at, so the
  // outcome is also announced: `role="status"` with a polite live region is
  // read without interrupting, which is the right weight for "it worked".
  const statusLine = el('p', {
    class: 'panel__note',
    role: 'status',
    'aria-live': 'polite',
  });

  /** @returns {object[]} The rows the current filters admit. */
  function filteredRows() {
    const rows = Array.isArray(state.envelope.data) ? state.envelope.data : [];
    const needle = state.search.trim().toLowerCase();
    return rows.filter((row) => {
      if (state.operation && String(row.operation) !== state.operation) {
        return false;
      }
      if (state.status && String(row.status) !== state.status) {
        return false;
      }
      if (!needle) {
        return true;
      }
      return DIMENSIONS.filter((dimension) => dimension.identifier).some((dimension) => {
        const value = row[dimension.key];
        return typeof value === 'string' && value.toLowerCase().includes(needle);
      });
    });
  }

  /** @returns {boolean} Whether anything is being filtered out. */
  function filtering() {
    return state.operation !== '' || state.status !== '' || state.search.trim() !== '';
  }

  /**
   * The scope statement: what these numbers are of, and as of when.
   *
   * @returns {Node}
   */
  function scopeBlock() {
    const envelope = state.envelope;
    const tenantWide = envelope.scope === 'tenant';
    const rows = Array.isArray(envelope.data) ? envelope.data : [];

    const entries = [
      [
        'Scope',
        el('span', {}, [
          pill(tenantWide ? 'Whole tenant' : 'This principal only', tenantWide ? 'ok' : 'warn'),
          text(
            tenantWide
              ? ' Every principal in the tenant.'
              : ' Only your own requests. The tenant-wide view needs read_tenant_usage.',
          ),
        ]),
      ],
      ['Tenant', envelope.tenant ? el('span', { class: 'mono', text: envelope.tenant }) : null],
      ['Counting since', formatTime(envelope.since)],
      ['Read at', formatTime(state.fetchedAt)],
      ['Distinct rows', formatCount(rows.length)],
    ];

    const blocks = [definitionList(entries)];

    if (envelope.truncated === true) {
      // Bounded aggregation, reported: the totals are still right, the
      // breakdown is not complete. Conflating the two would send an operator
      // hunting for spend that is present but unattributed.
      blocks.push(
        banner(
          'warn',
          'The breakdown is truncated. The router reached its bounded limit on distinct usage rows and folded the rest into an unattributed remainder, marked Folded below. The totals remain correct; the per-principal and per-alias attribution is incomplete.',
        ),
      );
    }

    return el('div', { class: 'view__body' }, blocks);
  }

  /**
   * The totals tiles.
   *
   * When nothing is filtered these are the router's own `totals` — the
   * authoritative sum for the authorized scope, including any folded
   * remainder. When something is filtered they are the sum of the visible rows
   * and are labelled as such, because a subtotal presented as a total is the
   * one mistake this screen must not make.
   *
   * @param {object[]} rows The rows currently admitted by the filters.
   * @returns {Node}
   */
  function totalsBlock(rows) {
    const narrowed = filtering();
    let totals;
    if (narrowed) {
      totals = zeroTotals();
      for (const row of rows) {
        addTotals(totals, row);
      }
    } else {
      totals = state.envelope.totals && typeof state.envelope.totals === 'object'
        ? state.envelope.totals
        : zeroTotals();
    }

    const requests = counter(totals.requests) || 0;
    const estimated = counter(totals.estimated_requests) || 0;
    const inputTokens = counter(totals.input_tokens) || 0;
    const outputTokens = counter(totals.output_tokens) || 0;
    const share = requests > 0 ? Math.round((estimated / requests) * 100) : 0;

    const tiles = [
      stat('Requests', formatCount(requests), narrowed ? 'matching rows' : 'authorized scope'),
      stat('Input tokens', formatCount(inputTokens)),
      stat('Output tokens', formatCount(outputTokens)),
      stat('Total tokens', formatCount(inputTokens + outputTokens), 'input plus output'),
      stat(
        'Cached input',
        formatCount(counter(totals.cached_input_tokens) || 0),
        'served from a provider prompt cache',
      ),
      stat('Reasoning tokens', formatCount(counter(totals.reasoning_tokens) || 0)),
      // Specification 14: an estimate must never be readable as a bill.
      stat(
        'Estimated requests',
        formatCount(estimated),
        `${share}% router-estimated, not provider-reported`,
      ),
    ];

    const note = el('p', {
      class: 'panel__note',
      text: narrowed
        ? `Sum of the ${formatCount(rows.length)} row(s) matching the current filters, not the whole scope. Clear the filters for the router's own total.`
        : 'As reported by the router for the whole authorized scope, including any folded remainder.',
    });

    return el('div', { class: 'view__body' }, [note, grid(tiles)]);
  }

  /**
   * The breakdown table.
   *
   * @param {object[]} rows The rows currently admitted by the filters.
   * @returns {Node}
   */
  function tableBlock(rows) {
    const breakdown =
      BREAKDOWNS.find((option) => option.value === state.breakdown) || BREAKDOWNS[0];
    const groups = groupRows(rows, breakdown.dimensions);
    const shown = groups.slice(0, state.limit);
    const anyFolded = shown.some((group) => group.aggregated);

    const columns = breakdown.dimensions.map((key) => {
      const dimension = DIMENSIONS.find((candidate) => candidate.key === key) || {
        key,
        label: key,
      };
      return {
        label: dimension.label,
        numeric: dimension.numeric === true,
        cell: (group) => {
          const value = group.values[key];
          if (value === null || value === undefined) {
            return text('—');
          }
          if (key === 'status') {
            return pill(String(value), statusTone(String(value)));
          }
          if (dimension.identifier) {
            return el('span', { class: 'mono', text: String(value) });
          }
          return text(String(value));
        },
      };
    });

    if (anyFolded) {
      // Only present when it has something to say. A column of em dashes would
      // be noise on the deployments that never reach the series bound.
      columns.push({
        label: 'Attribution',
        cell: (group) =>
          group.aggregated
            ? el('span', { title: 'Includes rows folded into the unattributed remainder' }, [
                pill('Folded', 'warn'),
              ])
            : text('—'),
      });
    }

    for (const measure of MEASURES) {
      columns.push({
        label: measure.label,
        numeric: true,
        cell: (group) => countCell(group.totals[measure.key]),
      });
    }

    const scopeWord = state.envelope.scope === 'tenant' ? 'the whole tenant' : 'this principal';
    const caption = filtering()
      ? `${formatCount(shown.length)} of ${formatCount(groups.length)} row(s) after filtering, grouped by ${breakdown.label.toLowerCase()}, for ${scopeWord}.`
      : `${formatCount(shown.length)} of ${formatCount(groups.length)} row(s), grouped by ${breakdown.label.toLowerCase()}, for ${scopeWord}.`;

    const blocks = [
      table({
        caption,
        columns,
        rows: shown,
        empty: filtering()
          ? 'No usage rows match the current filters. Widen or clear them to see the rest.'
          : 'The router returned no usage rows for this scope.',
      }),
    ];

    if (groups.length > shown.length) {
      const remaining = groups.length - shown.length;
      blocks.push(
        el('div', { class: 'button-row pager' }, [
          actionButton(
            `Show the remaining ${formatCount(remaining)} row(s)`,
            () => {
              state.limit = Number.MAX_SAFE_INTEGER;
              paint();
            },
            { tone: 'quiet' },
          ),
        ]),
      );
      blocks.push(
        el('p', {
          class: 'panel__note',
          text: `Rows are ordered by request count; the ${formatCount(remaining)} not drawn are already included in the totals above.`,
        }),
      );
    }

    return el('div', { class: 'view__body' }, blocks);
  }

  /**
   * Show or hide the filter row without ever rebuilding it.
   *
   * Attaching and detaching only on a real change is deliberate: repainting on
   * every keystroke would otherwise remove the control being typed into and
   * take the caret with it. The `hidden` attribute is not used because
   * `.toolbar` sets `display: flex`, which would win over it.
   *
   * @param {boolean} present
   */
  function setFiltersPresent(present) {
    if (present && !filters.isConnected) {
      filtersHost.appendChild(filters);
    } else if (!present && filters.isConnected) {
      filters.remove();
    }
  }

  /**
   * Repaint the scope statement.
   *
   * Separate from [`paint`] because it depends on the response alone: the scope
   * and the time it was read do not change when a filter does, and redrawing
   * them on every keystroke would make a fixed fact look like a moving one.
   */
  function paintScope() {
    render(scopeHost, scopeBlock());
  }

  /**
   * Repaint everything that depends on the response or the filters.
   *
   * One layout serves both the populated and the empty case, so that a refresh
   * which turns one into the other repaints in place. A screen whose "no usage
   * yet" state was a different, terminal branch would keep showing it after the
   * first request had been served.
   */
  function paint() {
    const all = Array.isArray(state.envelope.data) ? state.envelope.data : [];

    if (all.length === 0) {
      // Empty is a real answer here, and it has a reason: the aggregate has
      // been counting since a known moment and has seen nothing in this scope.
      // Saying so beats an empty table, which reads as a screen that failed to
      // load. There is nothing to filter, so the controls go with it.
      setFiltersPresent(false);
      render(
        resultsHost,
        emptyState(
          'No usage has been recorded in this scope',
          `The router has been aggregating since ${formatTime(state.envelope.since)} and has counted no requests it can attribute to ${
            state.envelope.scope === 'tenant' ? 'this tenant' : 'you'
          }. Rows appear here once the data plane has served a request.`,
        ),
      );
      return;
    }

    setFiltersPresent(true);
    const rows = filteredRows();
    render(resultsHost, [totalsBlock(rows), tableBlock(rows)]);
  }

  /** Rebuild the filter vocabularies from the response now held. */
  function syncFilters() {
    const rows = Array.isArray(state.envelope.data) ? state.envelope.data : [];
    fillOptions(operationSelect, distinctValues(rows, 'operation'), 'All operations');
    fillOptions(statusSelect, distinctValues(rows, 'status'), 'All statuses');
    state.operation = operationSelect.value;
    state.status = statusSelect.value;
  }

  breakdownSelect.addEventListener('change', () => {
    state.breakdown = breakdownSelect.value;
    // A new grouping is a new set of rows; the previous "show everything" is
    // not a statement about this one.
    state.limit = DEFAULT_ROW_LIMIT;
    paint();
  });
  operationSelect.addEventListener('change', () => {
    state.operation = operationSelect.value;
    paint();
  });
  statusSelect.addEventListener('change', () => {
    state.status = statusSelect.value;
    paint();
  });
  searchInput.addEventListener('input', () => {
    state.search = searchInput.value;
    paint();
  });

  const refresh = actionButton(
    'Refresh',
    async () => {
      statusLine.textContent = '';
      try {
        const next = await ctx.api.get('/usage');
        state.envelope = next.data || {};
        state.fetchedAt = Date.now();
        syncFilters();
        paintScope();
        paint();
        statusLine.textContent = `Updated at ${formatTime(state.fetchedAt)}.`;
      } catch (error) {
        if (error && error.name === 'AbortError') {
          // Navigation cancelled the read; the screen is already gone.
          return;
        }
        // The figures on screen are still the ones the router last gave, and
        // they are still labelled with the time they were read. Say that the
        // refresh failed, then let the shell name the error and its request id.
        statusLine.textContent = `Refresh failed. The figures shown were read at ${formatTime(state.fetchedAt)} and have not changed.`;
        throw error;
      }
    },
    { busyLabel: 'Refreshing…' },
  );

  const filters = toolbar(
    [
      inlineField({ id: 'usage-breakdown', label: 'Break down by', control: breakdownSelect }),
      inlineField({ id: 'usage-operation', label: 'Operation', control: operationSelect }),
      inlineField({ id: 'usage-status', label: 'Status', control: statusSelect }),
      inlineField({ id: 'usage-search', label: 'Search', control: searchInput }),
    ],
    { label: 'Usage filters' },
  );

  syncFilters();

  render(container, [
    pageHeader(meta.title, meta.lede),
    panel({
      title: 'Authorized scope',
      note: 'What these figures cover, and when they were read.',
      actions: [refresh],
      content: [scopeHost, statusLine],
    }),
    panel({
      title: 'Breakdown',
      note: 'Grouping and filtering are applied here, to the rows the router returned; the usage endpoint takes no filter parameters, so nothing on this screen changes what was asked for.',
      content: [filtersHost, resultsHost],
    }),
  ]);

  paintScope();
  paint();
}
