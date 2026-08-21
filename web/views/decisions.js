/**
 * The decision explorer.
 *
 * Specification 15.3: "Redacted candidate/exclusion/score/failover trace by
 * request id", served by `GET /admin/v1/decisions/{request_id}` (specification
 * 16) and gated on `read_decision_traces`.
 *
 * This screen exists to answer one question an operator asks during an
 * incident — *why did this request not go where I expected?* — so three
 * decisions shape it:
 *
 * - **The request id lives in the address bar, not in a variable.** The lookup
 *   form navigates to `#/decisions?request_id=…` and `mount` fetches whatever
 *   the query names. That makes every trace a link the operator can paste into
 *   a ticket, makes Back and Forward work through a sequence of lookups, and
 *   leaves exactly one code path that fetches — the shell's loading state and
 *   its abort-on-navigate come for free.
 * - **A 404 is not "not found".** The trace cache is bounded and in memory
 *   (`hypellm-admin-api::decisions`): the oldest entries are dropped as new
 *   requests arrive, and a trace belonging to another tenant deliberately reads
 *   as absent rather than forbidden. Telling an operator "no such trace" would
 *   invite them to conclude the request never happened. The empty state says
 *   what the router can and cannot know.
 * - **Nothing is inferred.** Every value shown is a field the handler emitted.
 *   The trace carries no timestamp, no prompt, no upstream URL and no
 *   credential — so none appears here, and no column is filled with a plausible
 *   substitute.
 *
 * The screen is read-only. It has no mutation, hence no `If-Match` and nothing
 * for the optimistic-UI prohibition of specification 15.4 to bite on.
 */

import { ApiError } from '../api.js';
import { el, formatCount, formatDuration, pill, text } from '../components/dom.js';
import { banner, card, pageHeader, render, table } from '../components/table.js';
import { definitionList, emptyState, inlineField, panel } from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/decisions',
  title: 'Decision explorer',
  lede: 'Reconstruct one routing decision: ranked candidates, why every other target was excluded, and how each attempt ended.',
  permission: 'read_decision_traces',
};

/**
 * Plain-language readings of the exclusion reason codes.
 *
 * The codes are the stable contract (`hypellm-core/src/decision.rs`,
 * `ExclusionReason::code`); this map only glosses them. An unknown code is
 * therefore rendered as itself with no meaning attached rather than guessed at:
 * if the router grows a reason this console has not learned, the operator sees
 * the router's own word for it and nothing invented on top.
 */
const EXCLUSION_MEANINGS = {
  not_authorized_for_alias: 'The principal is not authorized for the requested alias.',
  operation_unsupported: 'The target does not serve this operation.',
  not_permitted_for_alias: 'The alias does not permit this target.',
  provider_disabled: 'The provider is disabled.',
  target_disabled: 'The target is disabled.',
  target_draining: 'The target is draining.',
  target_maintenance: 'The target is in a maintenance window.',
  target_quarantined: 'An operator quarantined the target.',
  circuit_open: "The target's circuit breaker is open.",
  unhealthy: "The target is too unhealthy for this request's failure policy.",
  modality_unsupported: 'The target does not accept a required input modality.',
  tools_unsupported: 'The target does not support tool calling.',
  structured_output_unsupported: 'The target does not support the requested response format.',
  streaming_unsupported: 'The target does not support streaming.',
  context_window_too_small: "The input exceeds the target's context window.",
  output_limit_too_small: "The requested output length exceeds the target's limit.",
  residency_mismatch: "The target's data region does not satisfy the residency requirement.",
  endpoint_not_allowlisted: 'The provider endpoint is not on the static destination allowlist.',
  credential_scope_mismatch: "The credential's scope does not cover this tenant or target.",
  cost_ceiling_exceeded: "The target's cost class exceeds the request's ceiling.",
  budget_exceeded: 'A budget or quota would have been exceeded.',
  capacity_exhausted: 'Concurrency or queue capacity was exhausted.',
  denied_by_policy: 'A higher-precedence binding denies this target.',
  not_pinned_target: 'A hard pin selected a different target.',
  local_required: 'The request required local inference and this target is remote.',
  family_failover_not_allowed: 'Selecting this target would have changed model family without permission.',
  already_attempted: "The target was already tried in this request's retry chain.",
  not_selected_by_any_binding: 'No preference or default made this target reachable.',
};

/**
 * Attempt outcome codes and their tone.
 *
 * Same rule as the exclusions: the code is always shown, the tone is a display
 * choice, and an outcome this console does not know still renders.
 * (`hypellm-core/src/decision.rs`, `AttemptOutcome::code`.)
 */
const OUTCOME_TONES = {
  success: 'ok',
  cancelled: 'warn',
  deadline_exceeded: 'warn',
  failed_before_acceptance: 'danger',
  failed_after_acceptance: 'danger',
  failed_after_output: 'danger',
};

/** The nine integer score terms of specification 6.3, in the order they are scored. */
const SCORE_TERMS = [
  { key: 'priority_rank', label: 'Priority rank' },
  { key: 'policy_weight', label: 'Policy weight' },
  { key: 'health', label: 'Health' },
  { key: 'latency', label: 'Latency' },
  { key: 'queue', label: 'Queue' },
  { key: 'cost', label: 'Cost' },
  { key: 'locality', label: 'Locality' },
  { key: 'affinity', label: 'Affinity' },
  { key: 'jitter', label: 'Jitter' },
];

/** @param {unknown} value @returns {object[]} */
function asRows(value) {
  return Array.isArray(value) ? value : [];
}

/**
 * An identifier, in the monospaced face.
 *
 * Target ids, request ids and digests are compared character by character
 * during an incident; a proportional face makes that harder than it needs to be.
 *
 * @param {unknown} value
 * @returns {Node}
 */
function mono(value) {
  if (value === null || value === undefined || value === '') {
    return text('—');
  }
  return el('span', { class: 'mono', text: String(value) });
}

/**
 * An integer score term.
 *
 * Scoring is integer fixed-point (specification 6.3), so the value is shown as
 * the integer it is — no rounding, no unit, no percentage that would imply a
 * scale the router does not use.
 *
 * @param {unknown} value
 * @returns {string}
 */
function integer(value) {
  return typeof value === 'number' && Number.isFinite(value) ? formatCount(value) : '—';
}

/**
 * Routing time, which the trace reports in microseconds.
 *
 * `formatDuration` takes milliseconds and would print sub-millisecond routing —
 * the normal case, given the p50 < 2 ms budget of specification 21 — as "0 ms".
 *
 * @param {unknown} micros
 * @returns {string}
 */
function formatMicros(micros) {
  if (typeof micros !== 'number' || !Number.isFinite(micros)) {
    return '—';
  }
  if (micros < 1000) {
    return `${formatCount(micros)} µs`;
  }
  return `${(micros / 1000).toFixed(2)} ms`;
}

/**
 * One line an operator can act on, for a failure this screen handles itself.
 *
 * The shell's error boundary would render a better message, but it renders it
 * over an empty container: a mistyped identifier would blank the screen the
 * operator needs in order to correct it. So a lookup failure is reported inline
 * and the lookup form stays where it is.
 *
 * @param {unknown} error
 * @returns {string}
 */
function describeFailure(error) {
  if (!(error instanceof ApiError)) {
    return error instanceof Error && error.message
      ? error.message
      : 'the lookup failed for an unknown reason';
  }
  const parts = [error.message];
  if (Array.isArray(error.details) && error.details.length > 0) {
    parts.push(error.details.map((detail) => String(detail)).join('; '));
  }
  if (error.requestId) {
    parts.push(`request ${error.requestId}`);
  }
  if (error.code && error.code !== 'unknown') {
    parts.push(`code ${error.code}`);
  }
  return parts.join(' — ');
}

/**
 * The header block: what was decided, under which policy, and how quickly.
 *
 * @param {object} trace
 * @returns {HTMLElement}
 */
function summaryPanel(trace) {
  const chosen = trace.chosen
    ? el('span', {}, [mono(trace.chosen), ' ', pill('Chosen', 'ok')])
    : el('span', {}, [text('none'), ' ', pill('No target selected', 'warn')]);

  return panel({
    title: 'Decision',
    note: 'Redacted by construction: a trace carries identifiers, reason codes and integers only — never a prompt, an upstream address or a credential.',
    content: definitionList([
      ['Request', mono(trace.request_id)],
      ['Chosen target', chosen],
      // A pin is the one input that can make a decision fail closed rather than
      // fall back, so it is stated even when it is false.
      ['Hard pin', trace.pinned ? pill('Pinned', 'warn') : text('no')],
      ['Policy digest', mono(trace.policy_digest)],
      ['Routing time', formatMicros(trace.routing_micros)],
      ['Summary', trace.explanation ? mono(trace.explanation) : null],
    ]),
  });
}

/**
 * Tone for a residency class.
 *
 * Warm is good, cold is neutral rather than bad: a cold target is a perfectly
 * ordinary candidate that the router would have started. Only an outright
 * refusal is a problem, and a refused target is in the exclusions table rather
 * than this one.
 *
 * @param {string} residency
 * @returns {string}
 */
function residencyTone(residency) {
  if (residency === 'resident' || residency === 'unmanaged') return 'good';
  if (residency === 'resident_busy' || residency === 'activating') return 'warn';
  return 'neutral';
}

/**
 * The ranked candidates and their score breakdown.
 *
 * One table rather than two: a second table repeating the same targets would
 * let an operator read the ordering from one and the terms from the other and
 * believe they had compared them. The row order *is* the ranking the router
 * produced — candidates arrive best first and are not re-sorted here, because a
 * console that re-sorts a ranked list is showing its own opinion of the order.
 *
 * @param {object} trace
 * @returns {HTMLElement}
 */
function candidatesPanel(trace) {
  // The position is attached to each row rather than looked up per cell: the
  // ranking is the point of this table, and deriving it from array identity
  // would quietly produce the wrong number if two entries ever compared equal.
  const candidates = asRows(trace.candidates).map((candidate, index) => ({
    ...candidate,
    order: index + 1,
  }));
  const columns = [
    { label: 'Order', numeric: true, cell: (row) => String(row.order) },
    {
      label: 'Target',
      cell: (row) =>
        row.target === trace.chosen
          ? el('span', {}, [mono(row.target), ' ', pill('Chosen', 'ok')])
          : mono(row.target),
    },
    { label: 'Pref. rank', numeric: true, cell: (row) => integer(row.rank) },
    // Without this column the affinity total is unexplainable: an operator can
    // see that one target scored higher and not that it was the only warm one.
    // `unmanaged` means the target has no deployment record, so the fleet had
    // nothing to say about it.
    {
      label: 'Residency',
      cell: (row) => (row.residency ? pill(row.residency, residencyTone(row.residency)) : '—'),
    },
    { label: 'Score', numeric: true, cell: (row) => integer(row.score) },
    ...SCORE_TERMS.map((term) => ({
      label: term.label,
      numeric: true,
      cell: (row) => integer(row.terms ? row.terms[term.key] : undefined),
    })),
  ];

  return panel({
    title: 'Ranked candidates',
    note: 'Best first, in the order the router produced. Penalties are negative and bonuses positive; a better priority rank dominates every other term by construction, so a lower-ranked target never wins on health or cost alone. Residency feeds the affinity term under a bounded slice, so a warm target outranks a cold one at equal rank — and a cold rank-0 target still outranks a warm rank-1 one.',
    content: table({
      caption:
        'Targets that passed every eligibility filter, with the integer score terms of specification 6.3.',
      columns,
      rows: candidates,
      empty:
        'No target survived eligibility filtering. Every configured target was excluded — the exclusions below give the reason for each.',
    }),
  });
}

/**
 * Why the other targets were not considered.
 *
 * @param {object} trace
 * @returns {HTMLElement}
 */
function exclusionsPanel(trace) {
  return panel({
    title: 'Exclusions',
    note: 'Security, residency and capability constraints are eligibility filters, never score penalties (specification 6.3) — an excluded target was not outranked, it was never a candidate.',
    content: table({
      caption: 'Targets removed before scoring, with the reason code the router recorded.',
      columns: [
        { label: 'Target', cell: (row) => mono(row.target) },
        { label: 'Reason', cell: (row) => mono(row.reason) },
        {
          label: 'Meaning',
          cell: (row) => EXCLUSION_MEANINGS[row.reason] || '—',
        },
      ],
      rows: asRows(trace.exclusions),
      empty: 'No target was excluded: every configured target was eligible for this request.',
    }),
  });
}

/**
 * The attempt chain.
 *
 * @param {object} trace
 * @returns {HTMLElement}
 */
function attemptsPanel(trace) {
  return panel({
    title: 'Attempts',
    note: 'In the order they were made. Failover is unrestricted before the upstream accepts, permitted after acceptance only for an idempotent request, and forbidden once semantic output has reached the client (specification 6.5).',
    content: table({
      caption: 'Each upstream attempt, how it ended, and what it cost in wall-clock time.',
      columns: [
        { label: '#', numeric: true, cell: (row) => integer(row.sequence) },
        { label: 'Target', cell: (row) => mono(row.target) },
        {
          label: 'Outcome',
          cell: (row) =>
            typeof row.outcome === 'string' && row.outcome !== ''
              ? pill(row.outcome, OUTCOME_TONES[row.outcome] || 'neutral')
              : mono(row.outcome),
        },
        { label: 'Error class', cell: (row) => mono(row.error_class) },
        {
          label: 'First byte',
          numeric: true,
          // Absent when nothing ever arrived — a connection failure or a
          // deadline that expired before the upstream answered.
          cell: (row) => formatDuration(row.first_byte_millis),
        },
        { label: 'Total', numeric: true, cell: (row) => formatDuration(row.total_millis) },
      ],
      rows: asRows(trace.attempts),
      empty: trace.chosen
        ? 'A target was chosen but the trace records no attempt against it.'
        : 'No attempt was made: no target was selected, so nothing was sent upstream.',
    }),
  });
}

/**
 * The empty state for a request id the cache no longer holds.
 *
 * Deliberately not phrased as "not found". The handler returns the same 404 for
 * a trace that has aged out, a request that was never routed, and a request
 * belonging to another tenant — the last of those is a deliberate refusal to
 * confirm existence — so the wording covers all three rather than asserting the
 * one the operator would most readily believe.
 *
 * @param {string} requestId
 * @returns {HTMLElement}
 */
function agedOut(requestId) {
  return card('No trace held', [
    emptyState(
      'The router holds no trace for this request id',
      'Traces live in a bounded in-memory cache and the oldest are dropped as new requests arrive, so a trace can age out within minutes on a busy router. A request that was never routed, and one belonging to another tenant, read the same way here.',
    ),
    el('p', { class: 'panel__note' }, ['Requested: ', mono(requestId)]),
  ]);
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container  Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {URLSearchParams} ctx.query
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @returns {Promise<void>}
 */
export async function mount(container, ctx) {
  const requested = (ctx.query.get('request_id') || '').trim();

  /** @type {object|null} */
  let trace = null;
  /** @type {boolean} */
  let missing = false;
  /** @type {unknown} */
  let failure = null;

  if (requested !== '') {
    try {
      // The identifier is encoded into the path rather than concatenated: it is
      // operator input, and a path segment is the one place in this application
      // where an unescaped value could reach a different endpoint than the one
      // intended. The router validates the grammar itself (`RequestId::parse`,
      // 32 hexadecimal characters) and stays the authority on it — restating
      // that rule here would give it a second copy to drift from, and the
      // 400 it returns is rendered below like any other refusal.
      const { data } = await ctx.api.get(`/decisions/${encodeURIComponent(requested)}`);
      trace = data;
    } catch (error) {
      if (error && error.name === 'AbortError') {
        // The operator navigated away; the shell owns what happens next.
        return;
      }
      if (error instanceof ApiError && error.status === 404) {
        missing = true;
      } else {
        failure = error;
      }
    }
  }

  // The live region is populated after it is connected: content present in an
  // `aria-live` element at the moment it is inserted is not reliably announced,
  // and the outcome of a lookup is exactly the thing a screen-reader user needs
  // to hear without hunting for it.
  const status = el('p', { class: 'panel__note', role: 'status', 'aria-live': 'polite' });

  /** @param {string} message */
  const announce = (message) => {
    queueMicrotask(() => {
      if (status.isConnected) {
        status.textContent = message;
      }
    });
  };

  const input = el('input', {
    type: 'text',
    class: 'mono',
    value: requested,
    autocomplete: 'off',
    autocapitalize: 'none',
    spellcheck: 'false',
    size: '34',
    'aria-describedby': 'decision-lookup-hint',
  });

  const submit = el('button', { type: 'submit', class: 'button' }, 'Look up');
  const clear = el('button', { type: 'button', class: 'button button--quiet' }, 'Clear');
  clear.addEventListener('click', () => {
    ctx.navigate('/decisions');
  });

  const form = el('form', { class: 'toolbar', 'aria-label': 'Look up a decision trace' }, [
    inlineField({ id: 'decision-request-id', label: 'Request id', control: input }),
    submit,
    requested === '' ? null : clear,
  ]);

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = input.value.trim();
    if (value === '') {
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      announce('Enter a request id to look up.');
      return;
    }
    input.removeAttribute('aria-invalid');
    // The query is the state. Navigating re-mounts this screen, which means one
    // fetch path, a shareable URL, and a working Back button — and submitting
    // the same id again is a deliberate refresh rather than a no-op.
    ctx.navigate(`/decisions?request_id=${encodeURIComponent(value)}`);
  });

  const lookup = panel({
    title: 'Look up a trace',
    content: [
      form,
      el('p', {
        class: 'field__hint',
        id: 'decision-lookup-hint',
        text: 'The request id from the X-Request-Id response header of the inference call, or from the corresponding log line.',
      }),
      status,
    ],
  });

  /** @type {Array<Node|null>} */
  let result;
  if (failure) {
    announce('The lookup failed.');
    result = [banner('error', describeFailure(failure))];
  } else if (missing) {
    announce('No trace is held for that request id.');
    result = [agedOut(requested)];
  } else if (trace) {
    const candidates = asRows(trace.candidates).length;
    const exclusions = asRows(trace.exclusions).length;
    announce(
      `Trace loaded: ${formatCount(candidates)} candidate(s), ${formatCount(exclusions)} exclusion(s), chosen ${trace.chosen || 'none'}.`,
    );
    result = [
      summaryPanel(trace),
      candidatesPanel(trace),
      exclusionsPanel(trace),
      attemptsPanel(trace),
    ];
  } else {
    result = [
      card(
        'No trace requested',
        emptyState(
          'Enter a request id to reconstruct its routing decision',
          'Nothing is listed here: the trace cache is addressed by request id, and this console does not ask the router to enumerate the requests a tenant has made.',
        ),
      ),
    ];
  }

  render(container, [pageHeader(meta.title, meta.lede), lookup, ...result]);

  // Focus lands on the field only when there is nothing to read yet. After a
  // successful lookup the operator wants the trace, and the shell has already
  // moved focus to the top of the main region.
  if (requested === '' && !failure) {
    queueMicrotask(() => {
      if (input.isConnected) {
        input.focus();
      }
    });
  }
}
