/**
 * The Activations screen.
 *
 * Specification-extension 17: "a timeline of starts and stops, each with its
 * reason code and the decision that caused it."
 *
 * This is the "why was this evicted" view, and its whole value is the last
 * column. A list of activations without causes tells an operator that models
 * moved; the decision identifier tells them *which request* moved them, and
 * links to the trace that made the choice.
 *
 * Two things are deliberately absent:
 *
 * - **No prompt, no tenant, no principal.** An activation record carries a
 *   decision identifier and nothing that identifies who sent the request. The
 *   decision explorer is where a caller is looked up, behind its own permission.
 * - **No agent-authored text.** `detail` is one of a fixed set of router-written
 *   sentences. The agent is trusted to actuate, not to write strings that reach
 *   this table.
 */

import { ApiError } from '../api.js';
import { el, formatDuration, pill } from '../components/dom.js';
import { actionButton, emptyState, notAvailable, panel, toolbar } from '../components/layout.js';
import { pageHeader, render, table } from '../components/table.js';

/** Screen metadata, read by the shell to build navigation. */
export const meta = {
  path: '/activations',
  title: 'Activations',
  permission: 'read_fleet',
  lede:
    'Every deployment the router has started or stopped, what it displaced, how long it took, and the decision that caused it.',
};

/**
 * Tone for an activation outcome.
 *
 * @param {string|null} outcome
 * @returns {string}
 */
function outcomeTone(outcome) {
  switch (outcome) {
    case 'succeeded':
      return 'good';
    case 'rolled_back':
      return 'warn';
    case 'failed':
    case 'quarantined':
      return 'bad';
    default:
      return 'neutral';
  }
}

/**
 * Read the activation history, or report that this router has no fleet.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<object|null>}
 */
async function load(api) {
  try {
    return await api.get('/admin/v1/fleet/activations');
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      return null;
    }
    throw error;
  }
}

/**
 * Render the screen.
 *
 * @param {HTMLElement} container
 * @param {object} ctx
 * @returns {Promise<() => void>}
 */
export async function mount(container, ctx) {
  let stopped = false;
  let history = await load(ctx.api);

  if (!history) {
    render(container, [
      pageHeader(meta.title, meta.lede),
      notAvailable(
        'Activation history',
        'This router has no fleet configured, so it has never started or stopped a ' +
          'deployment.',
      ),
    ]);
    return () => {
      stopped = true;
    };
  }

  const body = el('div');
  const refresh = actionButton('Refresh', () => reload(), {
    tone: 'quiet',
    busyLabel: 'Reading…',
  });

  render(container, [
    pageHeader(meta.title, meta.lede),
    toolbar([el('div', { class: 'panel__actions' }, refresh)], { label: 'Activation controls' }),
    body,
  ]);
  paint();

  async function reload() {
    const next = await load(ctx.api);
    if (stopped || !next) return;
    history = next;
    paint();
  }

  function paint() {
    const items = history.items || [];
    if (items.length === 0) {
      render(body, [
        emptyState(
          'Nothing has been started or stopped yet.',
          'A healthy fleet under steady demand is one where this table stays short: each ' +
            'activation is amortised across every request that waited for it.',
        ),
      ]);
      return;
    }

    const rows = items.map((item) => [
      item.deployment,
      item.host,
      pill(item.outcome || item.state, outcomeTone(item.outcome)),
      formatDuration(item.duration_ms),
      (item.evicted || []).join(', ') || '—',
      item.detail || '—',
      item.decision
        ? el('a', { href: `#/decisions?id=${encodeURIComponent(item.decision)}`, text: item.decision.slice(0, 12) })
        : 'operator',
    ]);

    render(body, [
      panel({
        title: 'Recent activations',
        note:
          'Newest first, bounded to the most recent few hundred. Anything older is in the ' +
          'audit log, which is where a full history lives.',
        content: table({
          caption: 'Activation history',
          columns: ['Deployment', 'Host', 'Outcome', 'Took', 'Displaced', 'Detail', 'Cause'],
          rows,
          empty: 'Nothing to show.',
        }),
      }),
    ]);
  }

  return () => {
    stopped = true;
  };
}
