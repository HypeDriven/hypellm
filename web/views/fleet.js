/**
 * The Fleet screen.
 *
 * Specification-extension 17: "host cards with memory bars, resident sets,
 * activation budget remaining, observation age, drift warnings."
 *
 * Three decisions shape what is on this screen, and each is about not misleading
 * the person reading it during an incident.
 *
 * - **Observation age is first, not last.** Belief gates every fleet decision:
 *   past `observation_max_age_ms` the router refuses to plan at all. A screen
 *   that showed a tidy list of resident models without saying how old the
 *   information was would be answering a different question than the one an
 *   operator is asking.
 * - **A router that has never reached its agent shows "never", not "0 s".** The
 *   endpoint returns `null` for exactly that case rather than zero, and this
 *   renders it as an explicit unknown. A dashboard that reports an unreachable
 *   agent as perfectly fresh is worse than one that reports nothing.
 * - **Nothing here is optimistic.** Pinning a deployment repaints only after the
 *   router has answered and the view has been read back — specification 15.4
 *   permits optimistic UI for reversible view state and forbids it for
 *   security-sensitive mutations, and stopping a production model is not
 *   reversible view state.
 *
 * The activation controls are gated on `fleet_activate`, which no viewer holds;
 * the router enforces the same permission, so a control this screen hides is
 * also a request the router refuses.
 */

import { ApiError } from '../api.js';
import { el, formatCount, formatDuration, pill } from '../components/dom.js';
import {
  actionButton,
  confirmPrompt,
  emptyState,
  notAvailable,
  panel,
  toolbar,
} from '../components/layout.js';
import { card, grid, pageHeader, render, stat, table } from '../components/table.js';

/** Screen metadata, read by the shell to build navigation. */
export const meta = {
  path: '/fleet',
  title: 'Fleet',
  permission: 'read_fleet',
  lede:
    'The machines behind the aliases: what is resident on each accelerator, how much memory it holds, what the router may still start this hour, and how old that information is.',
};

/** Lifecycle states that mean the deployment is holding memory. */
const HOLDS_MEMORY = new Set(['draining', 'stopping', 'starting', 'probing', 'ready']);

/**
 * Tone for a deployment's lifecycle state.
 *
 * @param {string} state
 * @returns {string}
 */
function stateTone(state) {
  if (state === 'ready') return 'good';
  if (state === 'failed') return 'bad';
  if (HOLDS_MEMORY.has(state)) return 'warn';
  return 'neutral';
}

/**
 * Render bytes as a short human figure.
 *
 * Deliberately coarse: an operator comparing 64 GiB against 114 GiB does not
 * need the bytes, and a long number in a table cell is harder to compare at a
 * glance than a short one.
 *
 * @param {number} bytes
 * @returns {string}
 */
function bytes(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return '0';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let n = value;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit += 1;
  }
  return `${n >= 10 ? Math.round(n) : n.toFixed(1)} ${units[unit]}`;
}

/**
 * A memory bar for one pool.
 *
 * A `<meter>` rather than a styled div: it carries the value, the maximum, and
 * an accessible label without any script, and a screen reader announces the
 * numbers rather than "graphic".
 *
 * @param {number} used
 * @param {number} capacity
 * @returns {HTMLElement}
 */
function memoryBar(used, capacity) {
  const meter = el('meter', {
    class: 'meter',
    min: '0',
    max: String(Math.max(capacity, 1)),
    value: String(Math.min(used, capacity)),
    'aria-label': `${bytes(used)} of ${bytes(capacity)} committed`,
  });
  return el('div', { class: 'meter-row' }, [
    meter,
    el('span', { class: 'meter-row__label', text: `${bytes(used)} / ${bytes(capacity)}` }),
  ]);
}

/**
 * The freshness line.
 *
 * @param {object} fleet
 * @returns {HTMLElement}
 */
function freshness(fleet) {
  if (fleet.observation_age_ms === null || fleet.observation_age_ms === undefined) {
    return pill('never observed', 'bad');
  }
  const age = Number(fleet.observation_age_ms);
  const tone = age > 30000 ? 'bad' : age > 10000 ? 'warn' : 'good';
  return pill(`observed ${formatDuration(age)} ago`, tone);
}

/**
 * Read the fleet, or report that this router has none.
 *
 * @param {import('../api.js').Api} api
 * @returns {Promise<object|null>}
 */
async function load(api) {
  try {
    return await api.get('/admin/v1/fleet');
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
  let fleet = await load(ctx.api);

  if (!fleet) {
    render(
      container,
      [
        pageHeader(meta.title, meta.lede),
        notAvailable(
          'Fleet orchestration',
          'This router has no fleet configured, or `fleet_enabled` is false in the active ' +
            'configuration. Declare `fleet_agent`, `host`, `accelerator`, and `deployment` ' +
            'records and set `fleet_enabled=true` to bring this screen to life.',
        ),
      ],
    );
    return () => {
      stopped = true;
    };
  }

  const body = el('div');
  // The confirmation lives in its own region, outside the repainted body, so a
  // refresh cannot pull the prompt out from under an operator mid-decision.
  const confirmBox = el('div', { hidden: true });
  const refresh = actionButton('Refresh', () => reload(), {
    tone: 'quiet',
    busyLabel: 'Reading…',
  });

  render(container, [
    pageHeader(meta.title, meta.lede),
    toolbar([el('div', { class: 'panel__actions' }, [refresh])], { label: 'Fleet controls' }),
    confirmBox,
    body,
  ]);
  paint();

  async function reload() {
    const next = await load(ctx.api);
    if (stopped || !next) return;
    fleet = next;
    paint();
  }

  function paint() {
    const mayOperate = (ctx.session.permissions || []).includes('fleet_activate');
    const tiles = grid([
      stat('Hosts', formatCount((fleet.hosts || []).length)),
      stat('Deployments', formatCount((fleet.deployments || []).length)),
      stat(
        'Resident',
        formatCount((fleet.deployments || []).filter((d) => d.state === 'ready').length),
      ),
      stat(
        'Unknown identifiers',
        formatCount(fleet.unknown_identifiers || 0),
        'Reported by an agent and not declared here. Anything above zero means the two ' +
          'sides have diverged.',
      ),
    ]);

    const warnings = [];
    if (!fleet.digest_agreed) {
      warnings.push(
        panel({
          title: 'Configuration mismatch',
          content: el('p', {
            text:
              'The router and at least one agent disagree about the fleet configuration. No ' +
              'deployment will be started or stopped until they agree, and every ' +
              'orchestrated target is excluded from routing.',
          }),
        }),
      );
    }
    if (!fleet.agents_reachable) {
      warnings.push(
        panel({
          title: 'Agent unreachable',
          content: el('p', {
            text:
              'At least one configured fleet agent did not answer. Deployments already ' +
              'running keep serving; nothing cold can be started.',
          }),
        }),
      );
    }

    const hosts = (fleet.hosts || []).map((host) => {
      const accelerators = (host.accelerators || []).map((accelerator) =>
        el('div', { class: 'accelerator' }, [
          el('div', { class: 'accelerator__head' }, [
            el('strong', { text: accelerator.id }),
            pill(accelerator.kind, 'neutral'),
            accelerator.memory_drift ? pill('memory drift', 'warn') : null,
          ].filter(Boolean)),
          memoryBar(accelerator.pool_used_bytes, accelerator.pool_capacity_bytes),
        ]),
      );

      return card(
        host.id,
        el('div', {}, [
          el('div', { class: 'panel__actions' }, [
            pill(host.arch, 'neutral'),
            pill(host.state, host.state === 'enabled' ? 'good' : 'warn'),
            pill(
              `${formatCount(host.activation_budget_remaining)} activations left this hour`,
              host.activation_budget_remaining > 0 ? 'neutral' : 'bad',
            ),
            host.reachable === false ? pill('unreachable', 'bad') : null,
          ].filter(Boolean)),
          ...accelerators,
        ]),
      );
    });

    const rows = (fleet.deployments || []).map((deployment) => {
      const controls = [];
      if (mayOperate) {
        controls.push(
          actionButton(
            deployment.state === 'ready' ? 'Stop' : 'Start',
            () => act(deployment),
            { tone: deployment.state === 'ready' ? 'quiet' : 'default' },
          ),
        );
        controls.push(
          actionButton(deployment.pinned ? 'Unpin' : 'Pin', () => setPin(deployment), {
            tone: 'quiet',
            title:
              'A pinned deployment is never chosen for eviction, however badly something ' +
              'else wants its memory.',
          }),
        );
      }
      return [
        deployment.id,
        deployment.target,
        pill(deployment.state, stateTone(deployment.state)),
        bytes(deployment.memory_bytes),
        deployment.resident_for_ms
          ? formatDuration(deployment.resident_for_ms)
          : '—',
        deployment.pinned ? pill('pinned', 'warn') : deployment.evictable ? 'yes' : 'no',
        deployment.router_owned ? 'router' : 'adopted',
        el('div', { class: 'panel__actions' }, controls),
      ];
    });

    render(body, [
      tiles,
      el('div', { class: 'panel__actions' }, [freshness(fleet), pill(`digest ${fleet.digest.slice(0, 12)}`, 'neutral')]),
      ...warnings,
      ...(hosts.length ? hosts : [emptyState('No hosts are declared.')]),
      panel({
        title: 'Deployments',
        note:
          'A deployment the router did not start is shown as adopted: it is used for routing ' +
          'and never evicted, because an operator who started it by hand should not have to ' +
          'fight the router to keep it.',
        content: table({
          caption: 'Declared deployments',
          columns: [
            'Deployment',
            'Target',
            'State',
            'Memory',
            'Resident for',
            'Evictable',
            'Owner',
            'Actions',
          ],
          rows,
          empty: 'No deployments are declared.',
        }),
      }),
    ]);
  }

  function act(deployment) {
    const starting = deployment.state !== 'ready';
    const verb = starting ? 'activate' : 'deactivate';
    const prompt = confirmPrompt({
      message: starting ? `Start ${deployment.id}?` : `Stop ${deployment.id}?`,
      detail: starting
        ? 'The router frees memory first if it has to, which may stop another model. The ' +
          'dwell floor, the cooldown, and the hourly activation allowance still apply — an ' +
          'operator asking is demand, not an exemption.'
        : 'In-flight requests are drained first. The deployment then enters its ' +
          'reactivation cooldown and cannot be started again immediately.',
      confirmLabel: starting ? 'Start it' : 'Stop it',
      onConfirm: async () => {
        dismiss();
        try {
          await ctx.api.post(
            `/admin/v1/fleet/deployments/${encodeURIComponent(deployment.id)}:${verb}`,
            {},
          );
          ctx.notify('good', `${deployment.id} ${starting ? 'started' : 'stopped'}.`);
        } catch (error) {
          ctx.notify('bad', error instanceof ApiError ? error.message : String(error));
        }
        await reload();
      },
      onCancel: dismiss,
    });
    confirmBox.hidden = false;
    render(confirmBox, [prompt]);
  }

  function dismiss() {
    confirmBox.hidden = true;
    render(confirmBox, []);
  }

  async function setPin(deployment) {
    try {
      await ctx.api.patch(
        `/admin/v1/fleet/deployments/${encodeURIComponent(deployment.id)}`,
        { pinned: !deployment.pinned },
      );
      ctx.notify('good', `${deployment.id} ${deployment.pinned ? 'unpinned' : 'pinned'}.`);
    } catch (error) {
      ctx.notify('bad', error instanceof ApiError ? error.message : String(error));
    }
    await reload();
  }

  return () => {
    stopped = true;
  };
}
