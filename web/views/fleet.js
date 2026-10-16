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
  panel,
  toolbar,
} from '../components/layout.js';
import { card, grid, pageHeader, render, stat, table } from '../components/table.js';
import { accessPanel } from './fleet-access.js';
import { enrollmentPanel } from './fleet-enroll.js';
import { machinesPanel } from './fleet-machines.js';

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
 * Requests queued or parked for a deployment's model (specification 26.10).
 *
 * A whole-fleet figure: the demand waiting for this model, from every tenant.
 */
function waitingCell(deployment) {
  const waiting = Number(deployment.waiting || 0);
  return waiting > 0 ? pill(`${formatCount(waiting)} waiting`, 'warn') : '—';
}

/**
 * How long the deployment has gone unused, against when it would be stopped.
 *
 * Nothing is inferred: with no idle window the cell says so, and a model that
 * has never served reads as such rather than as a number.
 */
function idleCell(deployment) {
  const idle = deployment.idle_ms === null || deployment.idle_ms === undefined
    ? 'never used'
    : formatDuration(Number(deployment.idle_ms));
  if (deployment.idle_stop_ms === null || deployment.idle_stop_ms === undefined) {
    return `${idle} · never stopped`;
  }
  return `${idle} · stops after ${formatDuration(Number(deployment.idle_stop_ms))}`;
}

/** What each scheduling reason means, in the operator's words (specification 26.11). */
const NEXT_REASONS = {
  ranked: 'most waiting demand per second of load',
  starving: 'waited past the reordering bound',
  uncontended: 'the only model waiting',
  arrival_order: 'reordering off; oldest first',
};

/**
 * The line saying what this host would load next, or nothing when no model the
 * caller can see is waiting for it.
 *
 * @param {object} host
 * @returns {HTMLElement|null}
 */
function nextActivation(host) {
  const next = host.next_activation;
  if (!next) {
    return null;
  }
  const why = NEXT_REASONS[next.reason] || next.reason;
  return el('p', { class: 'muted' }, [
    'Next to load: ',
    el('strong', { text: next.deployment }),
    ` — ${formatCount(next.waiting)} waiting for ${formatDuration(Number(next.waited_ms))} (${why})`,
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
    // `api.get` resolves to `{ data, etag }` and already prefixes `/admin/v1`.
    const { data } = await api.get('/fleet');
    return data;
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
    // No runtime is not the end of the story: the fleet can be declared from
    // the Machines panel below and brought up by publishing that draft.
    render(
      container,
      [
        pageHeader(meta.title, meta.lede),
        emptyState(
          'No fleet is running.',
          'The active configuration declares no fleet, or fleet_enabled is not true. Declare an ' +
            'agent, hosts and deployments below — or in the configuration file — and enable ' +
            'orchestration.',
        ),
        enrollmentPanel(ctx),
        machinesPanel(ctx, null),
        accessPanel(ctx),
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
    // Outside `body`, so a refresh does not discard a half-filled form.
    enrollmentPanel(ctx),
    machinesPanel(ctx, fleet),
    accessPanel(ctx),
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
          nextActivation(host),
          ...accelerators,
        ].filter(Boolean)),
      );
    });

    const cells = (fleet.deployments || []).map((deployment) => {
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
        waitingCell(deployment),
        idleCell(deployment),
        el('div', { class: 'panel__actions' }, controls),
      ];
    });

    const mayTransfer = (ctx.session.permissions || []).includes('fleet_fetch');
    const artifactRows = [];
    for (const artifact of fleet.artifacts || []) {
      const placed = new Map((artifact.placements || []).map((p) => [p.host, p]));
      const source = (artifact.placements || []).find((p) => p.state === 'verified');
      for (const host of fleet.hosts || []) {
        if (host.arch !== artifact.arch) continue;
        const placement = placed.get(host.id);
        const state = placement ? placement.state : 'absent';
        const controls = [];
        if (mayTransfer && source && state !== 'verified' && artifact.checksum) {
          controls.push(
            actionButton('Copy here', () => copy(artifact, source.host, host.id), {
              tone: 'quiet',
              title: `Relay the image from ${source.host} through the fleet agent, verified ` +
                'against the kept checksum before it is loaded.',
            }),
          );
        }
        artifactRows.push([
          artifact.id,
          host.id,
          pill(state, state === 'verified' ? 'good' : state === 'tampered' ? 'bad' : 'neutral'),
          placement && placement.image_id ? placement.image_id.slice(0, 19) : '—',
          el('div', { class: 'panel__actions' }, controls),
        ]);
      }
    }
    const artifactHeadings = ['Artifact', 'Host', 'State', 'Image ID', 'Actions'];
    const artifactColumns = artifactHeadings.map((label, index) => ({
      label,
      cell: (row) => row[index],
    }));
    const checksums = (fleet.artifacts || []).map((artifact) =>
      el('p', {
        text: artifact.checksum
          ? `${artifact.id}: kept ${artifact.checksum.slice(0, 19)}… (${artifact.checksum_source})`
          : `${artifact.id}: no checksum kept yet, so it cannot be copied between hosts.`,
      }),
    );

    // `table` takes column objects and row objects; each row here is the list
    // of cells, so column `i` renders cell `i`.
    const headings = ['Deployment', 'Target', 'State', 'Memory', 'Resident for', 'Evictable', 'Owner', 'Waiting', 'Idle', 'Actions'];
    const columns = headings.map((label, index) => ({ label, cell: (row) => row[index] }));

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
          columns,
          rows: cells,
          empty: 'No deployments are declared.',
        }),
      }),
      panel({
        title: 'Images',
        note:
          'Each image is held to one checksum: pinned in the configuration, or learned from ' +
          'the first host whose copy matched its registry digest. A host reporting anything ' +
          'else is marked tampered and is never started with that image or copied from.',
        content: el('div', { class: 'policy-stack' }, [
          ...checksums,
          table({
            caption: 'Images on hosts',
            columns: artifactColumns,
            rows: artifactRows,
            empty: 'No deployment you can see uses a declared image.',
          }),
        ]),
      }),
    ]);
  }

  function copy(artifact, from, to) {
    const prompt = confirmPrompt({
      message: `Copy ${artifact.id} from ${from} to ${to}?`,
      detail:
        'The fleet agent saves the image on the source, hashes every layer against the kept ' +
        'checksum, and loads a rebuilt archive on the destination only if all of it matches. ' +
        'It uses disk on both machines and the agent machine while it runs.',
      confirmLabel: 'Copy it',
      onConfirm: async () => {
        dismiss();
        try {
          await ctx.api.post(`/fleet/artifacts/${encodeURIComponent(artifact.id)}:copy`, {
            from,
            to,
          });
          ctx.notify('good', `Copying ${artifact.id} to ${to}.`);
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
            `/fleet/deployments/${encodeURIComponent(deployment.id)}:${verb}`,
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
      // The tag the fleet view disclosed for this deployment, so a pin made
      // from a stale screen is refused rather than silently undoing someone
      // else's change.
      await ctx.api.patch(
        `/fleet/deployments/${encodeURIComponent(deployment.id)}`,
        { pinned: !deployment.pinned },
        deployment.etag,
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
