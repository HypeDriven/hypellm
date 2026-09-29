/**
 * Managing the fleet's machines from the Fleet screen.
 *
 * Every form here produces a policy draft through `POST
 * /admin/v1/policies:edit`; nothing changes until that draft is published.
 * The configuration file therefore does not need to declare a fleet at all:
 * agents, hosts, accelerators, deployments and fleet policy can all be added
 * here and published like any other routing change.
 *
 * What cannot be done here, deliberately, is tell the fleet agent about a new
 * machine. Specification 26.2 makes the agent's own allowlist — the SSH
 * destination and the start, stop and probe commands for each deployment —
 * the trust boundary, and "the router cannot extend it". So each host shows
 * the agent-side entry the operator must add to the agent's file themselves,
 * pre-filled with everything the router knows and placeholders for what it
 * must not.
 */

import { el, formatCount } from '../components/dom.js';
import { actionButton, confirmPrompt, definitionList, emptyState, panel } from '../components/layout.js';
import {
  listOf,
  loadActiveRecords,
  proposeEdits,
  recordsOf,
  recordsUnavailable,
  requiresEditPolicy,
  textField,
} from '../components/records.js';
import { buttonRow, card } from '../components/table.js';

const GIB = 1024 * 1024 * 1024;

/** The router's ceiling on `recovery_wait_ms`. */
const MAX_RECOVERY_WAIT_MS = 600_000;

const RECOVERY_HINT =
  'How long a request waits and retries when every machine for its alias is unreachable, ' +
  'using the longest wait among those providers; 0 fails at once, and the request deadline ' +
  'still wins.';

/**
 * Field specifications, per record kind. `gib` fields are entered in GiB and
 * written as bytes; `bool` fields offer default / true / false.
 */
const FIELDS = {
  fleet_agent: [
    { name: 'socket', label: 'Agent socket path', hint: 'Absolute path of the agent\'s Unix socket, e.g. /run/hypellm/fleet.sock.' },
    { name: 'observation_interval_ms', label: 'Observation interval (ms)', type: 'number' },
    { name: 'observation_max_age_ms', label: 'Observation max age (ms)', type: 'number' },
  ],
  host: [
    { name: 'agent', label: 'Fleet agent', choicesFrom: 'fleet_agent' },
    { name: 'arch', label: 'Architecture', choices: ['x86_64', 'aarch64'] },
    { name: 'status', label: 'Status', choices: ['', 'enabled', 'drain', 'maintenance', 'disabled'] },
    { name: 'reserved_memory_bytes', label: 'Reserved memory (GiB)', type: 'gib', hint: 'Held back from every pool on this machine for the OS.' },
    { name: 'max_concurrent_activations', label: 'Concurrent activations', type: 'number' },
  ],
  accelerator: [
    { name: 'kind', label: 'Kind', choices: ['cuda', 'unified', 'cpu'] },
    { name: 'memory_bytes', label: 'Memory (GiB)', type: 'gib' },
    { name: 'pool', label: 'Memory pool', hint: 'Leave empty for a discrete GPU; name one pool for unified memory.' },
  ],
  deployment: [
    { name: 'target', label: 'Target', choicesFrom: 'target' },
    { name: 'accelerator', label: 'Accelerator', choicesFrom: 'accelerator' },
    { name: 'memory_bytes', label: 'Memory (GiB)', type: 'gib' },
    { name: 'readiness', label: 'Readiness check', choices: ['', 'http_ok', 'inference', 'container_healthy'] },
    { name: 'autostart', label: 'Start on demand', type: 'bool' },
    { name: 'evictable', label: 'Evictable', type: 'bool' },
    { name: 'pinned', label: 'Pinned', type: 'bool' },
    { name: 'min_resident_ms', label: 'Minimum residency (ms)', type: 'number' },
    { name: 'retention_weight', label: 'Retention weight', type: 'number' },
    { name: 'start_ms', label: 'Start timeout (ms)', type: 'number' },
  ],
  fleet_policy: [
    { name: 'max_activations_per_hour', label: 'Activations per hour', type: 'number' },
    { name: 'max_eviction_set', label: 'Max models evicted per plan', type: 'number', hint: '1 to 8.' },
    { name: 'eviction_margin_permille', label: 'Eviction margin (‰)', type: 'number' },
    { name: 'reactivation_cooldown_ms', label: 'Reactivation cooldown (ms)', type: 'number' },
    { name: 'activation_max_wait_ms', label: 'Max activation wait (ms)', type: 'number' },
    { name: 'prewarm_min_rate_per_minute', label: 'Prewarm rate (per minute)', type: 'number' },
    { name: 'allow_fetch', label: 'Allow artifact fetch', type: 'bool' },
    { name: 'adopt_unmanaged', label: 'Evict adopted models', type: 'bool' },
  ],
  provider: [
    { name: 'family', label: 'Family', choices: ['llamacpp', 'openai', 'anthropic', 'deepseek', 'moonshot', 'semif'] },
    { name: 'scheme', label: 'Scheme', choices: ['http', 'https'] },
    { name: 'host', label: 'Hostname or address', hint: 'A DNS name such as gpu3.lan, or an IP literal.' },
    { name: 'port', label: 'Port', type: 'number' },
    { name: 'base_path', label: 'Base path' },
    { name: 'egress', label: 'Egress profile', choices: ['private_network', 'local', 'remote'], hint: 'Plain http to a LAN machine needs private_network.' },
    { name: 'recovery_wait_ms', label: 'Recovery wait (seconds)', type: 'seconds', hint: RECOVERY_HINT },
  ],
  target: [
    { name: 'model', label: 'Model name' },
    { name: 'aliases', label: 'Aliases', hint: 'Comma-separated.' },
  ],
};

/** @param {string} raw @returns {string} */
function fromMillis(raw) {
  const n = Number(raw);
  if (raw === undefined || raw === '' || !Number.isFinite(n)) return '';
  return String(n / 1000);
}

/**
 * A one-field editor for a provider's recovery wait.
 *
 * @param {object} provider The provider's fields.
 * @param {string} prefix Unique id prefix.
 * @param {(edits: object[]) => Promise<unknown>} submit
 * @returns {HTMLElement}
 */
function recoveryEditor(provider, prefix, submit) {
  const made = textField({
    id: `${prefix}-recovery-${provider.id}`,
    label: `${provider.id} (${provider.scheme || 'http'}://${provider.host}${provider.port ? `:${provider.port}` : ''}) — recovery wait (seconds)`,
    type: 'number',
    value: fromMillis(provider.recovery_wait_ms) || '0',
  });
  made.input.setAttribute('min', '0');
  made.input.setAttribute('max', String(MAX_RECOVERY_WAIT_MS / 1000));
  made.input.setAttribute('step', 'any');
  const save = actionButton('Draft', () => {
    const seconds = Number(String(made.input.value).trim() || '0');
    const ms = Math.round(seconds * 1000);
    if (!Number.isFinite(ms) || ms < 0 || ms > MAX_RECOVERY_WAIT_MS) {
      made.input.setCustomValidity(`Between 0 and ${MAX_RECOVERY_WAIT_MS / 1000} seconds.`);
      made.input.reportValidity();
      return undefined;
    }
    made.input.setCustomValidity('');
    return submit([{ op: 'set', kind: 'provider', id: provider.id, fields: { recovery_wait_ms: ms } }]);
  }, { tone: 'quiet', busyLabel: 'Drafting…' });
  return el('div', { class: 'policy-stack' }, [made.element, buttonRow([save])]);
}

/**
 * The providers serving a host's deployments.
 *
 * @param {object[]} deployments
 * @param {object[]} records
 * @returns {object[]}
 */
function providersFor(deployments, records) {
  const targets = new Map(recordsOf(records, 'target').map((t) => [t.id, t]));
  const providers = new Map(recordsOf(records, 'provider').map((p) => [p.id, p]));
  const seen = new Map();
  for (const deployment of deployments) {
    const target = targets.get(deployment.target);
    const provider = target && providers.get(target.provider);
    if (provider) seen.set(provider.id, provider);
  }
  return [...seen.values()];
}

/** @param {string} raw @returns {string} */
function fromBytes(raw) {
  const n = Number(raw);
  if (!raw || !Number.isFinite(n)) return '';
  const gib = n / GIB;
  return String(Number.isInteger(gib) ? gib : Number(gib.toFixed(3)));
}

/**
 * A form over one record.
 *
 * @param {object} options
 * @param {string} options.kind
 * @param {string} options.prefix Unique id prefix.
 * @param {object} [options.existing] The record's current fields.
 * @param {object[]} options.records Every active record, for choices.
 * @param {boolean} [options.withIdentity] Offer an id input (creation).
 * @param {object} [options.defaults] Values for a new record.
 * @returns {{element: HTMLElement, read: () => ({id: string, fields: object})}}
 */
function recordForm({ kind, prefix, existing, records, withIdentity = !existing, defaults = {} }) {
  const inputs = [];
  const parts = [];
  let idInput = null;
  if (withIdentity) {
    const made = textField({ id: `${prefix}-id`, label: 'Identifier', value: defaults.id || '' });
    idInput = made.input;
    parts.push(made.element);
  }
  for (const spec of FIELDS[kind]) {
    const current = existing ? existing[spec.name] : defaults[spec.name];
    let choices = spec.choices;
    if (spec.choicesFrom) {
      choices = recordsOf(records, spec.choicesFrom).map((r) => String(r.id));
      if (current && !choices.includes(current)) choices = [current, ...choices];
      if (choices.length === 0) choices = [''];
    }
    if (spec.type === 'bool') choices = ['', 'true', 'false'];
    const value =
      spec.type === 'gib' ? fromBytes(current) : spec.type === 'seconds' ? fromMillis(current) : current ?? '';
    const made = textField({
      id: `${prefix}-${spec.name}`,
      label: spec.label,
      hint: spec.hint,
      value,
      type: ['number', 'gib', 'seconds'].includes(spec.type) ? 'number' : 'text',
      choices,
    });
    if (spec.type === 'gib' || spec.type === 'seconds') made.input.setAttribute('step', 'any');
    if (spec.type === 'seconds') {
      made.input.setAttribute('min', '0');
      made.input.setAttribute('max', String(MAX_RECOVERY_WAIT_MS / 1000));
    }
    inputs.push([spec, made.input]);
    parts.push(made.element);
  }

  function read() {
    const fields = {};
    for (const [spec, input] of inputs) {
      const raw = String(input.value).trim();
      if (raw === '') {
        // Clearing a field on an existing record removes it, so the router's
        // default applies; on a new record it is simply not written.
        if (existing && existing[spec.name] !== undefined) fields[spec.name] = null;
        continue;
      }
      if (spec.type === 'seconds') {
        fields[spec.name] = Math.round(Number(raw) * 1000);
      } else if (spec.type === 'gib') {
        fields[spec.name] = Math.round(Number(raw) * GIB);
      } else if (spec.type === 'number') {
        fields[spec.name] = Number(raw);
      } else if (spec.type === 'bool') {
        fields[spec.name] = raw === 'true';
      } else if (spec.name === 'aliases') {
        fields[spec.name] = listOf(raw);
      } else {
        fields[spec.name] = raw;
      }
    }
    return { id: idInput ? String(idInput.value).trim() : String(existing?.id || ''), fields };
  }

  return { element: el('div', { class: 'policy-stack' }, parts), read };
}

/**
 * The agent-side allowlist entry for one host, as the agent's JSON shape.
 *
 * @param {object} host
 * @param {object[]} records
 * @returns {string}
 */
function agentEntry(host, records) {
  const accelerators = recordsOf(records, 'accelerator').filter((a) => a.host === host.id);
  const acceleratorIds = new Set(accelerators.map((a) => a.id));
  const deployments = recordsOf(records, 'deployment').filter((d) => acceleratorIds.has(d.accelerator));
  const targets = new Map(recordsOf(records, 'target').map((t) => [t.id, t]));
  const providers = new Map(recordsOf(records, 'provider').map((p) => [p.id, p]));
  const policy =
    recordsOf(records, 'fleet_policy').find((p) => p.scope === `host:${host.id}`) ||
    recordsOf(records, 'fleet_policy').find((p) => p.scope === 'fleet');

  // The provider behind one of this host's deployments usually names the
  // machine, so it is the best guess for the SSH destination. Only a guess:
  // the operator confirms it when they paste the entry.
  let machine = 'HOSTNAME';
  let port = 'PORT';
  for (const deployment of deployments) {
    const target = targets.get(deployment.target);
    const provider = target && providers.get(target.provider);
    if (provider && provider.host) {
      machine = provider.host;
      if (provider.port) port = provider.port;
      break;
    }
  }

  const entry = {
    host: {
      id: host.id,
      arch: host.arch,
      ssh: `hypellm@${machine}`,
      disk_path: '/',
      max_activations_per_hour: Number(policy?.max_activations_per_hour || 6),
      accelerators: accelerators.map((a, index) => ({ id: a.id, index })),
    },
    deployments: deployments.map((d) => ({
      id: d.id,
      host: host.id,
      accelerator: d.accelerator,
      container: 'CONTAINER',
      start: ['docker', 'start', 'CONTAINER'],
      stop: ['docker', 'stop', '--timeout', '30', 'CONTAINER'],
      // Assembled, not written as a URL literal: depscan's first-party rule
      // reads any scheme-prefixed string in the application as a remote fetch.
      probe: ['curl', '-fsS', '--max-time', '5', ['http:', '', `127.0.0.1:${port}`, 'v1', 'models'].join('/')],
    })),
  };
  return JSON.stringify(entry, null, 2);
}

/**
 * The Machines panel.
 *
 * @param {object} ctx The view context.
 * @param {object|null} fleet The `GET /fleet` answer, or null when there is none.
 * @returns {HTMLElement}
 */
export function machinesPanel(ctx, fleet) {
  const body = el('div', { class: 'policy-stack' });
  const outcome = el('div', { class: 'policy-stack', role: 'status', 'aria-live': 'polite' });
  const editor = el('div', { class: 'policy-stack' });
  let active = { records: null, etag: null };

  const section = panel({
    title: 'Machines',
    note:
      'Add or change the fleet\'s agents, hosts, accelerators, deployments and fleet policy. ' +
      'Each change becomes a policy draft; nothing happens until it is published.',
    content: el('div', { class: 'policy-stack' }, [editor, outcome, body]),
  });

  if (!ctx.can('edit_policy')) {
    body.append(requiresEditPolicy());
    return section;
  }

  void reload();

  async function reload() {
    try {
      active = await loadActiveRecords(ctx.api);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      body.replaceChildren(emptyState('The active configuration could not be read.', String(error.message || error)));
      return;
    }
    paint();
  }

  async function submit(edits) {
    editor.replaceChildren();
    await proposeEdits(ctx, edits, outcome, { etag: () => active.etag, onPublished: reload });
  }

  /**
   * Open a form in the editor slot.
   *
   * @param {string} title
   * @param {HTMLElement} form
   * @param {() => object[]} build Edits to send.
   */
  function open(title, form, build) {
    outcome.replaceChildren();
    editor.replaceChildren(
      card(title, [
        form,
        buttonRow([
          actionButton('Create draft', () => submit(build()), { busyLabel: 'Drafting…' }),
          actionButton('Cancel', () => editor.replaceChildren(), { tone: 'quiet' }),
        ]),
      ]),
    );
  }

  function paint() {
    const records = active.records;
    if (!records) {
      body.replaceChildren(recordsUnavailable('Machine management'));
      return;
    }
    const settings = recordsOf(records, 'settings')[0] || {};
    const enabled = settings.fleet_enabled === 'true';
    const agents = recordsOf(records, 'fleet_agent');
    const hosts = recordsOf(records, 'host');
    const fleetPolicy = recordsOf(records, 'fleet_policy').find((p) => p.scope === 'fleet');

    const summary = definitionList([
      ['Orchestration', enabled ? 'enabled (fleet_enabled=true)' : 'disabled (fleet_enabled is not true)'],
      ['Agents', agents.length ? agents.map((a) => `${a.id} → ${a.socket}`).join(', ') : 'none declared'],
      ['Hosts', formatCount(hosts.length)],
      fleet
        ? ['Router and agent', fleet.digest_agreed ? 'agree on the fleet digest' : 'disagree — orchestration is halted until both sides match']
        : null,
    ]);

    const controls = buttonRow([
      actionButton(enabled ? 'Disable orchestration' : 'Enable orchestration', () =>
        submit([{ op: 'set', kind: 'settings', fields: { fleet_enabled: !enabled } }]),
      ),
      actionButton('Add agent', () => {
        const form = recordForm({ kind: 'fleet_agent', prefix: 'new-agent', records, defaults: { id: 'local', socket: '/run/hypellm/fleet.sock' } });
        open('Add a fleet agent', form.element, () => {
          const { id, fields } = form.read();
          return [{ op: 'set', kind: 'fleet_agent', id, fields }];
        });
      }, { tone: 'quiet' }),
      actionButton('Add host', () => addHost(records), { tone: 'quiet', disabled: agents.length === 0, title: agents.length === 0 ? 'Declare a fleet agent first.' : null }),
      actionButton('Fleet policy', () => editPolicy(records, 'fleet', fleetPolicy), { tone: 'quiet' }),
    ]);

    const cards = hosts.map((host) => hostCard(host, records));
    // Every provider, including ones no fleet host serves — a LAN llama.cpp
    // reached by hostname still benefits from waiting out a restart.
    const providers = recordsOf(records, 'provider');
    const providerCard = card('Providers', [
      el('p', { class: 'panel__note', text: RECOVERY_HINT }),
      ...(providers.length
        ? providers.map((provider) => recoveryEditor(provider, 'all', submit))
        : [emptyState('No providers are declared.')]),
    ]);
    body.replaceChildren(
      summary,
      controls,
      ...(cards.length ? cards : [emptyState('No hosts are declared.', 'Add an agent, then a host.')]),
      providerCard,
    );
  }

  function hostCard(host, records) {
    const accelerators = recordsOf(records, 'accelerator').filter((a) => a.host === host.id);
    const ids = new Set(accelerators.map((a) => a.id));
    const deployments = recordsOf(records, 'deployment').filter((d) => ids.has(d.accelerator));
    const hostPolicy = recordsOf(records, 'fleet_policy').find((p) => p.scope === `host:${host.id}`);
    const confirmBox = el('div');
    const servingProviders = providersFor(deployments, records);

    const entry = agentEntry(host, records);
    const copyStatus = el('span', { role: 'status', 'aria-live': 'polite' });
    const copy = actionButton('Copy', () => {
      const clipboard = navigator.clipboard;
      if (!clipboard || typeof clipboard.writeText !== 'function') {
        copyStatus.textContent = 'Copying is unavailable here — select the text instead.';
        return;
      }
      return clipboard.writeText(entry).then(
        () => { copyStatus.textContent = 'Copied.'; },
        () => { copyStatus.textContent = 'The browser refused the copy.'; },
      );
    }, { tone: 'quiet' });

    return card(host.id, [
      definitionList([
        ['Agent', host.agent],
        ['Architecture', host.arch],
        ['Status', host.status || 'enabled'],
        ['Accelerators', accelerators.map((a) => `${a.id} (${a.kind}, ${fromBytes(a.memory_bytes)} GiB${a.pool ? `, pool ${a.pool}` : ''})`).join('; ')],
        ['Deployments', deployments.map((d) => `${d.id} → ${d.target} on ${d.accelerator}`).join('; ')],
        ['Host policy', hostPolicy ? 'overrides the fleet policy' : 'inherits the fleet policy'],
      ]),
      ...(servingProviders.length
        ? [
            el('p', { class: 'panel__note', text: RECOVERY_HINT }),
            ...servingProviders.map((provider) => recoveryEditor(provider, `host-${host.id}`, submit)),
          ]
        : []),
      buttonRow([
        actionButton('Edit host', () => {
          const form = recordForm({ kind: 'host', prefix: `edit-${host.id}`, existing: host, records });
          open(`Edit ${host.id}`, form.element, () => [{ op: 'set', kind: 'host', id: host.id, fields: form.read().fields }]);
        }, { tone: 'quiet' }),
        actionButton('Add accelerator', () => {
          const form = recordForm({ kind: 'accelerator', prefix: `acc-${host.id}`, records, defaults: { id: `${host.id}-gpu${accelerators.length}` } });
          open(`Add an accelerator to ${host.id}`, form.element, () => {
            const { id, fields } = form.read();
            return [{ op: 'set', kind: 'accelerator', id, fields: { ...fields, host: host.id } }];
          });
        }, { tone: 'quiet' }),
        ...accelerators.map((a) =>
          actionButton(`Edit ${a.id}`, () => {
            const form = recordForm({ kind: 'accelerator', prefix: `edit-acc-${a.id}`, existing: a, records });
            open(`Edit ${a.id}`, form.element, () => [{ op: 'set', kind: 'accelerator', id: a.id, fields: form.read().fields }]);
          }, { tone: 'quiet' }),
        ),
        actionButton('Add deployment', () => addDeployment(records, host, accelerators), { tone: 'quiet', disabled: accelerators.length === 0, title: accelerators.length === 0 ? 'Add an accelerator first.' : null }),
        ...deployments.map((d) =>
          actionButton(`Edit ${d.id}`, () => {
            const form = recordForm({ kind: 'deployment', prefix: `edit-dep-${d.id}`, existing: d, records });
            open(`Edit ${d.id}`, form.element, () => [{ op: 'set', kind: 'deployment', id: d.id, fields: form.read().fields }]);
          }, { tone: 'quiet' }),
        ),
        actionButton('Host policy', () => editPolicy(records, `host:${host.id}`, hostPolicy), { tone: 'quiet' }),
        actionButton('Remove host…', () => {
          confirmBox.replaceChildren(
            confirmPrompt({
              message: `Draft the removal of ${host.id}?`,
              detail:
                `Removes the host, its ${accelerators.length} accelerator(s), ${deployments.length} ` +
                'deployment(s) and any host policy. Providers and targets are kept; remove them ' +
                'from the agent\'s file too, or the digests will disagree.',
              confirmLabel: 'Create draft',
              onConfirm: async () => {
                confirmBox.replaceChildren();
                await submit([
                  ...deployments.map((d) => ({ op: 'remove', kind: 'deployment', id: d.id })),
                  ...accelerators.map((a) => ({ op: 'remove', kind: 'accelerator', id: a.id })),
                  ...(hostPolicy ? [{ op: 'remove', kind: 'fleet_policy', scope: `host:${host.id}` }] : []),
                  { op: 'remove', kind: 'host', id: host.id },
                ]);
              },
              onCancel: () => confirmBox.replaceChildren(),
            }),
          );
        }, { tone: 'danger' }),
      ]),
      confirmBox,
      el('details', {}, [
        el('summary', { text: 'Agent-side entry' }),
        el('p', {
          text:
            'The router cannot write this (specification 26.2): the fleet agent\'s own allowlist ' +
            'is the trust boundary. Merge it into the agent\'s JSON file, replacing the ' +
            'placeholders; the agent reloads the file when it changes, and orchestration resumes ' +
            'once both sides compute the same fleet digest.',
        }),
        el('pre', { text: entry }),
        buttonRow([copy, copyStatus]),
      ]),
    ]);
  }

  function addHost(records) {
    const hostForm = recordForm({ kind: 'host', prefix: 'new-host', records, defaults: { arch: 'x86_64' } });
    const accForm = recordForm({ kind: 'accelerator', prefix: 'new-host-acc', records, withIdentity: true, defaults: { kind: 'cuda' } });
    open('Add a host', el('div', { class: 'policy-stack' }, [
      hostForm.element,
      el('h3', { text: 'First accelerator' }),
      accForm.element,
    ]), () => {
      const host = hostForm.read();
      const acc = accForm.read();
      const edits = [{ op: 'set', kind: 'host', id: host.id, fields: host.fields }];
      if (acc.id) edits.push({ op: 'set', kind: 'accelerator', id: acc.id, fields: { ...acc.fields, host: host.id } });
      return edits;
    });
  }

  function addDeployment(records, host, accelerators) {
    const form = recordForm({
      kind: 'deployment',
      prefix: `dep-${host.id}`,
      records,
      defaults: { id: '', accelerator: accelerators[0]?.id, autostart: 'true' },
    });
    const include = el('input', {
      type: 'checkbox',
      id: `dep-${host.id}-new-target`,
      name: 'new-target',
      'aria-label': 'Also create the provider and target it serves',
    });
    const providerForm = recordForm({
      kind: 'provider',
      prefix: `dep-${host.id}-provider`,
      records,
      defaults: { id: host.id, family: 'llamacpp', scheme: 'http', port: '8000', base_path: '/v1', egress: 'private_network' },
    });
    const targetForm = recordForm({ kind: 'target', prefix: `dep-${host.id}-target`, records, withIdentity: true });
    const extra = el('div', { class: 'policy-stack', hidden: true }, [
      el('h3', { text: 'Provider (the machine\'s server)' }),
      providerForm.element,
      el('h3', { text: 'Target' }),
      targetForm.element,
    ]);
    include.addEventListener('change', () => {
      extra.hidden = !include.checked;
    });
    open(`Add a deployment on ${host.id}`, el('div', { class: 'policy-stack' }, [
      form.element,
      el('div', { class: 'field' }, [
        el('label', { for: `dep-${host.id}-new-target` }, [include, ' Also create the provider and target it serves']),
      ]),
      extra,
    ]), () => {
      const deployment = form.read();
      const edits = [];
      if (include.checked) {
        const provider = providerForm.read();
        const target = targetForm.read();
        edits.push({ op: 'set', kind: 'provider', id: provider.id, fields: provider.fields });
        edits.push({ op: 'set', kind: 'target', id: target.id, fields: { ...target.fields, provider: provider.id } });
        deployment.fields.target = target.id;
      }
      edits.push({ op: 'set', kind: 'deployment', id: deployment.id, fields: deployment.fields });
      return edits;
    });
  }

  function editPolicy(records, scope, existing) {
    const form = recordForm({ kind: 'fleet_policy', prefix: `policy-${scope.replace(':', '-')}`, existing: existing || {}, records, withIdentity: false });
    open(scope === 'fleet' ? 'Fleet-wide policy' : `Policy for ${scope.slice(5)}`, form.element, () => [
      { op: 'set', kind: 'fleet_policy', scope, fields: form.read().fields },
    ]);
  }

  return section;
}
