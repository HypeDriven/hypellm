/**
 * Enrolling a machine from the Fleet screen (specification 26.8).
 *
 * Two halves. **Enroll a machine** mints a one-time token and shows the
 * command to run on the new machine, once. **Enrollments** lists what has
 * registered: what the machine reported about itself, the fingerprints to
 * compare with what the install script printed, and the decision.
 *
 * Approving does not add the machine to the fleet. It drafts the machine's
 * host and accelerator records, and a second person publishes that draft from
 * Policies; only then does the router route to it and the fleet agent — if it
 * accepts enrollments — add it to its allowlist, pinned to the SSH host key
 * shown here.
 */

import { el, formatCount, formatTime, pill } from '../components/dom.js';
import { actionButton, confirmPrompt, emptyState, panel, secretOnce } from '../components/layout.js';
import { textField } from '../components/records.js';
import { buttonRow, table } from '../components/table.js';

const GIB = 1024 * 1024 * 1024;

const TONES = {
  issued: 'neutral',
  registered: 'warn',
  approved: 'ok',
  rejected: 'danger',
  expired: 'neutral',
  revoked: 'danger',
};

/** @param {number} bytes @returns {string} */
function gib(bytes) {
  return `${formatCount(Math.round((Number(bytes) || 0) / GIB))} GiB`;
}

/**
 * What the machine reported, in one cell.
 *
 * @param {object|null} registration
 * @returns {HTMLElement|string}
 */
function machine(registration) {
  if (!registration) return 'Not registered yet';
  const gpus = registration.gpus || [];
  return el('div', { class: 'policy-stack' }, [
    el('span', { text: `${registration.hostname} · ${registration.address} · ${registration.arch}` }),
    el('span', {
      text: gpus.length
        ? gpus.map((g) => `GPU ${g.index}: ${g.name} (${gib(g.memory_bytes)})`).join('; ')
        : `No GPU · ${gib(registration.memory_bytes)} memory`,
    }),
    el('span', { text: `${registration.ssh_user}@ · data ${registration.data_dir}` }),
  ]);
}

/**
 * The fingerprints an administrator compares before approving.
 *
 * @param {object|null} registration
 * @returns {HTMLElement|string}
 */
function fingerprints(registration) {
  if (!registration) return '—';
  return el('div', { class: 'policy-stack' }, [
    el('code', { text: `SSH ${registration.ssh_host_key_fingerprint}` }),
    el('code', { text: `Device ${registration.device_key_fingerprint}` }),
  ]);
}

/**
 * The Enrollment panel.
 *
 * @param {object} ctx The view context.
 * @returns {HTMLElement}
 */
export function enrollmentPanel(ctx) {
  const mayEnroll = ctx.can('fleet_enroll');
  const mayDraft = ctx.can('edit_policy');
  const issued = el('div', { class: 'policy-stack' });
  const outcome = el('div', { class: 'policy-stack', role: 'status', 'aria-live': 'polite' });
  const confirmBox = el('div', { class: 'policy-stack' });
  const list = el('div', { class: 'policy-stack' });
  const form = el('div', { class: 'policy-stack' });

  const section = panel({
    title: 'Enroll a machine',
    note:
      'Mint a one-time command for a new machine. It checks the machine, asks where containers ' +
      'should live, shows every change and asks before making any. A machine that registers ' +
      'stays unavailable until it is approved here and the resulting draft is published.',
    content: el('div', { class: 'policy-stack' }, [form, issued, confirmBox, outcome, list]),
  });

  void reload();

  async function request(method, path, body) {
    return ctx.api.request(method, path, { body, shared: true });
  }

  async function reload() {
    let data;
    try {
      ({ data } = await request('GET', '/fleet/enrollments'));
    } catch (error) {
      if (error && error.status === 403) {
        list.replaceChildren(
          emptyState('Enrollments are not visible to this session.', 'fleet_enroll or read_fleet is needed.'),
        );
        return;
      }
      throw error;
    }
    paintForm(data);
    paintList(data.items || []);
  }

  function paintForm(data) {
    if (!mayEnroll) {
      form.replaceChildren(el('p', { text: 'Minting a command needs the fleet_enroll permission.' }));
      return;
    }
    if (!data.configured) {
      form.replaceChildren(
        emptyState(
          'Enrollment is not configured on this router.',
          'Set settings fleet_enroll_url to the https origin new machines can reach (the tailnet ' +
            'address), and give the fleet_agent record an ssh_public_key.',
        ),
      );
      return;
    }
    const host = textField({
      id: 'enroll-host',
      label: 'Host identifier',
      hint: 'How the router will name this machine, e.g. gpu3. Letters, digits, ".", "_", "-".',
    });
    const agent = textField({
      id: 'enroll-agent',
      label: 'Fleet agent',
      value: 'local',
      hint: 'The fleet_agent that will manage it; its record must declare ssh_public_key.',
    });
    const mint = actionButton('Create install command', async () => {
      outcome.replaceChildren();
      const { data: minted } = await request('POST', '/fleet/enrollments', {
        host: String(host.input.value).trim(),
        agent: String(agent.input.value).trim(),
      });
      issued.replaceChildren(
        secretOnce({
          value: minted.command,
          label: `Run on ${minted.host}, as the account that will own its data directory`,
          notice:
            `This command carries a one-time token that expires ${formatTime(minted.expires_at)}. ` +
            'It is shown once; the router keeps only a digest of the token.',
          onDismiss: () => issued.replaceChildren(),
        }),
      );
      await reload();
    }, { busyLabel: 'Creating…' });
    form.replaceChildren(
      el('p', { text: `Host kit ${data.kit_version}.` }),
      host.element,
      agent.element,
      buttonRow([mint]),
    );
  }

  function decide(row, action, message, detail) {
    confirmBox.replaceChildren(
      confirmPrompt({
        message,
        detail,
        confirmLabel: action[0].toUpperCase() + action.slice(1),
        onConfirm: async () => {
          confirmBox.replaceChildren();
          const { data } = await request('POST', `/fleet/enrollments/${encodeURIComponent(row.id)}:${action}`);
          if (action === 'approve') {
            outcome.replaceChildren(
              el('p', {
                text:
                  `Approved. Draft ${data.draft_id} adds ${row.host} and its accelerators; it is not ` +
                  'published. A policy approver publishes it from Policies, after which the fleet ' +
                  'agent is offered the machine.',
              }),
            );
          } else {
            outcome.replaceChildren(el('p', { text: `${row.host}: ${data.state}.` }));
          }
          await reload();
        },
        onCancel: () => confirmBox.replaceChildren(),
      }),
    );
  }

  function actions(row) {
    if (!mayEnroll) return '—';
    const buttons = [];
    if (row.state === 'registered' && mayDraft) {
      buttons.push(
        actionButton('Approve', () =>
          decide(
            row,
            'approve',
            `Approve ${row.host}?`,
            'Compare the SSH and device fingerprints with what the install script printed on the ' +
              'machine first. Approval drafts its records; publishing them is a separate step.',
          ),
        ),
      );
    }
    if (row.state === 'registered' && !mayDraft) {
      buttons.push(el('span', { text: 'Approval also needs edit_policy.' }));
    }
    if (row.state === 'issued' || row.state === 'registered') {
      buttons.push(
        actionButton('Reject', () =>
          decide(row, 'reject', `Reject ${row.host}?`, 'Its token stops working at once.'),
        { tone: 'danger' }),
      );
    }
    if (row.state === 'approved') {
      buttons.push(
        actionButton('Revoke', () =>
          decide(
            row,
            'revoke',
            `Revoke ${row.host}?`,
            'The fleet agent drops the machine on its next offer. Its host and accelerator records ' +
              'stay in the configuration until a draft removes them.',
          ),
        { tone: 'danger' }),
      );
    }
    return buttons.length ? buttonRow(buttons) : '—';
  }

  function paintList(items) {
    list.replaceChildren(
      el('h3', { text: 'Enrollments' }),
      table({
        caption: 'Machines that were given an install command',
        columns: [
          { label: 'Host', cell: (row) => el('span', {}, [row.host, ' ', pill(row.state, TONES[row.state] || 'neutral')]) },
          { label: 'Machine', cell: (row) => machine(row.registration) },
          { label: 'Fingerprints', cell: (row) => fingerprints(row.registration) },
          { label: 'Issued', cell: (row) => `${formatTime(row.issued_at)} by ${row.issued_by}` },
          { label: 'Draft', cell: (row) => row.draft || '—' },
          { label: 'Actions', cell: actions },
        ],
        rows: items,
        empty: 'No machine has been given an install command.',
      }),
    );
  }

  return section;
}
