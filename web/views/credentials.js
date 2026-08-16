/**
 * Credentials.
 *
 * Specification 15.3: "Create/rotate opaque provider credentials; values
 * write-only." Specification 9.3 gives the rule this whole screen is built
 * around: a credential manager "cannot read secret back".
 *
 * The consequences are worth stating, because they shape everything below:
 *
 * - **Nothing here ever renders a secret.** `GET /admin/v1/credentials` has no
 *   `secret` field, `POST /admin/v1/credentials` answers `{id, stored}` and the
 *   rotation answers `{id, rotated, overlap_seconds}`. There is therefore no
 *   response value on this screen that could be a secret, and no code path that
 *   prints one. Unlike the API keys screen, `secretOnce` has no place here: the
 *   operator supplies the value, so showing it back would be a disclosure with
 *   no purpose. Secrets travel in one direction only — a masked input, a request
 *   body, and then out of the document.
 * - **What the table shows is configuration, not inventory.** The list is the
 *   set of references the *active configuration* declares. Storing a secret does
 *   not declare a reference, so a newly stored credential does not appear here
 *   until the configuration does declare it. Saying so plainly is the difference
 *   between an operator who understands the model and one who thinks the router
 *   lost their credential.
 * - **Rotation is two-phase** (specification 22.2): the router reports the
 *   overlap window during which both the old and the new secret are accepted.
 *   That number comes from the response and is not assumed here.
 * - **No optimistic update** (specification 15.4). Every mutation is followed by
 *   a re-read of the list; the table is never patched locally, so what is on
 *   screen is always what the router last said.
 *
 * Neither mutation carries `If-Match`. That is not an omission: both are `POST`
 * creations — a new secret, and a new rotation — not conditional updates of a
 * resource whose ETag the operator has read. The router checks `If-Match` on
 * `PATCH /admin/v1/targets/{id}` and on nothing here, and sending a precondition
 * the server ignores would be a claim of safety this screen cannot make. What it
 * does instead is confirm the act and re-read afterwards.
 *
 * `manage_credentials` also requires a fresh authentication (specification 9.1,
 * `Permission::requires_reauthentication`). The router enforces that; this
 * screen names it when it happens, because "forbidden" is not an instruction and
 * "sign in again" is.
 */

import { ApiError } from '../api.js';
import { el, formatDuration, pill, replace, text } from '../components/dom.js';
import { banner, buttonRow, card, field, pageHeader, render, table } from '../components/table.js';
import {
  actionButton,
  confirmPrompt,
  emptyState,
  notAvailable,
  panel,
} from '../components/layout.js';

/** Screen metadata, read by the router to build navigation. */
export const meta = {
  path: '/credentials',
  title: 'Credentials',
  lede:
    'Opaque provider credential references. Values are write-only: the router never returns a secret, and this screen never shows one.',
  // `list_credentials`, `create_credential`, and `rotate_credential` in
  // crates/hypellm-admin-api/src/handlers.rs each require exactly this one.
  permission: 'manage_credentials',
};

/**
 * The identifier grammar of `hypellm_core::ids` (`[A-Za-z0-9._:-]`, 128 bytes).
 *
 * Checked here so a typo is named next to the field that caused it rather than
 * arriving as a generic 400 after the operator has already committed the secret.
 */
const ID_GRAMMAR = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * References the rotation endpoint can actually address.
 *
 * `POST /admin/v1/credentials/{id}:rotate` is routed by `rest.split_once(':')`,
 * so a reference whose own identifier contains a colon splits in the wrong place
 * and the router answers "no such credential action". The control is disabled
 * with that explanation instead of sending a request that is guaranteed to fail:
 * a 404 would read as "the credential is gone", which is the wrong conclusion.
 */
const ROTATABLE = /^[A-Za-z0-9._-]+$/;

/**
 * Render the screen.
 *
 * @param {HTMLElement} container  Empty element to render into.
 * @param {object} ctx
 * @param {import('../api.js').Api} ctx.api
 * @param {object} ctx.session
 * @param {(path: string) => void} ctx.navigate
 * @param {(tone: string, message: string) => void} ctx.notify
 * @param {(permission: string) => boolean} ctx.can
 * @returns {Promise<void|(() => void)>}
 */
export async function mount(container, ctx) {
  const state = {
    /** @type {object[]} The declared references, exactly as the router listed them. */
    credentials: [],
    /** @type {object[]|null} Providers, or null when they were not read. */
    providers: null,
    /** @type {string|null} Why providers are absent, when they are. */
    providersNote: null,
    /** @type {unknown} The failure that stopped the list from loading. */
    error: null,
  };

  // ------------------------------------------------------------- controls --
  //
  // The form controls are built once and re-inserted by every paint, rather
  // than rebuilt. Two reasons: a refresh in the middle of typing must not
  // discard what the operator has entered, and an `aria-live` region only
  // announces changes to a node the assistive technology was already watching —
  // a freshly created region with the text already in it announces nothing.

  const rotateSelect = el('select', { autocomplete: 'off' });
  const rotateSecret = secretInput();
  const rotateRepeat = secretInput();
  const rotateStatus = liveStatus();
  const rotateActions = el('div', { class: 'button-row' });

  const createId = el('input', {
    type: 'text',
    autocomplete: 'off',
    spellcheck: 'false',
    // The reference is an identifier, not a sentence; the browser should not
    // "helpfully" capitalize or correct it.
    autocapitalize: 'none',
    maxlength: '128',
  });
  const createSecret = secretInput();
  const createRepeat = secretInput();
  const createStatus = liveStatus();
  const createActions = el('div', { class: 'button-row' });

  // ------------------------------------------------------------- loading ---

  /**
   * Read the declared references.
   *
   * Sequential with the provider read on purpose: `api.request` aborts whatever
   * else is in flight unless the caller asks for a shared request, so two
   * concurrent reads would cancel one another.
   */
  async function loadCredentials() {
    const { data } = await ctx.api.get('/credentials');
    state.credentials = Array.isArray(data.data) ? data.data : [];
  }

  /**
   * Read the providers, to show which of them reference each credential.
   *
   * Supporting information, not the subject of the screen: a session that
   * cannot read it still gets a fully working screen, with the gap named. The
   * `credential_ref` on a provider is the reference only — specification 9.3
   * again — so nothing sensitive is being assembled here.
   */
  async function loadProviders() {
    if (!ctx.can('read_summary')) {
      state.providers = null;
      state.providersNote =
        'Which providers use a reference is not shown: this session does not hold read_summary.';
      return;
    }
    try {
      const { data } = await ctx.api.get('/providers');
      state.providers = Array.isArray(data.data) ? data.data : [];
      state.providersNote = null;
    } catch (error) {
      if (error && error.name === 'AbortError') {
        throw error;
      }
      state.providers = null;
      state.providersNote = `Which providers use a reference could not be read: ${describe(error)}`;
    }
  }

  /** Re-read everything and repaint. Used after every mutation. */
  async function refresh() {
    state.error = null;
    try {
      await loadCredentials();
      await loadProviders();
    } catch (error) {
      if (error && error.name === 'AbortError') {
        throw error;
      }
      state.error = error;
    }
    paint();
  }

  // -------------------------------------------------------------- actions --

  /**
   * Run a mutation and turn the one error the operator can act on into an
   * instruction.
   *
   * Everything else is re-raised for the shell's error boundary, which is the
   * only place that knows how to name an `ApiError`, its details, and its
   * request id.
   *
   * @param {HTMLElement} status
   * @param {() => Promise<void>} run
   */
  async function guarded(status, run) {
    try {
      await run();
    } catch (error) {
      if (error && error.name === 'AbortError') {
        return;
      }
      if (error instanceof ApiError && error.needsReauthentication) {
        // Specification 9.1: credential changes require a fresh authentication.
        // Nothing was applied, and the secret the operator typed is still in the
        // field, so the recovery is to sign in again and press the button.
        status.textContent =
          'The router requires a fresh sign-in before a credential change. Sign out, sign in again, and repeat this action. Nothing was changed.';
        ctx.notify('warn', 'Credential changes need a fresh sign-in; nothing was changed.');
        return;
      }
      throw error;
    }
  }

  /** Ask for confirmation, then rotate. */
  function beginRotation() {
    const id = rotateSelect.value;
    if (!id) {
      rotateStatus.textContent = 'Choose a credential reference to rotate.';
      rotateSelect.focus();
      return;
    }
    const secret = readSecret(rotateSecret, rotateRepeat, rotateStatus, 'new secret');
    if (secret === null) {
      return;
    }

    rotateStatus.textContent = '';
    replace(
      rotateActions,
      confirmPrompt({
        message: `Rotate the credential reference ${id}?`,
        detail:
          'Every provider that uses this reference must accept the new secret. The router keeps accepting the previous secret only for the overlap window it reports, and then stops.',
        confirmLabel: 'Rotate credential',
        onConfirm: () =>
          guarded(rotateStatus, async () => {
            // The identifier goes into the path unencoded and unmodified: it
            // comes from the router's own list, it is checked against the
            // rotation-addressable alphabet before the option is offered, and
            // the router does not percent-decode this path segment.
            const { data } = await ctx.api.post(
              `/credentials/${id}:rotate`,
              { secret },
            );
            wipe(rotateSecret, rotateRepeat);
            rotateStatus.textContent = rotationOutcome(id, data);
            ctx.notify('ok', `Rotation recorded for ${id}.`);
            await refresh();
            rotateSelect.focus();
          }),
        onCancel: () => {
          paintRotateActions();
          rotateStatus.textContent = 'Rotation cancelled. Nothing was changed.';
        },
      }),
    );
  }

  /** Ask for confirmation, then store a secret. */
  function beginCreate() {
    const id = createId.value.trim();
    if (!ID_GRAMMAR.test(id)) {
      createStatus.textContent =
        'A reference is 1 to 128 characters from A–Z, a–z, 0–9, dot, underscore, hyphen, and colon.';
      createId.focus();
      return;
    }
    const secret = readSecret(createSecret, createRepeat, createStatus, 'secret');
    if (secret === null) {
      return;
    }

    // Storing under an id the configuration already declares is a different
    // act from creating a new one, and the confirmation says which one it is.
    const existing = state.credentials.some((entry) => String(entry.id) === id);
    createStatus.textContent = '';
    replace(
      createActions,
      confirmPrompt({
        message: existing
          ? `Store a new secret under the existing reference ${id}?`
          : `Store a secret under the reference ${id}?`,
        detail: existing
          ? 'The active configuration already declares this reference. If you meant a two-phase change with an overlap window, cancel and use Rotate instead.'
          : 'The secret is write-only: neither this screen nor any endpoint can read it back. The reference appears in the table below only once the active configuration declares it.',
        confirmLabel: 'Store credential',
        onConfirm: () =>
          guarded(createStatus, async () => {
            const { data } = await ctx.api.post('/credentials', { id, secret });
            wipe(createSecret, createRepeat);
            createId.value = '';
            createStatus.textContent = creationOutcome(id, data);
            ctx.notify('ok', `Credential ${id} submitted.`);
            await refresh();
            createId.focus();
          }),
        onCancel: () => {
          paintCreateActions();
          createStatus.textContent = 'Cancelled. Nothing was stored.';
        },
      }),
    );
  }

  function paintRotateActions() {
    replace(
      rotateActions,
      actionButton('Rotate…', beginRotation, {
        disabled: rotateSelect.disabled,
        busyLabel: 'Rotating…',
      }),
    );
  }

  function paintCreateActions() {
    replace(createActions, actionButton('Store credential…', beginCreate, { busyLabel: 'Storing…' }));
  }

  // -------------------------------------------------------------- painting --

  /**
   * Rebuild the rotation options, keeping the current choice where it survives.
   *
   * @returns {string[]} The addressable references.
   */
  function refreshRotationOptions() {
    const previous = rotateSelect.value;
    const ids = state.credentials
      .map((entry) => String(entry.id === undefined || entry.id === null ? '' : entry.id))
      .filter((id) => id !== '' && ROTATABLE.test(id));
    replace(
      rotateSelect,
      ids.map((id) => el('option', { value: id }, id)),
    );
    rotateSelect.disabled = ids.length === 0;
    if (ids.includes(previous)) {
      rotateSelect.value = previous;
    }
    return ids;
  }

  /** Providers that name a given reference. @returns {object[]} */
  function usersOf(id) {
    if (!state.providers) {
      return [];
    }
    return state.providers.filter((provider) => String(provider.credential_ref || '') === id);
  }

  /** Provider references the active configuration does not declare. */
  function danglingReferences() {
    if (!state.providers) {
      return [];
    }
    const declared = new Set(state.credentials.map((entry) => String(entry.id)));
    const missing = new Map();
    for (const provider of state.providers) {
      const ref = String(provider.credential_ref || '');
      if (ref !== '' && !declared.has(ref)) {
        const list = missing.get(ref) || [];
        list.push(String(provider.id));
        missing.set(ref, list);
      }
    }
    return [...missing.entries()];
  }

  function referencesTable() {
    const columns = [
      {
        label: 'Reference',
        cell: (row) => el('span', { class: 'mono', text: String(row.id) }),
      },
      {
        label: 'Scope',
        cell: (row) => scopeCell(row.scope),
      },
      {
        label: 'Rotation interval',
        cell: (row) => text(interval(row.rotates_after_days)),
      },
      {
        label: 'Description',
        cell: (row) => text(row.description ? String(row.description) : '—'),
      },
    ];

    if (state.providers) {
      columns.push({
        label: 'Used by',
        cell: (row) => providerCell(usersOf(String(row.id))),
      });
    }

    columns.push({
      label: 'Action',
      cell: (row) => rotateCell(String(row.id)),
    });

    return table({
      caption: 'Credential references declared by the active configuration',
      columns,
      rows: state.credentials,
      empty:
        'The active configuration declares no credential references. Storing a secret below does not declare one — that is a configuration change — so this table stays empty until the configuration names a reference.',
    });
  }

  /** The per-row rotation shortcut. */
  function rotateCell(id) {
    if (!ROTATABLE.test(id)) {
      return el('span', {
        class: 'mono',
        text: 'not rotatable',
        title:
          'The rotation endpoint splits the path at the first colon, so a reference containing a colon cannot be addressed by it.',
      });
    }
    const button = el('button', { type: 'button', class: 'button button--quiet' }, 'Rotate');
    button.addEventListener('click', () => {
      rotateSelect.value = id;
      rotateStatus.textContent = `${id} selected. Enter the new secret.`;
      rotateSecret.focus();
    });
    return button;
  }

  function paint() {
    const ids = refreshRotationOptions();
    paintRotateActions();
    paintCreateActions();

    if (state.error) {
      // No forms while the list is unreadable. Storing a secret under a
      // reference the operator cannot see is how a secret ends up under a
      // mistyped name, and a rotation needs the list to address anything at all.
      render(container, [
        pageHeader(meta.title, meta.lede),
        banner('error', text(`The credential references could not be read: ${describe(state.error)}`)),
        card('Credential references', [
          el('p', {
            class: 'empty',
            text: 'Nothing is shown rather than a stale or partial list. Credential actions are unavailable until the list can be read.',
          }),
          buttonRow([actionButton('Try again', () => refresh(), { busyLabel: 'Loading…' })]),
        ]),
      ]);
      return;
    }

    const dangling = danglingReferences();

    render(container, [
      pageHeader(meta.title, meta.lede),

      dangling.length > 0
        ? banner(
            'warn',
            text(
              `Configured but not declared: ${dangling
                .map(([ref, providers]) => `${ref} (used by ${providers.join(', ')})`)
                .join('; ')}. These providers name a credential reference that the credential list does not contain.`,
            ),
          )
        : null,

      panel({
        title: 'Credential references',
        note: `Read from ${configLabel(ctx.session)}. Secrets are not part of this view and no endpoint returns one.`,
        actions: [actionButton('Refresh', () => refresh(), { tone: 'quiet', busyLabel: 'Reading…' })],
        content: [
          referencesTable(),
          state.providersNote ? el('p', { class: 'field__hint', text: state.providersNote }) : null,
        ],
      }),

      panel({
        title: 'Rotate a credential',
        note:
          'Two-phase: the router accepts the previous and the new secret together for the overlap window it reports, then only the new one.',
        content: [
          ids.length === 0
            ? emptyState(
                'No reference can be rotated',
                'Rotation addresses a reference that the active configuration declares. Nothing is declared, or every declared reference contains a colon, which the rotation endpoint cannot address.',
              )
            : null,
          field({
            id: 'credential-rotate-id',
            label: 'Credential reference',
            hint: 'Only references declared by the active configuration can be rotated.',
            control: rotateSelect,
          }),
          field({
            id: 'credential-rotate-secret',
            label: 'New secret',
            hint: 'Write-only. It is sent to the router and never read back, displayed, or stored by this page.',
            control: rotateSecret,
          }),
          field({
            id: 'credential-rotate-repeat',
            label: 'New secret again',
            hint: 'Typed twice because a mistyped secret fails only once the overlap window closes.',
            control: rotateRepeat,
          }),
          rotateActions,
          rotateStatus,
        ],
      }),

      panel({
        title: 'Store a credential',
        note:
          'Submits a secret under a reference. The reference itself is declared by configuration; storing a secret does not create one.',
        content: [
          field({
            id: 'credential-new-id',
            label: 'Reference',
            hint: 'The opaque handle configuration uses to name this credential, for example openai-prod. A–Z, a–z, 0–9, dot, underscore, hyphen, colon.',
            control: createId,
          }),
          field({
            id: 'credential-new-secret',
            label: 'Secret',
            hint: 'Write-only. It is sent to the router and never read back, displayed, or stored by this page.',
            control: createSecret,
          }),
          field({
            id: 'credential-new-repeat',
            label: 'Secret again',
            hint: 'Typed twice because nothing can read the stored value back to check it.',
            control: createRepeat,
          }),
          createActions,
          createStatus,
        ],
      }),

      card('Rotation history', [
        notAvailable(
          'Rotation history',
          ctx.can('read_audit')
            ? 'The credential list carries the configured rotation interval only — not when each reference was last rotated. Rotations are recorded as audit events, which the Audit screen shows.'
            : 'The credential list carries the configured rotation interval only — not when each reference was last rotated. Rotations are recorded as audit events, which need the read_audit permission to view.',
        ),
        ctx.can('read_audit')
          ? buttonRow([navigateButton('Open the audit log', () => ctx.navigate('/audit'))])
          : null,
      ]),
    ]);
  }

  // ---------------------------------------------------------------- start --

  // Awaited before the first paint, so the shell's loading state covers it and
  // the screen never appears half-populated.
  try {
    await loadCredentials();
    await loadProviders();
  } catch (error) {
    if (error && error.name === 'AbortError') {
      throw error;
    }
    state.error = error;
  }

  paint();

  // Leaving the screen clears the typed secrets. The nodes are detached and
  // eventually collected either way; clearing is cheap and does not depend on
  // when that happens.
  return () => {
    wipe(rotateSecret, rotateRepeat, createSecret, createRepeat);
  };
}

// ------------------------------------------------------------------ helpers -

/**
 * A masked input for a secret.
 *
 * `autocomplete="off"` and `name`-less by design: a provider API key is not the
 * operator's password, and a browser or extension that offers to remember it is
 * copying a credential into a store the router knows nothing about.
 *
 * @returns {HTMLInputElement}
 */
function secretInput() {
  return el('input', {
    type: 'password',
    autocomplete: 'off',
    autocapitalize: 'none',
    spellcheck: 'false',
    // Guards a paste of a whole file, not the router's limit: the body limit is
    // the router's to enforce and it reports it precisely.
    maxlength: '4096',
  });
}

/**
 * Name the configuration the list came from.
 *
 * The version and digest are what tie a reference the operator is looking at to
 * a specific activation (specification 11); when the session did not carry them,
 * the sentence says "the active configuration" rather than inventing a version.
 *
 * @param {object} session
 * @returns {string}
 */
function configLabel(session) {
  const version = session.config_version;
  const digest = session.config_digest;
  if (typeof version === 'number' && digest) {
    return `configuration v${version} · ${digest}`;
  }
  if (digest) {
    return `configuration ${digest}`;
  }
  return 'the active configuration';
}

/** A polite live region for the outcome of an action. */
function liveStatus() {
  return el('p', { class: 'secret__status', role: 'status', 'aria-live': 'polite' });
}

/**
 * Read a secret from a pair of fields, or explain why it was not read.
 *
 * @param {HTMLInputElement} first
 * @param {HTMLInputElement} second
 * @param {HTMLElement} status
 * @param {string} what
 * @returns {string|null}
 */
function readSecret(first, second, status, what) {
  const value = first.value;
  if (value === '') {
    status.textContent = `Enter the ${what}.`;
    first.focus();
    return null;
  }
  if (value !== value.trim()) {
    // Trimming silently would send a different secret from the one on screen.
    // Refusing says what is wrong and leaves the decision with the operator.
    status.textContent =
      'The secret begins or ends with whitespace. Remove it, or paste the value again — it is sent exactly as typed.';
    first.focus();
    return null;
  }
  if (value !== second.value) {
    status.textContent = 'The two secret fields do not match.';
    second.focus();
    return null;
  }
  return value;
}

/** Clear secret fields. @param {...HTMLInputElement} inputs */
function wipe(...inputs) {
  for (const input of inputs) {
    input.value = '';
  }
}

/**
 * Describe a rotation response without assuming its shape.
 *
 * @param {string} id
 * @param {object} data
 * @returns {string}
 */
function rotationOutcome(id, data) {
  if (!data || data.rotated !== true) {
    return `The router accepted the request for ${id} but did not confirm the rotation. Check the audit log before relying on the new secret.`;
  }
  const seconds = data.overlap_seconds;
  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) {
    return `${id} rotated. The router did not report an overlap window.`;
  }
  return `${id} rotated. The previous secret is accepted for a further ${formatDuration(seconds * 1000)}.`;
}

/**
 * Describe a creation response without assuming its shape.
 *
 * @param {string} id
 * @param {object} data
 * @returns {string}
 */
function creationOutcome(id, data) {
  if (!data || data.stored !== true) {
    return `The router accepted the request for ${id} but did not confirm storage. Check the audit log before relying on it.`;
  }
  return `Secret stored for ${id}. It appears in the table above only once the active configuration declares the reference.`;
}

/**
 * The configured rotation interval, stated as the router stated it.
 *
 * @param {unknown} days
 * @returns {string}
 */
function interval(days) {
  if (typeof days !== 'number' || !Number.isFinite(days)) {
    return '—';
  }
  if (days === 0) {
    return '0 — no interval declared';
  }
  return days === 1 ? '1 day' : `${days} days`;
}

/** The scope list, or an honest dash. @param {unknown} scope */
function scopeCell(scope) {
  if (!Array.isArray(scope) || scope.length === 0) {
    return el('span', {
      text: '—',
      title: 'The configuration declared no scope entries for this reference.',
    });
  }
  return el('span', { class: 'mono', text: scope.map((entry) => String(entry)).join(', ') });
}

/**
 * The providers using a reference.
 *
 * A reference nothing uses is worth seeing: it is either about to be needed or
 * it is a leftover, and both are decisions for the operator rather than for this
 * screen to smooth over.
 *
 * @param {object[]} providers
 * @returns {Node}
 */
function providerCell(providers) {
  if (providers.length === 0) {
    return pill('unused', 'warn');
  }
  const parts = [];
  providers.forEach((provider, index) => {
    if (index > 0) {
      parts.push(text(', '));
    }
    parts.push(el('span', { class: 'mono', text: String(provider.id) }));
    if (provider.enabled === false) {
      parts.push(text(' '), pill('disabled', 'neutral'));
    }
  });
  return el('span', {}, parts);
}

/**
 * A button that moves to another screen.
 *
 * Not `link` from `dom.js`: routing is on `location.hash`, and a plain `/audit`
 * href would leave the application.
 *
 * @param {string} label
 * @param {() => void} onClick
 * @returns {HTMLButtonElement}
 */
function navigateButton(label, onClick) {
  const button = el('button', { type: 'button', class: 'button button--quiet' }, label);
  button.addEventListener('click', onClick);
  return button;
}

/** One line an operator can act on, for an error shown inside the screen. */
function describe(error) {
  if (error instanceof ApiError) {
    const parts = [error.message];
    if (Array.isArray(error.details) && error.details.length > 0) {
      parts.push(error.details.map((detail) => String(detail)).join('; '));
    }
    if (error.requestId) {
      parts.push(`request ${error.requestId}`);
    }
    return parts.join(' — ');
  }
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return 'the router did not explain the failure';
}
