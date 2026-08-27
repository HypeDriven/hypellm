/**
 * The management API client.
 *
 * Specification 15.1: "Router, session state, API client, abort/cancellation,
 * error boundary."
 *
 * Three behaviours matter here:
 *
 * - **The CSRF token travels in a header, not a cookie.** Specification 9.1
 *   requires a session-bound token on every state-changing request. The token
 *   arrives in the `GET /admin/v1/session` body and is echoed in
 *   `X-HypeLLM-Csrf`; a page that cannot read the response cannot forge one.
 * - **Every request is abortable.** Navigating away cancels the in-flight
 *   request rather than letting a slow response paint over a screen the
 *   operator has already left.
 * - **Mutations carry `If-Match`.** Specification 15.4 requires it, and the
 *   client refuses to send a mutation without one rather than letting the
 *   server reject it after the operator has already committed to the change.
 */

/** Raised for any non-2xx management response. */
export class ApiError extends Error {
  /**
   * @param {number} status
   * @param {object} body
   */
  constructor(status, body) {
    const error = body && body.error ? body.error : {};
    super(error.message || `request failed with status ${status}`);
    this.name = 'ApiError';
    this.status = status;
    this.code = error.code || 'unknown';
    this.details = error.details || [];
    this.requestId = body ? body.request_id : undefined;
  }

  /** Whether the operator needs to sign in again. */
  get needsSignIn() {
    return this.status === 401;
  }

  /** Whether the action needs a fresher authentication. */
  get needsReauthentication() {
    return this.code === 'reauthentication_required';
  }

  /** Whether the resource changed under the operator. */
  get isStale() {
    return this.status === 412;
  }
}

const BASE = '/admin/v1';

/** The management API client. */
export class Api {
  constructor() {
    /** @type {string|null} */
    this.csrfToken = null;
    /** @type {AbortController|null} */
    this.inFlight = null;
  }

  /**
   * Cancel whatever is in flight.
   *
   * Called on navigation: a response that arrives for a screen the operator
   * has left must not paint over the one they are on.
   */
  abort() {
    if (this.inFlight) {
      this.inFlight.abort();
      this.inFlight = null;
    }
  }

  /**
   * Perform a request.
   *
   * @param {string} method
   * @param {string} path Relative to `/admin/v1`.
   * @param {object} [options]
   * @param {object} [options.body]
   * @param {string} [options.ifMatch]
   * @param {boolean} [options.shared] Do not cancel other in-flight requests.
   * @returns {Promise<{data: object, etag: string|null}>}
   */
  async request(method, path, { body, ifMatch, shared = false } = {}) {
    const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(method);

    if (mutating && !this.csrfToken) {
      throw new ApiError(403, {
        error: {
          code: 'csrf_required',
          message: 'the session is not established; reload the page',
        },
      });
    }

    const headers = { Accept: 'application/json' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (mutating) {
      headers['X-HypeLLM-Csrf'] = this.csrfToken;
    }
    if (ifMatch) {
      headers['If-Match'] = ifMatch;
    }

    let controller = null;
    if (!shared) {
      this.abort();
      controller = new AbortController();
      this.inFlight = controller;
    }

    let response;
    try {
      response = await fetch(`${BASE}${path}`, {
        method,
        headers,
        // The session cookie is `__Host-` scoped and same-origin; credentials
        // must be included explicitly for a cross-origin admin deployment.
        credentials: 'same-origin',
        redirect: 'error',
        cache: 'no-store',
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller ? controller.signal : undefined,
      });
    } catch (cause) {
      if (cause && cause.name === 'AbortError') {
        throw cause;
      }
      throw new ApiError(0, {
        error: { code: 'network', message: 'the router could not be reached' },
      });
    } finally {
      if (controller && this.inFlight === controller) {
        this.inFlight = null;
      }
    }

    const etag = response.headers.get('ETag');
    if (response.status === 204) {
      return { data: {}, etag };
    }

    let payload = null;
    const raw = await response.text();
    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch {
        throw new ApiError(response.status, {
          error: {
            code: 'malformed_response',
            message: 'the router returned a response that could not be parsed',
          },
        });
      }
    }

    if (!response.ok) {
      throw new ApiError(response.status, payload || {});
    }
    return { data: payload || {}, etag };
  }

  /** @param {string} path @param {object} [options] */
  get(path, options) {
    return this.request('GET', path, options);
  }

  /** @param {string} path @param {object} body */
  post(path, body) {
    return this.request('POST', path, { body });
  }

  /**
   * @param {string} path
   * @param {object} body
   * @param {string} ifMatch The resource's current ETag.
   */
  patch(path, body, ifMatch) {
    if (!ifMatch) {
      // Refusing here beats letting the server reject it after the operator
      // has already committed to the change.
      throw new ApiError(428, {
        error: {
          code: 'precondition_required',
          message: 'this change needs the resource to be re-read first',
        },
      });
    }
    return this.request('PATCH', path, { body, ifMatch });
  }

  /** @param {string} path */
  delete(path) {
    return this.request('DELETE', path);
  }

  /**
   * Load the session and remember its CSRF token.
   *
   * @returns {Promise<object>}
   */
  async session() {
    const { data } = await this.get('/session', { shared: true });
    this.csrfToken = data.csrf_token || null;
    return data;
  }

  /** Sign out. */
  async logout() {
    await this.post('/logout', {});
    this.csrfToken = null;
  }

  /**
   * Begin a sign-in and return the authorization URL.
   *
   * @param {string} returnPath
   * @returns {Promise<string>}
   */
  async beginSignIn(returnPath) {
    // Sign-in has no session yet, so it carries no CSRF token; the transaction
    // cookie plus the `state` parameter is what binds the callback.
    const response = await fetch(`${BASE}/auth/google/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      redirect: 'error',
      body: JSON.stringify({ return_path: returnPath }),
    });
    if (!response.ok) {
      throw new ApiError(response.status, await response.json().catch(() => ({})));
    }
    const data = await response.json();
    return data.authorization_url;
  }

  /**
   * Sign in with the preprovisioned break-glass token.
   *
   * Specification 22.4's recovery path, and the only sign-in that must keep
   * working when the identity provider does not. Like `beginSignIn` it runs
   * before any session exists, so it carries no CSRF token; unlike it, there
   * is no redirect and the session cookie arrives on this response.
   *
   * The token goes in the body and nowhere else. A query parameter would reach
   * the router's access log and the browser's history, and this client keeps
   * no copy of it after the call: the session cookie is what the browser holds
   * afterwards, and that is `HttpOnly`.
   *
   * @param {string} token
   * @param {string} reason
   * @returns {Promise<{csrf_token: string, expires_in_seconds: number}>}
   */
  /**
   * Sign in with a local username and password.
   *
   * The same shape as `breakGlassSignIn`: no CSRF token is sent because there
   * is no session to bind one to yet, and the router answers this endpoint
   * before it looks at a cookie. `credentials: 'same-origin'` is what lets the
   * browser keep the session cookie the response sets.
   *
   * @param {string} username
   * @param {string} password
   */
  async passwordSignIn(username, password) {
    const response = await fetch(`${BASE}/auth/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      redirect: 'error',
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) {
      throw new ApiError(response.status, await response.json().catch(() => ({})));
    }
    const data = await response.json();
    this.csrfToken = data.csrf_token || null;
    return data;
  }

  async breakGlassSignIn(token, reason) {
    const response = await fetch(`${BASE}/auth/break-glass`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      redirect: 'error',
      body: JSON.stringify({ token, reason }),
    });
    if (!response.ok) {
      throw new ApiError(response.status, await response.json().catch(() => ({})));
    }
    const data = await response.json();
    this.csrfToken = data.csrf_token || null;
    return data;
  }
}

/** The shared client instance. */
export const api = new Api();
