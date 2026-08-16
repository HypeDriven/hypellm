/**
 * DOM construction helpers.
 *
 * Specification 15.1: "Small DOM-construction functions or native custom
 * elements; **no HTML string injection**."
 *
 * That rule is why this module exists and why nothing in this application ever
 * touches `innerHTML`, `insertAdjacentHTML`, or `document.write`. Every node is
 * built with `createElement` and every piece of text with `createTextNode`, so
 * a value that arrives from the API — a target identifier, an audit reason, a
 * provider error code — is inserted as *text* and cannot become markup.
 *
 * The content security policy of specification 15.2 already forbids inline
 * script, so an injected `<script>` would not execute. But an injected
 * `<img onerror>` or a `javascript:` href would, under some policies, and the
 * defence that does not depend on getting the policy exactly right is not
 * building markup from strings at all.
 */

/**
 * Create an element.
 *
 * @param {string} tag
 * @param {object} [attributes] Attribute names to values. `class` and `text`
 *   are handled specially; `false`, `null`, and `undefined` omit the attribute.
 * @param {Array<Node|string>|Node|string} [children]
 * @returns {HTMLElement}
 */
export function el(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);

  for (const [name, value] of Object.entries(attributes)) {
    if (value === false || value === null || value === undefined) {
      continue;
    }
    if (name === 'class') {
      node.className = value;
    } else if (name === 'text') {
      node.textContent = String(value);
    } else if (name === 'dataset') {
      for (const [key, item] of Object.entries(value)) {
        node.dataset[key] = String(item);
      }
    } else if (name.startsWith('on') && typeof value === 'function') {
      // Listeners are attached, never written as attributes: specification
      // 15.1 forbids inline event handlers, and an `onclick` attribute is one
      // even when set from script.
      node.addEventListener(name.slice(2).toLowerCase(), value);
    } else if (value === true) {
      node.setAttribute(name, '');
    } else {
      node.setAttribute(name, String(value));
    }
  }

  append(node, children);
  return node;
}

/**
 * Append children, flattening arrays and converting strings to text nodes.
 *
 * @param {Node} parent
 * @param {Array<Node|string>|Node|string} children
 */
export function append(parent, children) {
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) {
    if (child === null || child === undefined || child === false) {
      continue;
    }
    if (Array.isArray(child)) {
      append(parent, child);
    } else if (child instanceof Node) {
      parent.appendChild(child);
    } else {
      parent.appendChild(document.createTextNode(String(child)));
    }
  }
}

/**
 * Replace an element's children.
 *
 * @param {Node} parent
 * @param {Array<Node|string>|Node|string} children
 */
export function replace(parent, children) {
  parent.replaceChildren();
  append(parent, children);
}

/** @param {string} value @returns {Text} */
export function text(value) {
  return document.createTextNode(String(value));
}

/**
 * A same-origin link.
 *
 * The scheme is checked rather than assumed: a `javascript:` or `data:` href
 * built from a value that came back from the API would be a script-execution
 * path even under a strict policy. Anything that is not a bare path becomes
 * plain text.
 *
 * @param {string} href
 * @param {string} label
 * @param {object} [attributes]
 * @returns {HTMLElement|Text}
 */
export function link(href, label, attributes = {}) {
  const path = String(href);
  if (!path.startsWith('/') || path.startsWith('//')) {
    return text(label);
  }
  return el('a', { href: path, ...attributes }, label);
}

/**
 * A status pill.
 *
 * @param {string} label
 * @param {'ok'|'warn'|'danger'|'neutral'} tone
 * @returns {HTMLElement}
 */
export function pill(label, tone = 'neutral') {
  const suffix = tone === 'neutral' ? '' : ` pill--${tone}`;
  return el('span', { class: `pill${suffix}` }, label);
}

/**
 * A definition-style key/value row.
 *
 * @param {string} label
 * @param {Node|string} value
 * @returns {DocumentFragment}
 */
export function fact(label, value) {
  const fragment = document.createDocumentFragment();
  fragment.appendChild(el('dt', { text: label }));
  fragment.appendChild(el('dd', {}, value));
  return fragment;
}

/**
 * Format a millisecond timestamp for display.
 *
 * @param {number|string} value
 * @returns {string}
 */
export function formatTime(value) {
  if (value === null || value === undefined || value === '') {
    return '—';
  }
  const millis = typeof value === 'number' ? value : Date.parse(value);
  if (!Number.isFinite(millis)) {
    return String(value);
  }
  return new Date(millis).toISOString().replace('T', ' ').replace('Z', 'Z');
}

/**
 * Format a count with thousands separators.
 *
 * @param {number} value
 * @returns {string}
 */
export function formatCount(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return '—';
  }
  return value.toLocaleString('en-GB');
}

/**
 * Format a duration in milliseconds.
 *
 * @param {number} millis
 * @returns {string}
 */
export function formatDuration(millis) {
  if (typeof millis !== 'number' || !Number.isFinite(millis)) {
    return '—';
  }
  if (millis < 1000) {
    return `${millis} ms`;
  }
  if (millis < 60_000) {
    return `${(millis / 1000).toFixed(1)} s`;
  }
  return `${Math.round(millis / 60_000)} min`;
}
