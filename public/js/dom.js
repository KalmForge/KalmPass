/**
 * Small DOM helpers.
 *
 * Note that nothing here accepts HTML. Every value goes in as `textContent`, so
 * a password or note containing markup is displayed, never parsed. Combined with
 * the Content-Security-Policy in `_headers`, which forbids inline script
 * entirely, there is no route from vault content to executed code.
 */

export function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;

    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = String(value);
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key in node && key !== "list" && key !== "type") node[key] = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }

  for (const child of [children].flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "object" ? child : document.createTextNode(String(child)));
  }
  return node;
}

export const $ = (selector, root = document) => root.querySelector(selector);

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function show(node, visible) {
  node.hidden = !visible;
}

/** Focus without the scroll jump that a hidden-then-shown panel otherwise causes. */
export function focus(node) {
  requestAnimationFrame(() => node?.focus({ preventScroll: true }));
}

export function relativeTime(timestamp) {
  if (!timestamp) return "never";
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  const units = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["week", 604_800],
    ["day", 86_400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [name, size] of units) {
    const n = Math.floor(seconds / size);
    if (n >= 1) return `${n} ${name}${n === 1 ? "" : "s"} ago`;
  }
  return "just now";
}

/** The hostname, for display and for matching an item against a site. */
export function hostOf(url) {
  if (!url) return "";
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0];
  }
}
