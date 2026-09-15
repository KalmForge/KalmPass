/**
 * A deliberately inert service worker.
 *
 * It exists so the vault can be installed as an app, and it caches nothing at
 * all, a stale copy of a password manager's own crypto code is a far worse
 * problem than a slow first paint, and an offline vault would be useless
 * anyway since the ciphertext lives on the server.
 */

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => event.respondWith(fetch(event.request)));
