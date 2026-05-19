// PipSqueeze service worker.
// Bump CACHE_VERSION on every release so old assets get cleaned up.
const CACHE_VERSION = '2026-05-19a';
const CACHE = `pipsqueeze-${CACHE_VERSION}`;
const PRECACHE = ['/static/logo.png', '/static/manifest.json'];

self.addEventListener('install', e => {
    e.waitUntil(
        caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys().then(keys =>
            Promise.all(
                keys
                    .filter(k => k.startsWith('pipsqueeze-') && k !== CACHE)
                    .map(k => caches.delete(k))
            )
        ).then(() => self.clients.claim())
    );
});

// Network-first for everything dynamic. HTML pages must NEVER be cached
// because they embed per-session CSRF tokens — a stale cached page would
// post the wrong token and get rejected. Only static assets fall back to
// cache when the network is unavailable.
self.addEventListener('fetch', e => {
    if (e.request.method !== 'GET') return;
    const url = new URL(e.request.url);
    const isStatic = url.pathname.startsWith('/static/');
    if (!isStatic) {
        e.respondWith(fetch(e.request));
        return;
    }
    e.respondWith(
        fetch(e.request)
            .then(resp => {
                // Update cache opportunistically
                const copy = resp.clone();
                caches.open(CACHE).then(c => c.put(e.request, copy)).catch(() => {});
                return resp;
            })
            .catch(() => caches.match(e.request))
    );
});
