/* PipSqueeze — shared transition runtime. Loaded into every template.
   - Adds a top progress bar that runs during form submissions.
   - Upgrades any existing `showToast()` into a class-driven animated toast
     without changing the call sites.
   - No-ops gracefully under prefers-reduced-motion (CSS handles that side). */
(function () {
    'use strict';

    var reduced =
        window.matchMedia &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // ---------- Top progress bar ----------
    function ensureBar() {
        var bar = document.getElementById('pip-progress');
        if (bar) return bar;
        bar = document.createElement('div');
        bar.id = 'pip-progress';
        // Inject as early as possible.
        (document.body || document.documentElement).appendChild(bar);
        return bar;
    }

    var barTimer = null;
    function startProgress() {
        if (reduced) return;
        var bar = ensureBar();
        bar.classList.add('run');
        // Reset width, then animate to a "loading" plateau. The page will
        // navigate before we hit 100% — that's intended.
        bar.style.width = '0';
        // Force reflow so the next width change animates.
        // eslint-disable-next-line no-unused-expressions
        bar.offsetWidth;
        bar.style.width = '70%';
        clearTimeout(barTimer);
        barTimer = setTimeout(function () {
            bar.style.width = '92%';
        }, 700);
    }
    function finishProgress() {
        var bar = document.getElementById('pip-progress');
        if (!bar) return;
        clearTimeout(barTimer);
        bar.style.width = '100%';
        setTimeout(function () {
            bar.classList.remove('run');
            bar.style.width = '0';
        }, 220);
    }

    // Fire on POST form submits (state-changing operations) and on any
    // link click that leaves the current document.
    document.addEventListener('submit', function (e) {
        var f = e.target;
        if (!f || f.tagName !== 'FORM') return;
        // Skip forms that explicitly opt out (e.g. JS-handled).
        if (f.hasAttribute('data-no-progress')) return;
        startProgress();
    }, true);

    document.addEventListener('click', function (e) {
        var a = e.target && e.target.closest && e.target.closest('a[href]');
        if (!a) return;
        // Modifier keys → new tab, not in-page nav.
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        if (a.target && a.target !== '' && a.target !== '_self') return;
        var href = a.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
        // Only show progress for same-origin navigations.
        try {
            var u = new URL(a.href, window.location.href);
            if (u.origin !== window.location.origin) return;
            if (u.pathname === window.location.pathname && u.search === window.location.search) return;
        } catch (_) { return; }
        startProgress();
    }, true);

    // Clear bar when the page is restored from bfcache or when navigation
    // gets cancelled by the user.
    window.addEventListener('pageshow', finishProgress);
    window.addEventListener('load', finishProgress);

    // ---------- Toast upgrade ----------
    // Wait for DOMContentLoaded so the template's own showToast definition
    // has been parsed, then wrap it with class-driven animation.
    function upgradeToast() {
        var original = window.showToast;
        if (typeof original !== 'function') return;

        var hideTimer = null;
        window.showToast = function (msg, isErr) {
            var t = document.getElementById('toast');
            if (!t) {
                // Fall back to original if no toast element on this page.
                return original.call(this, msg, isErr);
            }
            t.innerText = msg;
            t.className = 'toast' + (isErr ? ' err' : '');
            // Force a frame before adding .show so the keyframe replays
            // on rapid back-to-back toasts.
            t.style.display = 'block';
            t.classList.remove('show', 'hide');
            // eslint-disable-next-line no-unused-expressions
            t.offsetWidth;
            t.classList.add('show');

            clearTimeout(hideTimer);
            hideTimer = setTimeout(function () {
                t.classList.remove('show');
                t.classList.add('hide');
                // After the exit animation, actually hide it.
                setTimeout(function () {
                    if (!t.classList.contains('show')) {
                        t.style.display = 'none';
                        t.classList.remove('hide');
                    }
                }, 220);
            }, 3600);
        };
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', upgradeToast);
    } else {
        upgradeToast();
    }

    // ---------- View Transition fallback hint ----------
    // For browsers that DO support the View Transitions API but want a
    // same-document animated state change (e.g. theme toggle, hamburger),
    // expose a tiny helper so other scripts can opt in without re-implementing.
    window.pipViewTransition = function (mutator) {
        if (reduced || !document.startViewTransition) {
            mutator();
            return;
        }
        document.startViewTransition(mutator);
    };
})();
