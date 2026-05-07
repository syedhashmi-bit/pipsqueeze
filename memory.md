# MEMORY.md — PipSqueeze Running Decision Log

This file tracks what has been built, what was fixed, and important decisions made. Update this after significant changes so future Claude Code sessions have full context.

---

## Current State (as of May 2026)

### Features Implemented
- [x] WireGuard peer management via MikroTik RouterOS API
- [x] Client creation (generates WireGuard keys, config file, QR code)
- [x] Client list with search, tag filtering, pagination (20/page)
- [x] Client tags (comma-separated, filter buttons with counts)
- [x] Client notes field
- [x] Client expiry date with auto-disable via monitor thread
- [x] Client location (name + lat/lon) with Nominatim geocode lookup
- [x] Enable/disable clients from dashboard
- [x] Rename client (updates DB, MikroTik comment, files)
- [x] Clone client (new keys + IP, inherits tags/notes/expiry/location)
- [x] Delete client (removes from MikroTik + DB + files)
- [x] Bulk actions (enable/disable/delete multiple clients)
- [x] Regenerate WireGuard keys (keeps same IP)
- [x] Portal token per client — self-serve download page at `/portal/<token>`
- [x] Rotate portal token (invalidates old link)
- [x] 2FA login (TOTP via pyotp)
- [x] Login rate limiting (configurable max attempts + lockout duration)
- [x] Session timeout (configurable inactivity limit)
- [x] IP whitelist (via `.env`, blocks non-whitelisted IPs at both login and all routes)
- [x] Login audit trail (every attempt logged with IP, username, result, reason)
- [x] Security page (`/security`) — audit log, locked IPs, unlock button
- [x] Background monitor thread (30s polling)
- [x] Traffic delta tracking (survives MikroTik reboots)
- [x] Cumulative RX/TX per client in DB
- [x] Connect/disconnect event logging
- [x] Last seen timestamp (updated when peer is online)
- [x] Ping/latency monitoring (pings online peers every 30s)
- [x] Uptime % calculation (7-day rolling window from `uptime_log` table)
- [x] Auto-disable expired clients (monitor thread checks daily)
- [x] Expiry warning banner (clients expiring within 7 days)
- [x] Notification bell with count badge
- [x] Discord webhook notifications
- [x] Email (SMTP) notifications with Gmail App Password support
- [x] Telegram bot notifications
- [x] Per-event notification toggles (connect/disconnect/expiry/new/delete/regen)
- [x] Test notification button (fires without saving)
- [x] Weekly digest email (auto-sends on configured weekday)
- [x] Weekly report page with top users, uptime leaders, expiry warnings, connection events
- [x] World map view (Leaflet.js + OpenStreetMap, dark-filtered tiles)
- [x] VPS system stats (CPU, RAM, disk bars, uptime) — live update every 10s
- [x] MikroTik API health check with recheck button
- [x] Dark/light mode toggle (saved in localStorage)
- [x] Keyboard shortcuts: N (focus create field), R (open peers), Esc (close modals)
- [x] Auto-focus on modal open
- [x] Relative timestamps ("2h ago") with full timestamp on hover
- [x] Copy IP button per client
- [x] Rotate portal link button per client
- [x] Client search across name, IP, notes, tags, location
- [x] Export to CSV
- [x] Backup ZIP (includes DB + notification settings JSON)
- [x] Full activity log page with pagination
- [x] Unsaved changes guard on notifications page
- [x] Session timeout warning (2min toast before expiry, JS timer resets on activity)
- [x] Multi-interface support (MikroTik can have multiple WireGuard interfaces)
- [x] Live traffic sparklines per peer (Chart.js)
- [x] Expand row per peer (traffic chart + online/offline history)
- [x] Sort fix — peer rows and expand rows stay bonded when sorting wireguard table
- [x] IP blocked page (`blocked.html`) with `.env` instructions
- [x] Notification settings with unsaved-changes guard
- [x] LAN Access Mode per client — "Internet Only" (0.0.0.0/0), "LAN Only" (192.168.88.0/24), "Full Access" (both); stored as `access_mode` TEXT in clients table; three-button selector in create form and edit modal; badge in client list; shown in portal; clone inherits mode; regen and update_client respect/regenerate mode
- [x] PipSqueeze logo (`/static/logo.png`) — favicon + apple-touch-icon in all 10 templates; 80px centered above login h1; 32px in index.html topbar brand-row (replaces ⚡ emoji); og-image.png copy at `/static/og-image.png` for social preview
- [x] PWA manifest (`/static/manifest.json`) + service worker (`/static/sw.js`) — standalone display, cyan theme-color, apple-mobile-web-app meta tags in all templates; SW caches / + static assets; Flask route `/sw.js` serves with correct MIME type
- [x] Project folder renamed from `/var/www/vpn-dashboard` to `/var/www/pipsqueeze`; venv rebuilt (shebang paths); systemd service file updated; CLAUDE.md updated
- [x] Bandwidth quota per client — `quota_mb` column in clients table; quota amount + unit (MB/GB) in create form and edit modal; progress bar (green/yellow/red) in client list; auto-disable in monitor thread when quota exceeded; `notify_quota` notification toggle
- [x] Scheduled expiry reminders — monitor thread sends notification 3 days before client expires (once per day per client); `notify_expiry_reminder` toggle in notifications
- [x] Login failure notifications — sends alert on each failed login attempt with IP + attempt count; sends lockout alert when IP is locked out; `notify_login_failure` and `notify_login_locked` toggles
- [x] Auto-provision URLs — one-time links that create a WireGuard client on first visit (no login required); `provision_tokens` DB table; `/provision/manage` page; `provision.html` (shows config + QR), `provision_error.html`; inherits tags/access_mode/quota/expiry from token; `notify_provision` toggle; PROVISION button in topbar
- [x] Multi-user admin accounts — `admin_users` table with bcrypt-hashed passwords + roles (admin/viewer); default admin seeded from .env on first run; login route uses DB; `admin_required` decorator for write routes; USERS button (admin only) in topbar; `/admin/users` management page; role badge in topbar
- [x] MikroTik firewall rule sync — address-list approach: one DROP rule (`pipsqueeze-lan-block`) blocks "internet" mode clients from LAN; `add_to_lan_block`/`remove_from_lan_block` called on create/delete/toggle/bulk/provision/access_mode change; `sync_firewall_rules()` reconciles on monitor thread first run; firewall rule count in `/api/mt-health` response

---

## Bugs Fixed (chronological)

| Bug | Fix |
|-----|-----|
| access_mode column missing from existing DBs | Added to `init_db()` migration block — auto-migrates on startup |
| Delete client didn't remove peer from MikroTik | Added `mt.delete_peer_by_comment()` call before DB delete |
| Handshake parsing broke on `1h2m30s` format | Rewrote with regex for `(\d+)h`, `(\d+)m`, `(\d+)s` |
| Traffic totals inflated every 30s | Changed to delta tracking using `_prev_traffic` dict |
| Portal URL used fragile JS workaround | Now built server-side with `url_for()` and passed to template directly |
| Sort on wireguard page detached expand rows | Sort now builds (peer, expand) pairs and moves them together |
| Flash message re-fired on every page refresh | Added `sessionStorage` key check — fires only once per action |
| VSCode flagged Jinja in JS as errors | `data-key` attribute pattern for onclick; `html.validate.scripts: false` option |
| `psutil` missing on VPS after app.py update | `pip install psutil` inside venv |
| MikroTik "not enough permissions" on wireguard page | Router API user needed `read+write+api` policy group on MikroTik |
| `@anthropic/claude-code` 404 on npm | Correct package name is `@anthropic-ai/claude-code` |

---

## Design Decisions Made

| Decision | Reason |
|----------|--------|
| Tactical dark NOC aesthetic | Feels like real network infrastructure tooling, not generic web app |
| Rajdhani + Share Tech Mono font pairing | Sharp geometric display + monospace data — strong contrast |
| Electric cyan (#00c8ff) primary accent | Visible on dark, not as harsh as pure white, maps to "network/tech" |
| Neon green (#00ff9d) for online/healthy states | Universal "green = good" reinforced |
| No email for notifications initially | Added later — Telegram is simpler (no SMTP setup) |
| SQLite not Postgres | Single admin, low concurrency, zero ops overhead |
| Background thread not Celery | No Redis dependency, simpler deployment |
| Nominatim for geocoding | Free, no API key, works immediately |
| PAGE_SIZE = 20 | Reasonable default for client list pagination |

---

## Things NOT Done Yet (future work)

- [x] Mobile responsive overhaul (card layout for small screens)
- [x] Historical uptime chart — 7-day uptime bar chart in /wireguard expand-row; `/api/uptime-history/<client>` endpoint
- [x] Login attempt notifications (done — login_failure + login_locked toggles)
- [x] PWA support (manifest + service worker + meta tags)
- [x] Auto-provision URL
- [x] Bandwidth quota per client
- [x] Multi-user admin accounts
- [x] MikroTik firewall rule sync
- [x] Scheduled expiry reminders (3 days before)
- [ ] Auto-cleanup (delete never-connected clients after X days)
- [ ] API key access for external scripts
- [ ] WireGuard config import (register existing peers created outside dashboard)
- [ ] Historical uptime % chart (currently just current 7-day percentage)
- [ ] Drag to reorder clients
- [ ] Keyboard shortcut cheatsheet (`?` key)
- [ ] SMTP password encryption at rest (currently plaintext in SQLite)
- [ ] Scheduled expiry reminders (3 days before, not just day-of)

---

## How to Update This File

After any significant session, add entries under the relevant sections:
- New features → add to "Features Implemented" checklist
- Bugs encountered and fixed → add to "Bugs Fixed" table
- Architectural choices → add to "Design Decisions Made" table
- Incomplete work → move from "Not Done Yet" or add new items
