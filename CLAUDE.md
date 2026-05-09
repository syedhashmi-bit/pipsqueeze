# CLAUDE.md

## Session Start

Always read CONTEXT.md and MEMORY.md at the start of every session 
before making any changes

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

PipSqueeze — a self-hosted WireGuard VPN management dashboard, like Tailscale but self-hosted — manages peers on a MikroTik router via the RouterOS API. Built in Python/Flask, deployed on a Ubuntu VPS via gunicorn + nginx.

## Deployment

- **Service**: `vpn-dashboard` (gunicorn systemd unit)
- **Project path**: `/var/www/pipsqueeze`
- **VPS**: any Ubuntu host (domain, hosting provider, and VM size are deployer's choice)
- **LAN subnet**: configurable via `LAN_SUBNET` env var (default `192.168.88.0/24` — MikroTik factory default)
- **VPN subnet**: `10.10.0.0/24` (clients get `.2` to `.254`)
- **Python venv**: `/var/www/pipsqueeze/venv`

## Service Commands

```bash
systemctl restart vpn-dashboard                    # restart after editing app.py, mikrotik_api.py, or notifications.py
systemctl status vpn-dashboard                     # check running state
journalctl -u vpn-dashboard -n 50 --no-pager      # view recent errors
```

HTML templates take effect immediately (Jinja2 reloads on request) — no restart needed.

## Python Environment

```bash
source /var/www/pipsqueeze/venv/bin/activate
python app.py                                      # run locally for testing
pip install <package>                              # install inside venv
```

## Git

```bash
git remote                                         # origin → git@github.com:syedhashmi-bit/pipsqueeze.git
git push                                           # push to main (SSH key at ~/.ssh/id_ed25519)
```

## Stack

- **Backend**: Python 3.12, Flask, SQLite (`vpn_dashboard.db`)
- **MikroTik**: `routeros_api` library → `mikrotik_api.py`
- **Frontend**: Jinja2 server-rendered HTML; JS only for live updates (`/peers` polls every 5s), Chart.js sparklines, Leaflet.js map
- **Auth**: Username/password + TOTP 2FA (pyotp), rate limiting, session timeout, IP whitelist
- **Notifications**: Discord webhook, SMTP email, Telegram bot — `notifications.py`
- **Design**: Tactical dark NOC aesthetic — electric cyan `#00c8ff`, neon green `#00ff9d`, deep navy background, Rajdhani + Share Tech Mono fonts from Google Fonts

## Architecture

### Key Files

| File | Purpose |
|------|---------|
| `app.py` | Flask app, all routes, background monitor thread |
| `mikrotik_api.py` | RouterOS API wrapper — connect, get_peers, add/delete/rename/enable/disable peers |
| `notifications.py` | Discord/Email/Telegram sender; no Flask dependency, safe to import from both routes and thread |
| `templates/login.html` | 2FA login page with rate limiting lockout display |
| `templates/index.html` | Main dashboard — create clients, manage list, stats, modals |
| `templates/wireguard.html` | Live peers page — ping, uptime, traffic sparklines, expand rows |
| `templates/security.html` | Login audit trail, locked IPs, IP whitelist info |
| `templates/notifications.html` | Discord/Email/Telegram alert channel settings |
| `templates/report.html` | Weekly digest — top users, uptime leaders, expiry warnings |
| `templates/map.html` | World map of client locations (Leaflet.js + OpenStreetMap) |
| `templates/portal.html` | Client self-serve portal (token-based, no login required) |
| `templates/logs.html` | Full paginated activity log |
| `templates/blocked.html` | IP whitelist rejection page (403) |
| `clients/` | WireGuard `.conf` files per client — **never read** |
| `qr_codes/` | QR code PNGs per client — **never read** |
| `vpn_dashboard.db` | SQLite DB — **never read** (contains credentials) |
| `.env` | All secrets — **never read** |
| `CONTEXT.md` | Architecture decisions, background, known quirks |
| `MEMORY.md` | Running log of features built, bugs fixed, and pending work |

### Background Monitor Thread

`_monitor_loop()` runs every 30 seconds in a daemon thread:
1. Polls MikroTik for all peers
2. Records traffic **deltas** (not cumulative) using `_prev_traffic` dict
3. Records connect/disconnect events and sends notifications
4. Records uptime status to `uptime_log` table
5. Pings online peers and records latency to `ping_history` table
6. Auto-disables expired clients on MikroTik + DB
7. Sends weekly digest email on configured weekday (`WEEKLY_DIGEST_DAY` env var)

The `_prev_states` and `_prev_traffic` module-level dicts must never be reset — they track state across loop iterations.

### Traffic Delta Tracking

MikroTik resets RX/TX counters on reboot. The monitor thread stores previous values in `_prev_traffic` and adds only the difference to `total_rx`/`total_tx` in the DB. `max(0, delta)` guards against negative values on router reboot.

### LAN Access Mode

Each client has an `access_mode` that controls what `AllowedIPs` is written into their `.conf` file:

| Mode | Value | AllowedIPs in .conf |
|------|-------|---------------------|
| `internet` | default | `0.0.0.0/0` |
| `lan` | LAN only | `192.168.88.0/24` |
| `full` | Full access | `0.0.0.0/0, 192.168.88.0/24` |

`AllowedIPs` is **client-side config only** — no MikroTik change is needed when mode changes. Regenerate the `.conf` and QR code when mode is updated via edit modal.

### Portal Tokens

Each client has a unique `portal_token`. Clients visit `/portal/<token>` to download their config/QR code without logging in. Rotating the token immediately invalidates the old link.

### Security

- Rate limiting: `MAX_LOGIN_ATTEMPTS` failed attempts trigger lockout for `LOCKOUT_MINUTES`
- Session timeout: `SESSION_TIMEOUT_MIN` inactivity → auto-logout
- IP whitelist: `IP_WHITELIST` env var (comma-separated); blank = allow all
- All security events logged to `login_audit` table

### Pages & API Routes

| Route | Purpose |
|-------|---------|
| `/` | Dashboard — create clients, manage list, stats |
| `/wireguard` | Live MikroTik peer status, ping, uptime |
| `/security` | Login audit, locked IPs, IP whitelist |
| `/notifications` | Discord/Email/Telegram alert settings |
| `/weekly-report` | Weekly usage and uptime summary |
| `/map` | Geographic client distribution (Leaflet.js) |
| `/logs` | Full paginated activity log |
| `/portal/<token>` | Client self-serve (no login required) |
| `/peers` | JSON — live peer list from MikroTik |
| `/api/sys` | JSON — CPU, RAM, disk, uptime |
| `/api/mt-health` | JSON — MikroTik API reachability |
| `/api/traffic/<client>` | JSON — RX/TX history |
| `/api/ping/<client>` | JSON — ping latency history |
| `/api/uptime/<client>` | JSON — 7-day uptime percentage |
| `/api/events/<client>` | JSON — connect/disconnect events |
| `/api/send-digest` | POST — trigger weekly digest email immediately |

## Database Schema

- `clients` — VPN clients (name, ip, tags, notes, location, lat, lon, expires_at, disabled, last_seen, total_rx, total_tx, portal_token, access_mode, created_at)
- `activity_logs` — All admin actions with timestamps
- `traffic_history` — RX/TX snapshots every 30s per peer
- `peer_events` — Connect/disconnect events
- `ping_history` — Latency per peer every 30s
- `uptime_log` — Online/offline status every 30s (used for 7-day rolling uptime %)
- `notifications` — Alert channel settings (one row: Discord/Email/Telegram config + per-event toggles)
- `login_attempts` — Rate limiting records per IP
- `login_audit` — Every login attempt with IP, username, result, reason

**DB migrations**: new columns must be added to both the `CREATE TABLE` statement and the `init_db()` migration block (`ALTER TABLE ... ADD COLUMN` guarded by PRAGMA column check).

## Environment Variables (.env)

```
# App
SECRET_KEY=
APP_USERNAME=
APP_PASSWORD=
TOTP_SECRET=

# WireGuard server
SERVER_PUBLIC_KEY=
SERVER_IP=
SERVER_PORT=
CLIENT_DNS=

# MikroTik API
MT_HOST=
MT_USERNAME=
MT_PASSWORD=
MT_PORT=
MT_WIREGUARD_INTERFACE=

# Security (optional — have defaults)
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_MINUTES=15
SESSION_TIMEOUT_MIN=30
IP_WHITELIST=

# Notifications (optional)
WEEKLY_DIGEST_DAY=monday
```

## Coding Rules

- **Never read `.env`, `vpn_dashboard.db`, `clients/`, or `qr_codes/`** — live credentials and private WireGuard keys
- Always restart the service after editing `app.py`, `mikrotik_api.py`, or `notifications.py`
- MikroTik peer IDs may be `id` or `.id` depending on API version — always use `get_peer_id()` helper
- Last handshake from MikroTik is formatted `1h2m30s` — parsed with regex; peer is "Online" if handshake < 120s ago
- Flash messages use a `sessionStorage` key trick to avoid re-firing on page refresh
- The wireguard page sorts (peer row, expand row) as bonded pairs — keep this invariant when touching sort logic
- All new DB columns go in both `CREATE TABLE` and the `init_db()` migration block
- Keep the tactical dark NOC design language consistent in all UI changes (cyan/green/navy, Rajdhani + Share Tech Mono)
- VSCode flags Jinja2 `{{ }}` inside `<script>` tags as JS errors — these are false positives, code works fine
- Geocoding uses OpenStreetMap Nominatim (browser-side JS, no API key, 1 req/sec rate limit)
- After any significant session, update `MEMORY.md` with what was changed
