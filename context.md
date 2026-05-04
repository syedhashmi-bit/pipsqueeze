# CONTEXT.md — Project Background & Architecture Decisions

## What Problem This Solves
The owner runs a MikroTik router at home with a WireGuard VPN interface. Previously, managing VPN clients meant SSH-ing into the router and running commands manually. This dashboard replaces that with a web UI — similar to how Tailscale works but fully self-hosted and connecting directly to the MikroTik RouterOS API.

## Infrastructure
- **VPS**: Ubuntu 4GB RAM, Hetzner (Nuremberg)
- **Domain**: `vpn.syedhashmi.trade`
- **Router**: MikroTik (home network)
- **WireGuard interface name**: stored in `.env` as `MT_WIREGUARD_INTERFACE`
- **VPN subnet**: `10.10.0.0/24` — clients get IPs from `10.10.0.2` to `10.10.0.254`
- **Server public key, endpoint IP/port, DNS**: all in `.env`

## Architecture Decisions & Why

### Flask + SQLite (not Django, not Postgres)
Single-admin dashboard with low concurrency. SQLite is more than enough and has zero ops overhead. Flask keeps it minimal and easy to understand.

### MikroTik RouterOS API (not SSH)
The `routeros_api` Python library gives structured access to the router. SSH would require parsing text output which is fragile. The API returns proper dicts.

### Background Thread (not Celery, not cron)
A single daemon thread polling every 30s is the simplest solution for a single-server deployment. No Redis, no worker queue, no separate process to manage.

### Traffic Delta Tracking
MikroTik resets RX/TX counters on reboot. The monitor thread tracks `_prev_traffic` in memory and only adds the *difference* to `total_rx`/`total_tx` in the DB. If the counter resets (reboot), delta goes negative → `max(0, delta)` prevents negative values.

### Portal Tokens (not shared passwords)
Each client gets a unique `portal_token` (random URL-safe string). They visit `/portal/<token>` to download their config and QR code without needing a login. Rotating the token immediately invalidates the old link.

### Jinja2 Templates (not React/Vue)
Server-rendered HTML keeps the stack simple. JavaScript is used only for live updates (peers auto-refresh every 5s via `/peers` JSON endpoint), charts (Chart.js for sparklines), and the map (Leaflet.js).

### Geocoding via Nominatim (no API key)
OpenStreetMap's Nominatim is called directly from the browser JS — no server-side proxy needed, no API key, no cost. Rate limit is 1 req/sec which is fine for manual use.

### Notification Module (separate file)
`notifications.py` is a standalone module with no Flask dependency. It can be imported and called from both the Flask routes and the background thread without circular imports.

## Pages & Their Purpose
| Page | URL | Purpose |
|------|-----|---------|
| Login | `/login` | 2FA auth with rate limiting |
| Dashboard | `/` | Create clients, manage list, view stats |
| Peers | `/wireguard` | Live MikroTik peer status, ping, uptime |
| Security | `/security` | Login audit trail, locked IPs, whitelist |
| Notifications | `/notifications` | Discord/Email/Telegram alert settings |
| Report | `/weekly-report` | Weekly data usage and uptime summary |
| Map | `/map` | Geographic client distribution (Leaflet) |
| Logs | `/logs` | Full paginated activity log |
| Portal | `/portal/<token>` | Client self-serve (no login required) |

## API Endpoints (JSON)
| Endpoint | Returns |
|----------|---------|
| `/peers` | Live peer list from MikroTik |
| `/api/sys` | CPU, RAM, disk, uptime |
| `/api/mt-health` | MikroTik API reachability |
| `/api/traffic/<client>` | RX/TX history (hours param) |
| `/api/ping/<client>` | Ping history |
| `/api/uptime/<client>` | Uptime percentage |
| `/api/events/<client>` | Connect/disconnect events |
| `/api/send-digest` | Trigger weekly digest email |

## Known Quirks
- MikroTik peer IDs can be `.id` or `id` depending on API version — always use `get_peer_id()` helper in `mikrotik_api.py`
- Last handshake from MikroTik is formatted as `1h2m30s` — parsed with regex in `get_peers()`
- Peer is considered "Online" if last handshake < 120 seconds ago
- `filesizeformat` Jinja2 filter is used for RX/TX display in wireguard.html
- Flash messages use a `sessionStorage` key to prevent re-firing on browser refresh
- The wireguard page sorts peer rows while keeping expand rows bonded to their peer row as pairs
- VSCode flags Jinja2 `{{ }}` inside `<script>` tags as JS errors — these are false positives, the code works fine