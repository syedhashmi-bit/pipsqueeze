from mikrotik_api import MikroTikAPI
from flask import (Flask, render_template, request, send_file,
                   session, redirect, url_for, flash, jsonify,
                   Response, send_from_directory)
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps
import subprocess, os, re, sqlite3, qrcode, pyotp, shutil
import secrets, zipfile, threading, time, psutil, csv, io, json
import notifications as notif

load_dotenv()

app = Flask(__name__)
application = app
app.secret_key = os.getenv("SECRET_KEY")

USERNAME          = os.getenv("APP_USERNAME")
PASSWORD          = os.getenv("APP_PASSWORD")
TOTP_SECRET       = os.getenv("TOTP_SECRET")
SERVER_PUBLIC_KEY = os.getenv("SERVER_PUBLIC_KEY")
SERVER_IP         = os.getenv("SERVER_IP")
SERVER_PORT       = os.getenv("SERVER_PORT")
CLIENT_DNS        = os.getenv("CLIENT_DNS")

DB_FILE             = "vpn_dashboard.db"
BASE_IP             = "10.10.0."
PAGE_SIZE           = 20
MAX_LOGIN_ATTEMPTS  = int(os.getenv("MAX_LOGIN_ATTEMPTS",  "5"))
LOCKOUT_MINUTES     = int(os.getenv("LOCKOUT_MINUTES",     "15"))
SESSION_TIMEOUT_MIN = int(os.getenv("SESSION_TIMEOUT_MIN", "30"))
IP_WHITELIST_RAW    = os.getenv("IP_WHITELIST", "")
WEEKLY_DIGEST_DAY   = os.getenv("WEEKLY_DIGEST_DAY", "monday").lower()  # day to send digest


# ─────────────────────────────────────────────
# DB
# ─────────────────────────────────────────────

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT UNIQUE NOT NULL,
            ip           TEXT UNIQUE NOT NULL,
            notes        TEXT DEFAULT '',
            tags         TEXT DEFAULT '',
            location     TEXT DEFAULT '',
            lat          REAL DEFAULT NULL,
            lon          REAL DEFAULT NULL,
            expires_at   TEXT DEFAULT NULL,
            portal_token TEXT DEFAULT NULL,
            disabled     INTEGER DEFAULT 0,
            last_seen    TEXT DEFAULT NULL,
            total_rx     INTEGER DEFAULT 0,
            total_tx     INTEGER DEFAULT 0,
            access_mode  TEXT DEFAULT 'internet',
            created_at   TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            action     TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client      TEXT NOT NULL,
            rx          INTEGER DEFAULT 0,
            tx          INTEGER DEFAULT 0,
            recorded_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS peer_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client      TEXT NOT NULL,
            event       TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ping_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client      TEXT NOT NULL,
            latency_ms  REAL DEFAULT NULL,
            reachable   INTEGER DEFAULT 0,
            recorded_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS uptime_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client      TEXT NOT NULL,
            status      TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id                INTEGER PRIMARY KEY,
            discord_enabled   INTEGER DEFAULT 0,
            discord_webhook   TEXT    DEFAULT '',
            email_enabled     INTEGER DEFAULT 0,
            email_host        TEXT    DEFAULT '',
            email_port        INTEGER DEFAULT 587,
            email_user        TEXT    DEFAULT '',
            email_pass        TEXT    DEFAULT '',
            email_from        TEXT    DEFAULT '',
            email_to          TEXT    DEFAULT '',
            email_tls         INTEGER DEFAULT 1,
            telegram_enabled  INTEGER DEFAULT 0,
            telegram_token    TEXT    DEFAULT '',
            telegram_chat_id  TEXT    DEFAULT '',
            notify_connect    INTEGER DEFAULT 1,
            notify_disconnect INTEGER DEFAULT 1,
            notify_expiry     INTEGER DEFAULT 1,
            notify_new_client INTEGER DEFAULT 1,
            notify_delete     INTEGER DEFAULT 1,
            notify_regen      INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT NOT NULL,
            attempts     INTEGER DEFAULT 1,
            locked_until TEXT DEFAULT NULL,
            last_attempt TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_audit (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT NOT NULL,
            username   TEXT NOT NULL,
            success    INTEGER NOT NULL,
            reason     TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
    """)

    # Migrate existing DB columns
    existing = [r[1] for r in conn.execute("PRAGMA table_info(clients)").fetchall()]
    for col, defn in [
        ("notes",        "TEXT DEFAULT ''"),
        ("tags",         "TEXT DEFAULT ''"),
        ("location",     "TEXT DEFAULT ''"),
        ("lat",          "REAL DEFAULT NULL"),
        ("lon",          "REAL DEFAULT NULL"),
        ("expires_at",   "TEXT DEFAULT NULL"),
        ("portal_token", "TEXT DEFAULT NULL"),
        ("disabled",     "INTEGER DEFAULT 0"),
        ("last_seen",    "TEXT DEFAULT NULL"),
        ("total_rx",     "INTEGER DEFAULT 0"),
        ("total_tx",     "INTEGER DEFAULT 0"),
        ("access_mode",  "TEXT DEFAULT 'internet'"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {defn}")

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def is_valid_client_name(name):
    return re.match(r"^[a-zA-Z0-9_]+$", name)


def fmt_bytes(b):
    b = int(b or 0)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.2f} {unit}" if unit != "B" else f"{b} B"
        b /= 1024
    return f"{b:.2f} TB"


def get_clients(page=1, tag=None, search=None):
    conn   = get_db_connection()
    query  = "SELECT * FROM clients WHERE 1=1"
    params = []
    if tag:
        query  += " AND (',' || tags || ',') LIKE ?"
        params.append(f"%,{tag},%")
    if search:
        s = f"%{search}%"
        query  += " AND (name LIKE ? OR ip LIKE ? OR notes LIKE ? OR tags LIKE ? OR location LIKE ?)"
        params += [s, s, s, s, s]
    total = conn.execute(query.replace("SELECT *", "SELECT COUNT(*)"), params).fetchone()[0]
    query  += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params += [PAGE_SIZE, (page - 1) * PAGE_SIZE]
    clients = conn.execute(query, params).fetchall()
    conn.close()
    return clients, total


def get_all_clients():
    conn = get_db_connection()
    c = conn.execute("SELECT * FROM clients ORDER BY id DESC").fetchall()
    conn.close()
    return c


def get_all_tags():
    conn = get_db_connection()
    rows = conn.execute("SELECT tags FROM clients WHERE tags != '' AND tags IS NOT NULL").fetchall()
    conn.close()
    tag_counts = {}
    for row in rows:
        for t in row["tags"].split(","):
            t = t.strip()
            if t:
                tag_counts[t] = tag_counts.get(t, 0) + 1
    return sorted(tag_counts.items())


def get_client(name):
    conn = get_db_connection()
    c = conn.execute("SELECT * FROM clients WHERE name = ?", (name,)).fetchone()
    conn.close()
    return c


def get_activity_logs(limit=10):
    conn = get_db_connection()
    logs = conn.execute(
        "SELECT action, created_at FROM activity_logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return logs


def add_log(action):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO activity_logs (action, created_at) VALUES (?, ?)",
        (action, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    conn.commit()
    conn.close()


def get_next_ip():
    conn = get_db_connection()
    used = {r["ip"] for r in conn.execute("SELECT ip FROM clients").fetchall()}
    conn.close()
    for i in range(2, 255):
        ip = BASE_IP + str(i)
        if ip not in used:
            return ip
    return None


def build_allowed_ips(access_mode):
    if access_mode == 'lan':
        return "192.168.88.0/24"
    if access_mode == 'full':
        return "0.0.0.0/0, 192.168.88.0/24"
    return "0.0.0.0/0"


def add_client(name, ip, notes="", tags="", location="", lat=None, lon=None, expires_at=None, access_mode='internet'):
    token = secrets.token_urlsafe(24)
    conn  = get_db_connection()
    conn.execute(
        """INSERT INTO clients
           (name,ip,notes,tags,location,lat,lon,expires_at,portal_token,access_mode,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (name, ip, notes, tags, location, lat, lon, expires_at,
         token, access_mode, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    conn.commit()
    conn.close()
    return token


def record_traffic(client, rx, tx, delta_rx=0, delta_tx=0):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO traffic_history (client, rx, tx, recorded_at) VALUES (?, ?, ?, ?)",
        (client, int(rx or 0), int(tx or 0),
         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    if delta_rx > 0 or delta_tx > 0:
        conn.execute(
            "UPDATE clients SET total_rx=total_rx+?, total_tx=total_tx+? WHERE name=?",
            (int(delta_rx), int(delta_tx), client)
        )
    conn.commit()
    conn.close()


def record_event(client, event):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO peer_events (client, event, recorded_at) VALUES (?, ?, ?)",
        (client, event, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    conn.commit()
    conn.close()


def update_last_seen(client):
    conn = get_db_connection()
    conn.execute(
        "UPDATE clients SET last_seen=? WHERE name=?",
        (datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), client)
    )
    conn.commit()
    conn.close()


def record_ping(client, latency_ms, reachable):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO ping_history (client, latency_ms, reachable, recorded_at) VALUES (?,?,?,?)",
        (client, latency_ms, int(reachable),
         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    conn.commit()
    conn.close()


def record_uptime(client, status):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO uptime_log (client, status, recorded_at) VALUES (?,?,?)",
        (client, status, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    conn.commit()
    conn.close()


def get_uptime_percent(client, hours=168):  # 168h = 7 days
    conn  = get_db_connection()
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = conn.execute(
        "SELECT COUNT(*) FROM uptime_log WHERE client=? AND recorded_at>=?",
        (client, since)
    ).fetchone()[0]
    online = conn.execute(
        "SELECT COUNT(*) FROM uptime_log WHERE client=? AND status='Online' AND recorded_at>=?",
        (client, since)
    ).fetchone()[0]
    conn.close()
    if total == 0:
        return None
    return round((online / total) * 100, 1)


def get_latest_ping(client):
    conn = get_db_connection()
    row  = conn.execute(
        "SELECT latency_ms, reachable FROM ping_history WHERE client=? ORDER BY id DESC LIMIT 1",
        (client,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_traffic_history(client, hours=6):
    conn  = get_db_connection()
    since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows  = conn.execute(
        "SELECT rx, tx, recorded_at FROM traffic_history WHERE client=? AND recorded_at>=? ORDER BY id ASC",
        (client, since)
    ).fetchall()
    conn.close()
    return rows


def get_peer_events(client, limit=20):
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT event, recorded_at FROM peer_events WHERE client=? ORDER BY id DESC LIMIT ?",
        (client, limit)
    ).fetchall()
    conn.close()
    return rows


def ping_ip(ip):
    """Ping a single IP. Returns (reachable, latency_ms)."""
    try:
        # Extract host from CIDR notation if present
        host = ip.split("/")[0]
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=4
        )
        if result.returncode == 0:
            # Parse latency from ping output: "time=12.3 ms"
            match = re.search(r"time[=<](\d+\.?\d*)", result.stdout)
            if match:
                return True, float(match.group(1))
            return True, None
        return False, None
    except Exception:
        return False, None


def build_weekly_digest():
    """Build the weekly digest data dict for both email and HTML rendering."""
    since     = (datetime.utcnow() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S UTC")
    today     = datetime.utcnow().strftime("%Y-%m-%d")
    soon      = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d")
    conn      = get_db_connection()

    top_users = conn.execute("""
        SELECT client, SUM(rx) as week_rx, SUM(tx) as week_tx, SUM(rx+tx) as week_total
        FROM traffic_history WHERE recorded_at >= ?
        GROUP BY client ORDER BY week_total DESC LIMIT 10
    """, (since,)).fetchall()

    events = conn.execute("""
        SELECT client, event, COUNT(*) as count
        FROM peer_events WHERE recorded_at >= ?
        GROUP BY client, event ORDER BY client
    """, (since,)).fetchall()

    total    = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    disabled = conn.execute("SELECT COUNT(*) FROM clients WHERE disabled=1").fetchone()[0]
    expiring = conn.execute(
        "SELECT name, expires_at FROM clients WHERE expires_at IS NOT NULL "
        "AND expires_at >= ? AND expires_at <= ? AND disabled=0 ORDER BY expires_at",
        (today, soon)
    ).fetchall()

    # Uptime leaders
    all_clients = conn.execute("SELECT name FROM clients WHERE disabled=0").fetchall()
    uptime_data = []
    for c in all_clients:
        pct = get_uptime_percent(c["name"], hours=168)
        if pct is not None:
            uptime_data.append({"client": c["name"], "uptime": pct})
    uptime_data.sort(key=lambda x: x["uptime"], reverse=True)

    conn.close()

    return {
        "generated_at":    datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "period":          "Last 7 days",
        "total_clients":   total,
        "disabled_clients":disabled,
        "expiring_soon":   [{"name": r["name"], "expires_at": r["expires_at"]} for r in expiring],
        "top_users": [
            {"client": r["client"], "rx": fmt_bytes(r["week_rx"]),
             "tx": fmt_bytes(r["week_tx"]), "total": fmt_bytes(r["week_total"])}
            for r in top_users
        ],
        "connection_events": [
            {"client": r["client"], "event": r["event"], "count": r["count"]}
            for r in events
        ],
        "uptime_leaders": uptime_data[:10],
    }


def send_weekly_digest():
    """Send weekly digest via email if configured."""
    s = notif.get_settings()
    if not int(s.get("email_enabled", 0)) or not s.get("email_to"):
        return

    data    = build_weekly_digest()
    lines   = [
        f"VPN Dashboard — Weekly Digest ({data['period']})",
        f"Generated: {data['generated_at']}",
        "",
        f"OVERVIEW",
        f"  Total clients: {data['total_clients']}",
        f"  Disabled: {data['disabled_clients']}",
        f"  Expiring soon: {len(data['expiring_soon'])}",
        "",
    ]
    if data["expiring_soon"]:
        lines.append("EXPIRING SOON")
        for e in data["expiring_soon"]:
            lines.append(f"  {e['name']} — {e['expires_at']}")
        lines.append("")

    if data["top_users"]:
        lines.append("TOP DATA USERS")
        for u in data["top_users"]:
            lines.append(f"  {u['client']}: ↓{u['rx']} ↑{u['tx']} (total {u['total']})")
        lines.append("")

    if data["uptime_leaders"]:
        lines.append("UPTIME (7 DAYS)")
        for u in data["uptime_leaders"]:
            lines.append(f"  {u['client']}: {u['uptime']}%")
        lines.append("")

    body = "\n".join(lines)
    notif._send_email(s, "VPN Dashboard — Weekly Digest", body)
    add_log("Sent weekly digest email")


# ─────────────────────────────────────────────
# BACKGROUND MONITOR THREAD
# ─────────────────────────────────────────────

_prev_states  = {}
_prev_traffic = {}
_last_digest_day = None   # track which weekday we last sent a digest


def _monitor_loop():
    global _last_digest_day
    while True:
        try:
            mt = MikroTikAPI()
            mt.connect()
            peers = mt.get_peers()
            mt.disconnect()

            now_str  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            today_wd = datetime.utcnow().strftime("%A").lower()

            for peer in peers:
                name   = peer.get("comment") or ""
                status = peer.get("status", "Offline")
                rx     = int(peer.get("rx", 0) or 0)
                tx     = int(peer.get("tx", 0) or 0)
                ip     = peer.get("allowed-address", "")
                if not name:
                    continue

                # Traffic delta
                prev_rx, prev_tx = _prev_traffic.get(name, (rx, tx))
                delta_rx = max(0, rx - prev_rx)
                delta_tx = max(0, tx - prev_tx)
                _prev_traffic[name] = (rx, tx)
                record_traffic(name, rx, tx, delta_rx, delta_tx)

                # Status change events
                prev = _prev_states.get(name)
                if prev != status:
                    if status == "Online":
                        record_event(name, "connected")
                        update_last_seen(name)
                        notif.send_notification("connect", f"Peer '{name}' connected to VPN.")
                    elif prev == "Online":
                        record_event(name, "disconnected")
                        notif.send_notification("disconnect", f"Peer '{name}' disconnected from VPN.")
                    _prev_states[name] = status
                elif status == "Online":
                    update_last_seen(name)

                # Uptime log
                record_uptime(name, status)

                # Ping (only online peers to save time; offline peers are unreachable by definition)
                if status == "Online" and ip:
                    reachable, latency = ping_ip(ip)
                    record_ping(name, latency, reachable)

            # Auto-disable expired clients
            conn = get_db_connection()
            expired = conn.execute(
                "SELECT name FROM clients WHERE expires_at IS NOT NULL AND expires_at != '' "
                "AND expires_at <= ? AND disabled = 0",
                (now_str[:10],)
            ).fetchall()
            conn.close()

            for row in expired:
                cname = row["name"]
                try:
                    mt2 = MikroTikAPI()
                    mt2.connect()
                    mt2.disable_peer_by_name(cname)
                    mt2.disconnect()
                except Exception:
                    pass
                c2 = get_db_connection()
                c2.execute("UPDATE clients SET disabled=1 WHERE name=?", (cname,))
                c2.commit()
                c2.close()
                add_log(f"Auto-disabled expired client {cname}")
                notif.send_notification("expiry", f"Client '{cname}' has expired and was automatically disabled.")

            # Weekly digest — send on configured day, once per day
            if today_wd == WEEKLY_DIGEST_DAY and _last_digest_day != today_wd:
                _last_digest_day = today_wd
                try:
                    send_weekly_digest()
                except Exception:
                    pass

        except Exception:
            pass

        time.sleep(30)


# ─────────────────────────────────────────────
# SECURITY HELPERS
# ─────────────────────────────────────────────

def get_client_ip():
    return (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr or "unknown")


def get_ip_whitelist():
    if not IP_WHITELIST_RAW.strip():
        return set()
    return {ip.strip() for ip in IP_WHITELIST_RAW.split(",") if ip.strip()}


def is_ip_allowed(ip):
    wl = get_ip_whitelist()
    return True if not wl else ip in wl


def get_lockout_record(ip):
    conn = get_db_connection()
    row  = conn.execute("SELECT * FROM login_attempts WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return row


def is_locked_out(ip):
    row = get_lockout_record(ip)
    if not row or not row["locked_until"]:
        return False, None
    lu = datetime.strptime(row["locked_until"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() < lu:
        remaining = int((lu - datetime.utcnow()).total_seconds() / 60) + 1
        return True, remaining
    return False, None


def record_failed_attempt(ip):
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    row  = conn.execute("SELECT * FROM login_attempts WHERE ip=?", (ip,)).fetchone()
    if row:
        n = row["attempts"] + 1
        lu = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S") if n >= MAX_LOGIN_ATTEMPTS else None
        conn.execute("UPDATE login_attempts SET attempts=?,locked_until=?,last_attempt=? WHERE ip=?", (n, lu, now, ip))
    else:
        conn.execute("INSERT INTO login_attempts (ip,attempts,locked_until,last_attempt) VALUES (?,1,NULL,?)", (ip, now))
    conn.commit()
    conn.close()


def clear_attempts(ip):
    conn = get_db_connection()
    conn.execute("DELETE FROM login_attempts WHERE ip=?", (ip,))
    conn.commit()
    conn.close()


def record_login_audit(ip, username, success, reason=""):
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO login_audit (ip,username,success,reason,created_at) VALUES (?,?,?,?,?)",
        (ip, username, int(success), reason, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    )
    conn.commit()
    conn.close()


def check_session_timeout():
    last = session.get("last_active")
    if not last:
        return False
    return (datetime.utcnow() - datetime.fromisoformat(last)).total_seconds() > SESSION_TIMEOUT_MIN * 60


def touch_session():
    session["last_active"] = datetime.utcnow().isoformat()


# ─────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = get_client_ip()
        if not is_ip_allowed(ip):
            return render_template("blocked.html", reason="Your IP is not whitelisted.", ip=ip), 403
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        if check_session_timeout():
            session.clear()
            flash("Session expired. Please log in again.")
            return redirect(url_for("login"))
        touch_session()
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()
    if not is_ip_allowed(ip):
        return render_template("blocked.html", reason="Your IP is not whitelisted.", ip=ip), 403

    locked, lockout_mins = is_locked_out(ip)
    error = None

    if request.method == "POST":
        if locked:
            error = f"Locked out for {lockout_mins} more minute(s)."
        else:
            user = request.form.get("username", "").strip()
            pw   = request.form.get("password", "")
            code = request.form.get("code", "")
            if user == USERNAME and pw == PASSWORD:
                totp = pyotp.TOTP(TOTP_SECRET)
                if totp.verify(code):
                    clear_attempts(ip)
                    session["logged_in"]   = True
                    session["last_active"] = datetime.utcnow().isoformat()
                    session["login_ip"]    = ip
                    record_login_audit(ip, user, True)
                    add_log(f"Login from {ip}")
                    return redirect(url_for("home"))
                record_failed_attempt(ip)
                record_login_audit(ip, user, False, "Bad 2FA code")
                error = "Invalid 2FA code."
            else:
                record_failed_attempt(ip)
                record_login_audit(ip, user, False, "Bad credentials")
                error = "Invalid username or password."
            locked, lockout_mins = is_locked_out(ip)
            if locked:
                error = f"Too many failed attempts. Locked for {lockout_mins} minute(s)."

    return render_template("login.html", error=error, locked=locked, lockout_mins=lockout_mins)


@app.route("/logout")
def logout():
    ip = session.get("login_ip", get_client_ip())
    add_log(f"Logout from {ip}")
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# SECURITY PAGE
# ─────────────────────────────────────────────

@app.route("/security")
@login_required
def security_page():
    page  = int(request.args.get("page", 1))
    limit = 50
    conn  = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM login_audit").fetchone()[0]
    audit = conn.execute("SELECT * FROM login_audit ORDER BY id DESC LIMIT ? OFFSET ?",
                         (limit, (page-1)*limit)).fetchall()
    locks = conn.execute("SELECT * FROM login_attempts WHERE attempts>0 ORDER BY last_attempt DESC").fetchall()
    conn.close()
    return render_template("security.html",
        audit=audit, locks=locks, page=page,
        total_pages=max(1,(total+limit-1)//limit), total=total,
        whitelist=sorted(get_ip_whitelist()),
        current_ip=get_client_ip(),
        max_attempts=MAX_LOGIN_ATTEMPTS,
        lockout_mins=LOCKOUT_MINUTES,
        session_timeout=SESSION_TIMEOUT_MIN)


@app.route("/security/unlock/<ip_addr>", methods=["POST"])
@login_required
def unlock_ip(ip_addr):
    clear_attempts(ip_addr)
    add_log(f"Manually unlocked IP {ip_addr}")
    flash(f"IP {ip_addr} unlocked.")
    return redirect(url_for("security_page"))


@app.route("/security/clear-audit", methods=["POST"])
@login_required
def clear_audit():
    conn = get_db_connection()
    conn.execute("DELETE FROM login_audit")
    conn.commit()
    conn.close()
    add_log("Cleared login audit log")
    flash("Audit log cleared.")
    return redirect(url_for("security_page"))


# ─────────────────────────────────────────────
# MAIN DASHBOARD
# ─────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    config    = None
    public_key = None
    client    = None
    new_client_portal_url = None

    if request.method == "POST":
        client   = request.form["client"].strip()
        notes    = request.form.get("notes", "").strip()
        tags     = ",".join(t.strip() for t in request.form.get("tags","").split(",") if t.strip())
        location = request.form.get("location", "").strip()
        lat_str  = request.form.get("lat", "").strip()
        lon_str  = request.form.get("lon", "").strip()
        expires     = request.form.get("expires_at", "").strip() or None
        access_mode = request.form.get("access_mode", "internet")
        allowed_ips = build_allowed_ips(access_mode)
        lat = float(lat_str) if lat_str else None
        lon = float(lon_str) if lon_str else None

        if not is_valid_client_name(client):
            flash("Invalid name. Letters, numbers, underscores only.")
            return redirect(url_for("home"))
        if get_client(client):
            flash("A client with that name already exists.")
            return redirect(url_for("home"))

        client_ip = get_next_ip()
        if not client_ip:
            flash("No available IPs left in the pool.")
            return redirect(url_for("home"))

        private_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
        public_key  = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode().strip()

        config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = {CLIENT_DNS}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_IP}:{SERVER_PORT}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
        os.makedirs("clients",  exist_ok=True)
        os.makedirs("qr_codes", exist_ok=True)
        with open(f"clients/{client}.conf", "w") as f:
            f.write(config)
        qr = qrcode.make(config)
        qr.save(f"qr_codes/{client}.png")

        token = add_client(client, client_ip, notes, tags, location, lat, lon, expires,
                           access_mode=access_mode)
        new_client_portal_url = url_for("portal", token=token, _external=True)
        add_log(f"Created client {client}")
        notif.send_notification("new_client", f"New VPN client '{client}' created with IP {client_ip}.")

        try:
            mt = MikroTikAPI()
            mt.connect()
            mt.add_peer(public_key, f"{client_ip}/32", client)
            mt.disconnect()
        except Exception as e:
            flash(f"MikroTik error: {e}")

        flash(f"Client {client} created successfully")

    page   = int(request.args.get("page", 1))
    tag    = request.args.get("tag", "").strip() or None
    search = request.args.get("search", "").strip() or None

    clients, total_clients = get_clients(page=page, tag=tag, search=search)
    all_count = get_db_connection().execute("SELECT COUNT(*) FROM clients").fetchone()[0]
    used_ips  = all_count
    available = 253 - used_ips
    total_pages = max(1, (total_clients + PAGE_SIZE - 1) // PAGE_SIZE)
    activity_logs = get_activity_logs()
    all_tags = get_all_tags()

    soon  = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d")
    today = datetime.utcnow().strftime("%Y-%m-%d")
    conn_tmp = get_db_connection()
    expiring_soon = conn_tmp.execute(
        "SELECT name, expires_at FROM clients WHERE expires_at IS NOT NULL AND expires_at != '' "
        "AND expires_at >= ? AND expires_at <= ? AND disabled=0",
        (today, soon)
    ).fetchall()
    conn_tmp.close()

    mt_ok = False
    try:
        mt = MikroTikAPI(); mt.connect(); mt.disconnect(); mt_ok = True
    except Exception:
        pass

    sys_stats = {
        "cpu":    psutil.cpu_percent(interval=0.3),
        "ram":    psutil.virtual_memory().percent,
        "disk":   psutil.disk_usage("/").percent,
        "uptime": int(time.time() - psutil.boot_time()),
    }

    interfaces = []
    if mt_ok:
        try:
            mt2 = MikroTikAPI(); mt2.connect()
            interfaces = mt2.get_all_wireguard_interfaces()
            mt2.disconnect()
        except Exception:
            interfaces = [os.getenv("MT_WIREGUARD_INTERFACE", "Test-Wireguard")]

    return render_template("index.html",
        config=config, public_key=public_key, client=client,
        new_client_portal_url=new_client_portal_url,
        clients=clients, total_clients=total_clients,
        all_clients_count=all_count,
        used_ips=used_ips, available_ips=available,
        activity_logs=activity_logs, mt_ok=mt_ok,
        sys_stats=sys_stats, interfaces=interfaces,
        all_tags=all_tags, active_tag=tag,
        search=search or "", page=page, total_pages=total_pages,
        expiring_soon=expiring_soon,
        config_session_timeout=SESSION_TIMEOUT_MIN)


# ─────────────────────────────────────────────
# CLIENT ACTIONS
# ─────────────────────────────────────────────

@app.route("/download/<client>")
@login_required
def download(client):
    path = f"clients/{client}.conf"
    if not os.path.exists(path):
        flash("Config not found.")
        return redirect(url_for("home"))
    return send_file(path, as_attachment=True)


@app.route("/delete/<client>", methods=["POST"])
@login_required
def delete_client(client):
    mt_error = None
    try:
        mt = MikroTikAPI(); mt.connect()
        if not mt.delete_peer_by_comment(client):
            mt_error = f"Peer '{client}' not found on MikroTik."
        mt.disconnect()
    except Exception as e:
        mt_error = str(e)

    conn = get_db_connection()
    for tbl in ["clients","traffic_history","peer_events","ping_history","uptime_log"]:
        col = "name" if tbl == "clients" else "client"
        conn.execute(f"DELETE FROM {tbl} WHERE {col}=?", (client,))
    conn.commit(); conn.close()

    for f in [f"clients/{client}.conf", f"qr_codes/{client}.png"]:
        if os.path.exists(f): os.remove(f)

    add_log(f"Deleted client {client}")
    notif.send_notification("delete", f"VPN client '{client}' was deleted.")
    flash(f"Client {client} deleted." + (f" Note: {mt_error}" if mt_error else ""))
    return redirect(url_for("home"))


@app.route("/rename/<client>", methods=["POST"])
@login_required
def rename_client(client):
    new_name = request.form.get("new_name", "").strip()
    if not is_valid_client_name(new_name):
        flash("Invalid name."); return redirect(url_for("home"))
    if get_client(new_name):
        flash(f"'{new_name}' already taken."); return redirect(url_for("home"))

    try:
        mt = MikroTikAPI(); mt.connect()
        mt.rename_peer(client, new_name); mt.disconnect()
    except Exception as e:
        flash(f"MikroTik error: {e}"); return redirect(url_for("home"))

    for src, dst in [(f"clients/{client}.conf", f"clients/{new_name}.conf"),
                     (f"qr_codes/{client}.png",  f"qr_codes/{new_name}.png")]:
        if os.path.exists(src): os.rename(src, dst)

    conn = get_db_connection()
    conn.execute("UPDATE clients SET name=? WHERE name=?", (new_name, client))
    for tbl in ["traffic_history","peer_events","ping_history","uptime_log"]:
        conn.execute(f"UPDATE {tbl} SET client=? WHERE client=?", (new_name, client))
    conn.commit(); conn.close()

    add_log(f"Renamed {client} → {new_name}")
    flash(f"Renamed to {new_name}")
    return redirect(url_for("home"))


@app.route("/update/<client>", methods=["POST"])
@login_required
def update_client(client):
    notes       = request.form.get("notes", "").strip()
    tags        = ",".join(t.strip() for t in request.form.get("tags","").split(",") if t.strip())
    location    = request.form.get("location", "").strip()
    lat_str     = request.form.get("lat", "").strip()
    lon_str     = request.form.get("lon", "").strip()
    expires     = request.form.get("expires_at", "").strip() or None
    access_mode = request.form.get("access_mode", "internet")
    lat = float(lat_str) if lat_str else None
    lon = float(lon_str) if lon_str else None

    row = get_client(client)
    if row:
        old_mode = row["access_mode"] or "internet"
        if old_mode != access_mode:
            conf_path = f"clients/{client}.conf"
            if os.path.exists(conf_path):
                with open(conf_path, "r") as f:
                    old_conf = f.read()
                new_conf = re.sub(r"AllowedIPs\s*=.*", f"AllowedIPs = {build_allowed_ips(access_mode)}", old_conf)
                with open(conf_path, "w") as f:
                    f.write(new_conf)
                qr = qrcode.make(new_conf)
                qr.save(f"qr_codes/{client}.png")

    conn = get_db_connection()
    conn.execute(
        "UPDATE clients SET notes=?,tags=?,location=?,lat=?,lon=?,expires_at=?,access_mode=? WHERE name=?",
        (notes, tags, location, lat, lon, expires, access_mode, client)
    )
    conn.commit(); conn.close()
    add_log(f"Updated {client}")
    flash(f"Client {client} updated.")
    return redirect(url_for("home"))


@app.route("/clone/<client>", methods=["POST"])
@login_required
def clone_client(client):
    src = get_client(client)
    if not src:
        flash("Source not found."); return redirect(url_for("home"))

    new_name = request.form.get("new_name", "").strip()
    if not is_valid_client_name(new_name):
        flash("Invalid name."); return redirect(url_for("home"))
    if get_client(new_name):
        flash(f"'{new_name}' already taken."); return redirect(url_for("home"))

    client_ip = get_next_ip()
    if not client_ip:
        flash("No IPs left."); return redirect(url_for("home"))

    private_key  = subprocess.check_output("wg genkey", shell=True).decode().strip()
    public_key   = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode().strip()
    src_mode     = src["access_mode"] or "internet"
    allowed_ips  = build_allowed_ips(src_mode)

    config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = {CLIENT_DNS}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_IP}:{SERVER_PORT}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    os.makedirs("clients",  exist_ok=True)
    os.makedirs("qr_codes", exist_ok=True)
    with open(f"clients/{new_name}.conf", "w") as f:
        f.write(config)
    qr = qrcode.make(config)
    qr.save(f"qr_codes/{new_name}.png")

    add_client(new_name, client_ip, notes=src["notes"] or "", tags=src["tags"] or "",
               location=src["location"] or "", lat=src["lat"], lon=src["lon"],
               expires_at=src["expires_at"], access_mode=src_mode)

    try:
        mt = MikroTikAPI(); mt.connect()
        mt.add_peer(public_key, f"{client_ip}/32", new_name); mt.disconnect()
    except Exception as e:
        flash(f"MikroTik error: {e}")

    add_log(f"Cloned {client} → {new_name}")
    flash(f"Cloned as {new_name}")
    return redirect(url_for("home"))


@app.route("/toggle/<client>", methods=["POST"])
@login_required
def toggle_client(client):
    row = get_client(client)
    if not row:
        flash("Not found."); return redirect(url_for("home"))
    new_state = not bool(row["disabled"])
    try:
        mt = MikroTikAPI(); mt.connect()
        mt.disable_peer_by_name(client) if new_state else mt.enable_peer_by_name(client)
        mt.disconnect()
    except Exception as e:
        flash(f"MikroTik error: {e}"); return redirect(url_for("home"))
    conn = get_db_connection()
    conn.execute("UPDATE clients SET disabled=? WHERE name=?", (int(new_state), client))
    conn.commit(); conn.close()
    action = "Disabled" if new_state else "Enabled"
    add_log(f"{action} client {client}")
    flash(f"Client {client} {action.lower()}.")
    return redirect(url_for("home"))


@app.route("/bulk-action", methods=["POST"])
@login_required
def bulk_action():
    action  = request.form.get("bulk_action")
    clients = request.form.getlist("selected_clients")
    if not clients:
        flash("No clients selected."); return redirect(url_for("home"))
    if action not in ("enable","disable","delete"):
        flash("Unknown action."); return redirect(url_for("home"))

    results = []
    for name in clients:
        try:
            mt = MikroTikAPI(); mt.connect()
            if action == "enable":
                mt.enable_peer_by_name(name)
                conn = get_db_connection()
                conn.execute("UPDATE clients SET disabled=0 WHERE name=?", (name,))
                conn.commit(); conn.close()
            elif action == "disable":
                mt.disable_peer_by_name(name)
                conn = get_db_connection()
                conn.execute("UPDATE clients SET disabled=1 WHERE name=?", (name,))
                conn.commit(); conn.close()
            elif action == "delete":
                mt.delete_peer_by_comment(name)
                conn = get_db_connection()
                for tbl in ["clients","traffic_history","peer_events","ping_history","uptime_log"]:
                    col = "name" if tbl == "clients" else "client"
                    conn.execute(f"DELETE FROM {tbl} WHERE {col}=?", (name,))
                conn.commit(); conn.close()
                for f in [f"clients/{name}.conf", f"qr_codes/{name}.png"]:
                    if os.path.exists(f): os.remove(f)
            mt.disconnect()
            results.append(name)
        except Exception as e:
            flash(f"Error on {name}: {e}")

    add_log(f"Bulk {action}: {', '.join(results)}")
    flash(f"Bulk {action} applied to {len(results)} client(s).")
    return redirect(url_for("home"))


@app.route("/regen/<client>", methods=["POST"])
@login_required
def regen_client(client):
    row = get_client(client)
    if not row:
        flash("Not found."); return redirect(url_for("home"))
    client_ip   = row["ip"]
    access_mode = row["access_mode"] or "internet"
    allowed_ips = build_allowed_ips(access_mode)
    private_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
    public_key  = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode().strip()
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/24
DNS = {CLIENT_DNS}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
Endpoint = {SERVER_IP}:{SERVER_PORT}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    os.makedirs("clients",  exist_ok=True)
    os.makedirs("qr_codes", exist_ok=True)
    with open(f"clients/{client}.conf","w") as f: f.write(config)
    qr = qrcode.make(config); qr.save(f"qr_codes/{client}.png")
    try:
        mt = MikroTikAPI(); mt.connect()
        mt.delete_peer_by_comment(client)
        mt.add_peer(public_key, f"{client_ip}/32", client); mt.disconnect()
    except Exception as e:
        flash(f"MikroTik error: {e}"); return redirect(url_for("home"))
    add_log(f"Regenerated keys for {client}")
    notif.send_notification("regen", f"Keys regenerated for '{client}'.")
    flash(f"Keys regenerated for {client}.")
    return redirect(url_for("home"))


@app.route("/rotate-portal/<client>", methods=["POST"])
@login_required
def rotate_portal(client):
    new_token = secrets.token_urlsafe(24)
    conn = get_db_connection()
    conn.execute("UPDATE clients SET portal_token=? WHERE name=?", (new_token, client))
    conn.commit(); conn.close()
    add_log(f"Rotated portal token for {client}")
    flash(f"Portal link rotated for {client}.")
    return redirect(url_for("home"))


@app.route("/logs")
@login_required
def all_logs():
    page  = int(request.args.get("page",1))
    limit = 50
    conn  = get_db_connection()
    total = conn.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    logs  = conn.execute("SELECT action,created_at FROM activity_logs ORDER BY id DESC LIMIT ? OFFSET ?",
                         (limit,(page-1)*limit)).fetchall()
    conn.close()
    return render_template("logs.html", logs=logs, page=page,
                           total_pages=max(1,(total+limit-1)//limit), total=total)


# ─────────────────────────────────────────────
# QR / BACKUP / EXPORT
# ─────────────────────────────────────────────

@app.route("/qr/<client>")
@login_required
def qr_code(client):
    path = f"qr_codes/{client}.png"
    if not os.path.exists(path): return "QR not found", 404
    return send_file(path, mimetype="image/png")


@app.route("/backup")
@login_required
def backup():
    zip_path = "/tmp/vpn_backup.zip"
    with zipfile.ZipFile(zip_path,"w",zipfile.ZIP_DEFLATED) as zf:
        for folder in ["clients","qr_codes"]:
            if os.path.exists(folder):
                for fname in os.listdir(folder):
                    zf.write(f"{folder}/{fname}", f"{folder}/{fname}")
        if os.path.exists(DB_FILE): zf.write(DB_FILE, DB_FILE)
        ns = notif.get_settings()
        zf.writestr("notification_settings.json", json.dumps(ns, indent=2))
    add_log("Downloaded backup ZIP")
    return send_file(zip_path, as_attachment=True, download_name="vpn_backup.zip")


@app.route("/export-csv")
@login_required
def export_csv():
    clients = get_all_clients()
    def generate():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Name","IP","Tags","Notes","Location","Lat","Lon","Status",
                         "Expires","Last Seen","Total RX","Total TX","Created"])
        for c in clients:
            writer.writerow([c["name"],c["ip"],c["tags"] or "",c["notes"] or "",
                             c["location"] or "",c["lat"] or "",c["lon"] or "",
                             "Disabled" if c["disabled"] else "Enabled",
                             c["expires_at"] or "",c["last_seen"] or "Never",
                             fmt_bytes(c["total_rx"]),fmt_bytes(c["total_tx"]),c["created_at"]])
        yield output.getvalue()
    add_log("Exported CSV")
    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition":"attachment;filename=vpn_clients.csv"})


# ─────────────────────────────────────────────
# REPORTS & MAP
# ─────────────────────────────────────────────

@app.route("/weekly-report")
@login_required
def weekly_report():
    report = build_weekly_digest()
    add_log("Viewed weekly report")
    return render_template("report.html", report=report)


@app.route("/map")
@login_required
def map_view():
    """World map showing client locations."""
    conn = get_db_connection()
    clients = conn.execute(
        "SELECT name, ip, location, lat, lon, disabled, last_seen, total_rx, total_tx "
        "FROM clients WHERE lat IS NOT NULL AND lon IS NOT NULL"
    ).fetchall()
    conn.close()

    # Attach latest ping and uptime to each client
    map_clients = []
    for c in clients:
        ping  = get_latest_ping(c["name"])
        uptm  = get_uptime_percent(c["name"])
        map_clients.append({
            "name":     c["name"],
            "ip":       c["ip"],
            "location": c["location"] or "",
            "lat":      c["lat"],
            "lon":      c["lon"],
            "disabled": bool(c["disabled"]),
            "last_seen":c["last_seen"] or "",
            "total_rx": fmt_bytes(c["total_rx"]),
            "total_tx": fmt_bytes(c["total_tx"]),
            "ping_ms":  ping["latency_ms"] if ping else None,
            "reachable":bool(ping["reachable"]) if ping else False,
            "uptime":   uptm,
        })

    return render_template("map.html", clients=map_clients,
                           clients_json=json.dumps(map_clients))


# ─────────────────────────────────────────────
# WIREGUARD / PEERS
# ─────────────────────────────────────────────

@app.route("/peers")
@login_required
def peers_api():
    interface = request.args.get("interface", None)
    mt = MikroTikAPI(interface=interface)
    mt.connect(); data = mt.get_peers(); mt.disconnect()
    return jsonify(data)


@app.route("/wireguard")
@login_required
def wireguard():
    interface = request.args.get("interface", None)
    mt = MikroTikAPI(interface=interface)
    mt.connect()
    peers      = mt.get_peers()
    interfaces = mt.get_all_wireguard_interfaces()
    mt.disconnect()

    conn = get_db_connection()
    db_clients = {r["name"]:r for r in conn.execute("SELECT * FROM clients").fetchall()}
    conn.close()

    for peer in peers:
        name = peer.get("comment","")
        db   = db_clients.get(name)
        peer["notes"]       = db["notes"]     if db else ""
        peer["expires_at"]  = db["expires_at"] if db else ""
        peer["db_disabled"] = bool(db["disabled"]) if db else False
        peer["last_seen"]   = db["last_seen"] if db else None
        peer["tags"]        = db["tags"]      if db else ""
        peer["location"]    = db["location"]  if db else ""

        history = get_traffic_history(name, hours=1)
        peer["rx_history"] = [r["rx"] for r in history]
        peer["tx_history"] = [r["tx"] for r in history]
        peer["events"] = [{"event":e["event"],"time":e["recorded_at"]} for e in get_peer_events(name,10)]

        # Attach ping + uptime
        ping = get_latest_ping(name)
        peer["ping_ms"]  = ping["latency_ms"] if ping else None
        peer["reachable"]= bool(ping["reachable"]) if ping else False
        peer["uptime"]   = get_uptime_percent(name)

    selected_interface = interface or os.getenv("MT_WIREGUARD_INTERFACE","Test-Wireguard")
    return render_template("wireguard.html", peers=peers,
                           interfaces=interfaces, selected_interface=selected_interface)


@app.route("/wireguard/enable/<peer_id>", methods=["POST"])
@login_required
def enable_peer(peer_id):
    mt = MikroTikAPI(); mt.connect(); mt.enable_peer(peer_id); mt.disconnect()
    add_log(f"Enabled peer {peer_id}"); flash("Peer enabled")
    return redirect(url_for("wireguard"))


@app.route("/wireguard/disable/<peer_id>", methods=["POST"])
@login_required
def disable_peer(peer_id):
    mt = MikroTikAPI(); mt.connect(); mt.disable_peer(peer_id); mt.disconnect()
    add_log(f"Disabled peer {peer_id}"); flash("Peer disabled")
    return redirect(url_for("wireguard"))


# ─────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────

@app.route("/api/traffic/<client>")
@login_required
def api_traffic(client):
    hours = int(request.args.get("hours",6))
    rows  = get_traffic_history(client, hours=hours)
    return jsonify([{"rx":r["rx"],"tx":r["tx"],"t":r["recorded_at"]} for r in rows])


@app.route("/api/events/<client>")
@login_required
def api_events(client):
    rows = get_peer_events(client, limit=20)
    return jsonify([{"event":r["event"],"time":r["recorded_at"]} for r in rows])


@app.route("/api/ping/<client>")
@login_required
def api_ping(client):
    """Return ping history for the last N hours."""
    hours = int(request.args.get("hours",1))
    conn  = get_db_connection()
    since = (datetime.utcnow()-timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows  = conn.execute(
        "SELECT latency_ms,reachable,recorded_at FROM ping_history "
        "WHERE client=? AND recorded_at>=? ORDER BY id ASC",
        (client,since)
    ).fetchall()
    conn.close()
    return jsonify([{"ms":r["latency_ms"],"ok":bool(r["reachable"]),"t":r["recorded_at"]} for r in rows])


@app.route("/api/uptime/<client>")
@login_required
def api_uptime(client):
    hours = int(request.args.get("hours",168))
    return jsonify({"uptime": get_uptime_percent(client, hours=hours)})


@app.route("/api/sys")
@login_required
def api_sys():
    return jsonify({
        "cpu":    psutil.cpu_percent(interval=0.3),
        "ram":    psutil.virtual_memory().percent,
        "disk":   psutil.disk_usage("/").percent,
        "uptime": int(time.time()-psutil.boot_time()),
    })


@app.route("/api/mt-health")
@login_required
def api_mt_health():
    try:
        mt = MikroTikAPI(); mt.connect(); mt.disconnect()
        return jsonify({"ok":True})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})


# ─────────────────────────────────────────────
# CLIENT PORTAL
# ─────────────────────────────────────────────

@app.route("/portal/<token>")
def portal(token):
    conn = get_db_connection()
    row  = conn.execute("SELECT * FROM clients WHERE portal_token=?", (token,)).fetchone()
    conn.close()
    if not row: return "Invalid link.", 404
    return render_template("portal.html", client=row,
                           has_conf=os.path.exists(f"clients/{row['name']}.conf"))


@app.route("/portal/<token>/download")
def portal_download(token):
    conn = get_db_connection()
    row  = conn.execute("SELECT * FROM clients WHERE portal_token=?", (token,)).fetchone()
    conn.close()
    if not row: return "Invalid link.", 404
    path = f"clients/{row['name']}.conf"
    if not os.path.exists(path): return "Config not found.", 404
    return send_file(path, as_attachment=True)


@app.route("/portal/<token>/qr")
def portal_qr(token):
    conn = get_db_connection()
    row  = conn.execute("SELECT * FROM clients WHERE portal_token=?", (token,)).fetchone()
    conn.close()
    if not row: return "Invalid link.", 404
    path = f"qr_codes/{row['name']}.png"
    if not os.path.exists(path): return "QR not found.", 404
    return send_file(path, mimetype="image/png")


# ─────────────────────────────────────────────
# NOTIFICATIONS
# ─────────────────────────────────────────────

@app.route("/notifications")
@login_required
def notifications_page():
    return render_template("notifications.html", s=notif.get_settings())


@app.route("/notifications/save", methods=["POST"])
@login_required
def notifications_save():
    def ib(k): return 1 if request.form.get(k) else 0
    def sv(k,d=""): return request.form.get(k,d).strip()
    def iv(k,d=587):
        try: return int(request.form.get(k,d))
        except: return d

    data = {
        "discord_enabled":   ib("discord_enabled"),
        "discord_webhook":   sv("discord_webhook"),
        "email_enabled":     ib("email_enabled"),
        "email_host":        sv("email_host"),
        "email_port":        iv("email_port",587),
        "email_user":        sv("email_user"),
        "email_pass":        sv("email_pass"),
        "email_from":        sv("email_from"),
        "email_to":          sv("email_to"),
        "email_tls":         ib("email_tls"),
        "telegram_enabled":  ib("telegram_enabled"),
        "telegram_token":    sv("telegram_token"),
        "telegram_chat_id":  sv("telegram_chat_id"),
        "notify_connect":    ib("notify_connect"),
        "notify_disconnect": ib("notify_disconnect"),
        "notify_expiry":     ib("notify_expiry"),
        "notify_new_client": ib("notify_new_client"),
        "notify_delete":     ib("notify_delete"),
        "notify_regen":      ib("notify_regen"),
    }
    notif.save_settings(data)
    add_log("Updated notification settings")
    flash("Notification settings saved.")
    return redirect(url_for("notifications_page"))


@app.route("/notifications/test", methods=["POST"])
@login_required
def notifications_test():
    def ib(k): return 1 if request.form.get(k) else 0
    def sv(k,d=""): return request.form.get(k,d).strip()
    def iv(k,d=587):
        try: return int(request.form.get(k,d))
        except: return d

    data = {
        "discord_enabled":  ib("discord_enabled"),
        "discord_webhook":  sv("discord_webhook"),
        "email_enabled":    ib("email_enabled"),
        "email_host":       sv("email_host"),
        "email_port":       iv("email_port",587),
        "email_user":       sv("email_user"),
        "email_pass":       sv("email_pass"),
        "email_from":       sv("email_from"),
        "email_to":         sv("email_to"),
        "email_tls":        ib("email_tls"),
        "telegram_enabled": ib("telegram_enabled"),
        "telegram_token":   sv("telegram_token"),
        "telegram_chat_id": sv("telegram_chat_id"),
    }
    return jsonify(notif.test_all(data))


@app.route("/api/send-digest", methods=["POST"])
@login_required
def api_send_digest():
    try:
        send_weekly_digest()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


# ─────────────────────────────────────────────
# RESETS
# ─────────────────────────────────────────────

@app.route("/reset-db", methods=["POST"])
@login_required
def reset_db():
    conn = get_db_connection()
    for tbl in ["clients","traffic_history","peer_events","ping_history","uptime_log"]:
        conn.execute(f"DELETE FROM {tbl}")
    conn.commit(); conn.close()
    add_log("Reset dashboard database")
    flash("Database wiped.")
    return redirect(url_for("home"))


@app.route("/reset-all", methods=["POST"])
@login_required
def reset_all():
    try:
        mt = MikroTikAPI(); mt.connect(); mt.delete_dashboard_peers(); mt.disconnect()
    except Exception as e:
        flash(f"MikroTik reset error: {e}"); return redirect(url_for("home"))

    conn = get_db_connection()
    for tbl in ["clients","traffic_history","peer_events","ping_history","uptime_log"]:
        conn.execute(f"DELETE FROM {tbl}")
    conn.commit(); conn.close()

    for folder in ["clients","qr_codes"]:
        if os.path.exists(folder): shutil.rmtree(folder)

    add_log("Reset all")
    flash("Dashboard and MikroTik peers reset.")
    return redirect(url_for("home"))


# ─────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────

init_db()
monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
monitor_thread.start()

if __name__ == "__main__":
    app.run(debug=True)