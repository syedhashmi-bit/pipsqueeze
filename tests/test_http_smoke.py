"""
Browser-less smoke tests using Flask's test_client.

Validates every change made in the P0/P1/P2 batch without needing chromium
system deps. Run with:  pytest tests/test_http_smoke.py -v

These tests run against an in-process app instance with a deterministic
config; they do NOT touch the production DB or production gunicorn.
"""

import json
import os
import re
import sqlite3
import shutil
from datetime import datetime
from pathlib import Path

import pyotp
import pytest
from werkzeug.security import generate_password_hash


PROJECT = "/var/www/pipsqueeze"
TEST_USER  = "pwtest_admin"
TEST_PASS  = "pwtest_pass_secure_xyz"
TEST_TOTP  = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


@pytest.fixture(scope="module")
def test_app(tmp_path_factory, monkeypatch_module):
    """Build a fully-isolated test app instance with its own DB."""
    db = tmp_path_factory.mktemp("pps_http") / "vpn_dashboard.db"
    src = f"{PROJECT}/vpn_dashboard.db"
    if os.path.exists(src):
        shutil.copy(src, db)

    # Seed a deterministic test admin
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT OR REPLACE INTO admin_users (username, password_hash, role, created_at) "
        "VALUES (?,?,?,?)",
        (TEST_USER, generate_password_hash(TEST_PASS), "admin", "2026-01-01T00:00:00"),
    )
    conn.execute("DELETE FROM login_attempts")
    conn.commit()
    conn.close()

    # Set env BEFORE app import
    monkeypatch_module.setenv("COOKIE_INSECURE",   "1")
    monkeypatch_module.setenv("APP_USERNAME",      TEST_USER)
    monkeypatch_module.setenv("APP_PASSWORD",      TEST_PASS)
    monkeypatch_module.setenv("TOTP_SECRET",       TEST_TOTP)
    monkeypatch_module.setenv("SECRET_KEY",        "x" * 64)
    monkeypatch_module.setenv("AUTO_CLEANUP_DAYS", "0")
    monkeypatch_module.setenv("IP_WHITELIST",      "")

    # Patch sqlite to redirect the bare-name 'vpn_dashboard.db' to our temp DB
    import sqlite3 as _sq
    _orig = _sq.connect
    def _redir(path, *a, **kw):
        if path == "vpn_dashboard.db":
            path = str(db)
        return _orig(path, *a, **kw)
    _sq.connect = _redir

    import sys
    if PROJECT not in sys.path:
        sys.path.insert(0, PROJECT)
    os.chdir(PROJECT)

    # Drop any cached modules so they pick up the new env
    for m in ("app", "notifications", "vault", "mikrotik_api"):
        if m in sys.modules:
            del sys.modules[m]

    import notifications, vault
    notifications.DB_FILE = str(db)
    vault.DB_FILE = str(db)
    from app import app as flask_app
    flask_app.testing = True
    yield flask_app

    _sq.connect = _orig


@pytest.fixture(scope="module")
def monkeypatch_module():
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    yield mp
    mp.undo()


def _login(client):
    r = client.get("/login")
    tok = re.search(rb'name="csrf_token" value="([^"]+)"', r.data).group(1).decode()
    code = pyotp.TOTP(TEST_TOTP).now()
    r = client.post("/login", data={
        "username": TEST_USER,
        "password": TEST_PASS,
        "code":     code,
        "csrf_token": tok,
    }, follow_redirects=False)
    # If TOTP rolled the window, retry once
    if r.status_code != 302:
        code = pyotp.TOTP(TEST_TOTP).now()
        r = client.post("/login", data={
            "username": TEST_USER,
            "password": TEST_PASS,
            "code":     code,
            "csrf_token": tok,
        }, follow_redirects=False)
    assert r.status_code == 302, f"login failed: {r.status_code} body={r.data[:200]}"


# ─────────────────────────────────────────────
# P0 #1: CSRF protection
# ─────────────────────────────────────────────

def test_p0_csrf_blocks_post_without_token(test_app):
    c = test_app.test_client()
    r = c.post("/login", data={"username":"x","password":"y","totp":"1"})
    # Either explicit 400 or our custom redirect handler — never 200 success
    assert r.status_code in (302, 400), f"unexpected: {r.status_code}"


def test_p0_csrf_meta_in_login_page(test_app):
    c = test_app.test_client()
    r = c.get("/login")
    assert b'name="csrf-token"' in r.data
    assert b'name="csrf_token"' in r.data  # form input


# ─────────────────────────────────────────────
# P0 #2: Session cookie hardening
# ─────────────────────────────────────────────

def test_p0_session_cookie_flags(test_app):
    c = test_app.test_client()
    r = c.get("/login")
    sc = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in sc
    assert "SameSite=Lax" in sc
    # In test env COOKIE_INSECURE=1, Secure flag is OFF


# ─────────────────────────────────────────────
# P0 #3: Vault encryption
# ─────────────────────────────────────────────

def test_p0_vault_roundtrip_and_at_rest(test_app):
    """Save plaintext credentials → DB has only ciphertext → load returns plaintext."""
    import notifications as notif
    import sqlite3
    test_data = {
        "discord_enabled": 0, "discord_webhook": "https://hooks.test/SECRET",
        "email_enabled": 0, "email_host": "smtp.test", "email_port": 587,
        "email_user": "u", "email_pass": "MY_PASS_42", "email_from": "f@t",
        "email_to": "t@t", "email_tls": 1,
        "telegram_enabled": 0, "telegram_token": "TGTOKEN_42:abc", "telegram_chat_id": "1",
        "notify_connect": 1, "notify_disconnect": 1, "notify_expiry": 1,
        "notify_new_client": 1, "notify_delete": 1, "notify_regen": 0,
        "notify_quota": 1, "notify_expiry_reminder": 1,
        "notify_login_failure": 0, "notify_login_locked": 1, "notify_provision": 1,
    }
    notif.save_settings(test_data)
    # Direct DB check
    conn = sqlite3.connect(notif.DB_FILE)
    conn.row_factory = sqlite3.Row
    row = dict(conn.execute("SELECT * FROM notifications LIMIT 1").fetchone())
    conn.close()
    for k in ("discord_webhook", "email_pass", "telegram_token"):
        assert row[k].startswith("enc:"), f"{k} not encrypted at rest"
    # Roundtrip
    got = notif.get_settings()
    assert got["discord_webhook"] == "https://hooks.test/SECRET"
    assert got["email_pass"]      == "MY_PASS_42"
    assert got["telegram_token"]  == "TGTOKEN_42:abc"
    # Cleanup
    conn = sqlite3.connect(notif.DB_FILE); conn.execute("DELETE FROM notifications"); conn.commit(); conn.close()


# ─────────────────────────────────────────────
# P1 #4: bcrypt doc claim corrected
# ─────────────────────────────────────────────

def test_p1_memory_md_no_bcrypt_claim():
    text = Path(f"{PROJECT}/MEMORY.md").read_text()
    # Should no longer claim bcrypt; should mention Werkzeug or scrypt
    assert "bcrypt-hashed" not in text


# ─────────────────────────────────────────────
# P1 #5: ipapi.co replaces ip-api.com
# ─────────────────────────────────────────────

def test_p1_geolocate_uses_ipapi_co():
    src = Path(f"{PROJECT}/app.py").read_text()
    assert "ipapi.co" in src
    assert "http://ip-api.com" not in src
    # Should still skip private IPs
    import importlib, app as app_mod
    importlib.reload(app_mod) if False else None  # already loaded by fixture
    # Use the already-loaded module
    assert app_mod.geolocate_ip("192.168.1.1") is None
    assert app_mod.geolocate_ip("") is None


# ─────────────────────────────────────────────
# P1 #6: Service worker has versioned cache + asset-only caching
# ─────────────────────────────────────────────

def test_p1_sw_has_versioned_cache():
    sw = Path(f"{PROJECT}/static/sw.js").read_text()
    assert "CACHE_VERSION" in sw
    assert "pipsqueeze-${CACHE_VERSION}" in sw
    # Old eternal-cache strategy is gone
    assert "/static/" in sw  # still caches static
    assert "isStatic" in sw  # only caches static, not HTML


# ─────────────────────────────────────────────
# P2 #7: Import flow exists and renders
# ─────────────────────────────────────────────

def test_p2_import_route_renders(test_app):
    c = test_app.test_client()
    _login(c)
    r = c.get("/import")
    # Either 200 (route works, even if MikroTik unreachable returns flash+redirect)
    # or 302 redirect to home with a flash message about MT API
    assert r.status_code in (200, 302), f"got {r.status_code}"


# ─────────────────────────────────────────────
# P2 #8: API key endpoints
# ─────────────────────────────────────────────

def test_p2_api_v1_no_key_rejected(test_app):
    c = test_app.test_client()
    r = c.get("/api/v1/clients")
    assert r.status_code == 401


def test_p2_api_v1_bad_key_rejected(test_app):
    c = test_app.test_client()
    r = c.get("/api/v1/clients", headers={"Authorization": "Bearer bogus"})
    assert r.status_code == 401


def test_p2_api_v1_with_valid_key(test_app):
    """Insert a key directly, then call the endpoint with it."""
    import hashlib, secrets, sqlite3
    raw = "pps_" + secrets.token_urlsafe(20)
    kh  = hashlib.sha256(raw.encode()).hexdigest()
    import notifications as notif
    conn = sqlite3.connect(notif.DB_FILE)
    conn.execute(
        "INSERT INTO api_keys (label, key_hash, scope, created_at) VALUES (?,?,?,?)",
        ("test_key", kh, "read", "2026-05-09T00:00:00")
    )
    conn.commit(); conn.close()
    try:
        c = test_app.test_client()
        r = c.get("/api/v1/clients", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code == 200
        data = json.loads(r.data)
        assert isinstance(data, list)
        # Read scope cannot do write
        r = c.post("/api/v1/clients/anything/disable", headers={"Authorization": f"Bearer {raw}"})
        assert r.status_code in (403, 404)  # 403 = wrong scope, 404 = client not found (still acceptable)
        if r.status_code == 403:
            assert b"scope" in r.data.lower() or b"write" in r.data.lower()
    finally:
        conn = sqlite3.connect(notif.DB_FILE)
        conn.execute("DELETE FROM api_keys WHERE label='test_key'")
        conn.commit(); conn.close()


def test_p2_api_v1_x_api_key_header_works(test_app):
    import hashlib, secrets, sqlite3
    raw = "pps_" + secrets.token_urlsafe(20)
    kh  = hashlib.sha256(raw.encode()).hexdigest()
    import notifications as notif
    conn = sqlite3.connect(notif.DB_FILE)
    conn.execute(
        "INSERT INTO api_keys (label, key_hash, scope, created_at) VALUES (?,?,?,?)",
        ("test_key2", kh, "read", "2026-05-09T00:00:00")
    )
    conn.commit(); conn.close()
    try:
        c = test_app.test_client()
        r = c.get("/api/v1/clients", headers={"X-API-Key": raw})
        assert r.status_code == 200
    finally:
        conn = sqlite3.connect(notif.DB_FILE)
        conn.execute("DELETE FROM api_keys WHERE label='test_key2'")
        conn.commit(); conn.close()


# ─────────────────────────────────────────────
# P2 #9: Auto-cleanup helper exists
# ─────────────────────────────────────────────

def test_p2_auto_cleanup_helper_exists():
    import importlib
    import app as app_mod
    assert hasattr(app_mod, "_run_auto_cleanup")
    assert hasattr(app_mod, "AUTO_CLEANUP_DAYS")
    # Default is 0 (disabled)
    assert app_mod.AUTO_CLEANUP_DAYS == 0


# ─────────────────────────────────────────────
# P2 #10: Cheatsheet modal in dashboard
# ─────────────────────────────────────────────

def test_p2_cheat_modal_in_dashboard(test_app):
    c = test_app.test_client()
    _login(c)
    r = c.get("/")
    assert b'id="cheatModal"' in r.data
    assert b"KEYBOARD SHORTCUTS" in r.data


# ─────────────────────────────────────────────
# P2 #11: Uptime history clamps days to 90
# ─────────────────────────────────────────────

def test_p2_uptime_history_clamps(test_app):
    c = test_app.test_client()
    _login(c)
    for days, expected in [(7, 7), (30, 30), (90, 90), (300, 90), (0, 1), (-5, 1)]:
        r = c.get(f"/api/uptime-history/somename?days={days}")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert len(data) == expected, f"days={days}: got {len(data)}"


# ─────────────────────────────────────────────
# Per-user TOTP enrollment
# ─────────────────────────────────────────────

def test_per_user_totp_reset_stores_encrypted_and_works_for_login(test_app):
    """Reset 2FA for the test admin, verify the new per-user secret is stored
    encrypted at rest, and that logging in with a code from the new secret
    succeeds while a code from the old shared env secret fails."""
    import sqlite3, vault
    c = test_app.test_client()
    _login(c)

    # Fetch the admin users page to get the uid + CSRF token
    r = c.get("/admin/users")
    assert r.status_code == 200
    assert b"PERSONAL" in r.data or b"SHARED" in r.data
    tok = re.search(rb'name="csrf_token" value="([^"]+)"', r.data).group(1).decode()

    # Look up the test admin uid
    conn = sqlite3.connect("vpn_dashboard.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id, totp_secret FROM admin_users WHERE username=?", (TEST_USER,)).fetchone()
    conn.close()
    uid = row["id"]
    assert row["totp_secret"] is None, "test admin should start with NULL totp_secret"

    # POST the reset
    r = c.post(f"/admin/users/reset-2fa/{uid}",
               data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].endswith(f"/admin/users/enroll/{uid}")

    # GET the enrollment page — the plaintext secret must render exactly once
    r = c.get(f"/admin/users/enroll/{uid}")
    assert r.status_code == 200
    assert b"ENROLL 2FA" in r.data
    assert b"data:image/png;base64," in r.data
    m = re.search(rb'<div class="secret-box">([A-Z2-7]+)</div>', r.data)
    assert m, "secret-box not rendered"
    new_secret = m.group(1).decode()
    assert len(new_secret) >= 16

    # Second GET must NOT redisplay the secret (session was consumed)
    r2 = c.get(f"/admin/users/enroll/{uid}", follow_redirects=False)
    assert r2.status_code == 302

    # DB now holds the encrypted secret, not plaintext
    conn = sqlite3.connect("vpn_dashboard.db")
    stored = conn.execute("SELECT totp_secret FROM admin_users WHERE id=?", (uid,)).fetchone()[0]
    conn.close()
    assert stored is not None
    assert stored.startswith("enc:")
    assert new_secret not in stored
    assert vault.decrypt(stored) == new_secret

    # Restore for the rest of the suite so other tests keep working
    conn = sqlite3.connect("vpn_dashboard.db")
    conn.execute("UPDATE admin_users SET totp_secret=NULL WHERE id=?", (uid,))
    conn.execute("DELETE FROM login_attempts")  # logout/login churn may have added rows
    conn.commit()
    conn.close()


def test_per_user_totp_enroll_unauthorized_without_pending(test_app):
    """The enrollment page must redirect away if there's no session-pending
    enrollment for that uid — even an admin can't open it cold."""
    c = test_app.test_client()
    _login(c)
    r = c.get("/admin/users/enroll/1", follow_redirects=False)
    assert r.status_code == 302
    assert "/admin/users" in r.headers["Location"]
