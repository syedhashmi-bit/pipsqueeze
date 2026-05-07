"""
notifications.py
Handles sending alerts via Discord webhook, Email (SMTP), and Telegram bot.
Settings are stored in the DB (notifications table).
"""

import sqlite3, smtplib, urllib.request, urllib.parse, json, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

DB_FILE = "vpn_dashboard.db"


# ─────────────────────────────────────────────
# DB HELPERS
# ─────────────────────────────────────────────

def get_settings():
    """Return notification settings as a dict. Returns defaults if not set."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM notifications LIMIT 1").fetchone()
    conn.close()
    if row:
        return dict(row)
    return {
        # Discord
        "discord_enabled": 0,
        "discord_webhook":  "",
        # Email
        "email_enabled":    0,
        "email_host":       "",
        "email_port":       587,
        "email_user":       "",
        "email_pass":       "",
        "email_from":       "",
        "email_to":         "",
        "email_tls":        1,
        # Telegram
        "telegram_enabled": 0,
        "telegram_token":   "",
        "telegram_chat_id": "",
        # Events to notify on
        "notify_connect":          1,
        "notify_disconnect":       1,
        "notify_expiry":           1,
        "notify_new_client":       1,
        "notify_delete":           1,
        "notify_regen":            0,
        "notify_quota":            1,
        "notify_expiry_reminder":  1,
        "notify_login_failure":    0,
        "notify_login_locked":     1,
        "notify_provision":        1,
    }


def save_settings(data: dict):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM notifications")
    conn.execute("""
        INSERT INTO notifications (
            discord_enabled, discord_webhook,
            email_enabled, email_host, email_port,
            email_user, email_pass, email_from, email_to, email_tls,
            telegram_enabled, telegram_token, telegram_chat_id,
            notify_connect, notify_disconnect, notify_expiry,
            notify_new_client, notify_delete, notify_regen,
            notify_quota, notify_expiry_reminder,
            notify_login_failure, notify_login_locked, notify_provision
        ) VALUES (
            :discord_enabled, :discord_webhook,
            :email_enabled, :email_host, :email_port,
            :email_user, :email_pass, :email_from, :email_to, :email_tls,
            :telegram_enabled, :telegram_token, :telegram_chat_id,
            :notify_connect, :notify_disconnect, :notify_expiry,
            :notify_new_client, :notify_delete, :notify_regen,
            :notify_quota, :notify_expiry_reminder,
            :notify_login_failure, :notify_login_locked, :notify_provision
        )
    """, data)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# SENDERS
# ─────────────────────────────────────────────

def _send_discord(webhook_url: str, message: str) -> tuple[bool, str]:
    try:
        payload = json.dumps({"content": message}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            if resp.status in (200, 204):
                return True, "OK"
            return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)


def _send_telegram(token: str, chat_id: str, message: str) -> tuple[bool, str]:
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = json.dumps({
            "chat_id":    chat_id,
            "text":       message,
            "parse_mode": "HTML"
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                return True, "OK"
            return False, result.get("description", "Unknown error")
    except Exception as e:
        return False, str(e)


def _send_email(settings: dict, subject: str, body: str) -> tuple[bool, str]:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = settings["email_from"]
        msg["To"]      = settings["email_to"]
        msg.attach(MIMEText(body, "plain"))

        port = int(settings.get("email_port", 587))
        use_tls = bool(int(settings.get("email_tls", 1)))

        if use_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(settings["email_host"], port, timeout=10) as server:
                server.ehlo()
                server.starttls(context=ctx)
                server.login(settings["email_user"], settings["email_pass"])
                server.sendmail(settings["email_from"], settings["email_to"], msg.as_string())
        else:
            with smtplib.SMTP_SSL(settings["email_host"], port, timeout=10) as server:
                server.login(settings["email_user"], settings["email_pass"])
                server.sendmail(settings["email_from"], settings["email_to"], msg.as_string())

        return True, "OK"
    except Exception as e:
        return False, str(e)


# ─────────────────────────────────────────────
# MAIN DISPATCH
# ─────────────────────────────────────────────

def send_notification(event: str, message: str, subject: str = None):
    """
    Send a notification for the given event type.
    event: 'connect' | 'disconnect' | 'expiry' | 'new_client' | 'delete' | 'regen' | 'test'
    """
    s = get_settings()

    # Check if this event type is enabled (test always goes through)
    event_map = {
        "connect":          "notify_connect",
        "disconnect":       "notify_disconnect",
        "expiry":           "notify_expiry",
        "new_client":       "notify_new_client",
        "delete":           "notify_delete",
        "regen":            "notify_regen",
        "quota":            "notify_quota",
        "expiry_reminder":  "notify_expiry_reminder",
        "login_failure":    "notify_login_failure",
        "login_locked":     "notify_login_locked",
        "provision":        "notify_provision",
    }

    if event != "test":
        key = event_map.get(event)
        if key and not int(s.get(key, 0)):
            return  # This event type is muted

    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    full = f"[PipSqueeze] {message}\n{now}"
    subj = subject or f"VPN Alert: {event.replace('_', ' ').title()}"

    results = []

    if int(s.get("discord_enabled", 0)) and s.get("discord_webhook"):
        ok, err = _send_discord(s["discord_webhook"], f"🔔 **{subj}**\n{message}\n`{now}`")
        results.append(("Discord", ok, err))

    if int(s.get("telegram_enabled", 0)) and s.get("telegram_token") and s.get("telegram_chat_id"):
        tg_msg = f"🔔 <b>{subj}</b>\n{message}\n<i>{now}</i>"
        ok, err = _send_telegram(s["telegram_token"], s["telegram_chat_id"], tg_msg)
        results.append(("Telegram", ok, err))

    if int(s.get("email_enabled", 0)) and s.get("email_host") and s.get("email_to"):
        ok, err = _send_email(s, subj, full)
        results.append(("Email", ok, err))

    return results


def test_all(settings: dict) -> list[dict]:
    """Send a test message using the provided (unsaved) settings. Returns results."""
    results = []
    msg  = "This is a test notification from your PipSqueeze dashboard."
    subj = "PipSqueeze — Test Notification"
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    if int(settings.get("discord_enabled", 0)) and settings.get("discord_webhook"):
        ok, err = _send_discord(
            settings["discord_webhook"],
            f"🔔 **{subj}**\n{msg}\n`{now}`"
        )
        results.append({"channel": "Discord", "ok": ok, "error": err})

    if int(settings.get("telegram_enabled", 0)) and settings.get("telegram_token") and settings.get("telegram_chat_id"):
        ok, err = _send_telegram(
            settings["telegram_token"],
            settings["telegram_chat_id"],
            f"🔔 <b>{subj}</b>\n{msg}\n<i>{now}</i>"
        )
        results.append({"channel": "Telegram", "ok": ok, "error": err})

    if int(settings.get("email_enabled", 0)) and settings.get("email_host") and settings.get("email_to"):
        ok, err = _send_email(settings, subj, f"{msg}\n{now}")
        results.append({"channel": "Email", "ok": ok, "error": err})

    if not results:
        results.append({"channel": "None", "ok": False, "error": "No channels are enabled or configured."})

    return results