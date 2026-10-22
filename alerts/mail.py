"""E-mail: templates (ES/EN), the message builder, and two transports (a directory of .eml files, and SMTP). Nothing is sent to an address that has not
confirmed it; every message carries a one-click unsubscribe (RFC 8058 headers) and no tracking pixel or link rewriting.

A bounce is a fact about a channel: a hard bounce switches it off at once, three soft bounces suspend it.
"""
from __future__ import annotations
import os
import re
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Any, Dict, List, Optional, Tuple

from . import rss, store

SUBJECT_CHARS = re.compile(r"[\r\n\x00-\x1f]")
S = {
    "es": {"confirm_subject": "Confirma tu dirección para las alertas de MacGuard", "confirm_body": "Alguien (probablemente tú) ha pedido recibir alertas de MacGuard en esta dirección.\nPara confirmarlo abre este enlace (caduca en 48 horas):\n{url}\n\nSi no has sido tú, ignora este mensaje: no recibirás nada.",
           "immediate_subject": "[MacGuard] {sev}: {title}", "digest_subject": "[MacGuard] Resumen de alertas ({n})", "digest_intro": "Estas alertas coinciden con tu suscripción «{name}»:",
           "footer": "Recibes este mensaje por tu suscripción «{name}». Darse de baja con un clic: {unsub}", "no_link": "Para darte de baja, usa la opción de baja de MacGuard o responde a este mensaje.", "test": "Mensaje de prueba de MacGuard: tu canal funciona."},
    "en": {"confirm_subject": "Confirm your address for MacGuard alerts", "confirm_body": "Someone (probably you) asked to receive MacGuard alerts at this address.\nTo confirm, open this link (it expires in 48 hours):\n{url}\n\nIf it was not you, ignore this message: you will receive nothing.",
           "immediate_subject": "[MacGuard] {sev}: {title}", "digest_subject": "[MacGuard] Alert digest ({n})", "digest_intro": "These alerts match your subscription \"{name}\":",
           "footer": "You get this message because of your subscription \"{name}\". One-click unsubscribe: {unsub}", "no_link": "To unsubscribe use the unsubscribe option of MacGuard or reply to this message.", "test": "MacGuard test message: your channel works."},
}


def _subject(s: str) -> str:
    return SUBJECT_CHARS.sub(" ", s)[:200]


def build(to: str, from_addr: str, subject: str, text: str, *, lang: str, delivery_id: str, unsubscribe_url: Optional[str] = None, now: Optional[datetime] = None) -> EmailMessage:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = from_addr, to, _subject(subject)
    m["Date"] = format_datetime((now or datetime.now(timezone.utc)).astimezone(timezone.utc), usegmt=True)
    m["Message-ID"] = make_msgid(domain="alerts.macguard.invalid")
    m["Auto-Submitted"] = "auto-generated"
    m["X-MacGuard-Delivery-Id"] = delivery_id
    m["Content-Language"] = lang
    if unsubscribe_url:
        m["List-Unsubscribe"] = f"<{unsubscribe_url}>"
        m["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    m.set_content(text)
    return m


def render_confirmation(to: str, token: str, lang: str, base_url: Optional[str], from_addr: str, delivery_id: str, now: datetime) -> EmailMessage:
    url = (base_url.rstrip("/") + "/api/v1/channels/confirm?token=" + token) if base_url else f"(token: {token})"
    return build(to, from_addr, S[lang]["confirm_subject"], S[lang]["confirm_body"].format(url=url), lang=lang, delivery_id=delivery_id, now=now)


def render_alerts(to: str, from_addr: str, lang: str, sub_name: str, items: List[Dict[str, Any]], mode: str, delivery_id: str, base_url: Optional[str], unsub_token: str, now: datetime) -> EmailMessage:
    """items: [{'view': publish view, 'match': {...}}]"""
    s = S[lang]
    unsub = (base_url.rstrip("/") + "/api/v1/channels/unsubscribe?token=" + unsub_token) if base_url else None
    body = []
    if mode == "digest":
        body.append(s["digest_intro"].format(name=sub_name))
    for it in items:
        v = it["view"]
        body.append(f"== {v['title']}\n{rss.alert_text(v, lang, it['match'].get('reasons'), it['match'].get('changes'))}\n")
    body.append(s["footer"].format(name=sub_name, unsub=unsub) if unsub else s["no_link"])
    if mode == "digest":
        subject = s["digest_subject"].format(n=len(items))
    else:
        v = items[0]["view"]
        subject = s["immediate_subject"].format(sev=v["severity"]["band"].upper(), title=v["title"])
    return build(to, from_addr, subject, "\n".join(body), lang=lang, delivery_id=delivery_id, unsubscribe_url=unsub, now=now)


# ---- transports ------------------------------------------------------------------------------------------------------------------
class FileTransport:
    """Writes each message as <dir>/<delivery id>.eml (mode 0600). The default: it needs no mail server and sends nothing anywhere."""

    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)

    def send(self, msg: EmailMessage) -> Tuple[str, str]:
        did = re.sub(r"[^A-Za-z0-9_-]", "_", msg["X-MacGuard-Delivery-Id"] or "message")
        path = os.path.join(self.dir, did + ".eml")
        fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(msg))
        return "ok", path


class SmtpTransport:
    """SMTP with mandatory STARTTLS (or implicit TLS on 465). 5xx answers are permanent, everything else is retried."""

    def __init__(self, host: str, port: int = 587, user: Optional[str] = None, password: Optional[str] = None, implicit_tls: bool = False, timeout: float = 20.0):
        self.host, self.port, self.user, self.password, self.implicit_tls, self.timeout = host, port, user, password, implicit_tls, timeout

    def send(self, msg: EmailMessage) -> Tuple[str, str]:
        try:
            ctx = ssl.create_default_context()
            smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx) if self.implicit_tls else smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            with smtp:
                if not self.implicit_tls:
                    smtp.starttls(context=ctx)
                if self.user:
                    smtp.login(self.user, self.password or "")
                smtp.send_message(msg)
            return "ok", "sent"
        except smtplib.SMTPRecipientsRefused as e:
            return "permanent", f"recipient refused: {list(e.recipients.values())[0][0] if e.recipients else ''}"
        except smtplib.SMTPResponseException as e:
            return ("permanent" if 500 <= e.smtp_code < 600 else "temporary"), f"smtp {e.smtp_code}"
        except (OSError, smtplib.SMTPException) as e:
            return "temporary", e.__class__.__name__


def handle_bounce(db, channel_id: str, kind: str, now: str) -> str:
    """kind: 'hard' | 'soft'. Returns the channel's new state."""
    r = db.execute("SELECT * FROM notification_channels WHERE channel_id=?", (channel_id,)).fetchone()
    if r is None:
        return "unknown"
    with store.tx(db):
        if kind == "hard":
            db.execute("UPDATE notification_channels SET state='bounced', disabled_reason='hard bounce', bounces=bounces+1 WHERE channel_id=?", (channel_id,))
            new = "bounced"
        else:
            b = r["bounces"] + 1
            new = "suspended" if b >= 3 else r["state"]
            db.execute("UPDATE notification_channels SET bounces=?, state=?, disabled_reason=CASE WHEN ?='suspended' THEN 'repeated soft bounces' ELSE disabled_reason END WHERE channel_id=?", (b, new, new, channel_id))
        store.audit(db, now, None, r["org_id"], "channel.bounce", channel_id, {"kind": kind, "state": new})
    return new
