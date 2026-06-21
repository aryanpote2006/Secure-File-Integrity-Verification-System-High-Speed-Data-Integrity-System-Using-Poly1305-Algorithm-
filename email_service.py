import html
import smtplib
from email.message import EmailMessage
from pathlib import Path

from flask import current_app


SUBJECT = "Reset Your Password - Secure File Integrity Verification System"


def render_reset_email(username, reset_url, expiry_minutes):
    safe_name = html.escape(username)
    safe_url = html.escape(reset_url, quote=True)
    return f"""<!doctype html>
<html>
<body style="margin:0;background:#071018;color:#e7f0f7;font-family:Segoe UI,Arial,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#071018;padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="620" cellpadding="0" cellspacing="0" style="max-width:620px;background:#101b26;border:1px solid #24394a;border-radius:10px;overflow:hidden;">
        <tr><td style="padding:24px 28px;background:#0b1621;border-bottom:1px solid #24394a;">
          <div style="font-size:12px;color:#35d0ba;text-transform:uppercase;font-weight:700;">Poly1305 Vault Security</div>
          <h1 style="margin:8px 0 0;font-size:24px;color:#ffffff;">Password reset requested</h1>
        </td></tr>
        <tr><td style="padding:28px;">
          <p>Hello {safe_name},</p>
          <p>A password reset was requested for your Secure File Integrity Verification System account.</p>
          <p style="margin:28px 0;"><a href="{safe_url}" style="background:#35d0ba;color:#031018;text-decoration:none;font-weight:800;padding:13px 18px;border-radius:8px;display:inline-block;">Reset Password</a></p>
          <p>This link expires in <strong>{expiry_minutes} minutes</strong> and can be used only once.</p>
          <p style="color:#ffc857;">If you did not request this, ignore this email and review account activity after your next login.</p>
          <p style="font-size:12px;color:#8da1b3;">Secure File Integrity Verification System · Cybersecurity Engineering Console</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def send_reset_email(to_email, username, reset_url):
    html_body = render_reset_email(username, reset_url, current_app.config["RESET_TOKEN_EXPIRY_MINUTES"])
    msg = EmailMessage()
    msg["Subject"] = SUBJECT
    msg["From"] = f"{current_app.config['MAIL_SENDER_NAME']} <{current_app.config['MAIL_SENDER']}>"
    msg["To"] = to_email
    msg.set_content(f"Hello {username},\n\nUse this link within 15 minutes to reset your password:\n{reset_url}\n\nIf you did not request this, ignore this email.")
    msg.add_alternative(html_body, subtype="html")

    if current_app.config["SMTP_HOST"]:
        with smtplib.SMTP(current_app.config["SMTP_HOST"], current_app.config["SMTP_PORT"]) as server:
            if current_app.config["SMTP_USE_TLS"]:
                server.starttls()
            if current_app.config["SMTP_USERNAME"]:
                server.login(current_app.config["SMTP_USERNAME"], current_app.config["SMTP_PASSWORD"])
            server.send_message(msg)
        return "smtp"

    outbox = Path(current_app.instance_path) / "mail_outbox"
    outbox.mkdir(parents=True, exist_ok=True)
    safe_name = to_email.replace("@", "_at_").replace(".", "_")
    (outbox / f"password_reset_{safe_name}.html").write_text(html_body, encoding="utf-8")
    (outbox / f"password_reset_{safe_name}.txt").write_text(msg.get_content(), encoding="utf-8")
    return "local-outbox"
