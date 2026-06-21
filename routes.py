import csv
import io
import os
from datetime import datetime, timedelta
from pathlib import Path

from flask import (
    Blueprint, Response, abort, current_app, flash, g, redirect, render_template,
    request, send_file, session, url_for
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.utils import secure_filename

from .db import get_db
from .email_service import send_reset_email
from .security import (
    check_password, create_csrf_token, create_reset_token, generate_mac,
    hash_password, hash_reset_lookup, hash_reset_token, is_bcrypt_hash,
    password_policy_errors, sha256_hex, validate_csrf
)


bp = Blueprint("main", __name__)


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        session.clear()
        return None
    if session.get("session_version") != user["session_version"]:
        session.clear()
        return None
    return user


@bp.before_app_request
def load_user_and_check_csrf():
    g.user = current_user()
    if request.method == "POST" and not validate_csrf(request.form.get("csrf_token")):
        abort(400, "CSRF validation failed")


@bp.app_context_processor
def inject_helpers():
    return {"csrf_token": create_csrf_token}


def login_required(view):
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


def admin_required(view):
    def wrapped(*args, **kwargs):
        if g.user is None or g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


def allowed_file(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def save_uploaded_file(file_storage):
    original = secure_filename(file_storage.filename)
    if not original or not allowed_file(original):
        raise ValueError("Unsupported or unsafe file type.")
    content = file_storage.read()
    if not content:
        raise ValueError("Empty files cannot be registered for integrity verification.")
    if len(content) > current_app.config["MAX_CONTENT_LENGTH"]:
        raise ValueError("File exceeds the configured size limit.")

    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    stored_name = f"{timestamp}_{original}"
    path = Path(current_app.config["UPLOAD_FOLDER"]) / stored_name
    path.write_bytes(content)
    return original, stored_name, path, content


def log_event(file_id, result, remarks, submitted_filename=None, calculated_mac=None, stored_mac=None):
    get_db().execute(
        """
        INSERT INTO verification_logs
        (file_id, user_id, result, remarks, ip_address, submitted_filename, calculated_mac, stored_mac)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            g.user["id"] if g.user else None,
            result,
            remarks,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            submitted_filename,
            calculated_mac,
            stored_mac,
        ),
    )
    get_db().commit()


def log_security_event(user_id, result, remarks):
    get_db().execute(
        """
        INSERT INTO verification_logs
        (file_id, user_id, result, remarks, ip_address)
        VALUES (?, ?, ?, ?, ?)
        """,
        (None, user_id, result, remarks, request.headers.get("X-Forwarded-For", request.remote_addr)),
    )
    get_db().commit()


def parse_db_datetime(value):
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def reset_request_allowed(user):
    requested_at = parse_db_datetime(user["reset_requested_at"])
    if not requested_at:
        return True, 0
    elapsed = (datetime.utcnow() - requested_at).total_seconds()
    cooldown = current_app.config["RESET_REQUEST_COOLDOWN_SECONDS"]
    if elapsed < cooldown:
        return False, int(cooldown - elapsed)
    return True, 0


@bp.route("/")
def index():
    return redirect(url_for("main.dashboard") if g.user else url_for("main.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if len(username) < 3 or len(password) < 8:
            flash("Username must be at least 3 characters and password at least 8 characters.", "danger")
            return render_template("register.html")
        errors = password_policy_errors(password)
        if errors:
            flash("Weak Password: " + ", ".join(errors), "danger")
            return render_template("register.html")

        db = get_db()
        role = "admin" if db.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0 else "user"
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (username, email, hash_password(password), role),
            )
            db.commit()
        except Exception:
            flash("That username or email is already registered.", "danger")
            return render_template("register.html")
        flash("Account created. You can now sign in.", "success")
        return redirect(url_for("main.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        identity = request.form["identity"].strip()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ? OR email = ?", (identity, identity.lower())
        ).fetchone()
        if user and check_password(user["password_hash"], password):
            if not is_bcrypt_hash(user["password_hash"]):
                get_db().execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user["id"]))
                get_db().commit()
            session.clear()
            session["user_id"] = user["id"]
            session["session_version"] = user["session_version"]
            return redirect(url_for("main.dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    cooldown_remaining = 0
    submitted_email = ""
    if request.method == "POST":
        submitted_email = request.form.get("email", "").strip().lower()
        if "@" not in submitted_email or "." not in submitted_email:
            flash("Invalid Email", "danger")
            return render_template("forgot_password.html", cooldown_remaining=cooldown_remaining, submitted_email=submitted_email)

        db = get_db()
        db.execute(
            "INSERT INTO password_reset_requests (email_hash, ip_address) VALUES (?, ?)",
            (hash_reset_lookup(submitted_email), request.headers.get("X-Forwarded-For", request.remote_addr)),
        )
        user = db.execute("SELECT * FROM users WHERE email = ?", (submitted_email,)).fetchone()
        if user:
            allowed, cooldown_remaining = reset_request_allowed(user)
            if allowed:
                token, token_hash = create_reset_token()
                expiry = datetime.utcnow() + timedelta(minutes=current_app.config["RESET_TOKEN_EXPIRY_MINUTES"])
                db.execute(
                    """
                    UPDATE users
                    SET reset_token = ?, reset_token_expiry = ?, reset_requested_at = ?
                    WHERE id = ?
                    """,
                    (token_hash, expiry.isoformat(timespec="seconds"), datetime.utcnow().isoformat(timespec="seconds"), user["id"]),
                )
                db.commit()
                send_reset_email(user["email"], user["username"], url_for("main.reset_password", token=token, _external=True))
            else:
                db.commit()
        else:
            db.commit()
        flash("If an account exists with this email, a password reset link has been sent.", "success")
        return render_template("forgot_password.html", sent=True, cooldown_remaining=60, submitted_email=submitted_email)
    return render_template("forgot_password.html", cooldown_remaining=cooldown_remaining, submitted_email=submitted_email)


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE reset_token = ?", (hash_reset_token(token),)).fetchone()
    if not user:
        flash("Invalid Token", "danger")
        return render_template("reset_password.html", token=token, invalid=True)
    expiry = parse_db_datetime(user["reset_token_expiry"])
    if expiry is None or datetime.utcnow() > expiry:
        db.execute("UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE id = ?", (user["id"],))
        db.commit()
        flash("Token Expired", "danger")
        return render_template("reset_password.html", token=token, expired=True, email=user["email"])

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if password != confirm:
            flash("Passwords Do Not Match", "danger")
            return render_template("reset_password.html", token=token, email=user["email"])
        errors = password_policy_errors(password)
        if errors:
            flash("Weak Password: " + ", ".join(errors), "danger")
            return render_template("reset_password.html", token=token, email=user["email"])
        db.execute(
            """
            UPDATE users
            SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL,
                reset_requested_at = NULL, password_updated_at = ?, session_version = session_version + 1
            WHERE id = ?
            """,
            (hash_password(password), datetime.utcnow().isoformat(timespec="seconds"), user["id"]),
        )
        db.commit()
        log_security_event(user["id"], "Password Reset", "Account password was reset through verified email token. All active sessions were invalidated.")
        session.clear()
        flash("Password Reset Successfully. Redirecting to Login", "success")
        return render_template("reset_password.html", token=token, reset_success=True)
    return render_template("reset_password.html", token=token, email=user["email"])


@bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out securely.", "info")
    return redirect(url_for("main.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    ownership = "" if g.user["role"] == "admin" else "WHERE uploaded_by = ?"
    params = () if g.user["role"] == "admin" else (g.user["id"],)
    total_files = db.execute(f"SELECT COUNT(*) AS c FROM files {ownership}", params).fetchone()["c"]
    verified = db.execute(
        "SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'Integrity Verified'"
    ).fetchone()["c"]
    tampered = db.execute(
        "SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'File Tampered'"
    ).fetchone()["c"]
    recent = db.execute(
        """
        SELECT l.*, f.original_filename, u.username
        FROM verification_logs l
        LEFT JOIN files f ON f.id = l.file_id
        LEFT JOIN users u ON u.id = l.user_id
        ORDER BY l.verification_date DESC LIMIT 8
        """
    ).fetchall()
    files = db.execute(
        f"SELECT * FROM files {ownership} ORDER BY upload_date DESC LIMIT 6", params
    ).fetchall()
    return render_template(
        "dashboard.html", total_files=total_files, verified=verified, tampered=tampered,
        recent=recent, files=files
    )


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded:
            flash("Choose a file to upload.", "warning")
            return redirect(url_for("main.upload"))
        try:
            original, stored_name, path, content = save_uploaded_file(uploaded)
            salt = os.urandom(16).hex()
            mac = generate_mac(content, salt)
            digest = sha256_hex(content)
            db = get_db()
            cur = db.execute(
                """
                INSERT INTO files
                (filename, original_filename, file_path, file_size, mime_type, file_hash, key_salt, poly1305_mac, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (stored_name, original, str(path), len(content), uploaded.mimetype, digest, salt, mac, g.user["id"]),
            )
            db.commit()
            log_event(cur.lastrowid, "Registered", "Original Poly1305 MAC generated and stored.", original, mac, mac)
            flash("File registered and Poly1305 MAC generated.", "success")
            return redirect(url_for("main.file_detail", file_id=cur.lastrowid))
        except ValueError as exc:
            flash(str(exc), "danger")
    return render_template("upload.html")


@bp.route("/files")
@login_required
def files():
    query = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    start = request.args.get("start", "").strip()
    sort = request.args.get("sort", "newest")
    clauses = []
    params = []
    if g.user["role"] != "admin":
        clauses.append("uploaded_by = ?")
        params.append(g.user["id"])
    if query:
        clauses.append("original_filename LIKE ?")
        params.append(f"%{query}%")
    if status:
        clauses.append("status = ?")
        params.append(status)
    if start:
        clauses.append("date(upload_date) >= date(?)")
        params.append(start)
    order = "upload_date ASC" if sort == "oldest" else "upload_date DESC"
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    rows = get_db().execute(f"SELECT * FROM files {where} ORDER BY {order}", params).fetchall()
    return render_template("files.html", files=rows)


@bp.route("/files/<int:file_id>")
@login_required
def file_detail(file_id):
    file = get_db().execute("SELECT f.*, u.username FROM files f JOIN users u ON u.id = f.uploaded_by WHERE f.id = ?", (file_id,)).fetchone()
    if not file or (g.user["role"] != "admin" and file["uploaded_by"] != g.user["id"]):
        abort(404)
    logs = get_db().execute("SELECT * FROM verification_logs WHERE file_id = ? ORDER BY verification_date DESC", (file_id,)).fetchall()
    return render_template("file_detail.html", file=file, logs=logs)


@bp.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
    db = get_db()
    user_files = db.execute(
        "SELECT id, original_filename, poly1305_mac FROM files WHERE uploaded_by = ? ORDER BY upload_date DESC",
        (g.user["id"],),
    ).fetchall()
    result = None
    if request.method == "POST":
        file_id = int(request.form["file_id"])
        uploaded = request.files.get("file")
        file = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not file or (g.user["role"] != "admin" and file["uploaded_by"] != g.user["id"]):
            abort(404)
        if not uploaded:
            flash("Upload the file copy you want to verify.", "warning")
            return redirect(url_for("main.verify"))
        content = uploaded.read()
        calculated = generate_mac(content, file["key_salt"])
        stored = file["poly1305_mac"]
        if calculated == stored:
            status = "Integrity Verified"
            remarks = "Calculated Poly1305 MAC matches the stored reference."
            db.execute("UPDATE files SET status = 'verified' WHERE id = ?", (file_id,))
        else:
            status = "File Tampered"
            remarks = "MAC mismatch detected. File contents differ from registered baseline."
            db.execute("UPDATE files SET status = 'tampered' WHERE id = ?", (file_id,))
        db.commit()
        log_event(file_id, status, remarks, uploaded.filename, calculated, stored)
        result = {"status": status, "remarks": remarks, "calculated": calculated, "stored": stored, "file": file}
    return render_template("verify.html", files=user_files, result=result)


@bp.route("/logs")
@login_required
def logs():
    result = request.args.get("result", "")
    q = request.args.get("q", "").strip()
    clauses = []
    params = []
    if g.user["role"] != "admin":
        clauses.append("l.user_id = ?")
        params.append(g.user["id"])
    if result:
        clauses.append("l.result = ?")
        params.append(result)
    if q:
        clauses.append("(f.original_filename LIKE ? OR l.submitted_filename LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    rows = get_db().execute(
        f"""
        SELECT l.*, f.original_filename, u.username
        FROM verification_logs l
        LEFT JOIN files f ON f.id = l.file_id
        LEFT JOIN users u ON u.id = l.user_id
        {where}
        ORDER BY l.verification_date DESC
        """,
        params,
    ).fetchall()
    return render_template("logs.html", logs=rows)


@bp.route("/logs/download")
@login_required
def download_logs():
    rows = get_db().execute(
        """
        SELECT l.id, u.username, f.original_filename, l.submitted_filename, l.verification_date,
               l.result, l.remarks, l.ip_address
        FROM verification_logs l
        LEFT JOIN files f ON f.id = l.file_id
        LEFT JOIN users u ON u.id = l.user_id
        ORDER BY l.verification_date DESC
        """
    ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "username", "registered_file", "submitted_file", "date", "result", "remarks", "ip"])
    for row in rows:
        writer.writerow(list(row))
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=verification_logs.csv"})


def build_pdf(title, rows):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Title"]), Spacer(1, 12)]
    table = Table(rows, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    return buffer


@bp.route("/reports")
@login_required
def reports():
    db = get_db()
    stats = {
        "files": db.execute("SELECT COUNT(*) AS c FROM files").fetchone()["c"],
        "verified": db.execute("SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'Integrity Verified'").fetchone()["c"],
        "tampered": db.execute("SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'File Tampered'").fetchone()["c"],
        "registered": db.execute("SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'Registered'").fetchone()["c"],
    }
    return render_template("reports.html", stats=stats)


@bp.route("/reports/download")
@login_required
def download_report():
    rows = [["Metric", "Value"]]
    db = get_db()
    rows.extend([
        ["Total Registered Files", db.execute("SELECT COUNT(*) AS c FROM files").fetchone()["c"]],
        ["Integrity Verified Events", db.execute("SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'Integrity Verified'").fetchone()["c"]],
        ["Tamper Detections", db.execute("SELECT COUNT(*) AS c FROM verification_logs WHERE result = 'File Tampered'").fetchone()["c"]],
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ])
    pdf = build_pdf("Secure File Integrity Verification Report", rows)
    return send_file(pdf, as_attachment=True, download_name="integrity_report.pdf", mimetype="application/pdf")


@bp.route("/certificate/<int:file_id>")
@login_required
def certificate(file_id):
    file = get_db().execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file or (g.user["role"] != "admin" and file["uploaded_by"] != g.user["id"]):
        abort(404)
    rows = [
        ["Field", "Value"],
        ["File", file["original_filename"]],
        ["Status", file["status"]],
        ["Poly1305 MAC", file["poly1305_mac"]],
        ["SHA-256 Fingerprint", file["file_hash"]],
        ["Upload Date", file["upload_date"]],
    ]
    pdf = build_pdf("File Integrity Verification Certificate", rows)
    return send_file(pdf, as_attachment=True, download_name=f"certificate_{file_id}.pdf", mimetype="application/pdf")


@bp.route("/admin")
@login_required
@admin_required
def admin():
    db = get_db()
    users = db.execute("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC").fetchall()
    files = db.execute("SELECT f.*, u.username FROM files f JOIN users u ON u.id = f.uploaded_by ORDER BY upload_date DESC").fetchall()
    alerts = db.execute(
        """
        SELECT l.*, f.original_filename, u.username
        FROM verification_logs l
        LEFT JOIN files f ON f.id = l.file_id
        LEFT JOIN users u ON u.id = l.user_id
        WHERE l.result = 'File Tampered'
        ORDER BY l.verification_date DESC
        """
    ).fetchall()
    return render_template("admin.html", users=users, files=files, alerts=alerts)


@bp.route("/admin/delete-file/<int:file_id>", methods=["POST"])
@login_required
@admin_required
def delete_file(file_id):
    db = get_db()
    file = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file:
        abort(404)
    try:
        Path(file["file_path"]).unlink(missing_ok=True)
    except OSError:
        pass
    db.execute("DELETE FROM verification_logs WHERE file_id = ?", (file_id,))
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    flash("File and related logs deleted.", "info")
    return redirect(url_for("main.admin"))
