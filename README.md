# Secure File Integrity Verification System Using Poly1305

A complete Flask-based cybersecurity engineering project for registering files, generating Poly1305 Message Authentication Codes, and detecting tampering during storage or transmission.

## Project Overview

The application stores a trusted baseline for every uploaded file. During verification, the user uploads a received or stored copy of the file. The backend recalculates the Poly1305 MAC using the original per-file key salt and compares it with the stored MAC. A match means the file is intact; a mismatch creates a tamper alert and audit log entry.

## Features

- User registration, login, logout, password hashing, and session management
- Dark cybersecurity dashboard with statistics and recent activity
- Drag-and-drop file registration with file type and size validation
- Poly1305 MAC generation using Python `cryptography`
- Per-file MAC key derivation from an application master key and random salt
- SQLite database for users, files, MAC records, and verification logs
- Integrity verification workflow with clear verified/tampered results
- Search, filter, and sort support for file registry and logs
- Downloadable audit logs as CSV
- PDF security report generation
- PDF verification certificate per file
- Admin panel for users, uploaded files, tamper alerts, and malicious file deletion
- CSRF token validation and secure filename handling

## Technology Stack

- Backend: Python Flask
- Frontend: HTML5, CSS3, JavaScript
- Database: SQLite
- Cryptography: Poly1305 MAC via `cryptography`
- Reports: PDF generation via `reportlab`

## Folder Structure

```text
secure-file-integrity-poly1305/
  app/
    static/
      css/style.css
      js/app.js
    templates/
      admin.html
      base.html
      dashboard.html
      file_detail.html
      files.html
      logs.html
      login.html
      register.html
      reports.html
      upload.html
      verify.html
    __init__.py
    db.py
    routes.py
    security.py
  config.py
  requirements.txt
  run.py
  README.md
```

## Database Schema

### Users

- `id`
- `username`
- `email`
- `password_hash`
- `role`
- `created_at`

### Files

- `id`
- `filename`
- `original_filename`
- `file_path`
- `file_size`
- `mime_type`
- `file_hash`
- `key_salt`
- `poly1305_mac`
- `upload_date`
- `uploaded_by`
- `status`

### VerificationLogs

- `id`
- `file_id`
- `user_id`
- `verification_date`
- `result`
- `remarks`
- `ip_address`
- `submitted_filename`
- `calculated_mac`
- `stored_mac`

## Installation

```bash
cd secure-file-integrity-poly1305
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Open:

```text
http://127.0.0.1:5000
```

The first registered account automatically receives the `admin` role.

## Optional Production Environment Variables

```bash
set SECRET_KEY=replace-with-a-random-flask-secret
set POLY1305_MASTER_KEY=replace-with-a-long-random-master-key
set DATABASE_URL=instance/integrity.db
set UPLOAD_FOLDER=instance/uploads
```

For a student demonstration, the app can run without these variables. It creates a local master key inside `instance/poly1305_master.key`.

## API / Route Summary

- `GET /` redirects to login or dashboard
- `GET, POST /register` creates users
- `GET, POST /login` authenticates users
- `GET /logout` clears session
- `GET /dashboard` shows analytics
- `GET, POST /upload` registers files and generates MAC values
- `GET /files` searches and filters stored files
- `GET /files/<id>` shows file details and audit trail
- `GET, POST /verify` verifies a file copy
- `GET /logs` displays verification logs
- `GET /logs/download` downloads CSV logs
- `GET /reports` shows analytics
- `GET /reports/download` downloads PDF report
- `GET /certificate/<id>` downloads file certificate
- `GET /admin` shows admin panel
- `POST /admin/delete-file/<id>` deletes suspicious files

## Presentation Explanation

This system solves a common cybersecurity problem: proving that a file has not changed after upload, storage, or transfer. Instead of relying only on filenames or timestamps, the system generates a Poly1305 MAC over the file bytes. Poly1305 is a fast message authentication code that detects unauthorized modification when used with a secret key.

When a user uploads a file, the backend validates the file, stores it securely, creates a random salt, derives a 32-byte Poly1305 key from the server master key, and generates the MAC. During verification, the uploaded comparison file is processed with the same derived key. If the calculated MAC matches the database value, integrity is verified. If not, the file is marked tampered and an audit log entry is created.

The dashboard, admin panel, reports, and certificates are included to make the project usable for real-world demonstrations and engineering evaluation.
