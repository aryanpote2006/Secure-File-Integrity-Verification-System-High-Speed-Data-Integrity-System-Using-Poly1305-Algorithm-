import hashlib
import hmac
import os
import re
import secrets
from pathlib import Path

import bcrypt
from cryptography.hazmat.primitives.poly1305 import Poly1305
from flask import current_app, session
from werkzeug.security import check_password_hash as check_legacy_password_hash


def get_master_key():
    env_key = os.environ.get("POLY1305_MASTER_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode("utf-8")).digest()

    key_file = Path(current_app.instance_path) / "poly1305_master.key"
    if not key_file.exists():
        key_file.write_bytes(os.urandom(32))
    return key_file.read_bytes()


def derive_poly1305_key(salt_hex):
    salt = bytes.fromhex(salt_hex)
    return hmac.new(get_master_key(), salt + b"file-integrity-poly1305", hashlib.sha256).digest()


def generate_mac(file_bytes, salt_hex):
    key = derive_poly1305_key(salt_hex)
    return Poly1305.generate_tag(key, file_bytes).hex()


def sha256_hex(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def check_password(stored_hash, password):
    if stored_hash.startswith("$2"):
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    return check_legacy_password_hash(stored_hash, password)


def is_bcrypt_hash(stored_hash):
    return stored_hash.startswith("$2")


def password_policy_errors(password):
    errors = []
    if len(password) < 8:
        errors.append("Minimum 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("At least 1 uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("At least 1 lowercase letter")
    if not re.search(r"\d", password):
        errors.append("At least 1 number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("At least 1 special character")
    return errors


def create_reset_token():
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return token, token_hash


def hash_reset_lookup(value):
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = os.urandom(24).hex()
        session["_csrf_token"] = token
    return token


def validate_csrf(token):
    expected = session.get("_csrf_token", "")
    return bool(token) and hmac.compare_digest(expected, token)
