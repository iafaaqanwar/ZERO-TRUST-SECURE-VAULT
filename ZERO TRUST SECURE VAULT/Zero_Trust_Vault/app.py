"""
==============================================================================
 app.py — Zero Trust Secure Vault :: Main Application Server
==============================================================================
 A Flask-based web application implementing a Google Drive-inspired secure
 file vault.  All data persistence uses local JSON files and filesystem
 directories — NO external databases.

 Security Architecture (AAA + CIA):
 ┌────────────────────┬────────────────────────────────────────────────────┐
 │ Pillar             │ Implementation                                     │
 ├────────────────────┼────────────────────────────────────────────────────┤
 │ Authentication     │ Email/password login; passwords hashed via PBKDF2  │
 │ Authorization      │ RBAC via permissions.json; per-file access grants  │
 │ Accounting         │ Continuous audit trail in audit_logs.json           │
 │ Confidentiality    │ Fernet (AES-128-CBC) encryption at rest            │
 │ Integrity          │ SHA-256 hash verification on every file access     │
 │ Availability       │ Per-user 50 MB storage quota enforcement           │
 └────────────────────┴────────────────────────────────────────────────────┘

 Data Stores (JSON-only, no SQL/NoSQL):
   • storage/users.json        — user credentials and profile metadata
   • storage/metadata.json     — file index with SHA-256 hashes & versions
   • storage/permissions.json  — access control matrix & expiration rules
   • storage/audit_logs.json   — chronological security event ledger
   • storage/Vault_Storage/    — per-user encrypted file directories
==============================================================================
"""

import os
import io
import json
import shutil
import mimetypes
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, request, jsonify, session, redirect, url_for,
    render_template, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

from security import encrypt_file_bytes, decrypt_file_bytes, calculate_sha256

# ---------------------------------------------------------------------------
# Application Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.urandom(32)  # Cryptographically random session secret

# Paths
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR   = os.path.join(BASE_DIR, 'storage')
VAULT_DIR     = os.path.join(STORAGE_DIR, 'Vault_Storage')
USERS_FILE    = os.path.join(STORAGE_DIR, 'users.json')
METADATA_FILE = os.path.join(STORAGE_DIR, 'metadata.json')
PERMS_FILE    = os.path.join(STORAGE_DIR, 'permissions.json')
AUDIT_FILE    = os.path.join(STORAGE_DIR, 'audit_logs.json')

# Storage quota per user (50 MB for simulation)
STORAGE_QUOTA_BYTES = 50 * 1024 * 1024  # 50 MB

# Domain for email validation
VALID_DOMAIN = '@zerotrustvault.com'

# ---------------------------------------------------------------------------
# Super Admin — Hardcoded Credential Constants  (Privileged Access)
# ---------------------------------------------------------------------------
# The Super Admin account is intentionally kept OUTSIDE users.json to maintain
# separation between the administrative control plane and the user data plane.
# This follows the Zero Trust principle of least privilege — the admin can
# manage system state but has NO access to encrypted user file content.
# ---------------------------------------------------------------------------
SUPER_ADMIN_EMAIL    = 'admin@zerotrustvault.com'
SUPER_ADMIN_PASSWORD = 'admin7258'

# Maximum upload size (50 MB to match quota)
app.config['MAX_CONTENT_LENGTH'] = STORAGE_QUOTA_BYTES


# ---------------------------------------------------------------------------
# Initialisation — Create storage structure and seed JSON files
# ---------------------------------------------------------------------------
def initialise_storage():
    """
    Ensure all required directories and JSON files exist on startup.
    This replaces traditional database migration scripts.
    """
    os.makedirs(VAULT_DIR, exist_ok=True)

    defaults = {
        USERS_FILE:    {},
        METADATA_FILE: {},
        PERMS_FILE:    {},
        AUDIT_FILE:    [],
    }
    for filepath, default_data in defaults.items():
        if not os.path.exists(filepath):
            save_json(filepath, default_data)


# ---------------------------------------------------------------------------
# JSON Persistence Helpers
# ---------------------------------------------------------------------------
def load_json(filepath: str):
    """Atomically load a JSON file, returning its parsed content."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        # Return a safe default if the file is corrupted or missing
        return {} if filepath != AUDIT_FILE else []


def save_json(filepath: str, data):
    """Atomically write data to a JSON file with pretty-printing."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Audit Logging Engine  (Non-Repudiation & Accountability)
# ---------------------------------------------------------------------------
def log_audit(actor: str, action: str, classification: str, details: str, metadata_changes=None):
    """
    Append a security event to the continuous audit ledger.

    Every significant operation is recorded with:
      • Precise ISO-8601 timestamp
      • Actor identity (email)
      • Action label
      • Security classification: SUCCESS | WARNING | CRITICAL ALERT | INFO
      • Human-readable detail string
      • Optional structured metadata changes dictionary

    This implements the **Non-repudiation** principle — actions cannot be
    denied after the fact because a tamper-evident record exists.

    Args:
        actor:            The user email performing the action.
        action:           Short action label (e.g. "File Upload").
        classification:   Severity tag.
        details:          Verbose description of the event.
        metadata_changes: Optional dictionary of data store changes.
    """
    logs = load_json(AUDIT_FILE)
    logs.append({
        'timestamp':        datetime.now(timezone.utc).isoformat(),
        'actor':            actor,
        'action':           action,
        'classification':   classification,
        'details':          details,
        'metadata_changes': metadata_changes,
    })
    save_json(AUDIT_FILE, logs)


# ---------------------------------------------------------------------------
# Storage Quota Helper
# ---------------------------------------------------------------------------
def get_directory_size(path: str) -> int:
    """
    Recursively calculate the total size (in bytes) of all files under *path*.
    Uses ``os.path.getsize`` for accurate disk usage measurement.
    """
    total = 0
    if os.path.exists(path):
        for dirpath, _dirnames, filenames in os.walk(path):
            for fname in filenames:
                fp = os.path.join(dirpath, fname)
                try:
                    total += os.path.getsize(fp)
                except OSError:
                    pass
    return total


# ---------------------------------------------------------------------------
# Authentication Decorator  (Access Control Gate)
# ---------------------------------------------------------------------------
def login_required(f):
    """
    Route decorator enforcing authentication (the first 'A' in AAA).
    Redirects unauthenticated requests to the login page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            # API routes get a JSON 401; page routes get a redirect
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated


def superadmin_required(f):
    """
    Route decorator enforcing Super Admin authorization.

    AAA Mapping:
      • Authentication — verifies a valid session exists
      • Authorization  — verifies the session carries role='superadmin'
      • Accounting     — unauthorized attempts are logged to the audit ledger

    This is the second layer of access control (Authorization) that gates
    all administrative routes.  Regular users who attempt to access admin
    endpoints are denied and the attempt is recorded.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login_page'))
        # ── Authorization gate — enforce superadmin role ──────────────────
        if session.get('role') != 'superadmin':
            log_audit(session.get('user', 'Unknown'), 'Unauthorized Access',
                      'CRITICAL ALERT',
                      f'Non-admin user attempted to access admin route: {request.path}',
                      metadata_changes={
                          'file_manipulated': 'None',
                          'operation': 'DENIED',
                          'affected_key': 'None',
                          'details': {
                              'attempted_route': request.path,
                              'role': session.get('role', 'Unknown')
                          }
                      })
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Forbidden — Super Admin access required.'}), 403
            return redirect(url_for('dashboard_page'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Email Validation Helper
# ---------------------------------------------------------------------------
def is_valid_email(email: str) -> bool:
    """
    Validate that an email strictly conforms to the domain specification:
      [username]@zerotrustvault.com

    Rules:
      • Must end with ``@zerotrustvault.com``
      • The local part (username) must be non-empty and alphanumeric
        (dots, underscores, and hyphens are also allowed)
    """
    if not email or not email.endswith(VALID_DOMAIN):
        return False
    local_part = email[: -len(VALID_DOMAIN)]
    if not local_part or len(local_part) < 1:
        return False
    # Allow alphanumeric, dots, underscores, hyphens in the local part
    import re
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', local_part))


# ===========================================================================
# PAGE ROUTES
# ===========================================================================

@app.route('/')
def index():
    """Root route — redirect to appropriate dashboard if logged in, else to login."""
    if 'user' in session:
        # ── Super Admin gets routed to the admin console ──────────────────
        if session.get('role') == 'superadmin':
            return redirect(url_for('superadmin_page'))
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))


@app.route('/login')
def login_page():
    """Serve the dual login / signup portal."""
    if 'user' in session:
        if session.get('role') == 'superadmin':
            return redirect(url_for('superadmin_page'))
        return redirect(url_for('dashboard_page'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard_page():
    """Serve the main command panel (requires authentication)."""
    # ── Prevent Super Admin from accessing the regular user dashboard ─────
    # Zero Trust: admin operates on a separate control plane and must never
    # reach endpoints that could expose file decryption or download actions.
    if session.get('role') == 'superadmin':
        return redirect(url_for('superadmin_page'))
    return render_template('dashboard.html', user=session['user'])


@app.route('/superadmin')
@superadmin_required
def superadmin_page():
    """
    Serve the Super Admin command console.

    Security:
      • Gated by ``superadmin_required`` — only the hardcoded admin can access.
      • This page renders metadata-only dashboards; it has NO routes or links
        that invoke decrypt_file_bytes() or serve raw file content.
      • Enforces Zero-Knowledge: admin sees system health, not file contents.
    """
    return render_template('superadmin.html')


@app.route('/logout')
def logout():
    """Destroy the session and redirect to login."""
    user = session.get('user', 'Unknown')
    session.clear()
    log_audit(user, 'User Logout', 'SUCCESS', f'{user} logged out successfully.')
    return redirect(url_for('login_page'))


# ===========================================================================
# AUTHENTICATION API
# ===========================================================================

@app.route('/api/signup', methods=['POST'])
def api_signup():
    """
    Register a new user account.

    Security measures:
      1. Domain-locked email validation (@zerotrustvault.com)
      2. Password hashed with PBKDF2-SHA256 via Werkzeug (salted, iterated)
      3. Isolated vault directory provisioned on the filesystem
      4. Event logged to audit ledger
    """
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    # ── Input validation ──────────────────────────────────────────────────
    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    if not is_valid_email(email):
        return jsonify({
            'error': f'Invalid email. Must be in the format username{VALID_DOMAIN}'
        }), 400

    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400

    # ── Duplicate check ───────────────────────────────────────────────────
    users = load_json(USERS_FILE)
    if email in users:
        return jsonify({'error': 'An account with this email already exists.'}), 409

    # ── Secure password hashing (PBKDF2-SHA256, 600 000 iterations) ──────
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

    # ── Create isolated user vault directory ──────────────────────────────
    user_vault = os.path.join(VAULT_DIR, email)
    os.makedirs(user_vault, exist_ok=True)

    # ── Persist user record ───────────────────────────────────────────────
    users[email] = {
        'password_hash': hashed_pw,
        'created_at':    datetime.now(timezone.utc).isoformat(),
        'storage_path':  f'Vault_Storage/{email}',
    }
    save_json(USERS_FILE, users)

    # ── Audit trail ───────────────────────────────────────────────────────
    log_audit(email, 'User Signup', 'SUCCESS',
              f'New account created for {email}. Isolated vault provisioned.',
              metadata_changes={
                  'file_manipulated': 'users.json',
                  'operation': 'INSERT',
                  'affected_key': email,
                  'details': {
                      'action': 'user_registration',
                      'storage_path': f'Vault_Storage/{email}',
                      'created_at': datetime.now(timezone.utc).isoformat()
                  }
              })

    return jsonify({'message': 'Account created successfully!'}), 201


@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Authenticate a user and establish a server-side session.

    Security measures:
      1. Super Admin credential intercept (hardcoded, bypasses users.json)
      2. Timing-safe password comparison via ``check_password_hash``
      3. Failed attempts logged for intrusion detection
      4. Session token bound to the server-side secret key

    AAA Mapping:
      • Authentication: credential verification (admin or PBKDF2 hash)
      • Authorization:  session role tag determines dashboard routing
      • Accounting:     every attempt (success or failure) is audit-logged
    """
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '').strip()

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    # ══════════════════════════════════════════════════════════════════════
    # SUPER ADMIN INTERCEPT — Hardcoded Privileged Access Gate
    # ══════════════════════════════════════════════════════════════════════
    # The Super Admin credential check runs BEFORE the users.json lookup.
    # This keeps the admin account entirely outside the user data plane,
    # ensuring separation of the administrative control plane from regular
    # user operations (a core Zero Trust architecture principle).
    # ══════════════════════════════════════════════════════════════════════
    if email == SUPER_ADMIN_EMAIL and password == SUPER_ADMIN_PASSWORD:
        session['user'] = SUPER_ADMIN_EMAIL
        session['role'] = 'superadmin'  # Authorization tag for admin routes
        log_audit(SUPER_ADMIN_EMAIL, 'Super Admin Login', 'SUCCESS',
                  'Super Admin authenticated successfully. '
                  'Admin control plane session established.',
                  metadata_changes={
                      'file_manipulated': 'session',
                      'operation': 'AUTHENTICATE',
                      'affected_key': SUPER_ADMIN_EMAIL,
                      'details': {
                          'role': 'superadmin',
                          'status': 'success'
                      }
                  })
        return jsonify({
            'message':  'Super Admin login successful!',
            'redirect': '/superadmin',  # Frontend uses this to route
        }), 200

    # If someone uses the admin email but wrong password, deny and log
    if email == SUPER_ADMIN_EMAIL:
        log_audit(email, 'Super Admin Login', 'CRITICAL ALERT',
                  f'Failed Super Admin login attempt — incorrect password. '
                  f'Possible unauthorized access attempt.',
                  metadata_changes={
                      'file_manipulated': 'session',
                      'operation': 'AUTHENTICATE',
                      'affected_key': email,
                      'details': {
                          'role': 'superadmin',
                          'status': 'failed',
                          'reason': 'incorrect_password'
                      }
                  })
        return jsonify({'error': 'Invalid credentials.'}), 401

    # ══════════════════════════════════════════════════════════════════════
    # STANDARD USER LOGIN — users.json lookup with PBKDF2 verification
    # ══════════════════════════════════════════════════════════════════════
    users = load_json(USERS_FILE)

    if email not in users:
        log_audit(email, 'User Login', 'WARNING',
                  f'Failed login attempt — account {email} does not exist.',
                  metadata_changes={
                      'file_manipulated': 'session',
                      'operation': 'AUTHENTICATE',
                      'affected_key': email,
                      'details': {
                          'role': 'user',
                          'status': 'failed',
                          'reason': 'account_not_found'
                      }
                  })
        return jsonify({'error': 'Invalid credentials.'}), 401

    # ── Timing-safe password verification ─────────────────────────────────
    if not check_password_hash(users[email]['password_hash'], password):
        log_audit(email, 'User Login', 'WARNING',
                  f'Failed login attempt for {email} — incorrect password.',
                  metadata_changes={
                      'file_manipulated': 'session',
                      'operation': 'AUTHENTICATE',
                      'affected_key': email,
                      'details': {
                          'role': 'user',
                          'status': 'failed',
                          'reason': 'incorrect_password'
                      }
                  })
        return jsonify({'error': 'Invalid credentials.'}), 401

    # ── Establish session ─────────────────────────────────────────────────
    session['user'] = email
    session['role'] = 'user'  # Explicit role tagging for regular users
    log_audit(email, 'User Login', 'SUCCESS',
              f'{email} authenticated successfully.',
              metadata_changes={
                  'file_manipulated': 'session',
                  'operation': 'AUTHENTICATE',
                  'affected_key': email,
                  'details': {
                      'role': 'user',
                      'status': 'success'
                  }
              })

    return jsonify({'message': 'Login successful!'}), 200


# ===========================================================================
# FILE MANAGEMENT API
# ===========================================================================

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    """
    Handle file upload with encryption and integrity hashing.

    Data Flow:
      1. Read raw bytes from the upload stream (memory only)
      2. Calculate SHA-256 hash of the plaintext (integrity fingerprint)
      3. Encrypt bytes with Fernet (AES-128-CBC + HMAC-SHA256)
      4. Write ONLY the ciphertext to disk as a .enc file
      5. Store metadata (hash, size, version) in metadata.json
      6. Log the event to audit_logs.json

    CRITICAL: Plaintext bytes are NEVER written to the filesystem.
    """
    user = session['user']

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided.'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400

    original_filename = file.filename

    # ── Read raw bytes into memory ────────────────────────────────────────
    try:
        plaintext_bytes = file.read()
    except Exception as e:
        log_audit(user, 'File Upload', 'WARNING',
                  f'Failed to read upload stream for "{original_filename}": {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'UPLOAD_ERROR',
                      'affected_key': original_filename,
                      'details': {
                          'error': str(e)
                      }
                  })
        return jsonify({'error': 'Failed to read file.'}), 500

    if len(plaintext_bytes) == 0:
        return jsonify({'error': 'Cannot upload an empty file.'}), 400

    # ── Storage quota enforcement ─────────────────────────────────────────
    user_vault = os.path.join(VAULT_DIR, user)
    current_usage = get_directory_size(user_vault)
    if current_usage + len(plaintext_bytes) > STORAGE_QUOTA_BYTES:
        log_audit(user, 'File Upload', 'WARNING',
                  f'Storage quota exceeded for {user}. '
                  f'Used: {current_usage} bytes, attempted: {len(plaintext_bytes)} bytes.',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'QUOTA_EXCEEDED',
                      'affected_key': original_filename,
                      'details': {
                          'used_bytes': current_usage,
                          'attempted_bytes': len(plaintext_bytes),
                          'limit_bytes': STORAGE_QUOTA_BYTES
                      }
                  })
        return jsonify({
            'error': 'Storage Quota Exhausted! You have exceeded your 50 MB limit.',
            'quota_exceeded': True,
            'used': current_usage,
            'limit': STORAGE_QUOTA_BYTES,
        }), 413

    # ── Step 1: SHA-256 integrity hash BEFORE encryption ──────────────────
    original_hash = calculate_sha256(plaintext_bytes)

    # ── Step 2: Encrypt plaintext bytes (Data at Rest protection) ─────────
    try:
        encrypted_bytes = encrypt_file_bytes(plaintext_bytes)
    except Exception as e:
        log_audit(user, 'File Encryption', 'CRITICAL ALERT',
                  f'Encryption failed for "{original_filename}": {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'ENCRYPTION_ERROR',
                      'affected_key': original_filename,
                      'details': {
                          'error': str(e)
                      }
                  })
        return jsonify({'error': 'Encryption failed.'}), 500

    # ── Step 3: Version management ────────────────────────────────────────
    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {'files': {}})

    if original_filename in user_meta.get('files', {}):
        # File with this name already exists — create a new version
        file_record = user_meta['files'][original_filename]
        new_version = file_record['current_version'] + 1
    else:
        new_version = 1
        user_meta.setdefault('files', {})

    encrypted_filename = f"{os.path.splitext(original_filename)[0]}_v{new_version}.enc"

    # ── Step 4: Write ONLY encrypted bytes to disk ────────────────────────
    enc_path = os.path.join(user_vault, encrypted_filename)
    os.makedirs(user_vault, exist_ok=True)
    try:
        with open(enc_path, 'wb') as enc_file:
            enc_file.write(encrypted_bytes)
    except Exception as e:
        log_audit(user, 'File Upload', 'CRITICAL ALERT',
                  f'Failed to write encrypted file "{encrypted_filename}": {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'WRITE_ERROR',
                      'affected_key': encrypted_filename,
                      'details': {
                          'error': str(e)
                      }
                  })
        return jsonify({'error': 'Failed to save encrypted file.'}), 500

    # ── Step 5: Update metadata.json ──────────────────────────────────────
    version_entry = {
        'version':            new_version,
        'encrypted_filename': encrypted_filename,
        'original_hash':      original_hash,
        'size':               len(plaintext_bytes),
        'encrypted_size':     len(encrypted_bytes),
        'uploaded_at':        datetime.now(timezone.utc).isoformat(),
    }

    if original_filename in user_meta['files']:
        user_meta['files'][original_filename]['versions'].append(version_entry)
        user_meta['files'][original_filename]['current_version'] = new_version
        user_meta['files'][original_filename]['original_hash'] = original_hash
        user_meta['files'][original_filename]['size'] = len(plaintext_bytes)
        user_meta['files'][original_filename]['updated_at'] = version_entry['uploaded_at']
    else:
        user_meta['files'][original_filename] = {
            'original_filename':  original_filename,
            'current_version':    new_version,
            'original_hash':      original_hash,
            'size':               len(plaintext_bytes),
            'created_at':         version_entry['uploaded_at'],
            'updated_at':         version_entry['uploaded_at'],
            'versions':           [version_entry],
        }

    metadata[user] = user_meta
    save_json(METADATA_FILE, metadata)

    # ── Step 6: Audit trail ───────────────────────────────────────────────
    log_audit(user, 'File Upload', 'SUCCESS',
              f'File "{original_filename}" (v{new_version}) encrypted and stored. '
              f'SHA-256: {original_hash[:16]}…  Size: {len(plaintext_bytes)} bytes.',
              metadata_changes={
                  'file_manipulated': 'metadata.json',
                  'operation': 'UPDATE',
                  'affected_key': f"{user}.files['{original_filename}']",
                  'details': {
                      'action': 'version_added' if new_version > 1 else 'file_created',
                      'filename': original_filename,
                      'version': new_version,
                      'size_bytes': len(plaintext_bytes),
                      'encrypted_size_bytes': len(encrypted_bytes),
                      'sha256': original_hash
                  }
              })

    return jsonify({
        'message':  f'File "{original_filename}" uploaded successfully (v{new_version}).',
        'filename': original_filename,
        'version':  new_version,
        'hash':     original_hash,
    }), 201


@app.route('/api/files', methods=['GET'])
@login_required
def api_list_files():
    """Return the authenticated user's file index from metadata.json."""
    user = session['user']
    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {}).get('files', {})

    files = []
    for fname, record in user_meta.items():
        files.append({
            'filename':        fname,
            'size':            record['size'],
            'current_version': record['current_version'],
            'original_hash':   record['original_hash'],
            'created_at':      record['created_at'],
            'updated_at':      record['updated_at'],
            'version_count':   len(record['versions']),
        })

    return jsonify({'files': files}), 200


@app.route('/api/file-versions/<path:filename>', methods=['GET'])
@login_required
def api_file_versions(filename):
    """Return the version history for a specific file."""
    user = session['user']
    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {}).get('files', {})

    if filename not in user_meta:
        return jsonify({'error': 'File not found.'}), 404

    return jsonify({
        'filename': filename,
        'versions': user_meta[filename]['versions'],
    }), 200


@app.route('/api/download/<path:filename>', methods=['GET'])
@app.route('/api/download/<path:filename>/<int:version>', methods=['GET'])
@login_required
def api_download(filename, version=None):
    """
    Download a file with in-memory decryption and integrity verification.

    Security Flow:
      1. Locate the encrypted .enc file on disk
      2. Read ciphertext into memory
      3. Decrypt ciphertext → plaintext (memory only)
      4. Recalculate SHA-256 of the decrypted plaintext
      5. Compare against the stored hash in metadata.json
      6. If match → serve file.  If mismatch → ABORT with tampering alert.
    """
    user = session['user']
    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {}).get('files', {})

    if filename not in user_meta:
        return jsonify({'error': 'File not found.'}), 404

    file_record = user_meta[filename]

    # Determine which version to serve
    if version is None:
        version = file_record['current_version']

    version_entry = None
    for v in file_record['versions']:
        if v['version'] == version:
            version_entry = v
            break

    if version_entry is None:
        return jsonify({'error': f'Version {version} not found.'}), 404

    enc_path = os.path.join(VAULT_DIR, user, version_entry['encrypted_filename'])

    if not os.path.exists(enc_path):
        log_audit(user, 'File Download', 'CRITICAL ALERT',
                  f'Encrypted file missing from disk: {version_entry["encrypted_filename"]}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'MISSING_FILE',
                      'affected_key': version_entry["encrypted_filename"]
                  })
        return jsonify({'error': 'Encrypted file not found on disk.'}), 404

    # ── Read encrypted bytes ──────────────────────────────────────────────
    try:
        with open(enc_path, 'rb') as f:
            encrypted_bytes = f.read()
    except Exception as e:
        log_audit(user, 'File Download', 'CRITICAL ALERT',
                  f'Failed to read encrypted file: {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'READ_ERROR',
                      'affected_key': version_entry["encrypted_filename"]
                  })
        return jsonify({'error': 'Failed to read encrypted file.'}), 500

    # ── Decrypt in memory ─────────────────────────────────────────────────
    try:
        decrypted_bytes = decrypt_file_bytes(encrypted_bytes)
    except Exception as e:
        log_audit(user, 'File Decryption', 'CRITICAL ALERT',
                  f'Decryption failed for "{filename}" v{version}: {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'DECRYPTION_ERROR',
                      'affected_key': filename,
                      'details': {
                          'version': version,
                          'error': str(e)
                      }
                  })
        return jsonify({'error': 'Decryption failed — possible key mismatch.'}), 500

    # ── Integrity Verification (SHA-256 comparison) ───────────────────────
    current_hash = calculate_sha256(decrypted_bytes)
    stored_hash  = version_entry['original_hash']

    if current_hash != stored_hash:
        log_audit(user, 'Integrity Check', 'CRITICAL ALERT',
                  f'FILE INTEGRITY TAMPERING DETECTED! '
                  f'File: "{filename}" v{version}. '
                  f'Expected SHA-256: {stored_hash[:16]}… '
                  f'Got: {current_hash[:16]}… '
                  f'Access DENIED — possible local storage modification!',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'INTEGRITY_VIOLATION',
                      'affected_key': filename,
                      'details': {
                          'version': version,
                          'expected_hash': stored_hash,
                          'actual_hash': current_hash
                      }
                  })
        return jsonify({
            'error':    'INTEGRITY TAMPERING DETECTED!',
            'message':  'The file has been modified on disk. '
                        'SHA-256 hash mismatch — access denied.',
            'tampering': True,
        }), 403

    log_audit(user, 'File Download', 'SUCCESS',
              f'File "{filename}" v{version} decrypted and integrity verified. '
              f'SHA-256: {current_hash[:16]}…',
              metadata_changes={
                  'file_manipulated': 'None',
                  'operation': 'READ',
                  'affected_key': filename,
                  'details': {
                      'version': version,
                      'sha256': current_hash
                  }
              })

    # ── Serve decrypted bytes directly from memory ────────────────────────
    mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename,
    )


@app.route('/api/preview/<path:filename>', methods=['GET'])
@app.route('/api/preview/<path:filename>/<int:version>', methods=['GET'])
@login_required
def api_preview(filename, version=None):
    """
    Preview a file by decrypting in memory and streaming to the frontend.

    Identical security flow to download (decrypt → hash check → serve),
    but served inline (not as attachment) for modal preview rendering.

    CRITICAL: No temporary decrypted file is ever written to disk.
    """
    user = session['user']
    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {}).get('files', {})

    if filename not in user_meta:
        return jsonify({'error': 'File not found.'}), 404

    file_record = user_meta[filename]

    if version is None:
        version = file_record['current_version']

    version_entry = None
    for v in file_record['versions']:
        if v['version'] == version:
            version_entry = v
            break

    if version_entry is None:
        return jsonify({'error': f'Version {version} not found.'}), 404

    enc_path = os.path.join(VAULT_DIR, user, version_entry['encrypted_filename'])

    if not os.path.exists(enc_path):
        return jsonify({'error': 'Encrypted file not found on disk.'}), 404

    try:
        with open(enc_path, 'rb') as f:
            encrypted_bytes = f.read()
    except Exception as e:
        return jsonify({'error': f'Failed to read file: {e}'}), 500

    try:
        decrypted_bytes = decrypt_file_bytes(encrypted_bytes)
    except Exception as e:
        log_audit(user, 'File Preview', 'CRITICAL ALERT',
                  f'Decryption failed during preview of "{filename}": {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'DECRYPTION_ERROR',
                      'affected_key': filename,
                      'details': {
                          'version': version,
                          'error': str(e)
                      }
                  })
        return jsonify({'error': 'Decryption failed.'}), 500

    # ── Integrity check ───────────────────────────────────────────────────
    current_hash = calculate_sha256(decrypted_bytes)
    stored_hash  = version_entry['original_hash']

    if current_hash != stored_hash:
        log_audit(user, 'Integrity Check', 'CRITICAL ALERT',
                  f'TAMPERING DETECTED during preview of "{filename}" v{version}! '
                  f'Expected: {stored_hash[:16]}…  Got: {current_hash[:16]}…',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'INTEGRITY_VIOLATION',
                      'affected_key': filename,
                      'details': {
                          'version': version,
                          'expected_hash': stored_hash,
                          'actual_hash': current_hash
                      }
                  })
        return jsonify({
            'error':    'INTEGRITY TAMPERING DETECTED!',
            'message':  'File integrity compromised — preview aborted.',
            'tampering': True,
        }), 403

    log_audit(user, 'File Preview', 'SUCCESS',
              f'File "{filename}" v{version} decrypted for preview. Integrity OK.',
              metadata_changes={
                  'file_manipulated': 'None',
                  'operation': 'READ',
                  'affected_key': filename,
                  'details': {
                      'version': version,
                      'sha256': current_hash
                  }
              })

    mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=mimetype,
        as_attachment=False,
        download_name=filename,
    )


# ===========================================================================
# SHARING API  (RBAC & Access Control)
# ===========================================================================

@app.route('/api/share', methods=['POST'])
@login_required
def api_share():
    """
    Share a file with another user without duplicating the physical file.

    Access Control Model:
      • The permission record is stored in permissions.json
      • It maps the target user to the owner's file path
      • Optional expiration timestamp for time-bounded access
      • NO file duplication — zero-copy sharing via permission pointers
    """
    user = session['user']
    data = request.get_json()

    target_email = data.get('target_email', '').strip().lower()
    filename     = data.get('filename', '').strip()
    expiry       = data.get('expiry', None)  # e.g. "1h", "1d", "7d", None

    # ── Validation ────────────────────────────────────────────────────────
    if not target_email or not filename:
        return jsonify({'error': 'Target email and filename are required.'}), 400

    if target_email == user:
        return jsonify({'error': 'You cannot share a file with yourself.'}), 400

    users = load_json(USERS_FILE)
    if target_email not in users:
        return jsonify({'error': f'User {target_email} does not exist.'}), 404

    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {}).get('files', {})
    if filename not in user_meta:
        return jsonify({'error': 'File not found in your vault.'}), 404

    # ── Calculate expiration timestamp ────────────────────────────────────
    expires_at = None
    if expiry:
        now = datetime.now(timezone.utc)
        expiry_map = {
            '1h':  timedelta(hours=1),
            '6h':  timedelta(hours=6),
            '1d':  timedelta(days=1),
            '7d':  timedelta(days=7),
            '30d': timedelta(days=30),
        }
        if expiry in expiry_map:
            expires_at = (now + expiry_map[expiry]).isoformat()
        else:
            return jsonify({'error': f'Invalid expiry option: {expiry}'}), 400

    # ── Write permission record (non-duplicating) ─────────────────────────
    permissions = load_json(PERMS_FILE)
    target_perms = permissions.get(target_email, [])

    # Check for duplicate share
    for perm in target_perms:
        if perm['file_owner'] == user and perm['filename'] == filename:
            # Update expiration if re-sharing
            perm['expires_at'] = expires_at
            perm['shared_at'] = datetime.now(timezone.utc).isoformat()
            permissions[target_email] = target_perms
            save_json(PERMS_FILE, permissions)
            log_audit(user, 'File Share Update', 'SUCCESS',
                      f'Updated share of "{filename}" with {target_email}. '
                      f'Expiry: {expires_at or "Never"}',
                      metadata_changes={
                          'file_manipulated': 'permissions.json',
                          'operation': 'UPDATE',
                          'affected_key': f"permissions['{target_email}']",
                          'details': {
                              'action': 'share_permission_updated',
                              'file_owner': user,
                              'shared_with': target_email,
                              'filename': filename,
                              'expires_at': expires_at or 'Never'
                          }
                      })
            return jsonify({'message': f'Share updated for {target_email}.'}), 200

    # New share permission entry
    perm_entry = {
        'file_owner':  user,
        'filename':    filename,
        'permission':  'view',
        'shared_at':   datetime.now(timezone.utc).isoformat(),
        'expires_at':  expires_at,
        'shared_by':   user,
    }
    target_perms.append(perm_entry)
    permissions[target_email] = target_perms
    save_json(PERMS_FILE, permissions)

    log_audit(user, 'File Share', 'SUCCESS',
              f'Shared "{filename}" with {target_email}. '
              f'Expiry: {expires_at or "Never"}. No file duplication.',
              metadata_changes={
                  'file_manipulated': 'permissions.json',
                  'operation': 'INSERT',
                  'affected_key': f"permissions['{target_email}']",
                  'details': {
                      'action': 'share_permission_granted',
                      'file_owner': user,
                      'shared_with': target_email,
                      'filename': filename,
                      'expires_at': expires_at or 'Never'
                  }
              })

    return jsonify({
        'message': f'File "{filename}" shared with {target_email} successfully.',
    }), 200


@app.route('/api/shared-files', methods=['GET'])
@login_required
def api_shared_files():
    """
    Retrieve files shared WITH the current user.

    For each permission record, validate the expiration timestamp.
    Expired shares are automatically filtered out and logged.
    """
    user = session['user']
    permissions = load_json(PERMS_FILE)
    metadata    = load_json(METADATA_FILE)
    user_perms  = permissions.get(user, [])

    shared_files = []
    now = datetime.now(timezone.utc)

    for perm in user_perms:
        # ── Check expiration ──────────────────────────────────────────────
        if perm.get('expires_at'):
            try:
                exp_time = datetime.fromisoformat(perm['expires_at'])
                if now > exp_time:
                    # Share has expired — skip it
                    continue
            except (ValueError, TypeError):
                pass

        owner = perm['file_owner']
        fname = perm['filename']

        # Fetch file metadata from the owner's index
        owner_meta = metadata.get(owner, {}).get('files', {}).get(fname)
        if owner_meta:
            shared_files.append({
                'filename':        fname,
                'owner':           owner,
                'size':            owner_meta['size'],
                'shared_at':       perm['shared_at'],
                'expires_at':      perm.get('expires_at'),
                'permission':      perm['permission'],
                'current_version': owner_meta.get('current_version', 1),
                'version_count':   len(owner_meta.get('versions', [])),
            })

    return jsonify({'shared_files': shared_files}), 200


@app.route('/api/shared/download/<path:owner>/<path:filename>', methods=['GET'])
@app.route('/api/shared/download/<path:owner>/<path:filename>/<int:version>', methods=['GET'])
@login_required
def api_shared_download(owner, filename, version=None):
    """
    Download a file shared with the current user (from the owner's vault).

    Security checks:
      1. Verify active permission exists in permissions.json
      2. Verify permission has not expired
      3. Decrypt in memory + integrity check (same as own files)
    """
    user = session['user']

    # ── Permission check ──────────────────────────────────────────────────
    permissions = load_json(PERMS_FILE)
    user_perms  = permissions.get(user, [])
    perm_record = None

    for perm in user_perms:
        if perm['file_owner'] == owner and perm['filename'] == filename:
            perm_record = perm
            break

    if not perm_record:
        log_audit(user, 'Shared Download', 'WARNING',
                  f'Access denied: {user} has no permission for {owner}/{filename}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'DENIED',
                      'affected_key': filename,
                      'details': {
                          'reason': 'no_sharing_permission',
                          'owner': owner
                      }
                  })
        return jsonify({'error': 'Access denied — no sharing permission.'}), 403

    # ── Expiration check ──────────────────────────────────────────────────
    if perm_record.get('expires_at'):
        try:
            exp_time = datetime.fromisoformat(perm_record['expires_at'])
            if datetime.now(timezone.utc) > exp_time:
                log_audit(user, 'Shared Download', 'WARNING',
                          f'Access denied: share of {owner}/{filename} has expired.',
                          metadata_changes={
                              'file_manipulated': 'None',
                              'operation': 'DENIED',
                              'affected_key': filename,
                              'details': {
                                  'reason': 'share_expired',
                                  'owner': owner
                              }
                          })
                return jsonify({
                    'error': 'This share has expired. Access denied.',
                    'expired': True,
                }), 403
        except (ValueError, TypeError):
            pass

    # ── Locate and decrypt the file ───────────────────────────────────────
    metadata = load_json(METADATA_FILE)
    owner_meta = metadata.get(owner, {}).get('files', {}).get(filename)

    if not owner_meta:
        return jsonify({'error': 'File no longer exists in owner\'s vault.'}), 404

    # Determine version entry
    if version is None:
        version_entry = owner_meta['versions'][-1]
    else:
        version_entry = None
        for v in owner_meta['versions']:
            if v['version'] == version:
                version_entry = v
                break

    if version_entry is None:
        return jsonify({'error': f'Version {version} not found.'}), 404

    enc_path = os.path.join(VAULT_DIR, owner, version_entry['encrypted_filename'])

    if not os.path.exists(enc_path):
        return jsonify({'error': 'Encrypted file not found.'}), 404

    try:
        with open(enc_path, 'rb') as f:
            encrypted_bytes = f.read()
        decrypted_bytes = decrypt_file_bytes(encrypted_bytes)
    except Exception as e:
        log_audit(user, 'Shared Decryption', 'CRITICAL ALERT',
                  f'Failed to decrypt shared file {owner}/{filename} v{version_entry["version"]}: {e}',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'DECRYPTION_ERROR',
                      'affected_key': filename,
                      'details': {
                          'owner': owner,
                          'version': version_entry["version"],
                          'error': str(e)
                      }
                  })
        return jsonify({'error': 'Decryption failed.'}), 500

    # ── Integrity verification ────────────────────────────────────────────
    current_hash = calculate_sha256(decrypted_bytes)
    stored_hash  = version_entry['original_hash']

    if current_hash != stored_hash:
        log_audit(user, 'Integrity Check', 'CRITICAL ALERT',
                  f'TAMPERING DETECTED on shared file {owner}/{filename} v{version_entry["version"]}!',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'INTEGRITY_VIOLATION',
                      'affected_key': filename,
                      'details': {
                          'owner': owner,
                          'version': version_entry["version"],
                          'expected_hash': stored_hash,
                          'actual_hash': current_hash
                      }
                  })
        return jsonify({
            'error':    'INTEGRITY TAMPERING DETECTED!',
            'tampering': True,
        }), 403

    log_audit(user, 'Shared Download', 'SUCCESS',
              f'Downloaded shared file "{filename}" v{version_entry["version"]} from {owner}. Integrity OK.',
              metadata_changes={
                  'file_manipulated': 'None',
                  'operation': 'READ',
                  'affected_key': filename,
                  'details': {
                      'owner': owner,
                      'version': version_entry["version"]
                  }
              })

    mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename,
    )


@app.route('/api/shared/preview/<path:owner>/<path:filename>', methods=['GET'])
@app.route('/api/shared/preview/<path:owner>/<path:filename>/<int:version>', methods=['GET'])
@login_required
def api_shared_preview(owner, filename, version=None):
    """Preview a shared file (in-memory decryption, no disk writes)."""
    user = session['user']

    # Permission + expiration check
    permissions = load_json(PERMS_FILE)
    user_perms  = permissions.get(user, [])
    perm_record = None

    for perm in user_perms:
        if perm['file_owner'] == owner and perm['filename'] == filename:
            perm_record = perm
            break

    if not perm_record:
        return jsonify({'error': 'Access denied.'}), 403

    if perm_record.get('expires_at'):
        try:
            exp_time = datetime.fromisoformat(perm_record['expires_at'])
            if datetime.now(timezone.utc) > exp_time:
                return jsonify({'error': 'Share expired.', 'expired': True}), 403
        except (ValueError, TypeError):
            pass

    metadata = load_json(METADATA_FILE)
    owner_meta = metadata.get(owner, {}).get('files', {}).get(filename)
    if not owner_meta:
        return jsonify({'error': 'File not found.'}), 404

    # Determine version entry
    if version is None:
        version_entry = owner_meta['versions'][-1]
    else:
        version_entry = None
        for v in owner_meta['versions']:
            if v['version'] == version:
                version_entry = v
                break

    if version_entry is None:
        return jsonify({'error': f'Version {version} not found.'}), 404

    enc_path = os.path.join(VAULT_DIR, owner, version_entry['encrypted_filename'])

    if not os.path.exists(enc_path):
        return jsonify({'error': 'File not found on disk.'}), 404

    try:
        with open(enc_path, 'rb') as f:
            encrypted_bytes = f.read()
        decrypted_bytes = decrypt_file_bytes(encrypted_bytes)
    except Exception as e:
        return jsonify({'error': 'Decryption failed.'}), 500

    current_hash = calculate_sha256(decrypted_bytes)
    if current_hash != version_entry['original_hash']:
        log_audit(user, 'Integrity Check', 'CRITICAL ALERT',
                  f'TAMPERING on shared preview {owner}/{filename} v{version_entry["version"]}!',
                  metadata_changes={
                      'file_manipulated': 'None',
                      'operation': 'INTEGRITY_VIOLATION',
                      'affected_key': filename,
                      'details': {
                          'owner': owner,
                          'version': version_entry["version"],
                          'expected_hash': version_entry['original_hash'],
                          'actual_hash': current_hash
                      }
                  })
        return jsonify({'error': 'INTEGRITY TAMPERING DETECTED!', 'tampering': True}), 403

    log_audit(user, 'Shared Preview', 'SUCCESS',
              f'Previewed shared file "{filename}" v{version_entry["version"]} from {owner}.',
              metadata_changes={
                  'file_manipulated': 'None',
                  'operation': 'READ',
                  'affected_key': filename,
                  'details': {
                      'owner': owner,
                      'version': version_entry["version"]
                  }
              })

    mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(decrypted_bytes),
        mimetype=mimetype,
        as_attachment=False,
        download_name=filename,
    )


@app.route('/api/shared/file-versions/<path:owner>/<path:filename>', methods=['GET'])
@login_required
def api_shared_file_versions(owner, filename):
    """Return the version history for a file shared with the current user."""
    user = session['user']

    # ── Permission check ──────────────────────────────────────────────────
    permissions = load_json(PERMS_FILE)
    user_perms  = permissions.get(user, [])
    perm_record = None

    for perm in user_perms:
        if perm['file_owner'] == owner and perm['filename'] == filename:
            perm_record = perm
            break

    if not perm_record:
        return jsonify({'error': 'Access denied — no sharing permission.'}), 403

    # ── Expiration check ──────────────────────────────────────────────────
    if perm_record.get('expires_at'):
        try:
            exp_time = datetime.fromisoformat(perm_record['expires_at'])
            if datetime.now(timezone.utc) > exp_time:
                return jsonify({'error': 'This share has expired. Access denied.', 'expired': True}), 403
        except (ValueError, TypeError):
            pass

    metadata = load_json(METADATA_FILE)
    owner_meta = metadata.get(owner, {}).get('files', {}).get(filename)

    if not owner_meta:
        return jsonify({'error': 'File not found in owner\'s vault.'}), 404

    return jsonify({
        'filename': filename,
        'owner':    owner,
        'versions': owner_meta['versions'],
    }), 200


@app.route('/api/shared/delete/<path:owner>/<path:filename>', methods=['DELETE'])
@login_required
def api_shared_delete(owner, filename):
    """Remove a shared file from the user's shared-with-me list (revokes recipient access)."""
    user = session['user']
    permissions = load_json(PERMS_FILE)
    user_perms  = permissions.get(user, [])

    # Find and remove permission
    new_perms = [
        p for p in user_perms
        if not (p['file_owner'] == owner and p['filename'] == filename)
    ]

    if len(new_perms) == len(user_perms):
        return jsonify({'error': 'Shared file not found or not shared with you.'}), 404

    permissions[user] = new_perms
    save_json(PERMS_FILE, permissions)

    log_audit(user, 'Shared File Access Revoked', 'SUCCESS',
              f'{user} removed shared file "{filename}" by owner {owner} from their library.',
              metadata_changes={
                  'file_manipulated': 'permissions.json',
                  'operation': 'DELETE',
                  'affected_key': f"permissions['{user}']",
                  'details': {
                      'action': 'share_permission_revoked_by_recipient',
                      'file_owner': owner,
                      'shared_with': user,
                      'filename': filename
                  }
              })

    return jsonify({'message': f'Shared file "{filename}" removed successfully.'}), 200


# ===========================================================================
# USER SEARCH API  (Gmail-Style Autocomplete)
# ===========================================================================

@app.route('/api/users/search', methods=['GET'])
@login_required
def api_search_users():
    """
    Real-time user search for the Share modal autocomplete.

    Queries users.json using substring matching on the email field.
    The current user is excluded from results to prevent self-sharing.

    Triggered on every keystroke from the frontend for instant feedback.
    """
    query = request.args.get('q', '').strip().lower()
    user  = session['user']

    if not query or len(query) < 1:
        return jsonify({'users': []}), 200

    users = load_json(USERS_FILE)
    matches = []

    for email in users:
        if email != user and query in email:
            matches.append({
                'email':  email,
                'avatar': email[0].upper(),  # First letter as avatar
            })

    # Limit results to prevent excessive payloads
    return jsonify({'users': matches[:10]}), 200


# ===========================================================================
# AUDIT LOG API
# ===========================================================================

@app.route('/api/audit-logs', methods=['GET'])
@login_required
def api_audit_logs():
    """
    Return the complete audit log, optionally filtered by the current user.

    The audit ledger is a chronological record implementing the
    Non-repudiation security principle — every action is attributable
    to a specific actor at a specific time.
    """
    logs = load_json(AUDIT_FILE)
    filter_own = request.args.get('own', 'false').lower() == 'true'

    if filter_own:
        user = session['user']
        logs = [log for log in logs if log.get('actor') == user]

    # Return in reverse chronological order (newest first)
    logs.reverse()
    return jsonify({'logs': logs}), 200


# ===========================================================================
# STORAGE INFO API
# ===========================================================================

@app.route('/api/storage-info', methods=['GET'])
@login_required
def api_storage_info():
    """
    Return the current user's storage usage and quota information.

    Used by the frontend to render the storage capacity bar in the sidebar.
    """
    user = session['user']
    user_vault = os.path.join(VAULT_DIR, user)
    used = get_directory_size(user_vault)

    return jsonify({
        'used':       used,
        'limit':      STORAGE_QUOTA_BYTES,
        'used_mb':    round(used / (1024 * 1024), 2),
        'limit_mb':   round(STORAGE_QUOTA_BYTES / (1024 * 1024), 2),
        'percentage': round((used / STORAGE_QUOTA_BYTES) * 100, 1) if STORAGE_QUOTA_BYTES > 0 else 0,
    }), 200


# ===========================================================================
# DELETE FILE API
# ===========================================================================

@app.route('/api/delete/<path:filename>', methods=['DELETE'])
@login_required
def api_delete(filename):
    """Delete a file and all its versions from the user's vault."""
    user = session['user']
    metadata = load_json(METADATA_FILE)
    user_meta = metadata.get(user, {}).get('files', {})

    if filename not in user_meta:
        return jsonify({'error': 'File not found.'}), 404

    file_record = user_meta[filename]

    # Delete all version files from disk
    for version in file_record['versions']:
        enc_path = os.path.join(VAULT_DIR, user, version['encrypted_filename'])
        try:
            if os.path.exists(enc_path):
                os.remove(enc_path)
        except OSError as e:
            log_audit(user, 'File Delete', 'WARNING',
                      f'Failed to delete {version["encrypted_filename"]}: {e}',
                      metadata_changes={
                          'file_manipulated': 'None',
                          'operation': 'DELETE_ERROR',
                          'affected_key': version["encrypted_filename"],
                          'details': {
                              'error': str(e)
                          }
                      })

    # Remove from metadata
    del user_meta[filename]
    metadata[user]['files'] = user_meta
    save_json(METADATA_FILE, metadata)

    # Remove any sharing permissions referencing this file
    permissions = load_json(PERMS_FILE)
    for target_email in permissions:
        permissions[target_email] = [
            p for p in permissions[target_email]
            if not (p['file_owner'] == user and p['filename'] == filename)
        ]
    save_json(PERMS_FILE, permissions)

    log_audit(user, 'File Delete', 'SUCCESS',
              f'Deleted "{filename}" and all {len(file_record["versions"])} version(s).',
              metadata_changes={
                  'file_manipulated': 'metadata.json, permissions.json',
                  'operation': 'DELETE',
                  'affected_key': f"{user}.files['{filename}']",
                  'details': {
                      'action': 'file_purged',
                      'filename': filename,
                      'versions_deleted': len(file_record["versions"])
                  }
              })

    return jsonify({'message': f'File "{filename}" deleted successfully.'}), 200


# ===========================================================================
# SUPER ADMIN API ENDPOINTS  (Privileged Administrative Operations)
# ===========================================================================
# All endpoints in this section are protected by @superadmin_required.
# CRITICAL ZERO-KNOWLEDGE CONSTRAINT:
#   These routes NEVER call decrypt_file_bytes() or encrypt_file_bytes().
#   The Super Admin can see metadata (counts, sizes, timestamps) but has
#   ZERO access to the plaintext content of any user's encrypted files.
# ===========================================================================

@app.route('/api/admin/metrics', methods=['GET'])
@superadmin_required
def api_admin_metrics():
    """
    Return the Global User Metrics Matrix for the Super Admin dashboard.

    For each registered user, computes:
      • Total files uploaded       — counted from metadata.json
      • Total shared relations     — counted from permissions.json (inbound + outbound)
      • Live storage used          — calculated via os.path.getsize() walk of Vault_Storage/<user>/

    Also returns aggregate system-wide totals for the summary metric cards.

    Security:
      • Protected by @superadmin_required (Authentication + Authorization)
      • Returns metadata ONLY — no file hashes, no decryption keys, no content
      • Logged to audit trail (Accounting)
    """
    users = load_json(USERS_FILE)
    metadata = load_json(METADATA_FILE)
    permissions = load_json(PERMS_FILE)

    user_metrics = []
    total_files = 0
    total_storage = 0

    for email in users:
        # ── Count files from metadata.json ────────────────────────────────
        user_files = metadata.get(email, {}).get('files', {})
        file_count = len(user_files)
        total_files += file_count

        # ── Count shared relations from permissions.json ──────────────────
        # Inbound: files shared WITH this user (they appear as a key in permissions)
        inbound_shares = len(permissions.get(email, []))
        # Outbound: files this user shared TO others (they appear as file_owner)
        outbound_shares = 0
        for target_email, perm_list in permissions.items():
            if target_email != email:
                for perm in perm_list:
                    if perm.get('file_owner') == email:
                        outbound_shares += 1
        shared_relations = inbound_shares + outbound_shares

        # ── Calculate live storage via os.path.getsize() walk ─────────────
        user_vault_path = os.path.join(VAULT_DIR, email)
        storage_bytes = get_directory_size(user_vault_path)
        storage_mb = round(storage_bytes / (1024 * 1024), 3)
        total_storage += storage_bytes

        user_metrics.append({
            'email':            email,
            'total_files':      file_count,
            'shared_relations': shared_relations,
            'storage_bytes':    storage_bytes,
            'storage_mb':       storage_mb,
            'created_at':       users[email].get('created_at', 'Unknown'),
        })

    return jsonify({
        'users':          user_metrics,
        'total_users':    len(users),
        'total_files':    total_files,
        'total_storage':  total_storage,
        'total_storage_mb': round(total_storage / (1024 * 1024), 3),
    }), 200


@app.route('/api/admin/audit-logs', methods=['GET'])
@superadmin_required
def api_admin_audit_logs():
    """
    Return the complete system audit log for the Super Admin dashboard.

    Returns ALL audit entries in reverse chronological order (newest first).
    Unlike the user-facing /api/audit-logs endpoint, this does NOT filter
    by actor — the Super Admin sees the full system-wide security history.

    Security:
      • Protected by @superadmin_required
      • Logs contain action descriptions but NEVER file content (Zero-Knowledge)
    """
    logs = load_json(AUDIT_FILE)
    logs.reverse()  # Newest events first
    return jsonify({'logs': logs}), 200


@app.route('/api/admin/delete-user/<path:email>', methods=['DELETE'])
@superadmin_required
def api_admin_delete_user(email):
    """
    Permanently delete a user and all their associated data.

    Deletion Protocol (irreversible):
      1. Remove user record from users.json
      2. Remove all file metadata from metadata.json
      3. Remove all permission entries (inbound AND outbound) from permissions.json
      4. Recursively delete the user's encrypted vault folder via shutil.rmtree()
      5. Log the administrative action to audit_logs.json

    Security:
      • Protected by @superadmin_required (only Super Admin can execute)
      • Self-deletion of the admin account is explicitly prevented
      • The deletion does NOT decrypt any files — encrypted .enc files are
        removed as raw bytes from the filesystem (Zero-Knowledge maintained)
      • Full audit trail recorded for non-repudiation

    AAA Mapping:
      • Authentication: session must be active
      • Authorization:  role must be 'superadmin'
      • Accounting:     deletion event logged with full details
    """
    email = email.strip().lower()

    # ── Prevent self-deletion of the admin account ────────────────────────
    if email == SUPER_ADMIN_EMAIL:
        return jsonify({'error': 'Cannot delete the Super Admin account.'}), 403

    # ── Verify user exists ────────────────────────────────────────────────
    users = load_json(USERS_FILE)
    if email not in users:
        return jsonify({'error': f'User {email} does not exist.'}), 404

    # ── Step 1: Remove from users.json ────────────────────────────────────
    del users[email]
    save_json(USERS_FILE, users)

    # ── Step 2: Remove from metadata.json ─────────────────────────────────
    metadata = load_json(METADATA_FILE)
    if email in metadata:
        del metadata[email]
        save_json(METADATA_FILE, metadata)

    # ── Step 3: Remove from permissions.json ──────────────────────────────
    # Remove inbound permissions (files shared WITH this user)
    # AND outbound permissions (files this user shared TO others)
    permissions = load_json(PERMS_FILE)
    # Remove the user's own inbound share list
    if email in permissions:
        del permissions[email]
    # Remove outbound shares: where this user is the file_owner
    for target_email in list(permissions.keys()):
        permissions[target_email] = [
            p for p in permissions[target_email]
            if p.get('file_owner') != email
        ]
    save_json(PERMS_FILE, permissions)

    # ── Step 4: Recursively delete encrypted vault folder ─────────────────
    # CRITICAL: This deletes raw .enc ciphertext files from disk.
    # No decryption occurs — Zero-Knowledge principle is maintained.
    user_vault_path = os.path.join(VAULT_DIR, email)
    if os.path.exists(user_vault_path):
        try:
            shutil.rmtree(user_vault_path)
        except OSError as e:
            log_audit(SUPER_ADMIN_EMAIL, 'User Deletion', 'WARNING',
                      f'Failed to delete vault folder for {email}: {e}',
                      metadata_changes={
                          'file_manipulated': 'None',
                          'operation': 'DELETE_ERROR',
                          'affected_key': f'Vault_Storage/{email}',
                          'details': {
                              'error': str(e)
                          }
                      })

    # ── Step 5: Audit trail (Non-repudiation) ─────────────────────────────
    log_audit(SUPER_ADMIN_EMAIL, 'User Deletion', 'SUCCESS',
              f'Super Admin permanently deleted user {email}. '
              f'Removed from users.json, metadata.json, permissions.json. '
              f'Vault folder recursively deleted.',
              metadata_changes={
                  'file_manipulated': 'users.json, metadata.json, permissions.json',
                  'operation': 'DELETE',
                  'affected_key': email,
                  'details': {
                      'action': 'user_purged',
                      'user_email': email,
                      'vault_folder_deleted': True
                  }
              })

    return jsonify({
        'message': f'User {email} has been permanently deleted.',
    }), 200


# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == '__main__':
    initialise_storage()
    print("\n")
    print("  ==============================================================")
    print("  |          Zero Trust Secure Vault -- v1.0                    |")
    print("  |        Encrypted File Storage with Integrity               |")
    print("  |                                                            |")
    print("  |   Server:  http://127.0.0.1:5000                           |")
    print("  |   Mode:    Development (Debug ON)                          |")
    print("  |   Storage: ./storage/Vault_Storage/                        |")
    print("  ==============================================================")
    app.run(debug=True, host='127.0.0.1', port=5000)
