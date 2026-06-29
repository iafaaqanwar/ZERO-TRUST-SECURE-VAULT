<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-3.1.1-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/Encryption-AES--128--CBC-blueviolet?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="Encryption"/>
  <img src="https://img.shields.io/badge/Hashing-SHA--256-orange?style=for-the-badge&logo=hashnode&logoColor=white" alt="Hashing"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🔐 Zero Trust Secure Vault</h1>

<p align="center">
  <strong>A Google Drive-inspired encrypted file vault built on Zero Trust security principles.</strong><br/>
  All files are encrypted at rest, integrity-verified on every access, and governed by strict role-based access control — with zero external databases.
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-security-architecture">Security</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-getting-started">Setup</a> •
  <a href="#-project-structure">Structure</a> •
  <a href="#-api-reference">API</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-team">Team</a>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Security Architecture](#-security-architecture)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Project Structure](#-project-structure)
- [Data Storage Design](#-data-storage-design)
- [API Reference](#-api-reference)
- [Super Admin Panel](#-super-admin-panel)
- [Screenshots](#-screenshots)
- [Team](#-team)
- [License](#-license)

---

## 🧭 Overview

**Zero Trust Secure Vault** is a web-based encrypted file storage system that implements the **Zero Trust security model** — _"Never trust, always verify."_ Every file operation (upload, download, preview, share) requires authentication, authorization checks, and integrity verification. The system uses **no external databases** — all persistence is handled through JSON files and the local filesystem.

### Why Zero Trust?

Traditional perimeter-based security trusts users once they are inside the network. Zero Trust eliminates implicit trust by:

- **Verifying every request** — Authentication is enforced on every API call
- **Applying least privilege** — Users can only access their own files; the Super Admin cannot read file contents
- **Assuming breach** — All files are encrypted at rest, so even physical disk access reveals nothing
- **Logging everything** — A continuous audit trail ensures non-repudiation

---

## ✨ Features

### 🔒 Core Security
| Feature | Description |
|---|---|
| **AES-128-CBC Encryption** | Every file is encrypted via Fernet (AES-128-CBC + HMAC-SHA256) before touching disk |
| **SHA-256 Integrity Verification** | Hashes are computed at upload and re-verified on every download/preview |
| **Tamper Detection** | Hash mismatch triggers a `CRITICAL ALERT` and blocks file access |
| **PBKDF2-SHA256 Password Hashing** | User passwords are salted and hashed with 600,000 iterations |
| **In-Memory Decryption** | Plaintext bytes are **never** written to disk — served directly from memory |

### 📂 File Management
| Feature | Description |
|---|---|
| **Drag & Drop Upload** | Modern drag-and-drop file upload interface |
| **File Versioning** | Automatic version tracking — upload the same filename to create a new version |
| **In-Browser File Preview** | Preview images, PDFs, text files, and videos directly in the browser |
| **Secure Download** | Files are decrypted in memory and streamed to the client |
| **File Deletion** | Removes all versions from disk and cleans up metadata + permissions |

### 🤝 Secure File Sharing
| Feature | Description |
|---|---|
| **Zero-Copy Sharing** | Files are shared via permission pointers — no file duplication |
| **Time-Bounded Access** | Share with expiration periods: 1h, 6h, 1d, 7d, or 30d |
| **Auto-Expiration** | Expired shares are automatically filtered and access is denied |
| **Gmail-Style User Search** | Real-time autocomplete search when selecting users to share with |
| **Revocable Access** | Both owner and recipient can revoke shared file access |

### 👨‍💼 Super Admin Console
| Feature | Description |
|---|---|
| **Zero-Knowledge Admin** | Admin can see metadata (counts, sizes) but **cannot** read file contents |
| **User Management** | View all users, their file counts, storage usage, and shared relations |
| **User Deletion** | Permanently purge a user and all their data (files, metadata, permissions) |
| **System-Wide Audit Logs** | View the complete security event history across all users |
| **Separate Control Plane** | Admin operates on a different dashboard, isolated from user file operations |

### 📊 Additional Features
| Feature | Description |
|---|---|
| **50 MB Storage Quota** | Per-user storage limit enforced at upload time |
| **Storage Usage Dashboard** | Real-time storage bar showing used vs. available space |
| **Comprehensive Audit Logging** | Every action (login, upload, download, share, delete) is recorded |
| **Domain-Locked Accounts** | Only `@zerotrustvault.com` email addresses can register |
| **Responsive UI** | Modern, dark-themed interface inspired by Google Drive |

---

## 🛡️ Security Architecture

### AAA Framework (Authentication, Authorization, Accounting)

```
┌────────────────────┬─────────────────────────────────────────────────────────┐
│ Pillar             │ Implementation                                          │
├────────────────────┼─────────────────────────────────────────────────────────┤
│ Authentication     │ Email/password login; passwords hashed via PBKDF2       │
│ Authorization      │ RBAC via permissions.json; per-file access grants       │
│ Accounting         │ Continuous audit trail in audit_logs.json               │
└────────────────────┴─────────────────────────────────────────────────────────┘
```

### CIA Triad Implementation

```
┌────────────────────┬─────────────────────────────────────────────────────────┐
│ Principle          │ Implementation                                          │
├────────────────────┼─────────────────────────────────────────────────────────┤
│ Confidentiality    │ Fernet (AES-128-CBC) encryption at rest                 │
│ Integrity          │ SHA-256 hash verification on every file access          │
│ Availability       │ Per-user 50 MB storage quota enforcement                │
└────────────────────┴─────────────────────────────────────────────────────────┘
```

### Encryption Data Flow

```
Upload:
  plaintext bytes ──► SHA-256 hash ──► AES-128-CBC encrypt ──► .enc file on disk
                         │
                         └──► stored in metadata.json (integrity fingerprint)

Download:
  .enc file ──► AES-128-CBC decrypt ──► SHA-256 hash ──► compare with stored hash
                       │                                         │
                       │                                   ┌─────┴─────┐
                       │                                   │  MATCH?   │
                       │                                   └─────┬─────┘
                       │                                   YES ↙     ↘ NO
                       └──► serve to client              ✅ Serve   🚨 BLOCK
                                                                    (Tampering Alert)
```

### Zero-Knowledge Admin Architecture

The Super Admin operates on a **separate control plane**:

- ✅ Can view user metadata (file counts, storage sizes, timestamps)
- ✅ Can view system-wide audit logs
- ✅ Can delete user accounts
- ❌ **Cannot** decrypt or download any user's files
- ❌ **Cannot** access the regular user dashboard
- ❌ Has **no routes** that invoke `decrypt_file_bytes()` or `encrypt_file_bytes()`

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, Flask 3.1.1 |
| **Encryption** | `cryptography` library (Fernet / AES-128-CBC + HMAC-SHA256) |
| **Password Hashing** | Werkzeug (PBKDF2-SHA256, 600k iterations) |
| **Frontend** | HTML5, CSS3 (custom dark theme), Vanilla JavaScript |
| **Data Storage** | JSON files + filesystem (no SQL/NoSQL databases) |
| **Session Management** | Flask server-side sessions with cryptographic secret key |

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10** or higher
- **pip** (Python package manager)
- **Git** (for cloning)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/<your-username>/Zero_Trust_Vault.git
   cd Zero_Trust_Vault
   ```

2. **Create a virtual environment** (recommended)

   ```bash
   python -m venv venv

   # Windows
   venv\Scripts\activate

   # macOS / Linux
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**

   ```bash
   python app.py
   ```

5. **Open in browser**

   ```
   http://127.0.0.1:5000
   ```

### Default Credentials

| Role | Email | Password |
|---|---|---|
| **Super Admin** | `admin@zerotrustvault.com` | `admin7258` |
| **Regular User** | Sign up with any `@zerotrustvault.com` email | Your chosen password |

> ⚠️ **Note:** Change the Super Admin credentials in `app.py` before any production deployment.

---

## 📁 Project Structure

```
Zero_Trust_Vault/
│
├── app.py                    # Main Flask application server (1800+ lines)
│                             #   ├── Route definitions (pages + API)
│                             #   ├── Authentication & Authorization decorators
│                             #   ├── File upload/download/delete/share logic
│                             #   ├── Super Admin API endpoints
│                             #   ├── Audit logging engine
│                             #   └── Storage quota management
│
├── security.py               # Cryptographic engine
│                             #   ├── Fernet (AES-128-CBC) encrypt/decrypt
│                             #   ├── SHA-256 integrity hashing
│                             #   └── Master key management
│
├── requirements.txt          # Python dependencies
│
├── static/                   # Frontend assets
│   ├── style.css             # Main application stylesheet (dark theme)
│   ├── superadmin.css        # Super Admin console stylesheet
│   ├── script.js             # Client-side JavaScript (42 KB)
│   ├── afaaq.jpg             # Team member photos
│   ├── ahsan.jpg
│   ├── arslan.jpg
│   └── taimoor.jpg
│
├── templates/                # Jinja2 HTML templates
│   ├── login.html            # Login & Signup portal
│   ├── dashboard.html        # Main user dashboard (Google Drive-style)
│   └── superadmin.html       # Super Admin console
│
└── storage/                  # Data persistence layer (auto-created)
    ├── users.json            # User credentials & profile metadata
    ├── metadata.json         # File index with SHA-256 hashes & versions
    ├── permissions.json      # Access control matrix & expiration rules
    ├── audit_logs.json       # Chronological security event ledger
    ├── secret.key            # Fernet master encryption key (⚠️ NEVER commit!)
    └── Vault_Storage/        # Per-user encrypted file directories
        ├── user1@zerotrustvault.com/
        │   ├── document_v1.enc
        │   └── image_v1.enc
        └── user2@zerotrustvault.com/
            └── report_v1.enc
```

---

## 💾 Data Storage Design

All data is persisted using **JSON files** — no external databases are required.

### `users.json` — User Registry

```json
{
  "john@zerotrustvault.com": {
    "password_hash": "pbkdf2:sha256:600000$...",
    "created_at": "2026-06-29T10:00:00+00:00",
    "storage_path": "Vault_Storage/john@zerotrustvault.com"
  }
}
```

### `metadata.json` — File Index

```json
{
  "john@zerotrustvault.com": {
    "files": {
      "report.pdf": {
        "original_filename": "report.pdf",
        "current_version": 2,
        "original_hash": "a1b2c3d4e5f6...",
        "size": 1048576,
        "created_at": "2026-06-29T10:00:00+00:00",
        "updated_at": "2026-06-29T12:00:00+00:00",
        "versions": [
          {
            "version": 1,
            "encrypted_filename": "report_v1.enc",
            "original_hash": "a1b2c3d4e5f6...",
            "size": 1048576,
            "encrypted_size": 1048620,
            "uploaded_at": "2026-06-29T10:00:00+00:00"
          }
        ]
      }
    }
  }
}
```

### `permissions.json` — Access Control Matrix

```json
{
  "jane@zerotrustvault.com": [
    {
      "file_owner": "john@zerotrustvault.com",
      "filename": "report.pdf",
      "permission": "view",
      "shared_at": "2026-06-29T11:00:00+00:00",
      "expires_at": "2026-07-06T11:00:00+00:00",
      "shared_by": "john@zerotrustvault.com"
    }
  ]
}
```

### `audit_logs.json` — Security Event Ledger

```json
[
  {
    "timestamp": "2026-06-29T10:00:00+00:00",
    "actor": "john@zerotrustvault.com",
    "action": "File Upload",
    "classification": "SUCCESS",
    "details": "File \"report.pdf\" (v1) encrypted and stored.",
    "metadata_changes": {
      "file_manipulated": "metadata.json",
      "operation": "UPDATE",
      "affected_key": "john@zerotrustvault.com.files['report.pdf']"
    }
  }
]
```

---

## 📡 API Reference

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/signup` | Register a new user account |
| `POST` | `/api/login` | Authenticate and establish session |
| `GET` | `/logout` | Destroy session and redirect to login |

### File Operations

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload and encrypt a file |
| `GET` | `/api/files` | List all files in user's vault |
| `GET` | `/api/file-versions/<filename>` | Get version history for a file |
| `GET` | `/api/download/<filename>` | Download & decrypt a file (latest version) |
| `GET` | `/api/download/<filename>/<version>` | Download a specific version |
| `GET` | `/api/preview/<filename>` | Preview a file inline in browser |
| `GET` | `/api/preview/<filename>/<version>` | Preview a specific version |
| `DELETE` | `/api/delete/<filename>` | Delete a file and all its versions |

### Sharing

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/share` | Share a file with another user |
| `GET` | `/api/shared-files` | List files shared with current user |
| `GET` | `/api/shared/download/<owner>/<filename>` | Download a shared file |
| `GET` | `/api/shared/preview/<owner>/<filename>` | Preview a shared file |
| `GET` | `/api/shared/file-versions/<owner>/<filename>` | Version history for shared file |
| `DELETE` | `/api/shared/delete/<owner>/<filename>` | Remove a file from shared-with-me |

### User Search

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/users/search?q=<query>` | Search users for sharing (autocomplete) |

### Storage & Audit

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/storage-info` | Get current user's storage usage |
| `GET` | `/api/audit-logs` | Get audit logs (optionally filtered by user) |

### Super Admin (Protected)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/admin/metrics` | Global user metrics matrix |
| `GET` | `/api/admin/audit-logs` | System-wide audit log (unfiltered) |
| `DELETE` | `/api/admin/delete-user/<email>` | Permanently delete a user |

---

## 👨‍💼 Super Admin Panel

The Super Admin console provides system-wide oversight without compromising user privacy:

- **User Metrics Matrix** — Overview of all users with file counts, storage usage, and sharing statistics
- **System-Wide Audit Trail** — Complete chronological security event log with classification filters (SUCCESS, WARNING, CRITICAL ALERT)
- **User Management** — Ability to permanently delete users and purge all associated data
- **Zero-Knowledge Design** — The admin dashboard has **no routes** that invoke decryption functions

> 🔑 **Access:** Login with `admin@zerotrustvault.com` / `admin7258`

---

## 📸 Screenshots

> Screenshots of the application can be added here after running the app locally.

<!-- Uncomment and replace with actual screenshot paths:
![Login Page](screenshots/login.png)
![User Dashboard](screenshots/dashboard.png)
![Super Admin Console](screenshots/superadmin.png)
-->

---

## 🔧 Configuration

Key configuration constants can be modified in `app.py`:

| Constant | Default | Description |
|---|---|---|
| `STORAGE_QUOTA_BYTES` | `50 MB` | Per-user storage limit |
| `VALID_DOMAIN` | `@zerotrustvault.com` | Required email domain for registration |
| `SUPER_ADMIN_EMAIL` | `admin@zerotrustvault.com` | Super Admin email |
| `SUPER_ADMIN_PASSWORD` | `admin7258` | Super Admin password |
| `MAX_CONTENT_LENGTH` | `50 MB` | Maximum upload file size |

---

## ⚠️ Security Considerations

> This project is designed as an **academic/educational demonstration** of Zero Trust security concepts. For production deployment, consider the following improvements:

1. **Key Management** — Move `secret.key` to a cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault)
2. **HTTPS** — Deploy behind a TLS-terminating reverse proxy (Nginx, Caddy)
3. **Rate Limiting** — Add brute-force protection on login endpoints
4. **CSRF Protection** — Enable Flask-WTF CSRF tokens for form submissions
5. **Session Store** — Use Redis or server-side session storage instead of filesystem
6. **Admin Credentials** — Use environment variables instead of hardcoded credentials
7. **Database** — Replace JSON files with a proper database for concurrent access
8. **Key Rotation** — Implement periodic encryption key rotation with versioning

---

## 👥 Team

This project was developed as part of the **Information Security (IS)** course — 4th Semester.

| Member | Photo |
|---|---|
| **Afaaq** | <img src="static/afaaq.jpg" width="80" style="border-radius: 50%"/> |
| **Ahsan** | <img src="static/ahsan.jpg" width="80" style="border-radius: 50%"/> |
| **Arslan** | <img src="static/arslan.jpg" width="80" style="border-radius: 50%"/> |
| **Taimoor** | <img src="static/taimoor.jpg" width="80" style="border-radius: 50%"/> |

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) — Lightweight WSGI web framework
- [Cryptography](https://cryptography.io/) — Fernet symmetric encryption
- [Werkzeug](https://werkzeug.palletsprojects.com/) — PBKDF2 password hashing utilities

---

<p align="center">
  <strong>🔐 Never Trust. Always Verify. Always Encrypt. 🔐</strong>
</p>
