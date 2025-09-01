# Secure Login System with Multifactor Authentication (Flask + TOTP)

A production‑minded starter kit that demonstrates a **secure username/password login** with
**Time‑based One‑Time Passwords (TOTP)** for multifactor authentication, **backup codes**, and basic **rate limiting**, built with **Flask** and **SQLite**.

## Features
- User registration with **email verification rules** (via WTForms validators).
- Password hashing using **bcrypt (passlib)**.
- **MFA (TOTP)** enable/verify flow with QR code provisioning (scan in Google Authenticator, Authy, Microsoft Authenticator, etc.).
- **Backup codes** (hashed-at-rest) to recover if TOTP device is lost.
- **Rate limiting** on login and TOTP verify endpoints.
- **CSRF protection** on all forms.
- Minimal **audit log** (login success/failure, MFA enable, etc.).
- Clean Bootstrap‑lite UI.

> This is an educational starter. Review, extend, and harden before production (e.g., HTTPS, CSP, secure cookies, account lockout, email/pass recovery, device management, WebAuthn/passkeys, etc.).

## Quickstart

```bash
# 1) Create & activate a venv (recommended)
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Run the app

python run.py

Open your browser:
👉 http://127.0.0.1:5000

Login flow (after enabling MFA):
1. Enter email + password.
2. If credentials are valid and MFA is enabled, you'll be asked for a **6‑digit TOTP**.
3. Alternatively, use **one backup code** (each can be used once).

## Default Security Settings
- Cookies: `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Lax'`.
- Forms protected by WTForms CSRF.
- Rate limiting: **5/minute** on `/login` and `/verify-2fa` per IP.

## Project Structure
```
app/
  __init__.py
  config.py
  models.py
  auth.py
  utils/
    security.py
  templates/
    base.html
    register.html
    login.html
    dashboard.html
    setup_mfa.html
    verify_2fa.html
  static/
    css/styles.css
requirements.txt
run.py
```


