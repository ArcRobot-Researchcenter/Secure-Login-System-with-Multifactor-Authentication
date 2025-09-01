
# Secure Login System with Multifactor Authentication (Flask + TOTP)

This project demonstrates the **Design and Implementation of a Secure Login System using Multifactor Authentication (MFA)**.
It was developed as part of an academic program to showcase modern security practices for user authentication.


## 🔑 Features

* User **registration** and **login** with password hashing (bcrypt).
* **TOTP-based MFA** (compatible with Google Authenticator, Microsoft Authenticator, Authy, etc.).
* **QR Code provisioning** for easy MFA setup.
* **Backup codes** (hashed at rest) to recover accounts if the device is lost.
* **Rate limiting** on login and MFA verification to block brute force.
* **Audit logging** of security events (login, logout, MFA enable/fail).
* Clean **Bootstrap-based UI** with project info displayed.


## 🚀 Quickstart

1. Clone the repo:

   ```bash
   git clone https://github.com/ArcRobot-Researchcenter/mfa-secure-login.git
   cd mfa-secure-login
   ```

2. Create & activate a virtual environment:

   ```bash
   python -m venv .venv
   .venv\Scripts\activate   # Windows
   # or
   source .venv/bin/activate   # macOS/Linux
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the server:

   ```bash
   python run.py
   ```

5. Open your browser:
   👉 [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 📸 Screenshots

* **Login Page with Project Info**

![Image](https://github.com/user-attachments/assets/0ca5cf29-4ab4-46c2-a888-e42b24bf58fa)

![Secure Login Screenshot](https://i.postimg.cc/Y0GmN0Nf/secure-login.jpg)

image 




* **Enable MFA with QR Code**
  ![MFA Setup](docs/mfa-setup.png)

---

## 🔒 Security Notes

* This is a **demo/academic project**.
* For production use:

  * Enforce HTTPS.
  * Use a stronger session store (Redis, DB) instead of in-memory limiter.
  * Add email verification & password reset flows.
  * Consider WebAuthn/Passkeys for phishing-resistant MFA.

---

## 📚 References

* [RFC 6238: TOTP Algorithm](https://www.rfc-editor.org/rfc/rfc6238)
* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [Flask Documentation](https://flask.palletsprojects.com/)

---

✨ *This project is part of academic research and demonstration of secure authentication practices.*

