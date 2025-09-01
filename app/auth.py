from flask import Blueprint, render_template, redirect, url_for, request, flash, session, send_file
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from . import db
from .models import User, AuditLog
from .utils.security import hash_password, verify_password, generate_backup_codes, hash_backup_code
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp, qrcode
import io

auth_bp = Blueprint("auth", __name__)

# Local limiter for sensitive endpoints
limiter = Limiter(get_remote_address)

# --------------------
# Forms
# --------------------
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField("Create Account")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

class Verify2FAForm(FlaskForm):
    token = StringField("6-digit code or backup code", validators=[DataRequired(), Length(min=4, max=16)])
    submit = SubmitField("Verify")

# NEW: Flask-WTF form for enabling MFA (handles CSRF automatically)
class EnableMFAForm(FlaskForm):
    token = StringField("Enter 6-digit code", validators=[DataRequired(), Length(min=6, max=16)])
    submit = SubmitField("Enable MFA")

# --------------------
# Routes
# --------------------
@auth_bp.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))
    return redirect(url_for("auth.login"))

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("Email is already registered.", "danger")
            return redirect(url_for("auth.register"))
        user = User(
            email=form.email.data.lower(),
            password_hash=hash_password(form.password.data),
            mfa_enabled=False
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        db.session.add(AuditLog(user_id=user.id, event="register", ip=request.remote_addr))
        db.session.commit()
        flash("Account created. Consider enabling MFA for better security.", "success")
        return redirect(url_for("auth.dashboard"))
    return render_template("register.html", form=form)

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if not user or not verify_password(form.password.data, user.password_hash):
            db.session.add(AuditLog(user_id=user.id if user else None, event="login_failed", ip=request.remote_addr))
            db.session.commit()
            flash("Invalid email or password.", "danger")
            return redirect(url_for("auth.login"))
        # Password is valid
        if user.mfa_enabled:
            session["pre_2fa_user_id"] = user.id
            return redirect(url_for("auth.verify_2fa"))
        login_user(user, remember=form.remember.data)
        db.session.add(AuditLog(user_id=user.id, event="login_success", ip=request.remote_addr))
        db.session.commit()
        return redirect(url_for("auth.dashboard"))
    return render_template("login.html", form=form)

@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_2fa():
    uid = session.get("pre_2fa_user_id")
    if not uid:
        return redirect(url_for("auth.login"))
    user = User.query.get(uid)
    form = Verify2FAForm()
    if form.validate_on_submit():
        token = form.token.data.strip().replace(" ", "").upper()

        # First, try as TOTP
        if user.mfa_secret:
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(token, valid_window=1):
                login_user(user)
                session.pop("pre_2fa_user_id", None)
                db.session.add(AuditLog(user_id=user.id, event="mfa_totp_success", ip=request.remote_addr))
                db.session.commit()
                return redirect(url_for("auth.dashboard"))

        # Then try as backup code
        if user.backup_codes_hash:
            hashes = set(h for h in user.backup_codes_hash.splitlines() if h.strip())
            import hashlib
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            if token_hash in hashes:
                # consume this code
                hashes.remove(token_hash)
                user.backup_codes_hash = "\n".join(hashes)
                db.session.add(user)
                db.session.add(AuditLog(user_id=user.id, event="mfa_backup_success", ip=request.remote_addr))
                db.session.commit()
                login_user(user)
                session.pop("pre_2fa_user_id", None)
                return redirect(url_for("auth.dashboard"))

        flash("Invalid or expired code.", "danger")
        db.session.add(AuditLog(user_id=user.id, event="mfa_failed", ip=request.remote_addr))
        db.session.commit()
        return redirect(url_for("auth.verify_2fa"))
    return render_template("verify_2fa.html", form=form)

@auth_bp.route("/enable-mfa", methods=["GET", "POST"])
@login_required
def enable_mfa():
    """
    Enable TOTP MFA:
    - GET: shows QR and secret; renders a Flask-WTF form (with CSRF).
    - POST: validates the 6-digit TOTP, saves secret, generates backup codes.
    """
    form = EnableMFAForm()

    # Prepare (or reuse) a provisioning secret for the current session
    issuer = "SecureLoginMFA"
    email = current_user.email
    secret = session.get("provision_secret")
    if not secret:
        secret = pyotp.random_base32()
        session["provision_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)

    # Handle POST with CSRF auto-validation
    if form.validate_on_submit():
        token = form.token.data.strip().replace(" ", "")
        totp = pyotp.TOTP(secret)
        if not totp.verify(token, valid_window=1):
            flash("Invalid code. Try again (codes change every ~30s).", "danger")
            return render_template("setup_mfa.html", secret=secret, totp_uri=uri, form=form)

        # Success: save secret & enable MFA
        current_user.mfa_secret = secret
        current_user.mfa_enabled = True

        # Generate backup codes (hash at rest)
        codes = generate_backup_codes()
        current_user.backup_codes_hash = "\n".join(hash_backup_code(c) for c in codes)

        db.session.add(current_user)
        db.session.add(AuditLog(user_id=current_user.id, event="mfa_enabled", ip=request.remote_addr))
        db.session.commit()

        # Show backup codes once
        session.pop("provision_secret", None)
        session["display_backup_codes"] = codes
        flash("MFA enabled!", "success")
        return redirect(url_for("auth.enable_mfa"))

    # GET (or POST with validation errors)
    backup_codes = session.pop("display_backup_codes", None)
    return render_template("setup_mfa.html", secret=secret, totp_uri=uri, backup_codes=backup_codes, form=form)

@auth_bp.route("/mfa-qr.png")
@login_required
def mfa_qr():
    # Generate QR for current provisioning secret
    secret = session.get("provision_secret")
    if not secret:
        flash("No provisioning session. Start enabling MFA.", "warning")
        return redirect(url_for("auth.enable_mfa"))
    issuer = "SecureLoginMFA"
    email = current_user.email
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@auth_bp.route("/logout")
@login_required
def logout():
    db.session.add(AuditLog(user_id=current_user.id, event="logout", ip=request.remote_addr))
    db.session.commit()
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("auth.login"))
