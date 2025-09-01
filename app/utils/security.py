import hashlib, secrets, base64
from passlib.hash import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.verify(password, password_hash)
    except Exception:
        return False

def hash_backup_code(code: str) -> str:
    # fast, one-way hash (sha256) suitable for backup codes
    return hashlib.sha256(code.encode('utf-8')).hexdigest()

def generate_backup_codes(n=8):
    # 10-digit base32-ish codes, displayed in groups like ABCD-EFGH
    codes = []
    for _ in range(n):
        raw = secrets.token_urlsafe(8)[:10].upper()
        code = f"{raw[:4]}-{raw[4:8]}"
        codes.append(code)
    return codes
