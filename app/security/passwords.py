import bcrypt


# bcrypt only considers the first 72 bytes. Reject longer inputs instead of
# silently truncating them or depending on backend-specific behavior.
_BCRYPT_MAX_PASSWORD_BYTES = 72


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > _BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError("Password must be at most 72 UTF-8 bytes for bcrypt")

    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return password_hash.decode("ascii")


def verify_password(
    plain_password: str,
    password_hash: str
) -> bool:
    password_bytes = plain_password.encode("utf-8")
    if len(password_bytes) > _BCRYPT_MAX_PASSWORD_BYTES:
        return False

    try:
        return bcrypt.checkpw(password_bytes, password_hash.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        return False
