import secrets
import hashlib
import hmac

KEY_PREFIX_LEN = 8


def generate_plaintext_key() -> str:
    return secrets.token_urlsafe(32)


def key_prefix(plain: str) -> str:
    return plain[:KEY_PREFIX_LEN]


def hash_key(plain: str) -> str:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
