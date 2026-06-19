"""Password hashing and verification.

Single source of truth for the passlib CryptContext used across the
project (bootstrap_admin CLI, /auth/login endpoint, password changes).
Bcrypt cost factor must stay at 12 so hashes created by the CLI
during DB bootstrap remain verifiable.
"""

from passlib.context import CryptContext

BCRYPT_ROUNDS = 12

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=BCRYPT_ROUNDS,
)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except (ValueError, TypeError):
        return False


def needs_rehash(hashed: str) -> bool:
    return pwd_context.needs_update(hashed)


# Dummy hash for timing equalization on missing-user login path.
# Bcrypt cost 12, ~250ms verify time. Never matches any real password.
_DUMMY_HASH = pwd_context.hash("dummy_for_timing_equalization")


def verify_dummy_for_timing() -> None:
    """Run a dummy bcrypt verify to equalize login timing.
    Used on missing-user path to prevent username enumeration."""
    try:
        pwd_context.verify("anything", _DUMMY_HASH)
    except Exception:
        pass  # never raises in practice; swallow for safety
