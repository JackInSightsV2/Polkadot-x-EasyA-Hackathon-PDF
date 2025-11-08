import hashlib
import hmac
import os
from typing import Dict


DEFAULT_SECRET = "dev-signing-secret"
SIGNING_SECRET_ENV = "DOCUMENT_SIGNING_SECRET"


def _load_secret() -> bytes:
    secret = os.getenv(SIGNING_SECRET_ENV, DEFAULT_SECRET)
    return secret.encode("utf-8")


def sign_payload(payload: Dict) -> str:
    json_repr = repr(sorted(payload.items())).encode("utf-8")
    digest = hmac.new(_load_secret(), json_repr, hashlib.sha256).hexdigest()
    return digest


def verify_signature(payload: Dict, signature: str) -> bool:
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)
