import hashlib
import logging
from dataclasses import dataclass
from typing import Dict

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.ellipticcurve import Point


logger = logging.getLogger(__name__)

CURVE = SECP256k1
GENERATOR = CURVE.generator
ORDER = CURVE.order


def _ensure_scalar(scalar: int) -> int:
    scalar = scalar % ORDER
    if scalar == 0:
        scalar = 1
    return scalar


def commitment_from_hash(hash_hex: str) -> str:
    """
    Derive a public commitment (compressed secp256k1 point) from a SHA-256 hash.
    """
    scalar = _ensure_scalar(int(hash_hex, 16))
    signing_key = SigningKey.from_secret_exponent(scalar, curve=CURVE, hashfunc=hashlib.sha256)
    verifying_key = signing_key.verifying_key
    return verifying_key.to_string("compressed").hex()


@dataclass
class SchnorrProof:
    rx: int
    ry: int
    s: int

    @classmethod
    def from_payload(cls, payload: Dict[str, str]) -> "SchnorrProof":
        try:
            return cls(
                rx=int(payload["rx"], 16),
                ry=int(payload["ry"], 16),
                s=int(payload["s"], 16),
            )
        except (KeyError, ValueError) as exc:
            raise ValueError("Invalid proof payload") from exc

    def challenge(self, commitment_hex: str, document_id: str, context: str = "") -> int:
        """
        Deterministically derive the Schnorr challenge.
        """
        commitment_bytes = bytes.fromhex(commitment_hex)
        rx_bytes = self.rx.to_bytes(32, "big")
        ry_bytes = self.ry.to_bytes(32, "big")
        challenge_material = b"".join(
            [
                rx_bytes,
                ry_bytes,
                commitment_bytes,
                document_id.encode("utf-8"),
                context.encode("utf-8"),
            ]
        )
        challenge = int.from_bytes(hashlib.sha256(challenge_material).digest(), "big")
        return challenge % ORDER

    def to_point(self) -> Point:
        """
        Convert the (rx, ry) pair into an elliptic curve point.
        """
        return Point(CURVE.curve, self.rx, self.ry)


def verify_schnorr_proof(
    commitment_hex: str,
    document_id: str,
    proof_payload: Dict[str, str],
    context: str = "",
) -> bool:
    """
    Verify a Schnorr proof of knowledge of the document scalar.
    """
    try:
        verifying_key = VerifyingKey.from_string(bytes.fromhex(commitment_hex), curve=CURVE)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("Failed to parse commitment for document %s: %s", document_id, exc)
        return False

    try:
        proof = SchnorrProof.from_payload(proof_payload)
    except ValueError:
        return False

    challenge = proof.challenge(commitment_hex, document_id, context)
    proof_point = proof.to_point()

    if proof_point == Point(None, None, None):  # pragma: no cover - safeguard
        return False

    try:
        left = GENERATOR * (_ensure_scalar(proof.s))
        right = proof_point + verifying_key.pubkey.point * challenge
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("Failed during proof verification for %s: %s", document_id, exc)
        return False

    return left == right
