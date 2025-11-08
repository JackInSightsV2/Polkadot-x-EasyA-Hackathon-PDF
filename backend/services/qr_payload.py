import base64
import io
import json
import logging
from typing import Dict

import qrcode


logger = logging.getLogger(__name__)


def encode_payload(data: Dict) -> str:
    """
    Encode verification payload to a compact base64 string.
    """
    serialized = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(serialized).decode("utf-8")


def decode_payload(encoded: str) -> Dict:
    decoded = base64.urlsafe_b64decode(encoded.encode("utf-8"))
    return json.loads(decoded.decode("utf-8"))


def generate_qr_png_base64(data: Dict) -> str:
    """
    Build a QR code PNG as base64 string ready for embedding in the UI.
    """
    encoded = encode_payload(data)
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(encoded)
    qr.make(fit=True)

    buffer = io.BytesIO()
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(buffer, format="PNG")
    base64_png = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return base64_png, encoded
