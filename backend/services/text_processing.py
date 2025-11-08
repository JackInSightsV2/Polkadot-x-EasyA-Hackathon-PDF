import hashlib
import logging
import re
import unicodedata
from pathlib import Path
from typing import Optional

from pypdf import PdfReader


logger = logging.getLogger(__name__)


def extract_text(file_path: Path) -> str:
    """
    Extract textual content from the provided document path.
    Currently supports PDF files. Returns an empty string if parsing fails.
    """
    suffix = file_path.suffix.lower()
    if suffix == ".pdf":
        return _extract_text_from_pdf(file_path)

    logger.warning("No extractor configured for %s. Returning empty text.", suffix)
    return ""


def _extract_text_from_pdf(file_path: Path) -> str:
    try:
        reader = PdfReader(str(file_path))
        text_chunks = []
        for page in reader.pages:
            page_text = page.extract_text() or ""
            text_chunks.append(page_text)
        return "\n".join(text_chunks)
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.exception("Failed to extract text from %s: %s", file_path, exc)
        return ""


def normalize_text(raw_text: str) -> str:
    """
    Apply deterministic normalization so the same logical content yields the same hash.
    Steps:
      * Unicode NFKC normalization
      * Lower-casing
      * Replace runs of whitespace (including newlines) with a single space
      * Strip leading/trailing whitespace
    """
    if not raw_text:
        return ""

    normalized = unicodedata.normalize("NFKC", raw_text)
    normalized = normalized.lower()
    normalized = re.sub(r"\s+", " ", normalized, flags=re.MULTILINE)
    normalized = normalized.strip()
    return normalized


def hash_normalized_text(normalized_text: str) -> Optional[str]:
    if not normalized_text:
        return None

    digest = hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
    return digest
