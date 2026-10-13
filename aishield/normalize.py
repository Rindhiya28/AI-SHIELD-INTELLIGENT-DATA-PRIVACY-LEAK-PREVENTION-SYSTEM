"""Text normalisation applied before detection (extract-service)."""
from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalize(text: str) -> str:
    """NFKC, drop zero-width characters, collapse repeated spaces and tabs."""
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)
    text = re.sub(r"[ \t]+", " ", text)
    return text
