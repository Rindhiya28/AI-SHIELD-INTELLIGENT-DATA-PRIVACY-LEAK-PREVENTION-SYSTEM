"""Document extraction service for TXT, PDF, and DOCX files."""
from __future__ import annotations

import io
from typing import Tuple

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_CHARS = 200_000


class DocumentExtractionError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def extract_text_from_bytes(file_bytes: bytes, filename: str) -> str:
    """Extract clean text from TXT, PDF, or DOCX bytes with size enforcement."""
    if len(file_bytes) > MAX_FILE_SIZE_BYTES:
        raise DocumentExtractionError("File exceeds maximum allowed size of 5 MB", status_code=413)

    lower_name = filename.lower()
    text = ""

    if lower_name.endswith(".txt"):
        try:
            text = file_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = file_bytes.decode("latin-1")
            except Exception as e:
                raise DocumentExtractionError(f"Failed to decode text file: {e}")

    elif lower_name.endswith(".pdf"):
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
                pages_text = []
                for p in pdf.pages:
                    pt = p.extract_text()
                    if pt:
                        pages_text.append(pt)
                text = "\n".join(pages_text)
        except Exception as e:
            raise DocumentExtractionError(f"Failed to extract text from PDF: {e}")

    elif lower_name.endswith(".docx"):
        try:
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))
            text = "\n".join([p.text for p in doc.paragraphs if p.text])
        except Exception as e:
            raise DocumentExtractionError(f"Failed to extract text from DOCX: {e}")

    else:
        raise DocumentExtractionError("Unsupported file type. Only .txt, .pdf, and .docx are supported.", status_code=400)

    if not text.strip():
        raise DocumentExtractionError("The uploaded document is empty or contains no extractable text.", status_code=400)

    if len(text) > MAX_CHARS:
        raise DocumentExtractionError(f"Extracted document length ({len(text)} chars) exceeds maximum limit of {MAX_CHARS} characters.", status_code=413)

    return text
