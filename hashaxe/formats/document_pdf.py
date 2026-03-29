# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/formats/document_pdf.py
#  PDF document format handler for all encryption revisions (40-bit to 256-bit).
#  Supports RC4 and AES encryption with user/owner password verification.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
PDF document format handler — all encryption revisions.

Supports:
  - PDF 1.x–2.0 encryption (40-bit RC4, 128-bit RC4, 128-bit AES, 256-bit AES)
  - User password and owner password testing

Dependencies:
  - ``pikepdf`` (optional) — preferred, handles all PDF versions
  - Falls back to pure-Python header detection if pikepdf is unavailable
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Optional

from hashaxe.formats._registry import FormatRegistry
from hashaxe.formats.base import (
    BaseFormat,
    FormatDifficulty,
    FormatMatch,
    FormatTarget,
)

log = logging.getLogger(__name__)

# ── Optional dependency ───────────────────────────────────────────────────────
try:
    import pikepdf  # type: ignore
    _HAS_PIKEPDF = True
except ImportError:
    _HAS_PIKEPDF = False


# ── Revision → Hashcat mode mapping ──────────────────────────────────────────
_PDF_HASHCAT_MODES: dict[int, int] = {
    2: 10400,   # PDF 1.1-1.3 (Acrobat 2-4), RC4-40
    3: 10500,   # PDF 1.4-1.6 (Acrobat 5-8), RC4-128
    4: 10600,   # PDF 1.7 Level 3 (Acrobat 9), AES-128
    5: 10700,   # PDF 1.7 Level 8 (Acrobat 10+), AES-256
    6: 10700,   # PDF 2.0, AES-256
}


def _detect_pdf_encryption(data: bytes) -> dict[str, Any]:
    """Analyse PDF bytes to detect encryption metadata and extract hashcat-compatible hash.

    Returns dict with keys:
      encrypted: bool
      version: PDF version string (e.g. '1.7')
      encryption_method: 'rc4-40' | 'rc4-128' | 'aes-128' | 'aes-256' | 'unknown'
      revision: encryption revision number (1–6)
      hashcat_mode: int (10400/10500/10600/10700)
      target_hash: str — $pdf$ hash string for hashcat GPU dispatch
    """
    result: dict[str, Any] = {
        "encrypted": False,
        "version": "unknown",
        "encryption_method": "none",
        "revision": 0,
        "hashcat_mode": 10500,
        "target_hash": None,
    }

    # Extract PDF version from header
    header_match = re.search(rb"%PDF-(\d+\.\d+)", data[:1024])
    if header_match:
        result["version"] = header_match.group(1).decode("ascii", errors="replace")

    # Check for /Encrypt dictionary — definitive encryption indicator
    if b"/Encrypt" not in data:
        return result

    result["encrypted"] = True

    # ── Locate the Encrypt dictionary object ──────────────────────────────
    # Find the object containing /Filter /Standard (unique to encrypt dict)
    encrypt_section = None
    enc_pattern = rb'(\d+\s+\d+\s+obj\s*<<(?:(?!>>).)*?/Filter\s*/Standard(?:(?!>>).)*?>>)'
    enc_m = re.search(enc_pattern, data, re.DOTALL)
    if enc_m:
        encrypt_section = enc_m.group(1)
    else:
        # Fallback: find << ... /Filter /Standard ... >>
        idx = data.find(b"/Filter /Standard")
        if idx == -1:
            idx = data.find(b"/Filter/Standard")
        if idx >= 0:
            start = data.rfind(b"<<", 0, idx)
            end = data.find(b">>", idx)
            if start >= 0 and end >= 0:
                encrypt_section = data[start:end + 2]

    if encrypt_section is None:
        # Can't find encrypt dict — fall back to global regex (less accurate)
        rev_match = re.search(rb"/R\s+(\d+)", data)
        if rev_match:
            result["revision"] = int(rev_match.group(1))
        rev = result["revision"]
        if rev <= 2:
            result["encryption_method"] = "rc4-40"
        elif rev == 3:
            result["encryption_method"] = "rc4-128"
        elif rev == 4:
            result["encryption_method"] = "aes-128"
        elif rev >= 5:
            result["encryption_method"] = "aes-256"
        result["hashcat_mode"] = _PDF_HASHCAT_MODES.get(rev, 10500)
        return result

    # ── Extract parameters from within the Encrypt dictionary ─────────────
    r_m = re.search(rb"/R\s+(\d+)", encrypt_section)
    v_m = re.search(rb"/V\s+(\d+)", encrypt_section)
    l_m = re.search(rb"/Length\s+(\d+)", encrypt_section)
    p_m = re.search(rb"/P\s+(-?\d+)", encrypt_section)

    R = int(r_m.group(1)) if r_m else 0
    V = int(v_m.group(1)) if v_m else 0
    L = int(l_m.group(1)) if l_m else 40
    P = int(p_m.group(1)) if p_m else 0

    result["revision"] = R

    if R <= 2:
        result["encryption_method"] = "rc4-40"
    elif R == 3:
        result["encryption_method"] = "rc4-128"
    elif R == 4:
        result["encryption_method"] = "aes-128"
    elif R >= 5:
        result["encryption_method"] = "aes-256"

    result["hashcat_mode"] = _PDF_HASHCAT_MODES.get(R, 10500)

    # ── Extract /U, /O password hashes (hex-encoded in PDF) ───────────────
    u_m = re.search(rb"/U\s*<([0-9A-Fa-f]+)>", encrypt_section)
    o_m = re.search(rb"/O\s*<([0-9A-Fa-f]+)>", encrypt_section)
    u_hex = u_m.group(1).decode("ascii").lower() if u_m else ""
    o_hex = o_m.group(1).decode("ascii").lower() if o_m else ""

    # ── Extract document /ID from trailer ─────────────────────────────────
    id_m = re.search(rb"/ID\s*\[\s*<([0-9A-Fa-f]+)>", data)
    doc_id = id_m.group(1).decode("ascii").lower() if id_m else ""

    # ── Build $pdf$ hash string (hashcat-compatible) ──────────────────────
    if u_hex and o_hex and doc_id:
        encrypt_meta = 1  # EncryptMetadata: True (default for rev < 4)
        if R >= 4:
            # Check for /EncryptMetadata false
            em_m = re.search(rb"/EncryptMetadata\s+(true|false)", encrypt_section, re.IGNORECASE)
            if em_m and em_m.group(1).lower() == b"false":
                encrypt_meta = 0

        doc_id_len = len(doc_id) // 2
        u_len = len(u_hex) // 2
        o_len = len(o_hex) // 2

        if R >= 5:
            # AES-256 (rev 5/6) uses different format: $pdf$5*6*256*P*encmeta*id_len*id*u_len*u*o_len*o
            pdf_hash = (
                f"$pdf${V}*{R}*{L}*{P}*{encrypt_meta}"
                f"*{doc_id_len}*{doc_id}"
                f"*{u_len}*{u_hex}"
                f"*{o_len}*{o_hex}"
            )
        else:
            pdf_hash = (
                f"$pdf${V}*{R}*{L}*{P}*{encrypt_meta}"
                f"*{doc_id_len}*{doc_id}"
                f"*{u_len}*{u_hex}"
                f"*{o_len}*{o_hex}"
            )

        result["target_hash"] = pdf_hash
        log.debug("Extracted PDF hash for GPU: %s", pdf_hash[:80] + "...")

    return result


class PDFFormat(BaseFormat):
    """Handler for password-protected PDF documents.

    Supports all PDF encryption revisions via pikepdf.
    """

    format_id   = "document.pdf"
    format_name = "PDF Document (RC4 / AES)"

    # ── Identification ────────────────────────────────────────────────────────

    def can_handle(self, data: bytes, path: Path | None = None) -> FormatMatch | None:
        """Detect PDF by %PDF- magic header."""
        if not data[:5] == b"%PDF-":
            return None

        meta = _detect_pdf_encryption(data)
        if not meta["encrypted"]:
            return FormatMatch(
                format_id=self.format_id,
                handler=self,
                confidence=0.3,
                metadata={"description": f"PDF v{meta['version']} (not encrypted)"},
            )

        return FormatMatch(
            format_id=self.format_id,
            handler=self,
            confidence=0.95,
            metadata={
                "description": (
                    f"Encrypted PDF v{meta['version']} "
                    f"({meta['encryption_method']}, rev {meta['revision']})"
                ),
            },
        )

    # ── Parsing ───────────────────────────────────────────────────────────────

    def parse(self, data: bytes, path: Path | None = None) -> FormatTarget:
        """Parse PDF and extract encryption metadata."""
        meta = _detect_pdf_encryption(data)

        if not meta["encrypted"]:
            return FormatTarget(
                format_id=self.format_id,
                display_name=f"PDF v{meta['version']} (not encrypted)",
                source_path=str(path) if path else "inline",
                is_encrypted=False,
                difficulty=FormatDifficulty.TRIVIAL,
                format_data=meta,
            )

        # Difficulty based on encryption method
        method = meta["encryption_method"]
        if method == "rc4-40":
            diff = FormatDifficulty.FAST
        elif method in ("rc4-128", "aes-128"):
            diff = FormatDifficulty.MEDIUM
        elif method == "aes-256":
            diff = FormatDifficulty.SLOW
        else:
            diff = FormatDifficulty.MEDIUM

        return FormatTarget(
            format_id=self.format_id,
            display_name=f"PDF v{meta['version']} ({method})",
            source_path=str(path) if path else "inline",
            is_encrypted=True,
            difficulty=diff,
            format_data={
                **meta,
                "raw_data": data,  # Store for pikepdf open attempts
                "file_path": str(path) if path else None,
            },
        )

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, target: FormatTarget, password: bytes) -> bool:
        """Try to open the PDF with the given password."""
        if not _HAS_PIKEPDF:
            return self._verify_fallback(target, password)
        return self._verify_pikepdf(target, password)

    def _verify_pikepdf(self, target: FormatTarget, password: bytes) -> bool:
        """Verify using pikepdf — handles all encryption versions."""
        from io import BytesIO
        data = target.format_data.get("raw_data")
        if not data:
            return False
        try:
            pdf = pikepdf.open(BytesIO(data), password=password.decode("utf-8", errors="replace"))
            pdf.close()
            return True
        except pikepdf.PasswordError:
            return False
        except Exception:
            return False

    def _verify_fallback(self, target: FormatTarget, password: bytes) -> bool:
        """Fallback when pikepdf is not available — extremely limited."""
        log.warning("pikepdf not installed — PDF cracking is unavailable")
        return False

    def verify_full(self, target: FormatTarget, password: bytes) -> bool:
        """Full verification — same as fast path for PDF."""
        return self.verify(target, password)

    # ── Metadata ──────────────────────────────────────────────────────────────

    def difficulty(self) -> FormatDifficulty:
        return FormatDifficulty.MEDIUM

    def display_info(self, target: FormatTarget) -> dict[str, str]:
        version = target.format_data.get("version", "unknown")
        method = target.format_data.get("encryption_method", "unknown")
        rev = target.format_data.get("revision", 0)
        hc_mode = target.format_data.get("hashcat_mode", 10500)
        has_hash = bool(target.format_data.get("target_hash"))
        return {
            "Format": "PDF Document",
            "Version": version,
            "Encryption": method.upper(),
            "Revision": str(rev),
            "Hashcat Mode": str(hc_mode),
            "GPU Ready": "Yes" if has_hash else "No (hash extraction failed)",
            "pikepdf": "Yes" if _HAS_PIKEPDF else "No (install pikepdf)",
        }


# ── Auto-register ────────────────────────────────────────────────────────────
_registry = FormatRegistry()
_registry.register(PDFFormat())
