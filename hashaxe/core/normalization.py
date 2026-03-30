"""
hashaxe.core.normalization — Hash Input Sanitization Engine

Standardizes errant CLI hash inputs, handles structural stripping
(e.g., surrounding quotes, shadow file formatting), and normalizes
line endings for downstream parsing modules safely.
"""

import re
from typing import NamedTuple, Optional

class NormalizedHash(NamedTuple):
    """Result of hash canonicalization."""
    raw_input: str
    clean_hash: str
    is_modified: bool
    context: str

def normalize_hash_string(raw_hash: str) -> NormalizedHash:
    """
    Sanitize and canonicalize a single hash string input.
    """
    if not raw_hash:
        return NormalizedHash(raw_input=raw_hash, clean_hash="", is_modified=False, context="empty")

    cleaned = raw_hash
    is_modified = False
    context = "raw"
    
    # 1. Strip surrounding structural quotes first ('', "", ``)
    if (cleaned.startswith('"') and cleaned.endswith('"')) or \
       (cleaned.startswith("'") and cleaned.endswith("'")) or \
       (cleaned.startswith("`") and cleaned.endswith("`")):
        cleaned = cleaned[1:-1]
        is_modified = True

    # 2. Trim whitespace / network padding
    stripped = cleaned.strip()
    if stripped != cleaned:
        cleaned = stripped
        is_modified = True

    # 3. Detect shadow-file patterns (user:hash or user:salt:hash)
    # Extracts the hash logic specifically for unix/DCC variations
    parts = cleaned.split(":")
    if len(parts) >= 2:
        if parts[1].startswith("$"): 
            # Classic unix shadow
            cleaned = parts[1]
            context = "shadow_file"
            is_modified = True
        elif len(parts) >= 4 and len(parts[3]) == 32:
            # Windows hashdump (user:rid:lm:ntlm:::)
            cleaned = parts[3]
            context = "hashdump"
            is_modified = True
            
    # 4. Handle trailing shell artifacts like `< /dev/null` accidentally pasted
    # by safely stripping spaces beyond word boundaries on strictly formatted standard hashes.
    if "<" in cleaned:
        cleaned = cleaned.split("<")[0].strip()
        is_modified = True

    return NormalizedHash(
        raw_input=raw_hash,
        clean_hash=cleaned,
        is_modified=is_modified,
        context=context
    )
    
def normalize_bytes_payload(raw_bytes: bytes) -> bytes:
    """
    Sanitize byte streams loaded from files by normalizing CR/LF variations.
    """
    if not raw_bytes:
        return raw_bytes
        
    return raw_bytes.replace(b"\\r\\n", b"\\n").replace(b"\\r", b"\\n")
