# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/osint/nlp_engine.py
#  NLP keyword extraction engine for security-relevant tokens.
#  Uses regex NER, frequency analysis, and optional spaCy for advanced extraction.
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
osint/nlp_engine.py — NLP keyword extraction engine.

Extracts security-relevant keywords from raw unstructured text using:
  1. Regex-based NER (dates, emails, usernames, phone numbers)
  2. Statistical token frequency analysis
  3. Optional spaCy NER if installed (PERSON, ORG, GPE, DATE)

Dependencies:
  - Built-in: always works (regex + frequency analysis)
  - Optional: ``spacy`` with a language model for advanced NER
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Compiled regex patterns for common PII ────────────────────────────────────

_RE_EMAIL = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_RE_DATE_SLASH = re.compile(r"\b(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})\b")
_RE_YEAR = re.compile(r"\b(19[5-9]\d|20[0-3]\d)\b")
_RE_PHONE = re.compile(r"\b\d{3}[\s\-.]?\d{3}[\s\-.]?\d{4}\b")
_RE_USERNAME = re.compile(r"@([A-Za-z0-9_]{2,30})")
_RE_HASHTAG = re.compile(r"#([A-Za-z0-9_]{2,40})")
_RE_WORD = re.compile(r"[A-Za-z]{3,20}")

# Common English stopwords to filter out
_STOPWORDS = frozenset({
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "has", "have", "been", "from",
    "this", "that", "with", "they", "will", "each", "make", "like",
    "just", "over", "such", "take", "than", "them", "very", "some",
    "could", "would", "about", "which", "come", "made", "find", "more",
    "long", "look", "many", "then", "also", "into", "year", "your",
    "what", "when", "where", "who", "how", "why", "here", "there",
    "does", "did", "doing", "should", "because", "being", "these",
    "those", "other", "than", "most", "must", "said", "say",
})


@dataclass
class ExtractedProfile:
    """Result of NLP extraction from raw text."""

    names: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    dates: list[str] = field(default_factory=list)
    years: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    hashtags: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)  # top frequent words

    @property
    def all_tokens(self) -> list[str]:
        """Return all extracted tokens as a flat deduplicated list."""
        seen: set[str] = set()
        result: list[str] = []
        for group in (
            self.names, self.emails, self.usernames, self.dates,
            self.years, self.phones, self.hashtags, self.organizations,
            self.locations, self.keywords,
        ):
            for token in group:
                low = token.lower()
                if low not in seen and len(token) >= 2:
                    seen.add(low)
                    result.append(token)
        return result

    def summary(self) -> dict[str, int]:
        """Return a summary of extraction counts."""
        return {
            "names": len(self.names),
            "emails": len(self.emails),
            "usernames": len(self.usernames),
            "dates": len(self.dates),
            "years": len(self.years),
            "phones": len(self.phones),
            "hashtags": len(self.hashtags),
            "organizations": len(self.organizations),
            "locations": len(self.locations),
            "keywords": len(self.keywords),
            "total_tokens": len(self.all_tokens),
        }


class NLPEngine:
    """Extract security-relevant keywords from unstructured text.

    Works in two modes:
      1. **Regex mode** (always available): Uses compiled regex patterns
         to extract emails, dates, usernames, and frequency-ranked words.
      2. **spaCy mode** (optional): If ``spacy`` is installed with a model,
         additionally extracts named entities (PERSON, ORG, GPE, DATE).
    """

    def __init__(self, use_spacy: bool = True):
        self._nlp = None
        self._spacy_available = False
        if use_spacy:
            self._try_load_spacy()

    def _try_load_spacy(self) -> None:
        """Attempt to load spaCy with English model."""
        try:
            import spacy  # type: ignore

            for model in ("en_core_web_sm", "en_core_web_md", "en_core_web_lg"):
                try:
                    self._nlp = spacy.load(model)
                    self._spacy_available = True
                    logger.info("spaCy loaded: %s", model)
                    return
                except OSError:
                    continue
            logger.info("spaCy installed but no English model found. "
                        "Run: python -m spacy download en_core_web_sm")
        except ImportError:
            logger.debug("spaCy not installed. Using regex-only NLP.")

    @property
    def has_spacy(self) -> bool:
        return self._spacy_available

    def extract(self, text: str) -> ExtractedProfile:
        """Extract all security-relevant tokens from raw text."""
        profile = ExtractedProfile()

        # ── Regex-based extraction (always available) ─────────────────────
        profile.emails = list(set(_RE_EMAIL.findall(text)))
        profile.usernames = list(set(_RE_USERNAME.findall(text)))
        profile.hashtags = list(set(_RE_HASHTAG.findall(text)))
        profile.years = list(set(_RE_YEAR.findall(text)))
        profile.phones = list(set(
            p.replace(" ", "").replace("-", "").replace(".", "")
            for p in _RE_PHONE.findall(text)
        ))

        # Date extraction (DD/MM/YYYY etc.)
        raw_dates = _RE_DATE_SLASH.findall(text)
        date_strings: list[str] = []
        for d, m, y in raw_dates:
            date_strings.append(f"{d}{m}{y}")
            date_strings.append(f"{d}{m}")
            date_strings.append(f"{m}{d}")
            if len(y) == 4:
                date_strings.append(y)
                date_strings.append(y[2:])
        profile.dates = list(set(date_strings))

        # Statistical word frequency
        words = _RE_WORD.findall(text.lower())
        filtered = [w for w in words if w not in _STOPWORDS and len(w) >= 3]
        freq = Counter(filtered)
        profile.keywords = [w for w, _ in freq.most_common(50)]

        # ── spaCy NER (if available) ──────────────────────────────────────
        if self._spacy_available and self._nlp:
            try:
                doc = self._nlp(text[:100_000])  # Limit to 100K chars
                for ent in doc.ents:
                    label = ent.label_
                    clean = ent.text.strip()
                    if not clean or len(clean) < 2:
                        continue
                    if label == "PERSON":
                        profile.names.append(clean)
                    elif label == "ORG":
                        profile.organizations.append(clean)
                    elif label in ("GPE", "LOC"):
                        profile.locations.append(clean)
                    elif label == "DATE" and clean not in profile.dates:
                        profile.dates.append(clean)

                profile.names = list(set(profile.names))
                profile.organizations = list(set(profile.organizations))
                profile.locations = list(set(profile.locations))
            except Exception as e:
                logger.warning("spaCy NER failed: %s", e)

        # Extract email local parts as potential names
        for email in profile.emails:
            local = email.split("@")[0]
            parts = re.split(r"[._\-+]", local)
            for part in parts:
                if len(part) >= 3 and part.isalpha():
                    if part.lower() not in _STOPWORDS:
                        profile.names.append(part.capitalize())
            profile.names = list(set(profile.names))

        logger.info("OSINT extraction complete: %s", profile.summary())
        return profile
