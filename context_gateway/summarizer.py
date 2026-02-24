"""Lossy summarizer — Story 12.8.

Replaces redaction markers with silent, lossy summarization that
preserves entities and facts while discarding instruction-shaped
content.  Attackers cannot observe redaction and refine payloads.
"""

from __future__ import annotations

import re

from context_gateway.injection_detector import INJECTION_PATTERNS
import re as _re_module

# H-08: Use local copy of pattern instead of importing private symbol
_EMAIL_RE = _re_module.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# ---------- entity extraction regexes ----------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b[0-9a-fA-F:]{7,}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(
    r"\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}\b"
)

# ---------- fact / instruction verb sets ------------------------------------

_FACTUAL_VERBS = re.compile(
    r"\b(?:connected|accessed|created|deleted|modified|executed|downloaded|uploaded)\b",
    re.IGNORECASE,
)

_INSTRUCTION_VERBS = re.compile(
    r"\b(?:ignore|pretend|override|forget|reveal|act\s+as)\b",
    re.IGNORECASE,
)

# ---------- sentence splitter ------------------------------------------------

_SENTENCE_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+")


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences on period/!/? followed by whitespace."""
    parts = _SENTENCE_BOUNDARY_RE.split(text)
    return [s.strip() for s in parts if s.strip()]


# ---------- Task 1: entity extraction ----------------------------------------

def extract_entities(text: str) -> list[str]:
    """Extract IOC-type entities from text (IPs, hashes, domains, emails)."""
    if not text:
        return []

    entities: list[str] = []

    # SHA256 first (64 hex chars) — before MD5 to avoid partial match
    entities.extend(_SHA256_RE.findall(text))

    # MD5 (32 hex chars) — exclude substrings already captured as SHA256
    sha256_set = set(entities)
    for m in _MD5_RE.findall(text):
        if not any(m in sha for sha in sha256_set):
            entities.append(m)

    # IPs
    entities.extend(_IPV4_RE.findall(text))
    entities.extend(_IPV6_RE.findall(text))

    # Domains
    entities.extend(_DOMAIN_RE.findall(text))

    # Emails
    entities.extend(_EMAIL_RE.findall(text))

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for e in entities:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    return unique


# ---------- Task 2: fact extraction ------------------------------------------

def extract_facts(text: str) -> list[str]:
    """Extract factual sentences, discard instruction-shaped ones."""
    if not text:
        return []

    sentences = _split_sentences(text)
    entity_list = extract_entities(text)
    facts: list[str] = []

    for sentence in sentences:
        # Discard sentences with instruction verbs
        if _INSTRUCTION_VERBS.search(sentence):
            continue
        # Discard sentences matching injection patterns
        if any(p.search(sentence) for p in INJECTION_PATTERNS):
            continue
        # Keep sentences with entities or factual verbs
        has_entity = any(e in sentence for e in entity_list)
        has_factual_verb = bool(_FACTUAL_VERBS.search(sentence))
        if has_entity or has_factual_verb:
            facts.append(sentence)

    return facts


# ---------- Task 3: instruction removal --------------------------------------

def remove_instructions(text: str) -> str:
    """Remove instruction-shaped sentences silently (no markers)."""
    if not text:
        return ""

    sentences = _split_sentences(text)
    kept: list[str] = []

    for sentence in sentences:
        # Remove sentences matching injection patterns
        if any(p.search(sentence) for p in INJECTION_PATTERNS):
            continue
        # Remove sentences with instruction verbs
        if _INSTRUCTION_VERBS.search(sentence):
            continue
        kept.append(sentence)

    return " ".join(kept)


# ---------- Task 4: lossy summarizer pipeline --------------------------------

def summarize(text: str) -> str:
    """Lossy summarization: extract entities + facts, discard instructions."""
    entities = extract_entities(text)
    facts = extract_facts(text)
    cleaned = remove_instructions(text)

    # Combine unique entities and factual sentences
    parts: list[str] = []

    # Add entity list if any
    if entities:
        parts.append("Entities: " + ", ".join(entities))

    # Add factual sentences (deduplicated)
    seen_facts: set[str] = set()
    for fact in facts:
        normalized = fact.strip()
        if normalized and normalized not in seen_facts:
            seen_facts.add(normalized)
            parts.append(normalized)

    # Also include cleaned text sentences not already covered by facts
    if cleaned.strip():
        for sentence in _split_sentences(cleaned):
            s = sentence.strip()
            if s and s not in seen_facts:
                seen_facts.add(s)
                parts.append(s)

    if not parts:
        return "No actionable content detected."

    return " ".join(parts)


def transform_content(text: str, action: str) -> str:
    """Transform content based on classification action.

    - ``"pass"``       → return text unchanged
    - ``"summarize"``  → lossy summarize (entities + facts, no instructions)
    - ``"quarantine"`` → neutral placeholder
    """
    if action == "pass":
        return text
    if action == "summarize":
        return summarize(text)
    if action == "quarantine":
        return "Content quarantined for security review."
    return text
