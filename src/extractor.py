"""
Regex-based intelligence extractor.
Extracts phone numbers, bank accounts, UPI IDs, phishing links, and emails
from raw conversation text without needing LLM parsing.
"""

import re
from typing import List, Set

from models import ExtractedIntelligence


# ─── Regex Patterns ────────────────────────────────────────────────────────────

# Phone numbers: Indian (+91, 91, 0) and generic 10-digit
PHONE_PATTERNS = [
    r'\+91[\s\-]?\d{5}[\s\-]?\d{5}',
    r'\b91[\s\-]?\d{5}[\s\-]?\d{5}\b',
    r'\b0\d{10}\b',
    r'\b[6-9]\d{9}\b',                         # 10-digit Indian mobile
    r'\+\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,5}[\s\-]?\d{4,6}',  # generic intl
]

# Bank account numbers: 9-18 digit numeric strings
BANK_ACCOUNT_PATTERNS = [
    r'\b\d{9,18}\b',
]

# Email addresses (must have TLD with 2+ chars after last dot)
EMAIL_PATTERNS = [
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
]

# UPI IDs: localpart@handle (NO dot-TLD — captured by word boundary)
UPI_PATTERNS = [
    r'[a-zA-Z0-9.\-_+]+@[a-zA-Z0-9]+\b(?!\.[a-zA-Z])',
]

# URLs: http/https, also bare domains that look suspicious
PHISHING_PATTERNS = [
    r'https?://[^\s\'"<>]+',
    r'www\.[^\s\'"<>]+\.[a-z]{2,6}(?:/[^\s]*)?',
    r'bit\.ly/[^\s]+',
    r'tinyurl\.com/[^\s]+',
]

# Suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "blocked", "suspended", "otp", "kyc", "account",
    "immediately", "verify now", "confirm", "click here", "claim",
    "reward", "prize", "lottery", "won", "refund", "tax", "customs",
    "parcel", "delivery", "pending", "overdue", "arrest", "police",
    "legal action", "cancel", "expire", "limited time", "act now",
]

# Known UPI handles (without TLD)
_UPI_HANDLES = {
    "upi", "ybl", "oksbi", "okhdfcbank", "okicici", "okaxis",
    "paytm", "gpay", "phonepe", "freecharge", "ibl", "axl",
    "apl", "waicici", "waaxis", "wahdfcbank", "wasbi", "rbl",
    "kotak", "federal", "sbi", "imobile", "hsbc", "sc",
    "fakebank", "fakeupi",  # test scenarios
}


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_phone(phone: str) -> str:
    """Normalize phone to last 10 digits for dedup comparison."""
    digits = re.sub(r'\D', '', phone)
    # Indian numbers: take last 10 digits
    if len(digits) >= 10:
        return digits[-10:]
    return digits


def _dedupe_sorted(items: List[str]) -> List[str]:
    """Deduplicate while preserving order (case-insensitive)."""
    seen: Set[str] = set()
    result = []
    for item in items:
        norm = item.strip()
        if norm and norm.lower() not in seen:
            seen.add(norm.lower())
            result.append(norm)
    return result


def _dedupe_phones(phones: List[str]) -> List[str]:
    """Deduplicate phone numbers by normalizing to last 10 digits.
    Keeps the longest (most complete) format for each unique number."""
    seen: dict = {}  # normalized -> original
    for phone in phones:
        norm = _normalize_phone(phone)
        if not norm:
            continue
        # Keep the longer format (e.g., +91-9876543210 over 9876543210)
        if norm not in seen or len(phone) > len(seen[norm]):
            seen[norm] = phone.strip()
    return list(seen.values())


def _clean_url(url: str) -> str:
    """Strip trailing punctuation that regex may capture from natural text."""
    return url.rstrip('.,;:!?)\'"]')


def _has_tld(domain: str) -> bool:
    """Check if domain part has a TLD like .com, .in, .org, etc."""
    return bool(re.search(r'\.[a-zA-Z]{2,}$', domain))


def _is_likely_upi(value: str) -> bool:
    """Distinguish UPI IDs from email addresses.
    Key rule: if the domain has a TLD (.com, .in, .org), it's an EMAIL, not UPI.
    UPI IDs use bare handles like name@paytm, name@ybl, name@oksbi — no TLD."""
    if "@" not in value:
        return False
    domain = value.split("@", 1)[1].lower()

    # If domain has a TLD (e.g., .com, .in, .org), it's an email
    if _has_tld(domain):
        return False

    # If bare handle matches known UPI handles, it's UPI
    if domain in _UPI_HANDLES:
        return True

    # If no TLD and no known handle, still treat as UPI (unknown handle)
    # since emails always have TLDs
    return True


def _is_likely_bank_account(value: str, context: str = "") -> bool:
    """Heuristic: bank account numbers are 9-18 digits, not timestamps/OTPs."""
    digits = re.sub(r'\D', '', value)
    if len(digits) < 9 or len(digits) > 18:
        return False
    # Exclude timestamps (13-digit epoch ms)
    if len(digits) == 13:
        return False
    return True


# ─── Main Extraction ──────────────────────────────────────────────────────────

def extract_intelligence(texts: List[str]) -> ExtractedIntelligence:
    """
    Run all regex extractors over a list of text strings.
    Returns deduplicated ExtractedIntelligence.
    """
    full_text = " ".join(texts)

    # ── Phones ─────────────────────────────────────────────────────────────
    phones: List[str] = []
    for pat in PHONE_PATTERNS:
        phones += re.findall(pat, full_text)

    # ── Emails (always extract emails first using the strict TLD pattern) ──
    email_addresses: List[str] = []
    for pat in EMAIL_PATTERNS:
        email_addresses += re.findall(pat, full_text)

    # Build a set of known emails for exclusion from UPI detection
    email_set = {e.lower() for e in email_addresses}

    # ── UPI IDs vs remaining emails ────────────────────────────────────────
    # The UPI pattern is broader (any localpart@handle), so we run it
    # and filter out anything already identified as an email
    raw_at_values: List[str] = []
    for pat in UPI_PATTERNS:
        raw_at_values += re.findall(pat, full_text)

    upi_ids: List[str] = []
    for val in raw_at_values:
        if val.lower() in email_set:
            continue  # already captured as email
        if _is_likely_upi(val):
            upi_ids.append(val)

    # ── Bank accounts (exclude phone number digits) ─────────────────────
    phone_digit_set = {_normalize_phone(p) for p in phones}
    bank_accounts: List[str] = []
    for pat in BANK_ACCOUNT_PATTERNS:
        candidates = re.findall(pat, full_text)
        for c in candidates:
            digits = re.sub(r'\D', '', c)
            # Skip if this is actually a phone number
            if digits[-10:] in phone_digit_set:
                continue
            if _is_likely_bank_account(c):
                bank_accounts.append(c)

    # ── Phishing links ─────────────────────────────────────────────────────
    phishing_links: List[str] = []
    for pat in PHISHING_PATTERNS:
        raw_links = re.findall(pat, full_text)
        phishing_links += [_clean_url(link) for link in raw_links]

    # ── Suspicious keywords ────────────────────────────────────────────────
    keywords_found: List[str] = []
    lower_text = full_text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower_text:
            keywords_found.append(kw)

    return ExtractedIntelligence(
        phoneNumbers=_dedupe_phones(phones),
        bankAccounts=_dedupe_sorted(bank_accounts),
        upiIds=_dedupe_sorted(upi_ids),
        phishingLinks=_dedupe_sorted(phishing_links),
        emailAddresses=_dedupe_sorted(email_addresses),
        suspiciousKeywords=_dedupe_sorted(keywords_found),
    )


def extract_from_conversation(conversation: List[dict]) -> ExtractedIntelligence:
    """Helper: extract from a list of message dicts (sender/text)."""
    texts = [msg.get("text", "") for msg in conversation if msg.get("text")]
    return extract_intelligence(texts)
