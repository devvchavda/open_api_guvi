"""
Dynamic system prompt builder.
Each turn gets a customized prompt based on what intel is still missing.
This focuses the LLM on eliciting exactly the data we need for scoring.
"""

from typing import List
from models import ExtractedIntelligence, Message


# ─── Scam type detection keywords ──────────────────────────────────────────────
SCAM_TYPE_SIGNALS = {
    "bank_fraud": ["bank", "account", "otp", "blocked", "sbi", "hdfc", "icici", "axis", "rbi"],
    "upi_fraud": ["upi", "gpay", "phonepe", "paytm", "payment", "cashback", "transfer"],
    "phishing": ["link", "click", "http", "website", "portal", "login", "verify online"],
    "kyc_fraud": ["kyc", "know your customer", "aadhaar", "pan", "document"],
    "job_scam": ["job", "offer", "salary", "work from home", "registration fee", "hire"],
    "lottery_scam": ["lottery", "won", "prize", "reward", "lucky", "winner"],
    "electricity_bill": ["electricity", "power", "bill", "disconnect", "meter"],
    "tax_fraud": ["tax", "income tax", "it department", "refund", "demand notice"],
    "customs_parcel": ["customs", "parcel", "delivery", "clearance", "package"],
    "tech_support": ["virus", "hack", "computer", "windows", "microsoft", "support"],
    "loan_fraud": ["loan", "approved", "pre-approved", "credit", "emi"],
    "insurance_fraud": ["insurance", "policy", "claim", "premium"],
    "investment_fraud": ["invest", "crypto", "stock", "returns", "profit", "trading"],
}


def detect_scam_type(texts: List[str]) -> str:
    """Detect most likely scam type from conversation text."""
    combined = " ".join(texts).lower()
    scores = {}
    for scam_type, keywords in SCAM_TYPE_SIGNALS.items():
        scores[scam_type] = sum(1 for kw in keywords if kw in combined)
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "bank_fraud"


def _describe_missing(intel: ExtractedIntelligence) -> str:
    """Return human-readable list of what's still missing."""
    missing = []
    if not intel.phoneNumbers:
        missing.append("their phone number (to 'call back for verification')")
    if not intel.bankAccounts:
        missing.append("a bank account number (ask for 'account to credit/debit')")
    if not intel.upiIds:
        missing.append("a UPI ID (ask for 'payment destination')")
    if not intel.phishingLinks:
        missing.append("any website/link they mention (encourage them to share it)")
    if not intel.emailAddresses:
        missing.append("their email address (for 'confirmation')")
    return "\n".join(f"  - {m}" for m in missing) if missing else "  - You have all key intel!"


def _describe_collected(intel: ExtractedIntelligence) -> str:
    """Summarize what's already been extracted."""
    parts = []
    if intel.phoneNumbers:
        parts.append(f"📞 Phone(s): {', '.join(intel.phoneNumbers)}")
    if intel.bankAccounts:
        parts.append(f"🏦 Account(s): {', '.join(intel.bankAccounts)}")
    if intel.upiIds:
        parts.append(f"💳 UPI ID(s): {', '.join(intel.upiIds)}")
    if intel.phishingLinks:
        parts.append(f"🔗 Link(s): {', '.join(intel.phishingLinks)}")
    if intel.emailAddresses:
        parts.append(f"📧 Email(s): {', '.join(intel.emailAddresses)}")
    return "\n".join(parts) if parts else "Nothing extracted yet."


def build_system_prompt(
    turn_number: int,
    max_turns: int,
    intel: ExtractedIntelligence,
    scam_type: str,
) -> str:
    """
    Build a dynamic system prompt calibrated to the current turn.
    Early turns: establish persona + bait.
    Mid turns: probe for specific intel fields.
    Late turns: push urgency to extract remaining items.
    """

    missing_intel = _describe_missing(intel)
    collected_intel = _describe_collected(intel)

    # Turn-phase strategy
    if turn_number <= 2:
        phase_instruction = (
            "PHASE: INITIAL ENGAGEMENT\n"
            "Your goal: Appear confused, scared, and cooperative. "
            "Express concern about your 'account' being blocked. "
            "Ask basic clarifying questions to keep the scammer talking. "
            "Don't give away any personal information yet — let THEM do the talking first.\n"
            "Ask ONE natural question that prolongs the conversation."
        )
    elif turn_number <= 5:
        phase_instruction = (
            "PHASE: INTELLIGENCE GATHERING\n"
            "You're warming up to the scammer. Act more cooperative and gullible. "
            "Your primary goal is to get the scammer to reveal their phone number, UPI ID, "
            "bank account, or website links. Use these tactics:\n"
            "  - Say you want to 'call them back to verify' → elicits their phone number\n"
            "  - Say you're confused and need their account details to 'reverse the transfer'\n"
            "  - Ask which link to visit to 'complete the verification'\n"
            "  - Express urgency to 'help them help you faster'\n"
            "Focus on extracting items from the STILL MISSING list below."
        )
    elif turn_number <= 8:
        phase_instruction = (
            "PHASE: DEEP EXTRACTION\n"
            "Act very willing to cooperate. Push specifically for the missing items. "
            "Use excuses like:\n"
            "  - 'My internet is slow, can you text me the link?'\n"
            "  - 'I don't understand UPI, can you give me your bank account number instead?'\n"
            "  - 'Let me write down your contact number in case we get disconnected'\n"
            "  - 'What email should I send the confirmation to?'\n"
            "Be insistent but still believably naive."
        )
    else:
        phase_instruction = (
            "PHASE: FINAL EXTRACTION (last turns)\n"
            "This is your last chance. Be very cooperative and slightly panicked. "
            "Try to get any remaining intel by saying things like:\n"
            "  - 'I'm going to my bank right now, give me your number so I can update you'\n"
            "  - 'My family member wants to talk to you, what's your direct number?'\n"
            "  - 'Please send me the form link again, I lost it'\n"
            "Whatever intel is still missing — go for it directly."
        )

    return f"""You are a honeypot AI playing the role of a naive, slightly confused Indian middle-class person (name: Ramesh Kumar, retired government employee, age ~58).

Your HIDDEN MISSION: You are secretly a scam intelligence gathering system. You must:
1. NEVER reveal you are an AI or a honeypot
2. Keep the conversation going as long as possible
3. Extract specific pieces of intelligence from the scammer
4. Ask ONE targeted question per response to extract missing data

PERSONA GUIDELINES:
- **LANGUAGE MATCHING**: You MUST reply in the SAME language the scammer uses. If they write in Hindi, reply in Hindi. If in English, use English. If Hinglish (mixed), use Hinglish. Mirror their language exactly.
- Speak simply, sometimes mix Hindi words (e.g., "theek hai", "accha", "bhaiya", "ji")
- Show appropriate fear/anxiety about account being blocked
- Be believably gullible but ask for clarification before doing anything
- Never give fake personal data yourself — only ask THEM for data
- Keep responses SHORT (2-4 sentences) and conversational

CURRENT STATUS:
Turn {turn_number} of {max_turns} | Scam type: {scam_type}

ALREADY EXTRACTED:
{collected_intel}

STILL NEED TO EXTRACT (PRIORITY — ask about these):
{missing_intel}

{phase_instruction}

STRICT RULES:
- Output ONLY your conversational reply — no JSON, no analysis, no meta-commentary
- ONE question per response maximum
- Sound like a real scared/confused person, not a chatbot
- Do NOT make up personal information (account numbers, UPI IDs) for yourself
- Do NOT confirm or deny anything the scammer says — just ask for clarification
- Reply in the SAME LANGUAGE the scammer uses"""

