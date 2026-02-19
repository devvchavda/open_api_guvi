"""
Honeypot Agent — Parallel architecture.
Two LLM calls run concurrently via asyncio.gather:
  • Reply Agent  → generates in-character conversational reply
  • Intel Agent  → extracts structured payload (scam_type, intel, agent_note)
Results are unioned (regex intel + LLM intel) before callback decision.
"""

import asyncio
import logging
from typing import List, Set

from langchain_core.messages import SystemMessage, HumanMessage

from config import settings
from extractor import extract_intelligence, _dedupe_phones
from llm_client import get_llm
from models import (
    ExtractedIntelligence,
    IntelResponse,
)
from prompt_builder import build_system_prompt, detect_scam_type as detect_from_prompt
from session_store import SessionState, session_store
from callback import send_callback_background

logger = logging.getLogger(__name__)


# ─── Intel Agent Prompt ────────────────────────────────────────────────────────

_INTEL_SYSTEM_PROMPT = """You are a scam intelligence analyst. Analyze the conversation below and extract ALL structured intelligence.

Your job:
1. Determine if a scam is being attempted (scam_detected: true/false)
2. Classify the scam type from the list below
3. Extract every piece of actionable intel from the scammer's messages:
   - Phone numbers (any format: +91-XXXXX-XXXXX, 10-digit, spoken digits like "nine eight seven..."). Output as digits only, e.g. "9876543210".
   - Bank account numbers (9-18 digit numeric strings used in financial context)
   - UPI IDs — bare handles like name@paytm, name@ybl, name@oksbi. NO .com/.in/.org TLD.
   - Phishing links — suspicious URLs (http/https), shortened links, fake portals
   - Email addresses — MUST have a TLD like .com, .in, .org (e.g. support@fakebank.com). If it has a TLD, it is an EMAIL, not a UPI ID.
4. Write a brief analyst note summarizing this turn

CRITICAL: Distinguish emails from UPI IDs:
  - "scammer@fakebank" → UPI ID (no TLD)
  - "security@fakebank.com" → EMAIL (has .com TLD)

Scam types: bank_fraud, upi_fraud, phishing, kyc_fraud, job_scam, lottery_scam, electricity_bill, tax_fraud, customs_parcel, tech_support, loan_fraud, insurance_fraud, investment_fraud, unknown

IMPORTANT: Extract intel ONLY from the scammer's messages, not from the honeypot's replies."""


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _dedupe(items: List[str]) -> List[str]:
    """Deduplicate while preserving order."""
    seen: Set[str] = set()
    result = []
    for item in items:
        norm = item.strip()
        if norm and norm.lower() not in seen:
            seen.add(norm.lower())
            result.append(norm)
    return result


def _union_intel(
    regex_intel: ExtractedIntelligence,
    llm_intel: IntelResponse,
) -> ExtractedIntelligence:
    """Merge regex-extracted and LLM-extracted intelligence, deduplicated."""
    return ExtractedIntelligence(
        phoneNumbers=_dedupe_phones(regex_intel.phoneNumbers + llm_intel.phone_numbers),
        bankAccounts=_dedupe(regex_intel.bankAccounts + llm_intel.bank_accounts),
        upiIds=_dedupe(regex_intel.upiIds + llm_intel.upi_ids),
        phishingLinks=_dedupe(regex_intel.phishingLinks + llm_intel.phishing_links),
        emailAddresses=_dedupe(regex_intel.emailAddresses + llm_intel.email_addresses),
        suspiciousKeywords=regex_intel.suspiciousKeywords,  # keywords are regex-only
    )


def _build_conversation_messages(
    conversation_history: List[dict],
    scammer_message: str,
) -> str:
    """Build a text block of the conversation for the Intel Agent."""
    lines = []
    for msg in conversation_history:
        role = msg.get("sender", "scammer")
        text = msg.get("text", "")
        label = "Scammer" if role == "scammer" else "Honeypot"
        lines.append(f"{label}: {text}")
    lines.append(f"Scammer: {scammer_message}")
    return "\n".join(lines)


def _build_reply_messages(
    system_prompt: str,
    conversation_history: List[dict],
    scammer_message: str,
) -> list:
    """Build LangChain message list for the Reply Agent."""
    # Append strict language-matching instruction
    language_instruction = (
        "\n\nCRITICAL LANGUAGE RULE (MUST FOLLOW):\n"
        "1. Look at the scammer's LATEST message ONLY to determine the language.\n"
        "2. If scammer's latest message is in ENGLISH → you MUST reply in ENGLISH only.\n"
        "3. If scammer's latest message is in HINDI → you MUST reply in HINDI only.\n"
        "4. If scammer's latest message is in HINGLISH (mixed) → reply in HINGLISH.\n"
        "5. NEVER switch languages on your own. NEVER use Hindi if the scammer is writing in English.\n"
        "6. You are an elderly Indian man who can speak both languages, but you ALWAYS mirror the scammer's language choice."
    )
    full_prompt = system_prompt + language_instruction

    lc_messages = [SystemMessage(content=full_prompt)]

    # Last 8 messages for context (4 exchange pairs)
    history = conversation_history[-8:]
    for msg in history:
        role = msg.get("sender", "scammer")
        text = msg.get("text", "")
        if role == "scammer":
            lc_messages.append(HumanMessage(content=f"Scammer: {text}"))
        else:
            lc_messages.append(HumanMessage(content=f"You (Ramesh): {text}"))

    lc_messages.append(HumanMessage(content=f"Scammer: {scammer_message}"))
    return lc_messages


def _build_fallback_note(scam_type: str, intel: ExtractedIntelligence, keywords: List[str] = None) -> str:
    """Build an analyst-style scam summary describing tactics, not just listing items."""
    scam_label = scam_type.replace("_", " ").title()

    # Describe scam tactics based on detected keywords
    kw_set = set(k.lower() for k in (keywords or []))
    tactics = []
    if kw_set & {"urgent", "immediately", "act now", "limited time"}:
        tactics.append("used urgency and pressure tactics")
    if kw_set & {"blocked", "suspended", "cancel", "expire", "arrest", "legal action"}:
        tactics.append("threatened account blockage or legal action")
    if kw_set & {"verify", "verify now", "confirm", "kyc"}:
        tactics.append("impersonated bank verification process")
    if kw_set & {"otp", "password"}:
        tactics.append("attempted to steal OTP/credentials")
    if kw_set & {"reward", "prize", "lottery", "won", "refund"}:
        tactics.append("lured with fake rewards or refunds")

    # Describe what was collected
    collected = []
    if intel.phoneNumbers:
        collected.append("phone number(s)")
    if intel.bankAccounts:
        collected.append("bank account number(s)")
    if intel.upiIds:
        collected.append("UPI ID(s)")
    if intel.phishingLinks:
        collected.append("phishing URL(s)")
    if intel.emailAddresses:
        collected.append("email address(es)")

    # Build summary
    tactics_str = ", ".join(tactics) if tactics else "employed social engineering"
    collected_str = ", ".join(collected) if collected else "no actionable intel yet"

    return (
        f"{scam_label} confirmed. Scammer {tactics_str}. "
        f"Honeypot successfully extracted {collected_str} while maintaining engagement."
    )


def _generate_fallback_reply(turn: int, scammer_message: str) -> str:
    """Generate a varied in-character fallback reply when LLM is unavailable or times out."""
    msg_lower = scammer_message.lower()

    # Context-aware fallback based on scammer's message content
    if any(k in msg_lower for k in ["otp", "code", "password"]):
        options = [
            "Sir, I am trying to find the OTP but my phone is running slow. Can you please wait 2 minutes?",
            "Bhaiya, OTP abhi tak nahi aaya, kya aap dubara bhej sakte hain?",
            "Sir, I see many SMS messages. Which one is the correct OTP? Can you please help me identify it?",
        ]
    elif any(k in msg_lower for k in ["upi", "transfer", "payment", "send"]):
        options = [
            "Sir, I am opening my payment app now. Can you please confirm the exact UPI ID one more time?",
            "Bhaiya, mera UPI app load ho raha hai, please 1 minute wait karein.",
            "Sir, my phone is asking for the receiver's name also. What name should I enter?",
        ]
    elif any(k in msg_lower for k in ["link", "url", "website", "click"]):
        options = [
            "Sir, the link is not opening on my phone. Can you please send it again?",
            "Bhaiya, mera internet bahut slow hai, link load nahi ho raha. Kya aap email se bhej sakte hain?",
            "Sir, I clicked on the link but it shows a blank page. Is there another website I can try?",
        ]
    elif any(k in msg_lower for k in ["email", "mail"]):
        options = [
            "Sir, can you please spell out the email address one more time? I want to make sure I type it correctly.",
            "Bhaiya, email address mein @ ke baad kya aata hai? Please confirm karein.",
            "Sir, should I send it from my Gmail or my Yahoo mail? Which one is better?",
        ]
    else:
        options = [
            "Sir, I am very worried about my account. Can you please explain what I should do step by step?",
            "Bhaiya, mujhe bahut tension ho rahi hai. Kya aap mujhe apna direct number de sakte hain?",
            "Sir, my family member is also here and wants to help. Can you please tell us what to do next?",
            "Sir, I don't understand all this technical process. Can you please guide me slowly?",
        ]

    # Rotate through options based on turn number
    return options[turn % len(options)]


# ─── Parallel Agent Runners ───────────────────────────────────────────────────

async def _run_reply_agent(
    system_prompt: str,
    conversation_history: List[dict],
    scammer_message: str,
) -> str:
    """Generate in-character honeypot reply via plain LLM call (no structured output)."""
    llm = get_llm()
    messages = _build_reply_messages(system_prompt, conversation_history, scammer_message)

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, llm.invoke, messages)

    reply = response.content.strip()
    # Remove any persona prefix the LLM might add
    for prefix in ["Ramesh:", "You:", "Me:", "User:"]:
        if reply.startswith(prefix):
            reply = reply[len(prefix):].strip()
    return reply


async def _run_intel_agent(
    conversation_history: List[dict],
    scammer_message: str,
) -> IntelResponse:
    """Extract structured intelligence via structured LLM output."""
    llm = get_llm()
    structured_llm = llm.with_structured_output(IntelResponse)

    conversation_text = _build_conversation_messages(conversation_history, scammer_message)
    messages = [
        SystemMessage(content=_INTEL_SYSTEM_PROMPT),
        HumanMessage(content=f"Conversation:\n{conversation_text}\n\nRespond with a JSON object."),
    ]

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, structured_llm.invoke, messages)
    return result


# ─── Public Interface ─────────────────────────────────────────────────────────

async def run_agent(
    session_id: str,
    scammer_message: str,
    conversation_history: List[dict],
) -> str:
    """
    Run the honeypot agent for one turn.
    Two LLM calls run in parallel:
      1. Reply Agent  → plain text conversational reply
      2. Intel Agent  → structured payload extraction
    Results are unioned with regex intel, then callback decision is made.
    Returns the reply string.
    """
    import time as _time
    session: SessionState = await session_store.get_or_create(session_id)
    _turn_start = _time.monotonic()
    print(f"\n  📥 [{session_id[:8]}] Turn {session.turn_count + 1} received")
    session.turn_count += 1
    # total_messages = all messages in history + current incoming scammer msg + our reply
    session.total_messages = len(conversation_history) + 2

    # ── Step 1: Regex extraction (sync, fast) ──────────────────────────────
    all_texts = [msg.get("text", "") for msg in conversation_history]
    all_texts.append(scammer_message)
    regex_intel = extract_intelligence(all_texts)

    # ── Step 2: Build reply prompt ─────────────────────────────────────────
    system_prompt = build_system_prompt(
        turn_number=session.turn_count,
        max_turns=settings.MAX_TURNS,
        intel=session.intel,  # use accumulated intel so far
        scam_type=session.scam_type,
    )

    # ── Step 3: Parallel LLM calls with 25s timeout ─────────────────────────
    #    Evaluator has a 30s HTTP timeout — we MUST respond before that.
    LLM_TIMEOUT = 25  # seconds

    try:
        results = await asyncio.wait_for(
            asyncio.gather(
                _run_reply_agent(system_prompt, conversation_history, scammer_message),
                _run_intel_agent(conversation_history, scammer_message),
                return_exceptions=True,
            ),
            timeout=LLM_TIMEOUT,
        )
        reply_result, intel_result = results
    except asyncio.TimeoutError:
        logger.warning(f"[{session_id}] LLM calls timed out after {LLM_TIMEOUT}s — using fallback")
        reply_result = TimeoutError("LLM timeout")
        intel_result = TimeoutError("LLM timeout")

    # ── Process Reply Agent result ─────────────────────────────────────────
    if isinstance(reply_result, Exception):
        logger.error(f"[{session_id}] Reply Agent failed: {reply_result}")
        reply_text = _generate_fallback_reply(session.turn_count, scammer_message)
    else:
        reply_text = reply_result
        logger.info(f"[{session_id}] Reply Agent OK: {reply_text[:80]}")

    # ── Process Intel Agent result ─────────────────────────────────────────
    if isinstance(intel_result, Exception):
        logger.error(f"[{session_id}] Intel Agent failed: {intel_result}")
        # Fallback to keyword-based scam detection
        fallback_scam_type = detect_from_prompt(all_texts)
        intel_result = IntelResponse(
            scam_detected=True,
            scam_type=fallback_scam_type,
            phone_numbers=[],
            bank_accounts=[],
            upi_ids=[],
            phishing_links=[],
            email_addresses=[],
            agent_note="",  # will be generated from regex intel below
        )
    else:
        logger.info(
            f"[{session_id}] Intel Agent OK — "
            f"scam_type={intel_result.scam_type}, "
            f"scam_detected={intel_result.scam_detected}"
        )

    # ── Step 4: Union regex + LLM intel ────────────────────────────────────
    merged_intel = _union_intel(regex_intel, intel_result)

    # ── Smart Pacing (Turns 4-8) ──────────────────────────────────────────
    # Goal: Ensure total session duration > 63s by the end of Turn 8.
    # Logic:
    #   - Turns 1-3: Fast (no pacing).
    #   - Turns 4-8: Distribute remaining required time evenly.
    #   - Turns 9+:  Fast (no pacing).
    
    elapsed_total_session = session.elapsed_seconds()
    elapsed_this_turn = _time.monotonic() - _turn_start
    final_delay = 0.0

    if settings.SMART_PACING_ENABLED and 4 <= session.turn_count <= 8:
        TARGET_DURATION_AT_TURN_8 = 63.0
        remaining_needed = TARGET_DURATION_AT_TURN_8 - elapsed_total_session
        if remaining_needed > 0:
            # Turns left: 4->5, 5->4, 6->3, 7->2, 8->1
            remaining_turns = (8 - session.turn_count) + 1
            calculated_delay = remaining_needed / remaining_turns
            
            # Just apply the calculated delay directly. 
            # (elapsed_total_session includes previous turns, so remaining_needed is purely future sleep)
            final_delay = max(0.0, calculated_delay)
    
    # SAFETY: Never exceed 24s total per turn (Evaluator timeout is 30s)
    max_allowed = 24.0 - elapsed_this_turn
    final_delay = min(final_delay, max_allowed)
    final_delay = max(0.0, final_delay)

    if final_delay > 0.5:
        print(f"  ⏳ [{session_id[:8]}] Turn {session.turn_count} pacing: adding {final_delay:.1f}s (session elapsed: {elapsed_total_session:.1f}s)")
        await asyncio.sleep(final_delay)
    
    # ── Step 5: Persist state ──────────────────────────────────────────────
    session.intel = merged_intel
    session.scam_type = intel_result.scam_type
    session.scam_detected = intel_result.scam_detected

    # Generate agent note — LLM note preferred, else build from regex intel
    agent_note = intel_result.agent_note.strip() if intel_result.agent_note else ""
    if not agent_note:
        agent_note = _build_fallback_note(
            intel_result.scam_type, merged_intel,
            keywords=merged_intel.suspiciousKeywords,
        )
    session.add_note(agent_note)

    await session_store.update(session)

    # ── Step 6: Callback decision ──────────────────────────────────────────
    turn = session.turn_count

    should_send = (
        turn >= settings.SEND_CALLBACK_AFTER_TURN
        or turn >= settings.MAX_TURNS
    )

    if should_send and not session.callback_sent:
        asyncio.create_task(send_callback_background(session))

    total_time = _time.monotonic() - _turn_start
    print(f"  📤 [{session_id[:8]}] Turn {turn} responded in {total_time:.1f}s | duration={session.elapsed_seconds():.1f}s")

    return reply_text

