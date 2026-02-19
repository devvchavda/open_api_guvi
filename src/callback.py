"""
Async callback sender — posts final intelligence payload to GUVI endpoint.
"""

import asyncio
import logging
import time

import httpx

from config import settings
from models import FinalPayload, EngagementMetrics, ExtractedIntelligence
from session_store import SessionState

logger = logging.getLogger(__name__)


def build_final_payload(session: SessionState) -> FinalPayload:
    """Construct the final scoring payload from session state."""
    duration_sec = int(round(session.elapsed_seconds()))
    return FinalPayload(
        status="success",
        scamDetected=session.scam_detected,
        scamType=session.scam_type,
        extractedIntelligence=session.intel,
        totalMessagesExchanged=session.total_messages,
        engagementDurationSeconds=duration_sec,
        engagementMetrics=EngagementMetrics(
            totalMessagesExchanged=session.total_messages,
            engagementDurationSeconds=duration_sec,
        ),
        agentNotes=session.get_agent_notes(),
    )


async def send_callback(session: SessionState) -> bool:
    """
    POST final payload to GUVI callback endpoint.
    Returns True on success, False on failure.
    Marks session as callback_sent to prevent duplicate sends.
    """
    if session.callback_sent:
        logger.info(f"[{session.session_id}] Callback already sent, skipping.")
        return True

    payload = build_final_payload(session)
    payload_dict = payload.model_dump()

    # Add sessionId (required by callback but not in FinalPayload model)
    payload_dict["sessionId"] = session.session_id



    logger.info(f"[{session.session_id}] Sending callback to {settings.CALLBACK_URL}")
    logger.debug(f"Payload: {payload_dict}")

    try:
        async with httpx.AsyncClient(timeout=settings.CALLBACK_TIMEOUT) as client:
            resp = await client.post(settings.CALLBACK_URL, json=payload_dict)
            if resp.status_code in (200, 201, 202):
                session.callback_sent = True
                logger.info(f"[{session.session_id}] Callback sent successfully: {resp.status_code}")
                return True
            else:
                logger.warning(
                    f"[{session.session_id}] Callback non-success: {resp.status_code} — {resp.text[:200]}"
                )
                return False
    except Exception as exc:
        logger.error(f"[{session.session_id}] Callback failed: {exc}")
        return False


async def send_callback_background(session: SessionState):
    """Fire-and-forget wrapper for background callback."""
    await send_callback(session)
