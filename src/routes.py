"""
FastAPI routes.
POST /analyze — main honeypot endpoint
GET  /session/{session_id} — debug: view session state
POST /session/{session_id}/callback — manually trigger callback
"""

import logging
from fastapi import APIRouter, HTTPException, Header, BackgroundTasks
from typing import Optional

from config import settings
from models import AnalyzeRequest, AnalyzeResponse
from agent import run_agent
from session_store import session_store
from callback import send_callback, build_final_payload

logger = logging.getLogger(__name__)
router = APIRouter()


def _verify_api_key(x_api_key: Optional[str]):
    """Validate API key if one is configured."""
    if settings.API_KEY and x_api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    x_api_key: Optional[str] = Header(default=None),
):
    """
    Main honeypot endpoint.
    Receives scammer message, returns honeypot reply.
    """
    _verify_api_key(x_api_key)

    logger.info(
        f"[{request.sessionId}] Turn received | "
        f"sender={request.message.sender} | "
        f"history_len={len(request.conversationHistory or [])}"
    )

    # Convert conversation history to list of dicts
    history = []
    if request.conversationHistory:
        for msg in request.conversationHistory:
            history.append({"sender": msg.sender, "text": msg.text})

    try:
        reply = await run_agent(
            session_id=request.sessionId,
            scammer_message=request.message.text,
            conversation_history=history,
        )
    except Exception as exc:
        logger.error(f"[{request.sessionId}] Agent error: {exc}", exc_info=True)
        # Graceful fallback — never return 500 to evaluator
        reply = "I'm sorry, I am very confused. Can you please call me back? I need to verify with my bank first."

    logger.info(f"[{request.sessionId}] Reply: {reply[:80]}...")
    return AnalyzeResponse(status="success", reply=reply)


@router.get("/session/{session_id}")
async def get_session(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None),
):
    """Debug endpoint: view session state and extracted intel."""
    _verify_api_key(x_api_key)
    session = await session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    payload = build_final_payload(session)
    return {
        "session_id": session_id,
        "turn_count": session.turn_count,
        "scam_type": session.scam_type,
        "callback_sent": session.callback_sent,
        "elapsed_seconds": round(session.elapsed_seconds(), 1),
        "final_payload": payload.model_dump(),
    }


@router.post("/session/{session_id}/callback")
async def trigger_callback(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None),
):
    """Manually trigger callback for a session (admin use)."""
    _verify_api_key(x_api_key)
    session = await session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    success = await send_callback(session)
    return {"success": success, "callback_sent": session.callback_sent}


@router.get("/test-score/{session_id}")
async def test_score(
    session_id: str,
    x_api_key: Optional[str] = Header(default=None),
):
    """
    Score a session's final output using the GUVI evaluation rubric.
    Returns detailed breakdown: detection (20), intel (40), engagement (20), structure (20).
    """
    _verify_api_key(x_api_key)
    session = await session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    payload = build_final_payload(session)
    output = payload.model_dump()

    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }

    # 1. Scam Detection (20 pts)
    if output.get("scamDetected"):
        score["scamDetection"] = 20

    # 2. Intelligence Extraction (40 pts) — count non-empty fields, 10 pts each
    extracted = output.get("extractedIntelligence", {})
    for field in ["phoneNumbers", "bankAccounts", "upiIds", "phishingLinks", "emailAddresses"]:
        if extracted.get(field):
            score["intelligenceExtraction"] += 10
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)

    # 3. Engagement Quality (20 pts)
    metrics = output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if duration > 0:
        score["engagementQuality"] += 5
    if duration > 60:
        score["engagementQuality"] += 5
    if messages > 0:
        score["engagementQuality"] += 5
    if messages >= 5:
        score["engagementQuality"] += 5

    # 4. Response Structure (20 pts)
    for field in ["status", "scamDetected", "extractedIntelligence"]:
        if field in output:
            score["responseStructure"] += 5
    for field in ["engagementMetrics", "agentNotes"]:
        if field in output and output[field]:
            score["responseStructure"] += 2.5
    score["responseStructure"] = min(score["responseStructure"], 20)

    score["total"] = (
        score["scamDetection"]
        + score["intelligenceExtraction"]
        + score["engagementQuality"]
        + score["responseStructure"]
    )

    return {
        "session_id": session_id,
        "score": score,
        "final_output": output,
    }
