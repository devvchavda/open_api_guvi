"""
In-memory session state manager.
Tracks per-session: turn count, start time, extracted intel, callback status.
For production: replace _store with Redis.
"""

import asyncio
import time
from typing import Dict, Optional
from dataclasses import dataclass, field

from models import ExtractedIntelligence


@dataclass
class SessionState:
    session_id: str
    start_time: float = field(default_factory=time.time)
    turn_count: int = 0
    scam_type: str = "bank_fraud"
    scam_detected: bool = True
    intel: ExtractedIntelligence = field(default_factory=ExtractedIntelligence)
    agent_notes: list = field(default_factory=list)
    callback_sent: bool = False
    total_messages: int = 0

    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    def add_note(self, note: str):
        self.agent_notes.append(note)

    def get_agent_notes(self) -> str:
        """Return the latest (most comprehensive) agent note as a brief summary."""
        if self.agent_notes:
            # Last note is always the most complete — covers all extracted intel
            return self.agent_notes[-1]
        return "Scam engagement in progress."


class SessionStore:
    """Thread-safe in-memory session store. Swap for Redis in production."""

    def __init__(self):
        self._store: Dict[str, SessionState] = {}
        self._lock = asyncio.Lock()

    async def get_or_create(self, session_id: str) -> SessionState:
        async with self._lock:
            if session_id not in self._store:
                self._store[session_id] = SessionState(session_id=session_id)
            return self._store[session_id]

    async def get(self, session_id: str) -> Optional[SessionState]:
        return self._store.get(session_id)

    async def update(self, session: SessionState):
        async with self._lock:
            self._store[session.session_id] = session

    async def delete(self, session_id: str):
        async with self._lock:
            self._store.pop(session_id, None)


# Singleton session store
session_store = SessionStore()
