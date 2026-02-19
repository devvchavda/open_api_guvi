"""
Pydantic models for API request/response validation.
"""

from typing import Any, Dict, List, Optional
from pydantic import AliasChoices, BaseModel, Field


# ─── Inbound ──────────────────────────────────────────────────────────────────

class Message(BaseModel):
    sender: str  # "scammer" | "user"
    text: str
    timestamp: Optional[Any] = None


class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"


class AnalyzeRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = Field(default_factory=list)
    metadata: Optional[Metadata] = Field(default_factory=Metadata)


# ─── Outbound (per-turn) ───────────────────────────────────────────────────────

class AnalyzeResponse(BaseModel):
    status: str = "success"
    reply: str


# ─── Intelligence Payload ──────────────────────────────────────────────────────

class ExtractedIntelligence(BaseModel):
    phoneNumbers: List[str] = Field(default_factory=list)
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)


# ─── Structured LLM Outputs (parallel agents) ─────────────────────────────────

class ReplyResponse(BaseModel):
    """Reply Agent output — conversational reply only."""
    reply: str = Field(
        description=(
            "Your in-character conversational reply as Ramesh Kumar. "
            "Short (2-4 sentences), natural, no JSON or meta-commentary. "
            "MUST be in the same language as the scammer's message."
        )
    )


class IntelResponse(BaseModel):
    """Intel Agent output — structured payload fields for the final callback."""
    model_config = {"populate_by_name": True}

    scam_detected: bool = Field(
        description="Whether a scam is being attempted in this conversation."
    )
    scam_type: str = Field(
        description=(
            "The type of scam detected. Must be one of: "
            "bank_fraud, upi_fraud, phishing, kyc_fraud, job_scam, "
            "lottery_scam, electricity_bill, tax_fraud, customs_parcel, "
            "tech_support, loan_fraud, insurance_fraud, investment_fraud, unknown"
        )
    )
    phone_numbers: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("phone_numbers", "phoneNumbers"),
        description="Phone numbers mentioned by the scammer (any format)."
    )
    bank_accounts: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("bank_accounts", "bank_account_numbers", "bankAccounts"),
        description="Bank account numbers mentioned by the scammer."
    )
    upi_ids: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("upi_ids", "upiIds"),
        description="UPI IDs mentioned by the scammer (e.g. name@bank)."
    )
    phishing_links: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("phishing_links", "phishingLinks"),
        description="Suspicious URLs or links shared by the scammer."
    )
    email_addresses: List[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("email_addresses", "emails", "emailAddresses"),
        description="Email addresses mentioned by the scammer."
    )
    agent_note: str = Field(
        default="",
        validation_alias=AliasChoices("agent_note", "analyst_note", "agentNote"),
        description=(
            "A concise analyst-style note (1-2 sentences) summarizing what happened this turn: "
            "what scam tactic the scammer used, what intel was extracted, and the honeypot strategy applied. "
            "Write in third person."
        )
    )


# ─── Final Callback Payload ───────────────────────────────────────────────────

class EngagementMetrics(BaseModel):
    totalMessagesExchanged: int
    engagementDurationSeconds: int


class FinalPayload(BaseModel):
    """Payload sent to GUVI callback endpoint."""
    status: str = "success"
    scamDetected: bool = True
    scamType: str = "bank_fraud"
    extractedIntelligence: ExtractedIntelligence
    totalMessagesExchanged: int
    engagementDurationSeconds: int
    engagementMetrics: EngagementMetrics
    agentNotes: str
