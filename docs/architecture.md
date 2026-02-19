# Architecture — Agentic Honeypot System

## Overview

The Honeypot API is an AI-powered scam detection and intelligence extraction system. It engages scammers in realistic conversations through a convincing persona while silently extracting actionable intelligence (phone numbers, bank accounts, UPI IDs, phishing links, emails).

---

## System Architecture

```
                         ┌──────────────────────┐
                         │   GUVI Evaluator      │
                         │   (sends scam msgs)   │
                         └──────────┬───────────┘
                                    │ POST /analyze
                                    ▼
                         ┌──────────────────────┐
                         │   FastAPI Server      │
                         │   (routes.py)         │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Honeypot Agent      │
                         │   (honeypot_agent.py) │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
            ┌───────▼──────┐ ┌─────▼──────┐ ┌──────▼──────┐
            │ Regex Engine │ │Reply Agent │ │Intel Agent  │
            │(extractor.py)│ │ (plain LLM)│ │(structured) │
            └───────┬──────┘ └─────┬──────┘ └──────┬──────┘
                    │               │               │
                    └───────────────┼───────────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Union & Merge      │
                         │   (deduplicate)      │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼                               ▼
            ┌──────────────┐              ┌──────────────────┐
            │ Reply to     │              │ Callback POST    │
            │ Scammer      │              │ (to GUVI eval)   │
            └──────────────┘              └──────────────────┘
```

---

## Component Details

### 1. FastAPI Server (`main.py` + `routes.py`)

- Entrypoint: `main.py` — creates FastAPI app with CORS middleware
- Routes: `routes.py` — handles `/analyze`, `/session`, `/test-score` endpoints
- API key authentication via `x-api-key` header
- Health check at `GET /health`

### 2. Honeypot Agent (`honeypot_agent.py`)

Core orchestration module that runs on every turn:

1. **Regex Extraction** (sync) — Fast pattern matching via `extractor.py`
2. **Parallel LLM Calls** (async) — Two agents run concurrently:
   - **Reply Agent** — Plain LLM call generating in-character conversational reply
   - **Intel Agent** — Structured output LLM call extracting scam type, intel fields, and analyst notes
3. **Union & Merge** — Combines regex + LLM results with deduplication
4. **Smart Pacing** — Adds calculated delays (turns 4-8) to meet engagement duration requirements
5. **Callback Decision** — Fires callback after configurable turn threshold

### 3. Regex Extractor (`extractor.py`)

Pattern-based extraction running before LLM calls:

| Category | Approach |
|---|---|
| Phone Numbers | Indian formats (+91, 91, 0-prefix, 10-digit), international |
| Bank Accounts | 9-18 digit numeric strings (filters out timestamps) |
| UPI IDs | `localpart@handle` without TLD (distinguished from emails) |
| Phishing Links | HTTP/HTTPS URLs, bit.ly, tinyurl shorteners |
| Emails | Standard format with TLD (`.com`, `.in`, `.org`) |
| Keywords | 30+ suspicious terms (urgent, verify, blocked, OTP, etc.) |

### 4. Prompt Builder (`prompt_builder.py`)

Generates dynamic system prompts based on:

- **Turn phase**: Initial Engagement (1-2) → Intelligence Gathering (3-5) → Deep Extraction (6-8) → Final Extraction (9+)
- **Missing intel**: Lists what's still needed, with suggested elicitation tactics
- **Collected intel**: Shows what's already been extracted
- **Scam type**: Detected from conversation keywords

### 5. Models (`models.py`)

Pydantic v2 models for:

- `AnalyzeRequest` / `AnalyzeResponse` — API request/response
- `ExtractedIntelligence` — Intel payload (phones, accounts, UPIs, links, emails, keywords)
- `IntelResponse` — Structured LLM output with alias support
- `FinalPayload` / `EngagementMetrics` — Callback payload structure

### 6. Callback (`callback.py`)

- Builds final payload from session state
- `engagementDurationSeconds` — elapsed seconds (int) at both root and metrics level
- `totalMessagesExchanged` — total message count
- Async POST to GUVI endpoint via httpx
- Prevents duplicate sends via `callback_sent` flag

### 7. Session Store (`session_store.py`)

- In-memory dataclass-based session storage
- Tracks: turn count, start time, extracted intel, scam type, callback status, agent notes
- Thread-safe via asyncio Lock
- Designed for Redis swap in production

### 8. LLM Client (`llm_client.py`)

- Factory function `get_llm()` — single place to swap providers
- Supports: Groq, OpenAI, Anthropic, Ollama
- Currently configured for Groq with `openai/gpt-oss-120b`

---

## Data Flow

```
Turn N arrives:
  │
  ├─► Session loaded/created (session_store)
  ├─► Regex extraction on all messages (extractor)
  ├─► System prompt built (prompt_builder) based on turn phase + missing intel
  │
  ├─► [PARALLEL] Reply Agent → plain text reply
  ├─► [PARALLEL] Intel Agent → structured IntelResponse
  │
  ├─► Union: regex_intel + llm_intel → merged ExtractedIntelligence
  ├─► Smart pacing delay (turns 4-8 only)
  ├─► Session state updated
  ├─► Callback fired if turn >= threshold
  │
  └─► Reply returned to caller
```

---

## Scoring Rubric (GUVI Evaluation)

| Category | Max | Criteria |
|---|---|---|
| Scam Detection | 20 | `scamDetected: true` |
| Intelligence Extraction | 40 | 10 pts per non-empty field (phones, accounts, UPIs, links, emails) |
| Engagement Quality | 20 | Duration > 60s, messages >= 5 |
| Response Structure | 20 | Required fields present in payload |
| **Total** | **100** | |

---

## Fault Tolerance

| Failure | Fallback |
|---|---|
| LLM timeout (>25s) | Context-aware pre-written replies |
| Intel Agent failure | Keyword-based scam type + regex-only intel |
| Reply Agent failure | Turn-aware fallback reply library |
| Callback failure | Logged, doesn't affect scammer reply |
| Any agent error | Route-level catch with graceful reply |
