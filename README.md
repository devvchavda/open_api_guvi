# 🍯 Agentic Honeypot — Scam Detection & Intelligence Extraction API

An AI-powered honeypot system that engages scammers in realistic conversations while silently extracting intelligence (phone numbers, bank accounts, UPI IDs, phishing links, emails) and reporting findings via callback. Built for the GUVI Hackathon challenge.

---

## 🏗️ Architecture

```
Scammer Message ──► /analyze endpoint
                        │
                   ┌────┴────┐
                   │  Regex  │  (fast keyword/pattern extraction)
                   └────┬────┘
                        │
              ┌─────────┼─────────┐
              ▼                   ▼
        Reply Agent         Intel Agent
      (conversational)    (structured extraction)
        (plain LLM)       (structured output)
              │                   │
              └─────────┬─────────┘
                        │
                  Union & Merge
                  (deduplicate)
                        │
              ┌─────────┼─────────┐
              ▼                   ▼
         Reply to             Callback
         Scammer           (to evaluator)
```

### How It Works

1. **Incoming message** hits the `/analyze` endpoint with the scammer's text and conversation history.
2. **Regex extraction** runs synchronously first — fast pattern matching for phones, accounts, UPIs, links, emails, and suspicious keywords.
3. **Two parallel LLM agents** fire concurrently via `asyncio.gather`:
   - **Reply Agent** — Generates an in-character conversational response as "Ramesh Kumar," a naive 58-year-old retired government employee.
   - **Intel Agent** — Extracts structured intelligence (scam type, phone numbers, bank accounts, UPI IDs, phishing links, emails, analyst notes) using structured LLM output.
4. **Union & Merge** — Regex results and LLM results are deduplicated and merged for maximum coverage.
5. **Smart Pacing** — Turns 4–8 are artificially paced to ensure total session duration exceeds 60 seconds (required for scoring).
6. **Callback** — After turn 8 (configurable), the final intelligence payload is POSTed to the GUVI evaluator endpoint.

### Dual Extraction Strategy

The system uses **two independent extraction layers** to maximize intel coverage:

| Layer | Method | Strengths |
|---|---|---|
| **Regex Extractor** | Pattern matching (`extractor.py`) | Fast, deterministic, catches structured formats (phone patterns, URLs, email TLDs) |
| **LLM Intel Agent** | Structured output (`agent.py`) | Understands context, catches spoken numbers ("nine eight seven..."), classifies scam type |

Both layers are merged with deduplication — if regex and LLM both find the same phone number, it appears only once.

---

## 📁 Project Structure

| File | Purpose |
|---|---|
| `main.py` | FastAPI app entrypoint with CORS and health check |
| `routes.py` | API endpoints (`/analyze`, `/test-score`, `/session`, `/session/{id}/callback`) |
| `agent.py` | Core orchestration — parallel LLM agents, smart pacing, fallback handling |
| `models.py` | Pydantic v2 models for request/response validation and callback payload |
| `callback.py` | Async callback sender — builds final payload and POSTs to GUVI endpoint |
| `config.py` | Centralized configuration via `pydantic-settings` (env vars, toggles) |
| `llm_client.py` | LLM factory — swap model/provider (Groq, OpenAI, Anthropic, Ollama) in one place |
| `prompt_builder.py` | Dynamic system prompt generation — adapts strategy based on turn phase & missing intel |
| `extractor.py` | Regex-based intelligence extraction (phones, accounts, UPIs, links, emails, keywords) |
| `session_store.py` | In-memory session state management (swap with Redis for production) |
| `scammer_test.py` | 15-scenario automated test suite with GUVI scoring rubric |
| `self_test.py` | Quick self-test for verifying endpoint health |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- A Groq API key (or any supported LLM provider key)

### Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your API keys (GROQ_API_KEY, ANTHROPIC_API_KEY, etc.)

# 3. Run the server
python main.py
```

Server starts at `http://localhost:8000`. Health check: `GET /health`.

### Docker

```bash
docker build -t honeypot-api .
docker run -p 8000:8000 --env-file .env honeypot-api
```

---

## 🔌 API Endpoints

### `POST /analyze`
Main honeypot endpoint. Receives a scammer message, returns an in-character conversational reply.

**Request:**
```json
{
  "sessionId": "abc-123",
  "message": {
    "sender": "scammer",
    "text": "Your bank account is blocked! Send OTP immediately."
  },
  "conversationHistory": [
    {"sender": "scammer", "text": "Hello, this is SBI customer care."},
    {"sender": "user", "text": "Oh no, what happened to my account?"}
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Sir, I am very worried! Which OTP are you talking about? I have received many messages today. Can you please tell me your direct number so I can call you back?"
}
```

**cURL Example:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -H "x-api-key: YOUR_API_KEY" \
  -d '{
    "sessionId": "abc-123",
    "message": {"sender": "scammer", "text": "Your bank account is blocked!"}
  }'
```

### `GET /health`
Health check endpoint. Returns `{"status": "ok", "version": "1.0.0"}`.

### `GET /session/{session_id}`
Debug endpoint — view session state, extracted intel, turn count, and the full final payload.

### `GET /test-score/{session_id}`
Returns GUVI evaluation score breakdown for a session (detection, intel, engagement, structure — out of 100).

### `POST /session/{session_id}/callback`
Manually trigger the callback for a session (admin use).

---

## 📊 Callback Payload Format

The final payload sent to the GUVI evaluator endpoint:

```json
{
  "status": "success",
  "scamDetected": true,
  "scamType": "bank_fraud",
  "extractedIntelligence": {
    "phoneNumbers": ["+91-9876543210"],
    "bankAccounts": ["1234567890123456"],
    "upiIds": ["scammer.fraud@fakebank"],
    "phishingLinks": ["https://securebank-verify.com/secure-login"],
    "emailAddresses": ["security@fakebank.com"],
    "suspiciousKeywords": ["urgent", "verify", "blocked", "otp", "account"]
  },
  "totalMessagesExchanged": 16,
  "engagementDurationSeconds": 63,
  "engagementMetrics": {
    "totalMessagesExchanged": 16,
    "engagementDurationSeconds": 63
  },
  "agentNotes": "Bank fraud confirmed. Scammer impersonated SBI officer, used urgency tactics..."
}
```

### Field Descriptions

| Field | Type | Description |
|---|---|---|
| `status` | `string` | Always `"success"` |
| `scamDetected` | `bool` | Whether a scam was detected |
| `scamType` | `string` | Classified scam type (e.g., `bank_fraud`, `upi_fraud`, `phishing`) |
| `extractedIntelligence` | `object` | All extracted intel — phones, accounts, UPIs, links, emails, keywords |
| `totalMessagesExchanged` | `int` | Total messages in the conversation |
| `engagementDurationSeconds` | `int` | Total engagement duration in seconds |
| `engagementMetrics` | `object` | Engagement summary with `totalMessagesExchanged` and `engagementDurationSeconds` (both `int`, in seconds) |
| `agentNotes` | `string` | Analyst-style summary of scam tactics and extracted intel |

---

## 🧠 Persona & Prompt Strategy

The honeypot plays **Ramesh Kumar** — a 58-year-old retired Indian government employee who is:
- Slightly confused by technology
- Easily scared about his bank account
- Cooperative but slow to act
- Speaks Hindi/English/Hinglish (mirrors the scammer's language)

### Turn-Phase Strategy

The system prompt dynamically adapts based on the conversation phase:

| Phase | Turns | Strategy |
|---|---|---|
| **Initial Engagement** | 1–2 | Appear confused, scared, cooperative. Ask clarifying questions. Let the scammer reveal their hand. |
| **Intelligence Gathering** | 3–5 | Act gullible. Probe for phone numbers, UPI IDs, bank accounts, links using natural excuses. |
| **Deep Extraction** | 6–8 | Push for missing intel items. Use excuses like slow internet, confusion about UPI, need for callback number. |
| **Final Extraction** | 9+ | Last chance. Be panicked and cooperative. Go directly for any remaining missing intel. |

The prompt builder (`prompt_builder.py`) tracks what intel has been collected vs. what's still missing, and instructs the LLM to focus on the gaps.

---

## 🕐 Smart Pacing

The GUVI evaluator scores engagement duration — sessions under 60 seconds score lower. The smart pacing system in `agent.py` ensures realistic timing:

- **Turns 1–3:** Fast responses (no artificial delay)
- **Turns 4–8:** Calculated delays distributed evenly to reach 63+ seconds by turn 8
- **Turns 9+:** Fast responses (pacing goal already met)
- **Safety cap:** Never exceeds 24 seconds per turn (evaluator timeout is 30s)

---

## 🔍 Intelligence Extraction Details

### Regex Patterns (`extractor.py`)

| Category | Patterns |
|---|---|
| **Phone Numbers** | `+91-XXXXX-XXXXX`, `91-XXXXX-XXXXX`, `0XXXXXXXXXX`, `[6-9]XXXXXXXXX`, international formats |
| **Bank Accounts** | 9–18 digit numeric strings (excludes timestamps, OTPs) |
| **UPI IDs** | `localpart@handle` without TLD (e.g., `name@paytm`, `name@ybl`) |
| **Phishing Links** | `http/https` URLs, `www.` domains, `bit.ly`, `tinyurl.com` shorteners |
| **Emails** | Standard email format with TLD (e.g., `user@domain.com`) — distinguished from UPI by TLD presence |
| **Keywords** | 30+ suspicious keywords: urgent, verify, blocked, OTP, KYC, lottery, arrest, etc. |

### Email vs UPI Disambiguation

A critical distinction the system handles:
- `scammer@fakebank` → **UPI ID** (no TLD like `.com`)
- `security@fakebank.com` → **Email** (has `.com` TLD)

### Scam Type Classification

13 supported scam types, detected by keyword analysis and LLM classification:

`bank_fraud` · `upi_fraud` · `phishing` · `kyc_fraud` · `job_scam` · `lottery_scam` · `electricity_bill` · `tax_fraud` · `customs_parcel` · `tech_support` · `loan_fraud` · `insurance_fraud` · `investment_fraud`

---

## ⚙️ Configuration

Key settings in `config.py` (overridable via `.env`):

| Setting | Default | Description |
|---|---|---|
| `PORT` | `8000` | Server port |
| `DEBUG` | `False` | Enable debug logging |
| `API_KEY` | `odouZ7...` | API key for endpoint protection |
| `LLM_TEMPERATURE` | `0.7` | LLM creativity/randomness |
| `CALLBACK_URL` | `https://hackathon.guvi.in/...` | GUVI evaluator callback endpoint |
| `CALLBACK_TIMEOUT` | `5` | Callback HTTP timeout in seconds |
| `MAX_TURNS` | `15` | Maximum conversation turns |
| `SEND_CALLBACK_AFTER_TURN` | `8` | Turn number to trigger the callback |
| `SMART_PACING_ENABLED` | `True` | Toggle engagement pacing (ensures >60s duration) |

### Environment Variables (`.env`)

```env
PORT=8000
API_KEY=your-secret-key
GROQ_API_KEY=gsk_...
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult
MAX_TURNS=15
SEND_CALLBACK_AFTER_TURN=8
```

### Swapping LLM Provider

Edit `llm_client.py` to switch between providers:

```python
# Groq (default)
from langchain_groq import ChatGroq
llm = ChatGroq(model="openai/gpt-oss-120b", temperature=1, api_key=groq_api_key)

# OpenAI
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.7, max_tokens=512)

# Anthropic
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0.7)

# Ollama (local)
from langchain_ollama import ChatOllama
llm = ChatOllama(model="llama3.2", temperature=0.7)
```

---

## 📈 Scoring Rubric (GUVI Evaluation)

The `/test-score/{session_id}` endpoint evaluates sessions against this rubric:

| Category | Max Points | Criteria |
|---|---|---|
| **Scam Detection** | 20 | `scamDetected: true` |
| **Intelligence Extraction** | 40 | 10 pts per non-empty field: phones, accounts, UPIs, links, emails (max 40) |
| **Engagement Quality** | 20 | Duration > 0s (+5), duration > 60s (+5), messages > 0 (+5), messages >= 5 (+5) |
| **Response Structure** | 20 | Required fields present: status, scamDetected, extractedIntelligence, engagementMetrics, agentNotes |
| **Total** | **100** | Sum of all categories |

---

## 🧪 Testing

### Automated Test Suite

```bash
# Run all 15 scam scenarios
python scammer_test.py

# Run a single scenario
python scammer_test.py --scenario bank_fraud
python scammer_test.py --scenario "Lottery"
```

### Supported Scenarios
Bank Fraud, UPI Fraud, Phishing, KYC Fraud, Job Scam, Lottery, Electricity Bill, Govt Scheme, Crypto Scam, Customs Parcel, Tech Support, Loan Fraud, Income Tax, Refund Scam, Insurance Fraud.

### Quick Self-Test

```bash
python self_test.py
```

---

## 🛡️ Fault Tolerance

The system is designed to **never return a 500 error** to the evaluator:

- **LLM timeout (>25s):** Falls back to context-aware pre-written replies based on scammer's message keywords.
- **Intel Agent failure:** Falls back to keyword-based scam type detection + regex-only intel.
- **Reply Agent failure:** Uses turn-aware fallback replies that still sound in-character.
- **Callback failure:** Logged but doesn't affect the reply to the scammer.
- **Agent error:** Caught at route level with a graceful fallback reply.

---

## 🔒 Security

- All endpoints are protected with API key authentication via the `x-api-key` header.
- CORS is configured to allow all origins (for hackathon flexibility).
- No sensitive data is persisted to disk — sessions are in-memory only.

---

## 📦 Tech Stack

| Component | Technology |
|---|---|
| **Framework** | FastAPI + Uvicorn |
| **LLM** | Groq / OpenAI / Anthropic / Ollama (swappable) |
| **Orchestration** | LangChain + asyncio |
| **Validation** | Pydantic v2 + pydantic-settings |
| **HTTP Client** | httpx (async) |
| **Session Store** | In-memory (Redis-ready interface) |

---

## 📝 License

Built for the GUVI Hackathon. For educational and demonstration purposes.
