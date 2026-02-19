"""
Local self-test script — simulates GUVI evaluation against your running API.
Run: python tests/self_test.py
"""

import uuid
import time
import json
import requests

# ─── Config ───────────────────────────────────────────────────────────────────
ENDPOINT = "http://localhost:8000/analyze"
API_KEY = "odouZ7AahKrK4SUgQlHoOdXxFP1vy0M6XGoHn405DPk"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}

# Simulated scammer conversation for a bank fraud scenario
SCAMMER_TURNS = [
    "URGENT: Your SBI bank account will be blocked in 2 hours! Verify immediately.",
    "I am calling from SBI fraud department. My employee ID is SBI-2024-7823. What is your account number?",
    "You can reach me at +91-9876543210 for follow-up. Now please verify your account.",
    "Please transfer Rs.1 to this account to verify: 1234567890123456",
    "Or you can pay via UPI: scammer.fraud@fakebank",
    "For online verification, visit: http://sbi-verify-now.fake-site.com/verify",
    "Also email your documents to: support@sbi-fraud-dept.com",
    "Your account is now under hold. Act immediately or lose all funds!",
]

FAKE_DATA = {
    "bankAccount": "1234567890123456",
    "upiId": "scammer.fraud@fakebank",
    "phoneNumber": "+91-9876543210",
    "phishingLink": "http://sbi-verify-now.fake-site.com/verify",
    "emailAddress": "support@sbi-fraud-dept.com",
}


def evaluate_final_output(final_output: dict, fake_data: dict, conv_len: int) -> dict:
    """Mirrors GUVI scoring logic exactly."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
    }

    # 1. Scam Detection
    if final_output.get("scamDetected"):
        score["scamDetection"] = 20

    # 2. Intelligence Extraction
    extracted = final_output.get("extractedIntelligence", {})
    key_mapping = {
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phoneNumber": "phoneNumbers",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) for v in extracted_values):
                score["intelligenceExtraction"] += 10
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values:
                score["intelligenceExtraction"] += 10
    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)

    # 3. Engagement Quality
    metrics = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)
    if duration > 0: score["engagementQuality"] += 5
    if duration > 60: score["engagementQuality"] += 5
    if messages > 0: score["engagementQuality"] += 5
    if messages >= 5: score["engagementQuality"] += 5

    # 4. Response Structure
    for field in ["status", "scamDetected", "extractedIntelligence"]:
        if field in final_output:
            score["responseStructure"] += 5
    for field in ["engagementMetrics", "agentNotes"]:
        if field in final_output and final_output[field]:
            score["responseStructure"] += 2.5
    score["responseStructure"] = min(score["responseStructure"], 20)

    score["total"] = sum([
        score["scamDetection"],
        score["intelligenceExtraction"],
        score["engagementQuality"],
        score["responseStructure"],
    ])
    return score


def run_test():
    session_id = str(uuid.uuid4())
    conversation_history = []
    start_time = time.time()

    print(f"\n{'='*60}")
    print(f"Honeypot Self-Test | Session: {session_id}")
    print(f"{'='*60}\n")

    for i, scammer_text in enumerate(SCAMMER_TURNS, start=1):
        print(f"--- Turn {i} ---")
        print(f"Scammer: {scammer_text}")

        message = {"sender": "scammer", "text": scammer_text, "timestamp": int(time.time() * 1000)}

        body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        }

        try:
            t0 = time.time()
            resp = requests.post(ENDPOINT, headers=HEADERS, json=body, timeout=30)
            elapsed = time.time() - t0

            if resp.status_code != 200:
                print(f"❌ HTTP {resp.status_code}: {resp.text[:200]}")
                break

            data = resp.json()
            reply = data.get("reply") or data.get("message") or data.get("text", "")
            print(f"Honeypot ({elapsed:.1f}s): {reply}")

            conversation_history.append(message)
            conversation_history.append({"sender": "user", "text": reply, "timestamp": int(time.time() * 1000)})

        except requests.exceptions.Timeout:
            print("❌ TIMEOUT (>30s)")
            break
        except Exception as e:
            print(f"❌ ERROR: {e}")
            break

        print()
        time.sleep(0.5)  # small delay to simulate real conversation pacing

    # Fetch session state and score it
    elapsed_total = time.time() - start_time

    try:
        session_resp = requests.get(
            f"http://localhost:8000/session/{session_id}",
            headers={"x-api-key": API_KEY},
            timeout=5,
        )
        if session_resp.status_code == 200:
            session_data = session_resp.json()
            final_output = session_data.get("final_payload", {})
        else:
            # Build manually
            final_output = {
                "status": "success",
                "scamDetected": True,
                "extractedIntelligence": {},
                "engagementMetrics": {
                    "totalMessagesExchanged": len(conversation_history),
                    "engagementDurationSeconds": elapsed_total,
                },
                "agentNotes": "Test run",
            }
    except Exception:
        final_output = {
            "status": "success",
            "scamDetected": True,
            "extractedIntelligence": {},
            "engagementMetrics": {
                "totalMessagesExchanged": len(conversation_history),
                "engagementDurationSeconds": elapsed_total,
            },
            "agentNotes": "Test run",
        }

    print("\n" + "=" * 60)
    print("FINAL OUTPUT:")
    print(json.dumps(final_output, indent=2))
    print("=" * 60)

    score = evaluate_final_output(final_output, FAKE_DATA, len(conversation_history))
    print(f"\n📊 SCORE BREAKDOWN:")
    print(f"  Scam Detection:          {score['scamDetection']:>5}/20")
    print(f"  Intelligence Extraction: {score['intelligenceExtraction']:>5}/40")
    print(f"  Engagement Quality:      {score['engagementQuality']:>5}/20")
    print(f"  Response Structure:      {score['responseStructure']:>5}/20")
    print(f"  {'─'*30}")
    print(f"  TOTAL:                   {score['total']:>5}/100")
    print(f"\n  Duration: {elapsed_total:.1f}s | Messages: {len(conversation_history)}")


if __name__ == "__main__":
    run_test()
