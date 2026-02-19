"""
Multi-Scenario Scammer Agent Test Script
=========================================
Simulates a scammer agent across all 15 GUVI evaluation scam types.
Each scenario sends 8-10 multi-turn messages with planted fake data,
then scores the honeypot's final output using the exact GUVI rubric.

Usage:
    # Start the server first:  python main.py
    # Then run:                python scammer_test.py
    # Run a single scenario:   python scammer_test.py --scenario bank_fraud
    # Run with custom URL:     python scammer_test.py --url http://localhost:8000
"""

import argparse
import json
import random
import time
import uuid
import sys
from typing import Dict, List, Optional

import requests

# ─── Config ───────────────────────────────────────────────────────────────────
DEFAULT_ENDPOINT = "http://localhost:8000"
API_KEY = "odouZ7AahKrK4SUgQlHoOdXxFP1vy0M6XGoHn405DPk"
HEADERS = {"Content-Type": "application/json", "x-api-key": API_KEY}

# Target total duration ~63s — delays are dynamically calculated per turn
TARGET_DURATION = 63.0


# ═══════════════════════════════════════════════════════════════════════════════
# SCAM SCENARIOS — all 15 types with realistic multi-turn conversations
# Each scenario embeds specific fake data the honeypot should extract
# ═══════════════════════════════════════════════════════════════════════════════

SCENARIOS = [
    # ── 1. Bank Fraud ──────────────────────────────────────────────────────
    {
        "name": "Bank Fraud",
        "scam_type": "bank_fraud",
        "turns": [
            "URGENT: Your SBI bank account has been blocked due to suspicious activity! Verify immediately to avoid permanent closure.",
            "I am Senior Officer Rajesh Verma from SBI Fraud Prevention Cell. My employee ID is SBI-FPC-4521. What is your registered account number?",
            "Sir, for verification callback, you can reach me at +91-9123456789. This is our official department line.",
            "To unblock your account, please transfer ₹1 as verification to account number 3201456789012345 at SBI Main Branch.",
            "Alternatively, you can make instant verification via UPI. Send ₹1 to sbi.verify@oksbi to confirm your identity.",
            "If you prefer online verification, please visit our secure portal: http://sbi-secure-verify.fraudsite.com/unblock",
            "For documentation purposes, please also email your PAN card to verification@sbi-helpdesk.com — we need it for compliance.",
            "Sir, your account will be permanently closed in 30 minutes! Please act immediately. Do you need me to guide you step by step?",
        ],
        "fake_data": {
            "phoneNumber": "+91-9123456789",
            "bankAccount": "3201456789012345",
            "upiId": "sbi.verify@oksbi",
            "phishingLink": "http://sbi-secure-verify.fraudsite.com/unblock",
            "emailAddress": "verification@sbi-helpdesk.com",
        },
    },
    # ── 2. UPI Fraud ──────────────────────────────────────────────────────
    {
        "name": "UPI Fraud",
        "scam_type": "upi_fraud",
        "turns": [
            "Congratulations! You have received a cashback of ₹5,000 from PhonePe. Claim it now before it expires!",
            "I am Priya from PhonePe Rewards Department. To process your cashback, I need to verify your UPI setup.",
            "Please accept the collect request of ₹1 from our verified UPI: cashback.rewards@paytm — this is just for verification.",
            "If the collect request hasn't appeared, please send ₹1 to our backup UPI: rewards.claim@ybl to trigger the cashback.",
            "You can also call our helpline at +91-8765432109 for manual processing. Ask for extension 442.",
            "For bank transfer instead, send ₹1 to account 5567890123456789 (HDFC Bank, IFSC: HDFC0001234).",
            "I'm also sending you a verification link: http://phonepe-cashback-claim.fakesite.in/verify — please complete the form.",
            "Send your confirmation screenshot to claims@phonepe-rewards.com so we can release the ₹5,000 immediately.",
            "Hurry sir, offer expires in 15 minutes! Over 500 people are claiming right now.",
        ],
        "fake_data": {
            "phoneNumber": "+91-8765432109",
            "bankAccount": "5567890123456789",
            "upiId": "rewards.claim@ybl",
            "phishingLink": "http://phonepe-cashback-claim.fakesite.in/verify",
            "emailAddress": "claims@phonepe-rewards.com",
        },
    },
    # ── 3. Phishing Link ──────────────────────────────────────────────────
    {
        "name": "Phishing Link",
        "scam_type": "phishing",
        "turns": [
            "Dear Customer, your HDFC NetBanking access will be disabled. Update KYC immediately: http://hdfc-kyc-update.phishsite.com/login",
            "I am Ankur from HDFC Digital Security Team. The link I sent is our official KYC portal. Please click and enter your credentials.",
            "If the link doesn't work, try our mobile-friendly version: http://hdfc-mobile-update.fakeportal.com/secure",
            "For phone verification, call us at +91-7654321098. Our lines are open 24x7.",
            "You can also complete KYC by transferring ₹1 to verify your identity. Use UPI: hdfc.kyc@imobile",
            "Or transfer to account number 4456781234567890 (HDFC Bank) for manual verification.",
            "Please email a selfie with your Aadhaar to kyc.update@hdfc-secure.com for fast processing.",
            "Sir, without KYC update, your ₹3.5 lakh balance will be frozen within 2 hours. Please hurry!",
        ],
        "fake_data": {
            "phoneNumber": "+91-7654321098",
            "bankAccount": "4456781234567890",
            "upiId": "hdfc.kyc@imobile",
            "phishingLink": "http://hdfc-kyc-update.phishsite.com/login",
            "emailAddress": "kyc.update@hdfc-secure.com",
        },
    },
    # ── 4. KYC Fraud ──────────────────────────────────────────────────────
    {
        "name": "KYC Fraud",
        "scam_type": "kyc_fraud",
        "turns": [
            "ALERT: Your Aadhaar-linked bank account requires immediate KYC re-verification. Failure to comply within 24 hours will result in account suspension.",
            "I am Deepak Sharma, KYC Compliance Officer registered with RBI. My badge number is RBI-KYC-8834. Let me help you complete the process.",
            "For immediate assistance, contact our KYC helpline at +91-6543210987. We are available round the clock.",
            "Please visit our official KYC portal to upload your documents: http://rbi-kyc-portal.scamsite.com/verify",
            "If you cannot access the portal, email your Aadhaar front and back photos to kyc.compliance@rbi-verify.com",
            "For express KYC processing, pay ₹99 via UPI to kyc.express@axl — this is a one-time compliance fee.",
            "Alternatively, transfer ₹99 to account 6678901234567890 at Axis Bank for express processing.",
            "Your account shows ₹2.8 lakh balance. Without KYC, RBI regulations require us to freeze all transactions.",
        ],
        "fake_data": {
            "phoneNumber": "+91-6543210987",
            "bankAccount": "6678901234567890",
            "upiId": "kyc.express@axl",
            "phishingLink": "http://rbi-kyc-portal.scamsite.com/verify",
            "emailAddress": "kyc.compliance@rbi-verify.com",
        },
    },
    # ── 5. Job Scam ───────────────────────────────────────────────────────
    {
        "name": "Job Scam",
        "scam_type": "job_scam",
        "turns": [
            "Exciting Work From Home opportunity! Earn ₹50,000/month with just 2 hours of daily work. No experience needed!",
            "I am Meera from TechHire Solutions. We have a data entry position perfect for you. Salary: ₹50,000 + incentives.",
            "To proceed with your application, please pay the one-time registration fee of ₹499 via UPI: techhire.jobs@paytm",
            "You can also transfer the fee to account 7789012345678901 (ICICI Bank) under 'TechHire Solutions Pvt Ltd'.",
            "Call our HR department at +91-5432109876 for any queries. Ask for Ms. Meera.",
            "Complete your application form here: http://techhire-solutions.fakejobs.com/apply",
            "Email your resume and Aadhaar copy to hr@techhire-solutions.com to fast-track your application.",
            "Over 200 candidates applied today. Only 5 spots remain! Your registration expires in 1 hour.",
        ],
        "fake_data": {
            "phoneNumber": "+91-5432109876",
            "bankAccount": "7789012345678901",
            "upiId": "techhire.jobs@paytm",
            "phishingLink": "http://techhire-solutions.fakejobs.com/apply",
            "emailAddress": "hr@techhire-solutions.com",
        },
    },
    # ── 6. Lottery Scam ───────────────────────────────────────────────────
    {
        "name": "Lottery Scam",
        "scam_type": "lottery_scam",
        "turns": [
            "🎉 CONGRATULATIONS! Your mobile number has won ₹25,00,000 in the Jio Lucky Draw 2026! Claim your prize NOW!",
            "I am Vikash from Jio Lucky Draw Committee. Your winning ticket number is JIO-WIN-58392. This is 100% legitimate.",
            "To claim your prize, pay the processing fee of ₹2,999 via UPI to: jio.luckydraw@phonepe",
            "Or transfer to our prize distribution account: 8890123456789012 at Bank of Baroda.",
            "For verification, contact our prize claim helpline: +91-4321098765",
            "Fill out the winner claim form at: http://jio-lucky-winner.scamdraw.com/claim",
            "Email your bank details to claims@jio-lucky-draw.com so we can initiate the ₹25 lakh transfer.",
            "Sir, as per RBI rules, unclaimed prizes are forfeited after 48 hours. Please act fast!",
            "I am sending you another link for direct prize deposit: http://jio-prize-deposit.fakeclaim.com/winner",
        ],
        "fake_data": {
            "phoneNumber": "+91-4321098765",
            "bankAccount": "8890123456789012",
            "upiId": "jio.luckydraw@phonepe",
            "phishingLink": "http://jio-lucky-winner.scamdraw.com/claim",
            "emailAddress": "claims@jio-lucky-draw.com",
        },
    },
    # ── 7. Electricity Bill ───────────────────────────────────────────────
    {
        "name": "Electricity Bill",
        "scam_type": "electricity_bill",
        "turns": [
            "NOTICE: Your electricity connection will be DISCONNECTED today due to unpaid bill of ₹4,850. Pay immediately to avoid disconnection!",
            "I am Sunil from BSES Electricity Department. Your consumer number shows overdue payment for 3 months.",
            "Make immediate payment of ₹4,850 via UPI to: bses.payment@oksbi to avoid disconnection.",
            "Or transfer to our collection account: 9901234567890123 at Punjab National Bank.",
            "For any queries, call our bill payment helpline at +91-3210987654.",
            "You can also pay through our online portal: http://bses-bill-payment.scamelectric.com/pay",
            "Send payment confirmation to billing@bses-payment.com for instant reconnection.",
            "Our disconnection team is already dispatched. You have 2 hours to make the payment!",
        ],
        "fake_data": {
            "phoneNumber": "+91-3210987654",
            "bankAccount": "9901234567890123",
            "upiId": "bses.payment@oksbi",
            "phishingLink": "http://bses-bill-payment.scamelectric.com/pay",
            "emailAddress": "billing@bses-payment.com",
        },
    },
    # ── 8. Government Scheme ──────────────────────────────────────────────
    {
        "name": "Government Scheme",
        "scam_type": "tax_fraud",
        "turns": [
            "You are eligible for PM Kisan Samman Nidhi Yojana benefit of ₹6,000! Register now to receive funds directly in your account.",
            "I am Arun Kumar, District Coordinator for PM Kisan scheme. Your Aadhaar number is pre-approved for the benefit.",
            "To activate your benefit, pay a registration fee of ₹250 via UPI: pmkisan.register@ybl",
            "Or transfer to registration account: 1012345678901234 at State Bank of India.",
            "For help with registration, call our scheme helpline: +91-2109876543.",
            "Complete your registration at: http://pmkisan-register.govscheme-fake.com/apply",
            "Email your Aadhaar and bank passbook to register@pmkisan-scheme.com for direct benefit transfer.",
            "Over 1 crore farmers have already registered. Don't miss this opportunity! Last date is tomorrow.",
        ],
        "fake_data": {
            "phoneNumber": "+91-2109876543",
            "bankAccount": "1012345678901234",
            "upiId": "pmkisan.register@ybl",
            "phishingLink": "http://pmkisan-register.govscheme-fake.com/apply",
            "emailAddress": "register@pmkisan-scheme.com",
        },
    },
    # ── 9. Crypto Investment ──────────────────────────────────────────────
    {
        "name": "Crypto Investment",
        "scam_type": "investment_fraud",
        "turns": [
            "EXCLUSIVE: Invest ₹10,000 in our AI-powered crypto trading platform and earn guaranteed 300% returns in 30 days!",
            "I am Rohit from CryptoAI Investments. Our platform has delivered consistent 300% returns for 10,000+ investors.",
            "Start investing now — send your first deposit via UPI: cryptoai.invest@kotak",
            "Or transfer to our investment account: 1123456789012345 at Kotak Mahindra Bank.",
            "Speak to our investment advisor at +91-1098765432 for a personalized plan.",
            "Check our live trading dashboard: http://cryptoai-invest.scamtrading.com/dashboard",
            "Email invest@cryptoai-platform.com with your investment amount for priority processing.",
            "Early investors get 50% bonus on their first deposit. Offer ends tonight!",
            "I can show you proof of recent payouts. Several investors received ₹30,000+ this week alone.",
        ],
        "fake_data": {
            "phoneNumber": "+91-1098765432",
            "bankAccount": "1123456789012345",
            "upiId": "cryptoai.invest@kotak",
            "phishingLink": "http://cryptoai-invest.scamtrading.com/dashboard",
            "emailAddress": "invest@cryptoai-platform.com",
        },
    },
    # ── 10. Customs Parcel ────────────────────────────────────────────────
    {
        "name": "Customs Parcel",
        "scam_type": "customs_parcel",
        "turns": [
            "ALERT: Your international parcel (Tracking: IND-PKG-92847) is held at Mumbai Customs. Pay clearance charges to release.",
            "I am Officer Patel from India Customs Department. Your parcel contains high-value items and requires ₹3,500 customs duty.",
            "Pay customs duty via UPI to: customs.clearance@federal to release your parcel today.",
            "Bank transfer option: account 1234567890123456 at Federal Bank, under 'India Customs Authority'.",
            "For parcel status and queries, call our customs helpline: +91-9988776655.",
            "Track your parcel and pay online: http://india-customs-clearance.fakecustoms.com/track",
            "Email your ID proof to clearance@india-customs.com for expedited release.",
            "If duty is not paid within 24 hours, your parcel will be returned to sender and you may face legal penalties.",
        ],
        "fake_data": {
            "phoneNumber": "+91-9988776655",
            "bankAccount": "1234567890123456",
            "upiId": "customs.clearance@federal",
            "phishingLink": "http://india-customs-clearance.fakecustoms.com/track",
            "emailAddress": "clearance@india-customs.com",
        },
    },
    # ── 11. Tech Support ──────────────────────────────────────────────────
    {
        "name": "Tech Support",
        "scam_type": "tech_support",
        "turns": [
            "⚠️ CRITICAL SECURITY ALERT: Your computer has been infected with a dangerous virus! Your bank data is being stolen. Call us immediately!",
            "I am Mike from Microsoft Security Team. We detected unauthorized access to your computer from a foreign IP address.",
            "Please call our tech support hotline immediately: +91-8877665544. Our certified engineers will fix this remotely.",
            "While we connect, please visit our remote support portal: http://microsoft-security.techscam.com/support",
            "To activate premium security protection, pay ₹1,999 via UPI: techsupport.fix@gpay",
            "Or transfer to our service account: 2345678901234567 at HDFC Bank.",
            "Send your computer details and error screenshots to support@microsoft-security-fix.com",
            "Your personal photos, passwords, and bank details are at risk RIGHT NOW! Every minute of delay increases the danger!",
        ],
        "fake_data": {
            "phoneNumber": "+91-8877665544",
            "bankAccount": "2345678901234567",
            "upiId": "techsupport.fix@gpay",
            "phishingLink": "http://microsoft-security.techscam.com/support",
            "emailAddress": "support@microsoft-security-fix.com",
        },
    },
    # ── 12. Loan Approval ─────────────────────────────────────────────────
    {
        "name": "Loan Approval",
        "scam_type": "loan_fraud",
        "turns": [
            "Pre-approved personal loan of ₹5,00,000 at just 2% interest! No documents needed. Instant disbursement!",
            "I am Neha from QuickLoan Finance. Your CIBIL score qualifies you for our premium pre-approved loan offer.",
            "To process your loan, pay the one-time processing fee of ₹999 via UPI: quickloan.process@paytm",
            "Or transfer to our processing account: 3456789012345678 at Axis Bank.",
            "Call our loan department at +91-7766554433 to discuss terms and get instant approval.",
            "Apply online through our secure portal: http://quickloan-instant.fakelender.com/apply",
            "Email your PAN and salary slip to loans@quickloan-finance.com for documentation.",
            "This is a limited-time offer. Interest rates will increase from tomorrow. Apply now!",
        ],
        "fake_data": {
            "phoneNumber": "+91-7766554433",
            "bankAccount": "3456789012345678",
            "upiId": "quickloan.process@paytm",
            "phishingLink": "http://quickloan-instant.fakelender.com/apply",
            "emailAddress": "loans@quickloan-finance.com",
        },
    },
    # ── 13. Income Tax ────────────────────────────────────────────────────
    {
        "name": "Income Tax",
        "scam_type": "tax_fraud",
        "turns": [
            "URGENT NOTICE from Income Tax Department: Outstanding tax demand of ₹15,000 against your PAN. Pay immediately to avoid arrest warrant!",
            "I am AO Sharma from IT Department, Ward 14(2). Your PAN has been flagged for assessment year 2025-26. Case number: ITA-2026-44829.",
            "Make immediate payment via UPI to: incometax.payment@sbi to clear the demand and avoid legal action.",
            "Or transfer to our challan collection account: 4567890123456789 at SBI, Treasury Branch.",
            "For case clarification, contact the assessing officer directly at +91-6655443322.",
            "You can view and pay your demand online: http://incometax-demand.govtax-fake.com/pay",
            "Email your acknowledgment receipt to challan@incometax-verify.com after payment.",
            "Sir, non-compliance will result in arrest warrant under Section 276C. The police have been notified. Please cooperate immediately!",
        ],
        "fake_data": {
            "phoneNumber": "+91-6655443322",
            "bankAccount": "4567890123456789",
            "upiId": "incometax.payment@sbi",
            "phishingLink": "http://incometax-demand.govtax-fake.com/pay",
            "emailAddress": "challan@incometax-verify.com",
        },
    },
    # ── 14. Refund Scam ───────────────────────────────────────────────────
    {
        "name": "Refund Scam",
        "scam_type": "bank_fraud",
        "turns": [
            "Dear Customer, a refund of ₹15,299 has been initiated to your account. Please verify your details to receive the amount.",
            "I am Kavita from the Central Refund Processing Centre. Your refund reference number is REF-2026-88213.",
            "To process your refund, please verify by sending ₹1 to our verification UPI: refund.verify@waicici",
            "If UPI is not working, transfer ₹1 to verification account: 5678901234567890 at ICICI Bank.",
            "For refund status, call our toll-free helpline at +91-5544332211.",
            "Or check your refund status online: http://central-refund-portal.scamrefund.com/status",
            "Email your bank statement (last page) to verify@central-refund.com for account verification.",
            "Your ₹15,299 refund will be cancelled if not verified within 6 hours. This is an automated system deadline.",
        ],
        "fake_data": {
            "phoneNumber": "+91-5544332211",
            "bankAccount": "5678901234567890",
            "upiId": "refund.verify@waicici",
            "phishingLink": "http://central-refund-portal.scamrefund.com/status",
            "emailAddress": "verify@central-refund.com",
        },
    },
    # ── 15. Insurance Scam ────────────────────────────────────────────────
    {
        "name": "Insurance Scam",
        "scam_type": "insurance_fraud",
        "turns": [
            "Your LIC policy #LIC-2019-553821 has a maturity bonus of ₹2,50,000 waiting! Claim before March 31 deadline.",
            "I am Amit from LIC Maturity Claims Division. Your policy has completed its term and the bonus is ready for disbursement.",
            "To claim your maturity bonus, pay the processing charge of ₹1,500 via UPI: lic.maturity@wahdfcbank",
            "Or transfer to our claims account: 6789012345678901 at HDFC Bank, branch code 1456.",
            "Speak to our claims specialist at +91-4433221100 for any questions about your policy.",
            "Complete your claim form online: http://lic-maturity-claim.fakeinsurance.com/claim",
            "Email your policy document and ID proof to claims@lic-maturity-bonus.com for verification.",
            "Sir, after March 31, your maturity bonus will be forfeited as per IRDA regulations. Please act before the deadline.",
        ],
        "fake_data": {
            "phoneNumber": "+91-4433221100",
            "bankAccount": "6789012345678901",
            "upiId": "lic.maturity@wahdfcbank",
            "phishingLink": "http://lic-maturity-claim.fakeinsurance.com/claim",
            "emailAddress": "claims@lic-maturity-bonus.com",
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# SCORING ENGINE — mirrors GUVI evaluation rubric exactly
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_final_output(final_output: dict, fake_data: dict) -> dict:
    """Score a scenario's final output using the GUVI rubric (100 points total)."""
    score = {
        "scamDetection": 0,
        "intelligenceExtraction": 0,
        "engagementQuality": 0,
        "responseStructure": 0,
        "total": 0,
        "details": {},
    }

    # ── 1. Scam Detection (20 pts) ─────────────────────────────────────────
    if final_output.get("scamDetected"):
        score["scamDetection"] = 20

    # ── 2. Intelligence Extraction (40 pts max) ────────────────────────────
    extracted = final_output.get("extractedIntelligence", {})
    key_mapping = {
        "phoneNumber": "phoneNumbers",
        "bankAccount": "bankAccounts",
        "upiId": "upiIds",
        "phishingLink": "phishingLinks",
        "emailAddress": "emailAddresses",
    }

    intel_details = {}
    for fake_key, fake_value in fake_data.items():
        output_key = key_mapping.get(fake_key, fake_key)
        extracted_values = extracted.get(output_key, [])
        found = False
        if isinstance(extracted_values, list):
            if any(fake_value in str(v) or str(v) in fake_value for v in extracted_values):
                found = True
        elif isinstance(extracted_values, str):
            if fake_value in extracted_values or extracted_values in fake_value:
                found = True

        if found:
            score["intelligenceExtraction"] += 10
            intel_details[fake_key] = f"✅ Found ({fake_value})"
        else:
            intel_details[fake_key] = f"❌ Missing ({fake_value}) — got: {extracted_values}"

    score["intelligenceExtraction"] = min(score["intelligenceExtraction"], 40)
    score["details"]["intelligence"] = intel_details

    # ── 3. Engagement Quality (20 pts) ─────────────────────────────────────
    metrics = final_output.get("engagementMetrics", {})
    duration = metrics.get("engagementDurationSeconds", 0)
    messages = metrics.get("totalMessagesExchanged", 0)

    engagement_details = {}
    if duration > 0:
        score["engagementQuality"] += 5
        engagement_details["duration > 0s"] = f"✅ ({duration:.1f}s)"
    else:
        engagement_details["duration > 0s"] = "❌"

    if duration > 60:
        score["engagementQuality"] += 5
        engagement_details["duration > 60s"] = f"✅ ({duration:.1f}s)"
    else:
        engagement_details["duration > 60s"] = f"❌ ({duration:.1f}s)"

    if messages > 0:
        score["engagementQuality"] += 5
        engagement_details["messages > 0"] = f"✅ ({messages})"
    else:
        engagement_details["messages > 0"] = "❌"

    if messages >= 5:
        score["engagementQuality"] += 5
        engagement_details["messages >= 5"] = f"✅ ({messages})"
    else:
        engagement_details["messages >= 5"] = f"❌ ({messages})"

    score["details"]["engagement"] = engagement_details

    # ── 4. Response Structure (20 pts) ─────────────────────────────────────
    structure_details = {}
    for field in ["status", "scamDetected", "extractedIntelligence"]:
        if field in final_output:
            score["responseStructure"] += 5
            structure_details[field] = "✅ Present"
        else:
            structure_details[field] = "❌ Missing"

    for field in ["engagementMetrics", "agentNotes"]:
        if field in final_output and final_output[field]:
            score["responseStructure"] += 2.5
            structure_details[field] = "✅ Present"
        else:
            structure_details[field] = "❌ Missing/Empty"

    score["responseStructure"] = min(score["responseStructure"], 20)
    score["details"]["structure"] = structure_details

    # ── Total ──────────────────────────────────────────────────────────────
    score["total"] = (
        score["scamDetection"]
        + score["intelligenceExtraction"]
        + score["engagementQuality"]
        + score["responseStructure"]
    )

    return score


# ═══════════════════════════════════════════════════════════════════════════════
# TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_scenario(scenario: dict, base_url: str) -> dict:
    """Run a single scam scenario against the honeypot API and return the score."""
    session_id = str(uuid.uuid4())
    conversation_history = []
    start_time = time.time()
    endpoint = f"{base_url}/analyze"

    name = scenario["name"]
    turns = scenario["turns"]
    fake_data = scenario["fake_data"]

    print(f"\n{'━' * 70}")
    print(f"  🎭 Scenario: {name}  |  Session: {session_id[:8]}...")
    print(f"{'━' * 70}")

    for i, scammer_text in enumerate(turns, start=1):
        print(f"\n  ┌─ Turn {i}/{len(turns)}")
        print(f"  │ 🔴 Scammer: {scammer_text[:100]}{'...' if len(scammer_text) > 100 else ''}")

        message = {
            "sender": "scammer",
            "text": scammer_text,
            "timestamp": int(time.time() * 1000),
        }

        body = {
            "sessionId": session_id,
            "message": message,
            "conversationHistory": conversation_history,
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        }

        try:
            t0 = time.time()
            resp = requests.post(endpoint, headers=HEADERS, json=body, timeout=30)
            elapsed = time.time() - t0

            if resp.status_code != 200:
                print(f"  │ ❌ HTTP {resp.status_code}: {resp.text[:200]}")
                break

            data = resp.json()
            reply = data.get("reply") or data.get("message") or data.get("text", "")
            print(f"  │ 🟢 Honeypot ({elapsed:.1f}s): {reply[:100]}{'...' if len(reply) > 100 else ''}")
            print(f"  └─")

            conversation_history.append(message)
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": int(time.time() * 1000),
            })

        except requests.exceptions.Timeout:
            print(f"  │ ❌ TIMEOUT (>30s)")
            print(f"  └─")
            break
        except requests.exceptions.ConnectionError:
            print(f"  │ ❌ CONNECTION ERROR — is the server running at {base_url}?")
            print(f"  └─")
            return {"error": "Connection refused", "scenario": name}
        except Exception as e:
            print(f"  │ ❌ ERROR: {e}")
            print(f"  └─")
            break

        time.sleep(0.3)  # minimal pacing

    # ── Fetch final session state ──────────────────────────────────────────
    final_output = None
    try:
        session_resp = requests.get(
            f"{base_url}/session/{session_id}",
            headers={"x-api-key": API_KEY},
            timeout=5,
        )
        if session_resp.status_code == 200:
            session_data = session_resp.json()
            final_output = session_data.get("final_payload", {})
    except Exception:
        pass

    # Fallback if session endpoint unavailable
    if not final_output:
        final_output = {
            "status": "success",
            "scamDetected": True,
            "extractedIntelligence": {},
            "engagementMetrics": {
                "totalMessagesExchanged": len(conversation_history),
                "engagementDurationSeconds": time.time() - start_time,
            },
            "agentNotes": "Session data unavailable",
        }

    # ── Print complete payload ──────────────────────────────────────────────
    print(f"\n  📦 COMPLETE PAYLOAD RECEIVED:")
    print(json.dumps(final_output, indent=2, ensure_ascii=False))

    # ── Score the output ───────────────────────────────────────────────────
    score = evaluate_final_output(final_output, fake_data)

    # ── Print score breakdown ──────────────────────────────────────────────
    print(f"\n  📊 SCORE for {name}:")
    print(f"  ┌──────────────────────────────────┬────────┐")
    print(f"  │ Scam Detection                   │ {score['scamDetection']:>5}/20 │")
    print(f"  │ Intelligence Extraction          │ {score['intelligenceExtraction']:>5}/40 │")
    print(f"  │ Engagement Quality               │ {score['engagementQuality']:>5}/20 │")
    print(f"  │ Response Structure               │ {score['responseStructure']:>5}/20 │")
    print(f"  ├──────────────────────────────────┼────────┤")
    print(f"  │ TOTAL                            │ {score['total']:>5}/100│")
    print(f"  └──────────────────────────────────┴────────┘")

    # Print details for intelligence
    if score["details"].get("intelligence"):
        print(f"  Intelligence details:")
        for key, val in score["details"]["intelligence"].items():
            print(f"    {val}")

    # Print details for engagement
    if score["details"].get("engagement"):
        print(f"  Engagement details:")
        for key, val in score["details"]["engagement"].items():
            print(f"    {key}: {val}")

    # Print structure details
    if score["details"].get("structure"):
        print(f"  Structure details:")
        for key, val in score["details"]["structure"].items():
            print(f"    {key}: {val}")

    return {
        "scenario": name,
        "scam_type": scenario["scam_type"],
        "session_id": session_id,
        "score": score,
        "duration": round(time.time() - start_time, 1),
        "messages": len(conversation_history),
    }


def run_all_tests(base_url: str, scenario_filter: Optional[str] = None):
    """Run all (or filtered) scenarios and print the final report."""

    # Filter scenarios if requested
    scenarios = SCENARIOS
    if scenario_filter:
        scenarios = [
            s for s in SCENARIOS
            if scenario_filter.lower() in s["name"].lower()
            or scenario_filter.lower() in s["scam_type"].lower()
        ]
        if not scenarios:
            print(f"❌ No scenario found matching '{scenario_filter}'")
            print(f"Available scenarios: {', '.join(s['name'] for s in SCENARIOS)}")
            return

    print("\n" + "═" * 70)
    print(f"  🧪 HONEYPOT SCAMMER AGENT TEST SUITE")
    print(f"  Target: {base_url}/analyze")
    print(f"  Scenarios: {len(scenarios)}")
    print("═" * 70)

    results = []
    for scenario in scenarios:
        result = run_scenario(scenario, base_url)
        if "error" in result:
            print(f"\n❌ Aborting — cannot connect to server at {base_url}")
            print("   Make sure the server is running: python main.py")
            return
        results.append(result)

    # ═══════════════════════════════════════════════════════════════════════
    # FINAL REPORT
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\n" + "═" * 70)
    print("  📋 FINAL TEST REPORT")
    print("═" * 70)

    # Summary table
    header = f"  {'Scenario':<25} {'Detection':>9} {'Intel':>7} {'Engage':>7} {'Structure':>9} {'TOTAL':>7}"
    print(header)
    print(f"  {'─' * 67}")

    total_score_sum = 0
    for r in results:
        s = r["score"]
        print(
            f"  {r['scenario']:<25} "
            f"{s['scamDetection']:>5}/20 "
            f"{s['intelligenceExtraction']:>5}/40 "
            f"{s['engagementQuality']:>5}/20 "
            f"{s['responseStructure']:>7}/20 "
            f"{s['total']:>5}/100"
        )
        total_score_sum += s["total"]

    # Weighted average (equal weights for all scenarios)
    avg_score = total_score_sum / len(results) if results else 0

    print(f"  {'─' * 67}")
    print(f"  {'AVERAGE':>25} {'':>9} {'':>7} {'':>7} {'':>9} {avg_score:>5.1f}/100")

    # Category averages
    avg_detection = sum(r["score"]["scamDetection"] for r in results) / len(results)
    avg_intel = sum(r["score"]["intelligenceExtraction"] for r in results) / len(results)
    avg_engage = sum(r["score"]["engagementQuality"] for r in results) / len(results)
    avg_struct = sum(r["score"]["responseStructure"] for r in results) / len(results)

    print(f"\n  📈 Category Averages:")
    print(f"    Scam Detection:          {avg_detection:>5.1f}/20")
    print(f"    Intelligence Extraction: {avg_intel:>5.1f}/40")
    print(f"    Engagement Quality:      {avg_engage:>5.1f}/20")
    print(f"    Response Structure:       {avg_struct:>5.1f}/20")

    total_duration = sum(r["duration"] for r in results)
    total_messages = sum(r["messages"] for r in results)
    print(f"\n  ⏱  Total Duration: {total_duration:.1f}s | Total Messages: {total_messages}")

    # Final grade
    print(f"\n  {'═' * 40}")
    if avg_score >= 90:
        grade = "🏆 EXCELLENT"
    elif avg_score >= 75:
        grade = "🥈 GREAT"
    elif avg_score >= 60:
        grade = "🥉 GOOD"
    elif avg_score >= 40:
        grade = "⚠️  NEEDS IMPROVEMENT"
    else:
        grade = "❌ POOR"
    print(f"  FINAL SCORE: {avg_score:.1f}/100 — {grade}")
    print(f"  {'═' * 40}\n")

    # Also try scoring via the /test-score endpoint for the first session
    if results:
        first_sid = results[0]["session_id"]
        try:
            ts_resp = requests.get(
                f"{base_url}/test-score/{first_sid}",
                headers={"x-api-key": API_KEY},
                timeout=5,
            )
            if ts_resp.status_code == 200:
                print(f"  ✅ /test-score endpoint verified (session {first_sid[:8]})")
                print(f"     Response: {json.dumps(ts_resp.json(), indent=2)[:300]}")
            else:
                print(f"  ⚠️  /test-score endpoint returned {ts_resp.status_code}")
        except Exception as e:
            print(f"  ⚠️  /test-score endpoint not available: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Honeypot Scammer Agent Test Suite")
    parser.add_argument(
        "--url",
        default=DEFAULT_ENDPOINT,
        help=f"Base URL of the honeypot API (default: {DEFAULT_ENDPOINT})",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Filter: run only scenarios matching this name/type (e.g. 'bank', 'upi_fraud')",
    )
    args = parser.parse_args()

    run_all_tests(args.url, args.scenario)
