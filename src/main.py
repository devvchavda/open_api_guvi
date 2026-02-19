"""
Honeypot Scam Detection & Intelligence Extraction API
FastAPI application entrypoint
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import router
from config import settings

app = FastAPI(
    title="Honeypot Scam Detection API",
    description="Agentic honeypot system for scam detection and intelligence extraction",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


