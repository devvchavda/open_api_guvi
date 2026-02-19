"""
Configuration management - change LLM, ports, keys in ONE place.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Server
    PORT: int = 8000
    DEBUG: bool = False
    API_KEY: str = "odouZ7AahKrK4SUgQlHoOdXxFP1vy0M6XGoHn405DPk"

    # LLM Configuration — change model here only
    LLM_TEMPERATURE: float = 0.7

    # Callback
    CALLBACK_URL: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    CALLBACK_TIMEOUT: int = 5

    # Honeypot strategy
    MAX_TURNS: int = 15
    SEND_CALLBACK_AFTER_TURN: int = 8  # GUVI evaluator sends ~10 turns; fire at 8 to ensure delivery
    SMART_PACING_ENABLED: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
