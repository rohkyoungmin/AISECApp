from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class ClaudeSettings:
    api_key: str | None
    model: str
    max_tokens: int
    temperature: float

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)


def load_dotenv_if_available() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv()


def load_claude_settings() -> ClaudeSettings:
    load_dotenv_if_available()
    return ClaudeSettings(
        api_key=_optional_env("ANTHROPIC_API_KEY"),
        model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
        max_tokens=_int_env("ANTHROPIC_MAX_TOKENS", 4096),
        temperature=_float_env("ANTHROPIC_TEMPERATURE", 0.0),
    )


def require_llm_by_default() -> bool:
    load_dotenv_if_available()
    return os.getenv("AISEC_REQUIRE_LLM", "true").lower() in {"1", "true", "yes", "on"}


def _optional_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return int(value)


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return float(value)
