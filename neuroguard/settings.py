"""
NeuroGuard settings — persisted to ~/.neuroguard/settings.json (or env override).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

DEFAULT_DIR = Path.home() / ".neuroguard"
SETTINGS_FILENAME = "settings.json"


def _settings_path() -> Path:
    env_path = os.environ.get("NEUROGUARD_SETTINGS_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_DIR / SETTINGS_FILENAME


class Settings(BaseModel):
    """NeuroGuard runtime settings (MVP)."""

    vault_backend: Literal["in_memory", "file"] = Field(
        default="in_memory",
        description="Backend for vault storage: in_memory or file",
    )
    ledger_path: str = Field(
        default="",
        description="Path to consent ledger file; empty uses default ~/.neuroguard/consent_ledger.jsonl",
    )
    vault_store_path: str = Field(
        default="",
        description="Path for file vault store; empty uses package default",
    )
    strict_mode: bool = Field(
        default=False,
        description="When True, enforce stricter validation and fail fast on consent/audit errors",
    )
    telemetry_enabled: bool = Field(
        default=False,
        description="When True, allow optional anonymous usage/error telemetry",
    )


def _default_settings() -> Settings:
    return Settings(
        vault_backend="in_memory",
        ledger_path="",
        vault_store_path="",
        strict_mode=False,
        telemetry_enabled=False,
    )


def load_settings() -> Settings:
    """Load settings from disk or return defaults."""
    path = _settings_path()
    if not path.exists():
        return _default_settings()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Settings(**data)
    except Exception:
        return _default_settings()


def save_settings(settings: Settings) -> None:
    """Persist settings to disk."""
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(settings.model_dump_json(indent=2), encoding="utf-8")


def reset_settings() -> Settings:
    """Restore default settings and persist them."""
    settings = _default_settings()
    save_settings(settings)
    return settings
