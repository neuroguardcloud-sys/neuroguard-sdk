"""
NeuroGuard settings API — GET/PUT settings, reset to defaults.
"""

from fastapi import APIRouter

from neuroguard.settings import Settings, load_settings, save_settings, reset_settings

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("", response_model=Settings)
def get_settings() -> Settings:
    """Return current settings (from disk or defaults)."""
    return load_settings()


@router.put("", response_model=Settings)
def update_settings(settings: Settings) -> Settings:
    """Update and persist settings."""
    save_settings(settings)
    return load_settings()


@router.post("/reset", response_model=Settings)
def reset_settings_endpoint() -> Settings:
    """Restore default settings and persist them."""
    return reset_settings()
