"""
User Settings Router

Handles user-specific AWS and Bedrock configuration settings.
Settings are applied immediately without requiring application restart.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.user_settings import UserSettings
from app.schemas.settings import (
    UserSettingsResponse,
    UserSettingsUpdate,
    UserSettingsCreate,
    BedrockModelsResponse,
    BedrockModelOption,
)
from app.dependencies import get_current_user
import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


# ============================================================================
# Bedrock Models Reference
# ============================================================================

AVAILABLE_BEDROCK_MODELS = [
    BedrockModelOption(
        model_id="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        display_name="Claude 3.5 Sonnet v2 (US)",
        description="Most intelligent model. Best for complex tasks requiring advanced reasoning.",
        max_tokens=8192
    ),
    BedrockModelOption(
        model_id="us.anthropic.claude-3-5-sonnet-20240620-v1:0",
        display_name="Claude 3.5 Sonnet v1 (US)",
        description="Previous version of Claude 3.5 Sonnet.",
        max_tokens=8192
    ),
    BedrockModelOption(
        model_id="us.anthropic.claude-3-5-haiku-20241022-v1:0",
        display_name="Claude 3.5 Haiku (US)",
        description="Fastest and most compact model. Best for simple tasks and high-volume operations.",
        max_tokens=8192
    ),
    BedrockModelOption(
        model_id="us.anthropic.claude-3-opus-20240229-v1:0",
        display_name="Claude 3 Opus (US)",
        description="Most powerful Claude 3 model. Best for highly complex tasks.",
        max_tokens=4096
    ),
]


# ============================================================================
# Settings Endpoints
# ============================================================================

@router.get("/models", response_model=BedrockModelsResponse)
def get_available_models(
    current_user: User = Depends(get_current_user)
):
    """
    Get list of available Bedrock models.

    Returns:
        List of available Bedrock models with metadata
    """
    return BedrockModelsResponse(models=AVAILABLE_BEDROCK_MODELS)


@router.get("", response_model=UserSettingsResponse)
def get_user_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current user's settings.

    If user has no settings record, creates one with default values.

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        User settings
    """
    # Try to get existing settings
    settings = db.query(UserSettings).filter(
        UserSettings.user_id == current_user.id
    ).first()

    # Create default settings if none exist
    if not settings:
        logger.info("Creating default settings for user", user_id=current_user.id)
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
        db.commit()
        db.refresh(settings)

    return settings


@router.put("", response_model=UserSettingsResponse)
def update_user_settings(
    settings_update: UserSettingsUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user's settings.

    Settings are applied immediately. Only provided fields are updated.

    Args:
        settings_update: Fields to update
        current_user: Authenticated user
        db: Database session

    Returns:
        Updated user settings
    """
    # Get or create settings
    settings = db.query(UserSettings).filter(
        UserSettings.user_id == current_user.id
    ).first()

    if not settings:
        # Create new settings with defaults, then apply updates
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)

    # Update only provided fields
    update_data = settings_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(settings, field, value)

    db.commit()
    db.refresh(settings)

    logger.info(
        "User settings updated",
        user_id=current_user.id,
        updated_fields=list(update_data.keys())
    )

    return settings


@router.post("/reset", response_model=UserSettingsResponse)
def reset_user_settings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Reset user's settings to default values.

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        Reset user settings
    """
    # Get or create settings
    settings = db.query(UserSettings).filter(
        UserSettings.user_id == current_user.id
    ).first()

    if not settings:
        settings = UserSettings(user_id=current_user.id)
        db.add(settings)
    else:
        # Reset to defaults
        settings.bedrock_model_id = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
        settings.bedrock_max_tokens = 4096
        settings.bedrock_temperature = 0.0
        settings.default_aws_region = "us-east-1"
        settings.default_aws_output_format = "json"

    db.commit()
    db.refresh(settings)

    logger.info("User settings reset to defaults", user_id=current_user.id)

    return settings
