"""
Configuration for worker (shared with API)
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""

    # Database
    database_url: str = "postgresql://admin:devpassword@db:5432/iam_copilot"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # AWS Configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None

    # Bedrock
    bedrock_model_id: str = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"
    bedrock_max_tokens: int = 4096
    bedrock_temperature: float = 0.0

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
