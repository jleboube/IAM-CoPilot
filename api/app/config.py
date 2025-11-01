"""
Application configuration management
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""

    # Application
    app_name: str = "IAM Copilot"
    environment: str = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # Database
    database_url: str = "postgresql://admin:devpassword@localhost:5432/iam_copilot"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # AWS Configuration
    aws_region: str = "us-east-1"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None

    # Bedrock
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    bedrock_max_tokens: int = 4096
    bedrock_temperature: float = 0.0

    # Security (for AWS credentials encryption)
    secret_key: str = "change-me-in-production"

    # Cookie domain for session management (e.g., ".iam-copilot.com" for production, None for localhost)
    cookie_domain: str | None = None

    # Google OAuth
    google_client_id: str | None = None
    google_client_secret: str | None = None
    google_redirect_uri: str | None = None

    # Rate Limiting
    rate_limit_per_second: int = 5

    # CORS - comma-separated string
    cors_origins: str = "http://localhost:3000,http://localhost:8000"

    def get_cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string to list"""
        return [origin.strip() for origin in self.cors_origins.split(',')]

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
