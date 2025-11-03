"""
IAM Copilot - FastAPI Application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog

from app.config import get_settings
from app.database import engine, Base
from app.routers import (
    policy,
    iam_management,
    identity_center,
    organizations,
    api_monitoring,
    iam_api_update_agent,
    policy_validation,
    auth
)
from app.routers import settings as settings_router

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ]
)

logger = structlog.get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events"""
    # Startup
    logger.info("application_startup", environment=settings.environment)
    # Create database tables
    Base.metadata.create_all(bind=engine)
    yield
    # Shutdown
    logger.info("application_shutdown")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="AI-Powered AWS IAM Management Platform",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
# In development, allow all origins; in production, restrict to specific origins
cors_origins = settings.get_cors_origins_list()
if settings.environment == "development" or settings.debug:
    cors_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True if cors_origins != ["*"] else False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check endpoint
@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint"""
    return JSONResponse(
        content={
            "status": "healthy",
            "service": "iam-copilot-api",
            "version": "1.0.0"
        }
    )


@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint"""
    return JSONResponse(
        content={
            "message": "IAM Copilot API",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/health"
        }
    )


# Include routers
app.include_router(auth.router)  # Auth router (has its own prefix)
app.include_router(settings_router.router)  # Settings router (has its own prefix)
app.include_router(policy.router, prefix=settings.api_v1_prefix)
app.include_router(iam_management.router, prefix=settings.api_v1_prefix)
app.include_router(identity_center.router, prefix=settings.api_v1_prefix)
app.include_router(organizations.router, prefix=settings.api_v1_prefix)
app.include_router(api_monitoring.router)
app.include_router(iam_api_update_agent.router)
app.include_router(policy_validation.router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug
    )
