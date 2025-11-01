"""
Authentication Router - Google OAuth

Handles user authentication via Google OAuth and AWS credentials management.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User, UserAWSCredentials
from app.schemas.auth import (
    UserResponse,
    AWSCredentialsCreate,
    AWSCredentialsResponse,
    AWSCredentialsUpdate,
    GoogleAuthResponse,
    GoogleTokenRequest
)
from app.services.google_oauth_service import GoogleOAuthService
from app.services.auth_service import AuthService
from app.dependencies import get_current_user, get_user_aws_credentials
from app.config import get_settings
import structlog

logger = structlog.get_logger()
settings = get_settings()

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


# ============================================================================
# Google OAuth Endpoints
# ============================================================================

@router.get("/google/login")
def google_login(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Initiate Google OAuth login flow.

    Redirects user to Google's OAuth consent screen.

    Returns:
        Redirect to Google OAuth authorization URL
    """
    google_service = GoogleOAuthService(db)

    # Generate authorization URL
    authorization_url = google_service.get_authorization_url()

    logger.info("Initiating Google OAuth login")

    return RedirectResponse(url=authorization_url)


@router.get("/google/callback")
def google_callback(
    code: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Handle Google OAuth callback.

    Exchanges authorization code for tokens and creates/updates user.

    Args:
        code: Authorization code from Google
        request: FastAPI request object
        response: FastAPI response object
        db: Database session

    Returns:
        User information and authentication status
    """
    google_service = GoogleOAuthService(db)

    try:
        # Exchange code for token and get user info
        token_data = google_service.exchange_code_for_token(code)
        user_info = token_data["user_info"]

        # Get client IP for audit logging
        client_ip = request.client.host if request.client else None

        # Get or create user
        user = google_service.get_or_create_user(
            google_id=user_info["google_id"],
            email=user_info["email"],
            full_name=user_info.get("full_name"),
            avatar_url=user_info.get("avatar_url"),
            ip_address=client_ip
        )

        # Store user ID in session (using cookies)
        cookie_params = {
            "key": "user_id",
            "value": str(user.id),
            "httponly": True,
            "secure": True,  # HTTPS only
            "samesite": "lax",
            "max_age": 30 * 24 * 60 * 60  # 30 days
        }
        if settings.cookie_domain:
            cookie_params["domain"] = settings.cookie_domain
        response.set_cookie(**cookie_params)

        logger.info(
            "Google OAuth callback successful",
            user_id=user.id,
            email=user.email
        )

        # Redirect to frontend with success
        frontend_url = request.headers.get("referer", "/")
        return RedirectResponse(url=f"{frontend_url}?auth=success")

    except ValueError as e:
        logger.error("Google OAuth callback failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error("Unexpected error in Google OAuth callback", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/google/verify")
def verify_google_token(
    token_request: GoogleTokenRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
) -> GoogleAuthResponse:
    """
    Verify Google ID token and authenticate user.

    This endpoint can be used for client-side Google Sign-In.

    Args:
        token_request: Request containing Google ID token
        request: FastAPI request object
        response: FastAPI response object
        db: Database session

    Returns:
        User information
    """
    google_service = GoogleOAuthService(db)

    try:
        # Verify ID token
        id_info = google_service.verify_id_token(token_request.id_token)

        # Get client IP for audit logging
        client_ip = request.client.host if request.client else None

        # Get or create user
        user = google_service.get_or_create_user(
            google_id=id_info.get('sub'),
            email=id_info.get('email'),
            full_name=id_info.get('name'),
            avatar_url=id_info.get('picture'),
            ip_address=client_ip
        )

        # Store user ID in session
        cookie_params = {
            "key": "user_id",
            "value": str(user.id),
            "httponly": True,
            "secure": True,
            "samesite": "lax",
            "max_age": 30 * 24 * 60 * 60  # 30 days
        }
        if settings.cookie_domain:
            cookie_params["domain"] = settings.cookie_domain
        response.set_cookie(**cookie_params)

        logger.info(
            "Google ID token verification successful",
            user_id=user.id,
            email=user.email
        )

        return GoogleAuthResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            created_at=user.created_at,
            last_login=user.last_login
        )

    except ValueError as e:
        logger.error("Google ID token verification failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    except Exception as e:
        logger.error("Unexpected error in token verification", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/logout")
def logout(response: Response):
    """
    Logout user by clearing session cookie.

    Returns:
        Success message
    """
    delete_params = {"key": "user_id"}
    if settings.cookie_domain:
        delete_params["domain"] = settings.cookie_domain
    response.delete_cookie(**delete_params)
    logger.info("User logged out")
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Get current authenticated user information.

    Returns:
        Current user details
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at,
        last_login=current_user.last_login
    )


# ============================================================================
# AWS Credentials Management Endpoints
# ============================================================================

@router.post("/aws-credentials", response_model=AWSCredentialsResponse)
def add_aws_credentials(
    credentials_data: AWSCredentialsCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Add AWS credentials for the authenticated user.

    Credentials are encrypted before storage.

    Args:
        credentials_data: AWS credential information
        current_user: Authenticated user
        db: Database session

    Returns:
        Created credentials information (without sensitive data)
    """
    auth_service = AuthService(db)

    try:
        credentials = auth_service.add_aws_credentials(
            user_id=current_user.id,
            label=credentials_data.label,
            access_key_id=credentials_data.access_key_id,
            secret_access_key=credentials_data.secret_access_key,
            session_token=credentials_data.session_token,
            aws_region=credentials_data.aws_region,
            aws_account_id=credentials_data.aws_account_id,
            is_default=credentials_data.is_default,
            cross_account_role_arn=credentials_data.cross_account_role_arn
        )

        logger.info(
            "AWS credentials added",
            user_id=current_user.id,
            credential_id=credentials.id,
            label=credentials.label
        )

        return AWSCredentialsResponse(
            id=credentials.id,
            user_id=credentials.user_id,
            label=credentials.label,
            aws_region=credentials.aws_region,
            aws_account_id=credentials.aws_account_id,
            is_default=credentials.is_default,
            created_at=credentials.created_at,
            updated_at=credentials.updated_at,
            last_used=credentials.last_used,
            cross_account_role_arn=credentials.cross_account_role_arn
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/aws-credentials", response_model=List[AWSCredentialsResponse])
def list_aws_credentials(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all AWS credentials for the authenticated user.

    Returns:
        List of user's AWS credential sets (without sensitive data)
    """
    credentials_list = db.query(UserAWSCredentials).filter(
        UserAWSCredentials.user_id == current_user.id
    ).all()

    logger.info(
        "Listed AWS credentials",
        user_id=current_user.id,
        count=len(credentials_list)
    )

    return [
        AWSCredentialsResponse(
            id=cred.id,
            user_id=cred.user_id,
            label=cred.label,
            aws_region=cred.aws_region,
            aws_account_id=cred.aws_account_id,
            is_default=cred.is_default,
            created_at=cred.created_at,
            updated_at=cred.updated_at,
            last_used=cred.last_used,
            cross_account_role_arn=cred.cross_account_role_arn
        )
        for cred in credentials_list
    ]


@router.get("/aws-credentials/{credential_id}", response_model=AWSCredentialsResponse)
def get_aws_credentials(
    credential_id: int,
    credentials: UserAWSCredentials = Depends(get_user_aws_credentials)
):
    """
    Get specific AWS credentials by ID.

    Args:
        credential_id: ID of the credentials to retrieve
        credentials: Retrieved credentials (from dependency)

    Returns:
        Credentials information (without sensitive data)
    """
    return AWSCredentialsResponse(
        id=credentials.id,
        user_id=credentials.user_id,
        label=credentials.label,
        aws_region=credentials.aws_region,
        aws_account_id=credentials.aws_account_id,
        is_default=credentials.is_default,
        created_at=credentials.created_at,
        updated_at=credentials.updated_at,
        last_used=credentials.last_used,
        cross_account_role_arn=credentials.cross_account_role_arn
    )


@router.put("/aws-credentials/{credential_id}", response_model=AWSCredentialsResponse)
def update_aws_credentials(
    credential_id: int,
    update_data: AWSCredentialsUpdate,
    credentials: UserAWSCredentials = Depends(get_user_aws_credentials),
    db: Session = Depends(get_db)
):
    """
    Update AWS credentials.

    Args:
        credential_id: ID of the credentials to update
        update_data: Updated credential information
        credentials: Retrieved credentials (from dependency)
        db: Database session

    Returns:
        Updated credentials information
    """
    auth_service = AuthService(db)

    try:
        updated_credentials = auth_service.update_aws_credentials(
            credentials=credentials,
            label=update_data.label,
            access_key_id=update_data.access_key_id,
            secret_access_key=update_data.secret_access_key,
            session_token=update_data.session_token,
            aws_region=update_data.aws_region,
            aws_account_id=update_data.aws_account_id,
            is_default=update_data.is_default,
            cross_account_role_arn=update_data.cross_account_role_arn
        )

        logger.info(
            "AWS credentials updated",
            credential_id=credential_id,
            label=updated_credentials.label
        )

        return AWSCredentialsResponse(
            id=updated_credentials.id,
            user_id=updated_credentials.user_id,
            label=updated_credentials.label,
            aws_region=updated_credentials.aws_region,
            aws_account_id=updated_credentials.aws_account_id,
            is_default=updated_credentials.is_default,
            created_at=updated_credentials.created_at,
            updated_at=updated_credentials.updated_at,
            last_used=updated_credentials.last_used,
            cross_account_role_arn=updated_credentials.cross_account_role_arn
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/aws-credentials/{credential_id}")
def delete_aws_credentials(
    credential_id: int,
    credentials: UserAWSCredentials = Depends(get_user_aws_credentials),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete AWS credentials.

    Args:
        credential_id: ID of the credentials to delete
        credentials: Retrieved credentials (from dependency)
        current_user: Authenticated user
        db: Database session

    Returns:
        Success message
    """
    db.delete(credentials)
    db.commit()

    logger.info(
        "AWS credentials deleted",
        user_id=current_user.id,
        credential_id=credential_id
    )

    return {"message": "AWS credentials deleted successfully"}


@router.post("/aws-credentials/{credential_id}/set-default")
def set_default_aws_credentials(
    credential_id: int,
    credentials: UserAWSCredentials = Depends(get_user_aws_credentials),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Set AWS credentials as default.

    Only one credential set can be default per user.

    Args:
        credential_id: ID of the credentials to set as default
        credentials: Retrieved credentials (from dependency)
        current_user: Authenticated user
        db: Database session

    Returns:
        Success message
    """
    # Unset all other default credentials for this user
    db.query(UserAWSCredentials).filter(
        UserAWSCredentials.user_id == current_user.id,
        UserAWSCredentials.is_default == True
    ).update({"is_default": False})

    # Set this credential as default
    credentials.is_default = True
    db.commit()

    logger.info(
        "AWS credentials set as default",
        user_id=current_user.id,
        credential_id=credential_id
    )

    return {"message": f"Credentials '{credentials.label}' set as default"}
