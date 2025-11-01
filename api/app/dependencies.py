"""
FastAPI Dependencies - Session-Based Authentication

Provides authentication via session cookies, current user, and AWS credentials injection.
"""

from fastapi import Depends, HTTPException, status, Request, Cookie
from sqlalchemy.orm import Session
from typing import Optional
import structlog

from app.database import get_db
from app.services.auth_service import AuthService
from app.models.user import User, UserAWSCredentials

logger = structlog.get_logger()


def get_current_user(
    request: Request,
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Get current authenticated user from session cookie.

    This dependency extracts the user ID from the session cookie
    and returns the authenticated user.

    Args:
        request: FastAPI request object
        user_id: User ID from session cookie
        db: Database session

    Returns:
        Authenticated user object

    Raises:
        HTTPException: If user is not authenticated or not found
    """
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please log in with Google."
        )

    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session"
        )

    # Get user from database
    user = db.query(User).filter(User.id == user_id_int).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    return user


def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current active user.

    Additional check to ensure user is active.

    Args:
        current_user: Current user from get_current_user dependency

    Returns:
        Active user object

    Raises:
        HTTPException: If user is not active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


def get_user_aws_credentials(
    credential_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> UserAWSCredentials:
    """
    Get specific AWS credentials for the current user.

    This dependency retrieves the user's AWS credentials by ID
    and verifies ownership.

    Args:
        credential_id: ID of credentials to retrieve
        current_user: Current authenticated user
        db: Database session

    Returns:
        User's AWS credentials

    Raises:
        HTTPException: If credentials not found or don't belong to user
    """
    credentials = db.query(UserAWSCredentials).filter(
        UserAWSCredentials.id == credential_id,
        UserAWSCredentials.user_id == current_user.id
    ).first()

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS credentials not found"
        )

    # Update last used timestamp
    from datetime import datetime
    credentials.last_used = datetime.utcnow()
    db.commit()

    return credentials


def get_default_aws_credentials(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> UserAWSCredentials:
    """
    Get default AWS credentials for the current user.

    This dependency retrieves the user's default AWS credentials.
    If no default is set, it returns the first available credentials.

    Args:
        current_user: Current authenticated user
        db: Database session

    Returns:
        User's default AWS credentials

    Raises:
        HTTPException: If no credentials found
    """
    # Try to get default credentials
    credentials = db.query(UserAWSCredentials).filter(
        UserAWSCredentials.user_id == current_user.id,
        UserAWSCredentials.is_default == True
    ).first()

    # If no default, get first available
    if not credentials:
        credentials = db.query(UserAWSCredentials).filter(
            UserAWSCredentials.user_id == current_user.id
        ).first()

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No AWS credentials found. Please add your AWS credentials in Settings."
        )

    # Update last used timestamp
    from datetime import datetime
    credentials.last_used = datetime.utcnow()
    db.commit()

    return credentials


def get_decrypted_aws_credentials(
    credentials: UserAWSCredentials = Depends(get_default_aws_credentials),
    db: Session = Depends(get_db)
) -> dict:
    """
    Get decrypted AWS credentials ready for boto3.

    Returns a dictionary that can be passed directly to boto3 clients.

    Args:
        credentials: User's AWS credentials (from dependency)
        db: Database session

    Returns:
        Dictionary with decrypted AWS credentials

    Example:
        credentials = get_decrypted_aws_credentials()
        s3_client = boto3.client('s3', **credentials)
    """
    auth_service = AuthService(db)
    return auth_service.decrypt_aws_credentials(credentials)


def optional_authentication(
    user_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Optional authentication for endpoints that work with or without auth.

    Returns user if authenticated, None otherwise.
    Does not raise exceptions for missing/invalid sessions.

    Args:
        user_id: User ID from session cookie (optional)
        db: Database session

    Returns:
        User object if authenticated, None otherwise
    """
    if not user_id:
        return None

    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        return None

    user = db.query(User).filter(User.id == user_id_int).first()
    return user if user and user.is_active else None
