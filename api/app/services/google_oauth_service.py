"""
Google OAuth Authentication Service

Handles Google OAuth 2.0 authentication flow for user registration and login.
"""

import os
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from google.oauth2 import id_token
from google.auth.transport import requests
from google_auth_oauthlib.flow import Flow
import structlog

from app.models.user import User, AuditLog
from app.config import get_settings

logger = structlog.get_logger()


class GoogleOAuthService:
    """
    Service for handling Google OAuth authentication.

    Provides methods for:
    - Initiating OAuth flow
    - Handling OAuth callback
    - Verifying Google ID tokens
    - Creating/updating users
    """

    def __init__(self, db: Session):
        self.db = db
        settings = get_settings()

        # Google OAuth configuration
        self.client_id = settings.google_client_id
        self.client_secret = settings.google_client_secret
        self.redirect_uri = settings.google_redirect_uri

        # OAuth scopes
        self.scopes = [
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        Generate Google OAuth authorization URL.

        Args:
            state: Optional state parameter for CSRF protection

        Returns:
            Authorization URL to redirect user to
        """
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uris": [self.redirect_uri],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state,
            prompt='consent'
        )

        logger.info("Generated Google OAuth authorization URL", state=state)
        return authorization_url

    def exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access token and user info.

        Args:
            code: Authorization code from Google OAuth callback

        Returns:
            Dictionary containing access token and user information

        Raises:
            ValueError: If code exchange fails
        """
        flow = Flow.from_client_config(
            client_config={
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uris": [self.redirect_uri],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )

        try:
            flow.fetch_token(code=code)
            credentials = flow.credentials

            # Verify the ID token
            id_info = id_token.verify_oauth2_token(
                credentials.id_token,
                requests.Request(),
                self.client_id
            )

            logger.info(
                "Successfully exchanged code for token",
                google_id=id_info.get('sub'),
                email=id_info.get('email')
            )

            return {
                "access_token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "id_token": credentials.id_token,
                "user_info": {
                    "google_id": id_info.get('sub'),
                    "email": id_info.get('email'),
                    "full_name": id_info.get('name'),
                    "avatar_url": id_info.get('picture'),
                    "email_verified": id_info.get('email_verified', False)
                }
            }
        except Exception as e:
            logger.error("Failed to exchange code for token", error=str(e))
            raise ValueError(f"Failed to authenticate with Google: {str(e)}")

    def verify_id_token(self, token: str) -> Dict[str, Any]:
        """
        Verify a Google ID token.

        Args:
            token: Google ID token to verify

        Returns:
            Decoded token payload

        Raises:
            ValueError: If token is invalid
        """
        try:
            id_info = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                self.client_id
            )

            logger.info("Successfully verified ID token", google_id=id_info.get('sub'))
            return id_info
        except Exception as e:
            logger.error("Failed to verify ID token", error=str(e))
            raise ValueError(f"Invalid ID token: {str(e)}")

    def get_or_create_user(
        self,
        google_id: str,
        email: str,
        full_name: Optional[str] = None,
        avatar_url: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> User:
        """
        Get existing user or create new user from Google OAuth data.

        Args:
            google_id: Google user ID
            email: User email from Google
            full_name: User's full name
            avatar_url: URL to user's avatar/profile picture
            ip_address: User's IP address for audit logging

        Returns:
            User object (existing or newly created)
        """
        # Check if user already exists by Google ID
        user = self.db.query(User).filter(User.google_id == google_id).first()

        if user:
            # Update existing user's information
            user.email = email
            user.full_name = full_name
            user.avatar_url = avatar_url
            user.last_login = datetime.utcnow()
            user.updated_at = datetime.utcnow()

            logger.info(
                "Updated existing user from Google OAuth",
                user_id=user.id,
                google_id=google_id,
                email=email
            )

            # Log the login action
            audit_log = AuditLog(
                user_id=user.id,
                action="google_oauth_login",
                resource_type="user",
                resource_id=str(user.id),
                ip_address=ip_address,
                success=True
            )
            self.db.add(audit_log)
        else:
            # Check if email already exists (user might have registered with different method)
            existing_user = self.db.query(User).filter(User.email == email).first()
            if existing_user:
                # Update existing user with Google ID
                existing_user.google_id = google_id
                existing_user.full_name = full_name or existing_user.full_name
                existing_user.avatar_url = avatar_url
                existing_user.is_verified = True  # Google users are pre-verified
                existing_user.last_login = datetime.utcnow()
                existing_user.updated_at = datetime.utcnow()
                user = existing_user

                logger.info(
                    "Linked Google account to existing email",
                    user_id=user.id,
                    google_id=google_id,
                    email=email
                )
            else:
                # Create new user
                user = User(
                    email=email,
                    google_id=google_id,
                    full_name=full_name,
                    avatar_url=avatar_url,
                    is_active=True,
                    is_verified=True,  # Google users are pre-verified
                    last_login=datetime.utcnow()
                )
                self.db.add(user)
                self.db.flush()  # Get the user ID

                logger.info(
                    "Created new user from Google OAuth",
                    user_id=user.id,
                    google_id=google_id,
                    email=email
                )

                # Log the registration action
                audit_log = AuditLog(
                    user_id=user.id,
                    action="google_oauth_register",
                    resource_type="user",
                    resource_id=str(user.id),
                    ip_address=ip_address,
                    success=True
                )
                self.db.add(audit_log)

        self.db.commit()
        self.db.refresh(user)
        return user

    def get_user_by_google_id(self, google_id: str) -> Optional[User]:
        """
        Get user by Google ID.

        Args:
            google_id: Google user ID

        Returns:
            User object if found, None otherwise
        """
        return self.db.query(User).filter(User.google_id == google_id).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.

        Args:
            email: User email

        Returns:
            User object if found, None otherwise
        """
        return self.db.query(User).filter(User.email == email).first()
