"""
Authentication Service - Google OAuth

Handles secure AWS credential encryption/decryption.
"""

from datetime import datetime
from typing import Optional
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session
import structlog
import hashlib
import os

from app.models.user import UserAWSCredentials
from app.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# AWS credentials encryption
# In production, use environment variable or secrets manager
ENCRYPTION_KEY = os.getenv('AWS_CREDENTIALS_ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # Generate from SECRET_KEY if not provided
    # This ensures the same key is used across restarts
    if hasattr(settings, 'secret_key') and settings.secret_key:
        ENCRYPTION_KEY = hashlib.sha256(settings.secret_key.encode()).digest()
    else:
        # Fallback for development - this should never be used in production
        ENCRYPTION_KEY = hashlib.sha256(b'development-key-change-in-production').digest()

# Create Fernet cipher from the key (needs to be base64 encoded)
import base64
cipher_suite = Fernet(base64.urlsafe_b64encode(ENCRYPTION_KEY))


class AuthService:
    """Authentication service for AWS credential security."""

    def __init__(self, db: Session):
        """Initialize auth service with database session."""
        self.db = db

    # ==================
    # AWS Credentials Encryption
    # ==================

    @staticmethod
    def encrypt_credential(value: str) -> str:
        """
        Encrypt a credential string.

        Args:
            value: The credential value to encrypt

        Returns:
            Encrypted credential as a string
        """
        return cipher_suite.encrypt(value.encode()).decode()

    @staticmethod
    def decrypt_credential(encrypted_value: str) -> str:
        """
        Decrypt a credential string.

        Args:
            encrypted_value: The encrypted credential

        Returns:
            Decrypted credential value
        """
        return cipher_suite.decrypt(encrypted_value.encode()).decode()

    # ==================
    # AWS Credentials Management
    # ==================

    def add_aws_credentials(
        self,
        user_id: int,
        label: str,
        access_key_id: str,
        secret_access_key: str,
        session_token: Optional[str] = None,
        aws_region: str = "us-east-1",
        aws_account_id: Optional[str] = None,
        is_default: bool = False,
        cross_account_role_arn: Optional[str] = None
    ) -> UserAWSCredentials:
        """
        Add encrypted AWS credentials for a user.

        Args:
            user_id: User ID
            label: Label for this credential set
            access_key_id: AWS access key ID
            secret_access_key: AWS secret access key
            session_token: Optional session token for temporary credentials
            aws_region: AWS region (default: us-east-1)
            aws_account_id: Optional AWS account ID
            is_default: Whether this is the default credential set
            cross_account_role_arn: Optional cross-account role ARN

        Returns:
            Created UserAWSCredentials object

        Raises:
            ValueError: If label already exists for this user
        """
        # Check if label already exists for this user
        existing = self.db.query(UserAWSCredentials).filter(
            UserAWSCredentials.user_id == user_id,
            UserAWSCredentials.label == label
        ).first()

        if existing:
            raise ValueError(f"Credentials with label '{label}' already exist")

        # If setting as default, unset other defaults
        if is_default:
            self.db.query(UserAWSCredentials).filter(
                UserAWSCredentials.user_id == user_id,
                UserAWSCredentials.is_default == True
            ).update({"is_default": False})

        # Encrypt the credentials
        encrypted_access_key = self.encrypt_credential(access_key_id)
        encrypted_secret_key = self.encrypt_credential(secret_access_key)
        encrypted_session_token = None
        if session_token:
            encrypted_session_token = self.encrypt_credential(session_token)

        # Create new credentials
        credentials = UserAWSCredentials(
            user_id=user_id,
            label=label,
            encrypted_access_key_id=encrypted_access_key,
            encrypted_secret_access_key=encrypted_secret_key,
            encrypted_session_token=encrypted_session_token,
            aws_region=aws_region,
            aws_account_id=aws_account_id,
            is_default=is_default,
            cross_account_role_arn=cross_account_role_arn
        )

        self.db.add(credentials)
        self.db.commit()
        self.db.refresh(credentials)

        logger.info(
            "AWS credentials added",
            user_id=user_id,
            credential_id=credentials.id,
            label=label
        )

        return credentials

    def get_user_aws_credentials(
        self,
        user_id: int,
        credential_id: Optional[int] = None
    ) -> Optional[UserAWSCredentials]:
        """
        Get AWS credentials for a user.

        Args:
            user_id: User ID
            credential_id: Optional specific credential ID. If None, returns default.

        Returns:
            UserAWSCredentials object or None
        """
        if credential_id:
            return self.db.query(UserAWSCredentials).filter(
                UserAWSCredentials.id == credential_id,
                UserAWSCredentials.user_id == user_id
            ).first()
        else:
            # Get default credentials
            credentials = self.db.query(UserAWSCredentials).filter(
                UserAWSCredentials.user_id == user_id,
                UserAWSCredentials.is_default == True
            ).first()

            # If no default, get first available
            if not credentials:
                credentials = self.db.query(UserAWSCredentials).filter(
                    UserAWSCredentials.user_id == user_id
                ).first()

            return credentials

    def list_user_credentials(self, user_id: int) -> list[UserAWSCredentials]:
        """
        List all AWS credentials for a user.

        Args:
            user_id: User ID

        Returns:
            List of UserAWSCredentials objects
        """
        return self.db.query(UserAWSCredentials).filter(
            UserAWSCredentials.user_id == user_id
        ).all()

    def decrypt_aws_credentials(
        self,
        credentials: UserAWSCredentials
    ) -> dict:
        """
        Decrypt AWS credentials for use with boto3.

        Args:
            credentials: UserAWSCredentials object

        Returns:
            Dictionary with decrypted credentials
        """
        decrypted = {
            "aws_access_key_id": self.decrypt_credential(credentials.encrypted_access_key_id),
            "aws_secret_access_key": self.decrypt_credential(credentials.encrypted_secret_access_key),
            "region_name": credentials.aws_region
        }

        if credentials.encrypted_session_token:
            decrypted["aws_session_token"] = self.decrypt_credential(
                credentials.encrypted_session_token
            )

        return decrypted

    def update_aws_credentials(
        self,
        credentials: UserAWSCredentials,
        label: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        session_token: Optional[str] = None,
        aws_region: Optional[str] = None,
        aws_account_id: Optional[str] = None,
        is_default: Optional[bool] = None,
        cross_account_role_arn: Optional[str] = None
    ) -> UserAWSCredentials:
        """
        Update AWS credentials.

        Args:
            credentials: UserAWSCredentials object to update
            label: Optional new label
            access_key_id: Optional new access key ID
            secret_access_key: Optional new secret access key
            session_token: Optional new session token
            aws_region: Optional new region
            aws_account_id: Optional new account ID
            is_default: Optional new default status
            cross_account_role_arn: Optional new cross-account role ARN

        Returns:
            Updated UserAWSCredentials object
        """
        if label is not None:
            credentials.label = label

        if access_key_id is not None:
            credentials.encrypted_access_key_id = self.encrypt_credential(access_key_id)

        if secret_access_key is not None:
            credentials.encrypted_secret_access_key = self.encrypt_credential(secret_access_key)

        if session_token is not None:
            credentials.encrypted_session_token = self.encrypt_credential(session_token)

        if aws_region is not None:
            credentials.aws_region = aws_region

        if aws_account_id is not None:
            credentials.aws_account_id = aws_account_id

        if cross_account_role_arn is not None:
            credentials.cross_account_role_arn = cross_account_role_arn

        if is_default is not None and is_default:
            # Unset other defaults
            self.db.query(UserAWSCredentials).filter(
                UserAWSCredentials.user_id == credentials.user_id,
                UserAWSCredentials.is_default == True
            ).update({"is_default": False})
            credentials.is_default = True

        credentials.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(credentials)

        logger.info(
            "AWS credentials updated",
            credential_id=credentials.id,
            label=credentials.label
        )

        return credentials

    def delete_aws_credentials(
        self,
        user_id: int,
        credential_id: int
    ) -> bool:
        """
        Delete AWS credentials.

        Args:
            user_id: User ID (for verification)
            credential_id: Credential ID to delete

        Returns:
            True if deleted, False if not found
        """
        credentials = self.db.query(UserAWSCredentials).filter(
            UserAWSCredentials.id == credential_id,
            UserAWSCredentials.user_id == user_id
        ).first()

        if not credentials:
            return False

        self.db.delete(credentials)
        self.db.commit()

        logger.info(
            "AWS credentials deleted",
            user_id=user_id,
            credential_id=credential_id
        )

        return True
