# Multi-Tenant Migration Guide

## Overview

IAM Copilot has been transformed from a single-tenant application to a **multi-tenant SaaS platform** where:

- ✅ Users register and login with email/password
- ✅ Each user stores their own AWS credentials (encrypted at rest)
- ✅ All AWS operations use the authenticated user's credentials
- ✅ Complete isolation between users
- ✅ Audit logging of all user actions

## Architecture Changes

### Before (Single-Tenant)
```
.env file → AWS credentials → Shared by all users
```

### After (Multi-Tenant)
```
User Login → JWT Token → User's Encrypted AWS Credentials → AWS APIs
```

## What's New

### 1. User Authentication System
- **Email/password registration** with strong password requirements
- **JWT tokens** for stateless authentication (access + refresh tokens)
- **Secure password hashing** using bcrypt
- **Session management** with refresh tokens (30-day validity)

### 2. Encrypted AWS Credentials Storage
- **Per-user AWS credentials** encrypted using Fernet (symmetric encryption)
- **Multiple credential sets** per user (e.g., "Production", "Development")
- **Default credentials** selection
- **Audit trail** of credential usage

### 3. New Database Models

**Users Table:**
- email, hashed_password, full_name
- is_active, is_verified
- created_at, last_login

**User AWS Credentials Table:**
- encrypted_access_key_id
- encrypted_secret_access_key
- encrypted_session_token (optional)
- aws_region, aws_account_id
- is_default flag

**Refresh Tokens Table:**
- token, expires_at, revoked
- user_agent, ip_address (for security)

**Audit Logs Table:**
- user_id, action, resource_type
- aws_account_id, aws_region
- success, error_message, ip_address

## API Changes

### New Authentication Endpoints

```bash
POST /api/v1/auth/register          # Register new user
POST /api/v1/auth/login             # Login and get JWT tokens
POST /api/v1/auth/refresh           # Refresh access token
POST /api/v1/auth/logout            # Logout (revoke refresh token)
GET  /api/v1/auth/me                # Get current user profile
PATCH /api/v1/auth/me               # Update user profile
POST /api/v1/auth/me/change-password # Change password

# AWS Credentials Management
POST   /api/v1/auth/aws-credentials      # Add AWS credentials
GET    /api/v1/auth/aws-credentials      # List all credential sets
DELETE /api/v1/auth/aws-credentials/{id} # Delete credentials

# Audit Log
GET  /api/v1/auth/audit-log         # View user's audit log
```

### Protected Endpoints

**All existing endpoints now require authentication:**

```python
# Example: Policy generation now requires authentication
@router.post("/generate")
async def generate_policy(
    request: GeneratePolicyRequest,
    current_user: User = Depends(get_current_user),  # ← New
    aws_creds = Depends(get_decrypted_aws_credentials),  # ← New
    db: Session = Depends(get_db)
):
    # Use aws_creds instead of environment variables
    # Use current_user.id to associate resources with user
    ...
```

## Migration Steps

### Step 1: Update Environment Variables

Remove AWS credentials from `.env` (they're now per-user):

```bash
# .env - REMOVE THESE:
# AWS_ACCESS_KEY_ID=...
# AWS_SECRET_ACCESS_KEY=...

# KEEP THESE for Bedrock access (used by backend for AI):
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_REGION=us-east-1
```

### Step 2: Run Database Migration

```bash
# Generate migration for new tables
docker compose exec api alembic revision --autogenerate -m "add multi-tenant auth tables"

# Apply migration
docker compose exec api alembic upgrade head
```

### Step 3: Update main.py

Add auth router to your FastAPI app:

```python
# api/app/main.py
from app.routers import (
    policy,
    iam_management,
    identity_center,
    organizations,
    api_monitoring,
    iam_api_update_agent,
    policy_validation,
    auth  # ← Add this
)

# Include auth router
app.include_router(auth.router)
```

### Step 4: Update Existing Services

**Example: Updating IAM Service to use per-user credentials**

**Before:**
```python
# api/app/services/iam_service.py
class IAMService:
    def __init__(self, aws_account_id: str = None):
        # Uses environment variables
        self.iam_client = boto3.client('iam')
```

**After:**
```python
# api/app/services/iam_service.py
class IAMService:
    def __init__(self, aws_credentials: dict, aws_account_id: str = None):
        # Uses user-specific credentials
        self.iam_client = boto3.client('iam', **aws_credentials)
        self.aws_account_id = aws_account_id
```

**Update router to inject user credentials:**

```python
# api/app/routers/iam_management.py
from app.dependencies import get_current_user, get_decrypted_aws_credentials

@router.post("/users")
def create_user(
    request: CreateUserRequest,
    current_user: User = Depends(get_current_user),  # ← Add auth
    aws_creds = Depends(get_decrypted_aws_credentials),  # ← Add creds
    db: Session = Depends(get_db)
):
    # Pass credentials to service
    iam_service = IAMService(aws_credentials=aws_creds)
    result = iam_service.create_user(request.username)

    # Associate with user
    # ... save to database with user_id=current_user.id

    return result
```

### Step 5: Update Database Models

Add `user_id` foreign key to existing models:

```python
# api/app/models/policy.py
class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # ← Add this
    # ... other fields

    user = relationship("User", back_populates="policies")  # ← Add this
```

### Step 6: Update Frontend

**Add Authentication Context:**

```tsx
// web/src/contexts/AuthContext.tsx
import React, { createContext, useState, useContext, useEffect } from 'react';

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(
    localStorage.getItem('access_token')
  );

  const login = async (email: string, password: string) => {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();
    setToken(data.access_token);
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);

    // Fetch user profile
    await fetchUserProfile();
  };

  const fetchUserProfile = async () => {
    const response = await fetch('/api/v1/auth/me', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const userData = await response.json();
    setUser(userData);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, register, logout, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
```

**Add Protected Route Component:**

```tsx
// web/src/components/ProtectedRoute.tsx
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};
```

**Update API Client to include JWT:**

```tsx
// web/src/services/api.ts
const getAuthHeaders = () => {
  const token = localStorage.getItem('access_token');
  return token ? { 'Authorization': `Bearer ${token}` } : {};
};

export const apiClient = {
  async request(endpoint: string, options: RequestInit = {}) {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders(),
        ...options.headers,
      },
    });

    // Handle 401 - try refresh token
    if (response.status === 401) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry request
        return this.request(endpoint, options);
      }
      // Redirect to login
      window.location.href = '/login';
    }

    return response.json();
  }
};
```

## User Flow

### 1. New User Registration

```bash
# User registers
POST /api/v1/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123",
  "full_name": "John Doe"
}

# Response: User created
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "is_active": true,
  "created_at": "2025-11-01T10:00:00"
}
```

### 2. Login

```bash
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123"
}

# Response: JWT tokens
{
  "access_token": "eyJ0eXAi...",
  "refresh_token": "dGhpc2lz...",
  "token_type": "bearer",
  "expires_in": 900
}
```

### 3. Add AWS Credentials

```bash
POST /api/v1/auth/aws-credentials
Authorization: Bearer eyJ0eXAi...

{
  "label": "Production AWS",
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "aws_region": "us-east-1",
  "aws_account_id": "123456789012",
  "is_default": true
}

# Response: Credentials added (encrypted at rest)
{
  "id": 1,
  "label": "Production AWS",
  "aws_region": "us-east-1",
  "aws_account_id": "123456789012",
  "is_default": true,
  "access_key_id_preview": "AKIA..."
}
```

### 4. Use IAM Copilot Features

All existing features now work with user's own AWS account:

```bash
# Generate policy (uses user's AWS credentials automatically)
POST /api/v1/policies/generate
Authorization: Bearer eyJ0eXAi...

{
  "description": "Allow Lambda to read S3",
  "resource_arns": ["arn:aws:s3:::my-bucket/*"]
}
```

## Security Features

### 1. Encryption at Rest
- AWS credentials encrypted using Fernet (AES-128)
- Encryption key derived from `SECRET_KEY` in .env
- **IMPORTANT:** Generate a strong SECRET_KEY and never commit it

```bash
# Generate secure key
openssl rand -hex 32

# Add to .env
SECRET_KEY=your_generated_key_here
```

### 2. Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- Hashed using bcrypt (cost factor 12)

### 3. JWT Security
- Access tokens: 15 minutes expiry
- Refresh tokens: 30 days expiry
- Tokens include user ID and email
- Refresh tokens can be revoked

### 4. Audit Logging
- All user actions logged
- AWS operations tracked
- IP address and user agent recorded
- Success/failure status

## Frontend Pages to Create

### 1. Login Page (`/login`)
- Email/password form
- "Forgot password?" link
- "Register" link

### 2. Registration Page (`/register`)
- Email, password, full name fields
- Password strength indicator
- Terms acceptance checkbox

### 3. Settings Page (`/settings`)
**AWS Credentials Tab:**
- List of credential sets
- Add new credentials button
- Set default, edit, delete actions

**Profile Tab:**
- Update full name
- Change email
- Change password

**Audit Log Tab:**
- Recent actions
- AWS operations history
- Filterable by date/action

### 4. Dashboard Updates
- Show user's name/email
- Logout button
- "No AWS credentials" banner if not configured

## Testing the Migration

### 1. Create Test User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123",
    "full_name": "Test User"
  }'
```

### 2. Login

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123"
  }'

# Save the access_token from response
```

### 3. Add AWS Credentials

```bash
curl -X POST http://localhost:8000/api/v1/auth/aws-credentials \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "label": "My AWS Account",
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_region": "us-east-1",
    "is_default": true
  }'
```

### 4. Test Protected Endpoint

```bash
curl -X GET http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Environment Variables

```bash
# .env

# Authentication (REQUIRED)
SECRET_KEY=your-secure-random-key-from-openssl-rand-hex-32
ACCESS_TOKEN_EXPIRE_MINUTES=15

# Remove these (now per-user):
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

# Keep for Bedrock AI (backend service account):
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# Database, Redis, etc. (unchanged)
DATABASE_URL=postgresql://admin:password@db:5432/iam_copilot
REDIS_URL=redis://redis:6379/0
```

## Deployment Checklist

- [ ] Generate secure `SECRET_KEY` (never use default)
- [ ] Run database migrations
- [ ] Update main.py to include auth router
- [ ] Update all existing endpoints to require authentication
- [ ] Update all services to accept user AWS credentials
- [ ] Build and deploy frontend with auth pages
- [ ] Test user registration flow
- [ ] Test AWS credentials encryption/decryption
- [ ] Verify audit logging works
- [ ] Set up monitoring for auth failures
- [ ] Configure rate limiting on auth endpoints

## Summary

This migration transforms IAM Copilot into a true SaaS platform where:

✅ **Users control their own data** - Each user's AWS credentials are isolated and encrypted
✅ **Secure by default** - Strong password requirements, JWT tokens, bcrypt hashing
✅ **Audit trail** - Complete logging of all user actions
✅ **Scalable** - Can support unlimited users on one deployment
✅ **Production-ready** - Follows security best practices for multi-tenant SaaS

Users can now safely use IAM Copilot with their own AWS accounts without sharing credentials!
