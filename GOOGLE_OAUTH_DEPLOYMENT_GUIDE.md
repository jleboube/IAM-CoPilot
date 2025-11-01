# Google OAuth Deployment Guide

This guide will walk you through deploying the Google OAuth authentication system for IAM Copilot.

## Overview

The authentication system has been completely refactored to use Google OAuth instead of email/password authentication. Key changes:

- **User Registration/Login**: Users sign in with their Google account
- **Session-Based Authentication**: Uses secure HTTP-only cookies instead of JWT tokens
- **AWS Credentials**: Users can still add multiple AWS credential sets (encrypted at rest)
- **No Password Management**: No passwords to remember or reset

## Prerequisites

Before deploying, you'll need:
1. A Google Cloud Platform (GCP) project
2. OAuth 2.0 credentials configured
3. Access to your remote server

---

## Part 1: Set Up Google OAuth Credentials

### Step 1: Create GCP Project (if you don't have one)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a Project" → "New Project"
3. Enter project name (e.g., "IAM Copilot")
4. Click "Create"

### Step 2: Enable Google+ API

1. In your GCP project, go to **APIs & Services** → **Library**
2. Search for "Google+ API"
3. Click on it and click "Enable"

### Step 3: Configure OAuth Consent Screen

1. Go to **APIs & Services** → **OAuth consent screen**
2. Select **External** user type (unless you have Google Workspace)
3. Click "Create"

4. Fill in the required fields:
   - **App name**: IAM Copilot
   - **User support email**: Your email
   - **Developer contact email**: Your email
   - **Authorized domains**: Add your domain (e.g., `iam-copilot.com`)

5. Click "Save and Continue"

6. **Scopes**: Click "Add or Remove Scopes"
   - Add these scopes:
     - `openid`
     - `.../auth/userinfo.email`
     - `.../auth/userinfo.profile`
   - Click "Update" → "Save and Continue"

7. **Test users** (if using "External" and not published):
   - Add email addresses that can test the app
   - Click "Save and Continue"

8. Review and click "Back to Dashboard"

### Step 4: Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click "Create Credentials" → "OAuth 2.0 Client ID"
3. Select **Application type**: Web application
4. **Name**: IAM Copilot Web Client

5. **Authorized JavaScript origins**:
   - Development: `http://localhost:3000`
   - Production: `https://iam-copilot.com`

6. **Authorized redirect URIs**:
   - Development: `http://localhost:8000/api/v1/auth/google/callback`
   - Production: `https://api.iam-copilot.com/api/v1/auth/google/callback`

7. Click "Create"

8. **IMPORTANT**: Copy your credentials:
   - **Client ID**: (e.g., `123456789-abc123.apps.googleusercontent.com`)
   - **Client Secret**: (e.g., `GOCSPX-abc123def456`)

   **Save these securely** - you'll need them in the next step.

---

## Part 2: Update Environment Variables

### Local Development (.env)

Create or update your `.env` file:

```bash
# Google OAuth (REQUIRED)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback

# Database
DATABASE_URL=postgresql://admin:devpassword@db:5432/iam_copilot
DB_PASSWORD=devpassword

# Other settings
ENVIRONMENT=development
DEBUG=true
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

### Production (.env on remote server)

SSH into your remote server and update the `.env` file:

```bash
ssh user@your-remote-host
cd /path/to/IAM-Copilot
nano .env
```

Update with your production values:

```bash
# Google OAuth (REQUIRED)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REDIRECT_URI=https://api.iam-copilot.com/api/v1/auth/google/callback

# Database
DATABASE_URL=postgresql://admin:your_strong_password@db:5432/iam_copilot
DB_PASSWORD=your_strong_password

# Application
ENVIRONMENT=production
DEBUG=false

# CORS - Your actual domains
CORS_ORIGINS=https://iam-copilot.com,https://api.iam-copilot.com

# Frontend API URL
VITE_API_URL=https://api.iam-copilot.com

# AWS Configuration
AWS_REGION=us-east-1

# Bedrock
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
BEDROCK_MAX_TOKENS=4096
BEDROCK_TEMPERATURE=0.0

# Redis
REDIS_URL=redis://redis:6379/0

# Rate Limiting
RATE_LIMIT_PER_SECOND=5
```

Save and exit (`Ctrl+X`, then `Y`, then `Enter`).

---

## Part 3: Deploy to Remote Server

### Step 1: Copy Updated Files to Remote

From your local machine:

```bash
# Using rsync (recommended)
rsync -avz --exclude 'node_modules' --exclude '.git' --exclude '__pycache__' \
  /Users/joeleboube/Development/IAM-Copilot/ \
  user@your-remote-host:/path/to/IAM-Copilot/
```

**Critical files that must be updated:**
- `api/app/models/user.py`
- `api/app/services/google_oauth_service.py`
- `api/app/services/auth_service.py`
- `api/app/routers/auth.py`
- `api/app/dependencies.py`
- `api/app/schemas/auth.py`
- `api/app/config.py`
- `api/requirements.txt`
- `api/alembic/versions/002_google_oauth.py`
- `.env.example`

### Step 2: Stop Services

```bash
ssh user@your-remote-host
cd /path/to/IAM-Copilot

# Stop containers
docker compose down
```

### Step 3: Rebuild API Container

The API container needs to be rebuilt with new dependencies (Google OAuth libraries):

```bash
# Rebuild API container
docker compose build api

# Expected output:
# [+] Building X.Xs (13/13) FINISHED
# => => naming to docker.io/library/iam-copilot-api:latest
```

### Step 4: Start Services

```bash
docker compose up -d

# Verify all containers are running
docker compose ps
```

You should see all containers running:
- `iam-copilot-db-1` (healthy)
- `iam-copilot-redis-1` (running)
- `iam-copilot-api-1` (running)
- `iam-copilot-web-1` (running)
- `iam-copilot-worker-1` (running)

### Step 5: Run Database Migration

**IMPORTANT**: This migration will modify the `users` table by:
- Dropping the `hashed_password` column
- Adding `google_id` column
- Adding `avatar_url` column

If you have test users, they will be deleted. This is expected since we're switching authentication methods.

```bash
# Check database connection
docker compose exec db pg_isready -U admin

# Run the migration
docker compose exec api alembic upgrade head
```

**Expected output:**
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade 001 -> 002, Switch to Google OAuth authentication
```

### Step 6: Verify Database Schema

```bash
docker compose exec db psql -U admin -d iam_copilot -c "\d users"
```

**You should see:**
```
Column       | Type                     | Nullable | Default
-------------+--------------------------+----------+---------
id           | integer                  | not null |
email        | character varying(255)   | not null |
google_id    | character varying(255)   |          |    <- NEW
full_name    | character varying(255)   |          |
avatar_url   | character varying(500)   |          |    <- NEW
is_active    | boolean                  | not null | true
is_verified  | boolean                  | not null | true
created_at   | timestamp                | not null |
updated_at   | timestamp                | not null |
last_login   | timestamp                |          |

Indexes:
    "users_pkey" PRIMARY KEY, btree (id)
    "ix_users_email" UNIQUE, btree (email)
    "ix_users_google_id" UNIQUE, btree (google_id)  <- NEW
```

**Notice**: `hashed_password` is gone, `google_id` and `avatar_url` are added.

---

## Part 4: Testing Google OAuth

### Test 1: Health Check

```bash
curl https://api.iam-copilot.com/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-01T12:00:00.000000",
  "version": "1.0.0"
}
```

### Test 2: Initiate Google Login (Browser)

1. Open your browser
2. Go to: `https://api.iam-copilot.com/api/v1/auth/google/login`
3. You should be redirected to Google's OAuth consent screen
4. Sign in with your Google account
5. Authorize the app
6. You should be redirected back to your frontend with `?auth=success`

### Test 3: Check User Session (Browser)

After logging in, open browser developer tools:

1. Go to **Application** tab → **Cookies**
2. You should see a cookie named `user_id` with:
   - **HttpOnly**: ✓
   - **Secure**: ✓
   - **SameSite**: Lax
   - **Value**: (your user ID)

### Test 4: Get Current User Info

In browser console or using curl with cookies:

```bash
curl -X GET https://api.iam-copilot.com/api/v1/auth/me \
  -H "Cookie: user_id=1" \
  --cookie-jar cookies.txt
```

**Expected response:**
```json
{
  "id": 1,
  "email": "your-email@gmail.com",
  "full_name": "Your Name",
  "avatar_url": "https://lh3.googleusercontent.com/...",
  "is_active": true,
  "is_verified": true,
  "created_at": "2025-11-01T12:00:00.000000",
  "last_login": "2025-11-01T12:00:00.000000"
}
```

### Test 5: Add AWS Credentials

Now that you're logged in, test adding AWS credentials:

```bash
curl -X POST https://api.iam-copilot.com/api/v1/auth/aws-credentials \
  -H "Content-Type: application/json" \
  -H "Cookie: user_id=1" \
  -d '{
    "label": "My AWS Account",
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_region": "us-east-1",
    "is_default": true
  }'
```

**Expected response:**
```json
{
  "id": 1,
  "user_id": 1,
  "label": "My AWS Account",
  "aws_region": "us-east-1",
  "aws_account_id": null,
  "is_default": true,
  "created_at": "2025-11-01T12:00:00.000000",
  "updated_at": "2025-11-01T12:00:00.000000",
  "last_used": null,
  "cross_account_role_arn": null
}
```

### Test 6: List AWS Credentials

```bash
curl -X GET https://api.iam-copilot.com/api/v1/auth/aws-credentials \
  -H "Cookie: user_id=1"
```

### Test 7: Logout

```bash
curl -X POST https://api.iam-copilot.com/api/v1/auth/logout \
  -H "Cookie: user_id=1"
```

**Expected response:**
```json
{
  "message": "Logged out successfully"
}
```

---

## Part 5: Frontend Integration

Your frontend needs to be updated to use Google OAuth. Here's how:

### Option 1: Server-Side Flow (Recommended)

1. Add a "Sign in with Google" button:
```html
<a href="https://api.iam-copilot.com/api/v1/auth/google/login">
  <button>Sign in with Google</button>
</a>
```

2. After successful login, the user will be redirected back to your frontend with `?auth=success`

3. Check authentication status:
```javascript
fetch('https://api.iam-copilot.com/api/v1/auth/me', {
  credentials: 'include' // Include cookies
})
  .then(res => res.json())
  .then(user => {
    console.log('Logged in as:', user.email);
  });
```

### Option 2: Client-Side Flow (Google Sign-In Button)

If you prefer using Google's Sign-In button on your frontend:

1. Load Google Sign-In library
2. Get ID token from Google
3. Send to your API:
```javascript
fetch('https://api.iam-copilot.com/api/v1/auth/google/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ id_token: googleIdToken }),
  credentials: 'include'
})
  .then(res => res.json())
  .then(user => {
    console.log('Logged in as:', user.email);
  });
```

### Making Authenticated Requests

For all API requests, include credentials:

```javascript
fetch('https://api.iam-copilot.com/api/v1/policy/generate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include', // Include cookies
  body: JSON.stringify({ /* ... */ })
});
```

---

## Troubleshooting

### Error: "Not authenticated. Please log in with Google."

**Cause**: No session cookie or invalid cookie.

**Solution**:
- Clear browser cookies and log in again
- Ensure `credentials: 'include'` is set in fetch requests
- Check that cookies are enabled in browser

### Error: "Failed to authenticate with Google"

**Cause**: Invalid Google OAuth configuration.

**Solution**:
1. Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`
2. Check that redirect URI matches exactly in GCP and `.env`
3. Ensure OAuth consent screen is configured
4. Check API container logs: `docker compose logs api`

### Error: "Invalid session"

**Cause**: Cookie value is not a valid user ID.

**Solution**:
- Clear cookies and log in again
- Check database for user existence

### Migration Error: "column 'google_id' already exists"

**Cause**: Migration was already run.

**Solution**:
```bash
# Check migration status
docker compose exec api alembic current

# If needed, mark as applied without running
docker compose exec api alembic stamp head
```

### API Container Won't Start

**Check logs:**
```bash
docker compose logs api
```

**Common issues:**
- Missing Google OAuth environment variables
- Syntax errors in code (check Python traceback)
- Database connection issues

**Solution**:
```bash
# Rebuild from scratch
docker compose down
docker compose build --no-cache api
docker compose up -d
```

### Google OAuth Redirect Not Working

**Cause**: Redirect URI mismatch.

**Solution**:
1. Go to [GCP Console](https://console.cloud.google.com/) → APIs & Services → Credentials
2. Edit your OAuth 2.0 Client ID
3. Ensure redirect URI exactly matches: `https://api.iam-copilot.com/api/v1/auth/google/callback`
4. No trailing slashes, exact protocol (https), exact domain

### CORS Errors in Browser

**Cause**: Frontend domain not in CORS_ORIGINS.

**Solution**:
Update `.env`:
```bash
CORS_ORIGINS=https://iam-copilot.com,https://api.iam-copilot.com
```

Restart API:
```bash
docker compose restart api
```

---

## Security Considerations

### Production Checklist

- [ ] HTTPS enabled (via Cloudflare Tunnel or SSL certificate)
- [ ] Secure cookies enabled (`secure=True` in production)
- [ ] Google OAuth credentials stored securely (not in Git)
- [ ] Strong database password set
- [ ] CORS_ORIGINS set to actual domains only
- [ ] Session cookie expiry configured appropriately
- [ ] Rate limiting enabled
- [ ] Database backups configured
- [ ] AWS credentials encrypted at rest (already implemented)

### Google OAuth Best Practices

1. **Keep Client Secret Secure**: Never commit to Git
2. **Use HTTPS Only**: OAuth requires secure connections
3. **Restrict Redirect URIs**: Only allow your actual domains
4. **Monitor OAuth Usage**: Check GCP quotas and usage
5. **Rotate Credentials**: Periodically regenerate client secrets

---

## Rollback Procedure

If you need to rollback to password-based authentication:

```bash
# Rollback migration
docker compose exec api alembic downgrade -1

# Restore from backup (if you have one)
docker compose exec -T db psql -U admin iam_copilot < backup.sql

# Revert code changes
git checkout <previous-commit>
docker compose down
docker compose up --build -d
```

---

## Summary

After successful deployment:

✅ Users authenticate with Google (no passwords!)
✅ Sessions managed via secure HTTP-only cookies
✅ Users can add multiple AWS credential sets (encrypted)
✅ Multi-tenant architecture with user isolation
✅ Production-ready with HTTPS and CORS

Your IAM Copilot is now using modern, secure Google OAuth authentication!

---

## Need Help?

**Check logs:**
```bash
# API logs
docker compose logs -f api

# Database logs
docker compose logs db

# All logs
docker compose logs --tail=100
```

**Verify database:**
```bash
docker compose exec db psql -U admin -d iam_copilot
\dt  # List tables
\d users  # Describe users table
SELECT * FROM users;  # View users
```

**Test endpoints:**
```bash
# Health check
curl https://api.iam-copilot.com/health

# API documentation
# Open in browser: https://api.iam-copilot.com/docs
```

