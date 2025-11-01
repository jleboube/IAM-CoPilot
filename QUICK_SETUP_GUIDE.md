# Quick Setup Guide - Google OAuth for Frontend & API

## What Changed

I've added Google OAuth authentication to **BOTH** the frontend (https://iam-copilot.com) and API (https://api.iam-copilot.com).

### Frontend (React App)
- ✅ Login page with Google Sign-In button
- ✅ Protected routes (requires authentication)
- ✅ User menu with avatar and logout
- ✅ Session state management with Zustand
- ✅ All API calls include credentials (cookies)

### API (FastAPI)
- ✅ Google OAuth verification endpoint
- ✅ Session-based authentication (cookies)
- ✅ User management endpoints

## Quick Setup (2 Steps)

### 1. Update Your `.env` File

```bash
# Google OAuth (Backend)
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_REDIRECT_URI=https://api.iam-copilot.com/api/v1/auth/google/callback

# Google OAuth (Frontend)
VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com

# Other settings (keep existing)
VITE_API_URL=https://api.iam-copilot.com
CORS_ORIGINS=https://iam-copilot.com,https://api.iam-copilot.com
DATABASE_URL=postgresql://admin:devpassword@db:5432/iam_copilot
# ... etc
```

**Note:** Use the **SAME** Google Client ID for both `GOOGLE_CLIENT_ID` and `VITE_GOOGLE_CLIENT_ID`.

### 2. Rebuild & Start

```bash
# Install new frontend dependencies
cd web
npm install

# Go back to root
cd ..

# Rebuild and start everything
docker compose up --build -d

# Run database migration
docker compose exec api alembic upgrade head
```

## How It Works

1. **User visits https://iam-copilot.com**
   - Sees login page with Google Sign-In button

2. **User clicks "Sign in with Google"**
   - Google OAuth flow handles authentication
   - Frontend receives Google ID token

3. **Frontend sends token to API**
   - API verifies token with Google
   - Creates/updates user in database
   - Sets secure HTTP-only cookie

4. **User is logged in**
   - All protected routes are now accessible
   - All API calls include the session cookie
   - User sees their name/avatar in top right
   - Can logout anytime

## Testing Locally

If you want to test on localhost first:

```bash
# .env for local testing
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/api/v1/auth/google/callback

VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
VITE_API_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
```

**Important**: Add `http://localhost:3000` as an authorized JavaScript origin and `http://localhost:8000/api/v1/auth/google/callback` as an authorized redirect URI in your Google Cloud Console.

## Files Created/Modified

### Frontend
- ✅ `web/src/store/authStore.ts` - Auth state management
- ✅ `web/src/components/Login.tsx` - Login page
- ✅ `web/src/components/ProtectedRoute.tsx` - Route protection
- ✅ `web/src/App.tsx` - Updated with auth flow
- ✅ `web/src/services/api.ts` - Added auth methods, withCredentials
- ✅ `web/package.json` - Added @react-oauth/google

### Backend
- ✅ `api/app/config.py` - Made Google OAuth settings optional
- ✅ `api/app/services/google_oauth_service.py` - OAuth service
- ✅ `api/app/routers/auth.py` - OAuth endpoints
- ✅ `api/app/dependencies.py` - Cookie-based auth
- ✅ `api/app/schemas/auth.py` - Auth schemas
- ✅ `api/app/models/user.py` - Google OAuth fields
- ✅ `api/requirements.txt` - Google OAuth libraries

### Configuration
- ✅ `.env.example` - Added frontend Google OAuth setting

## Troubleshooting

### "VITE_GOOGLE_CLIENT_ID is not set"
Make sure `VITE_GOOGLE_CLIENT_ID` is in your `.env` file and rebuild:
```bash
docker compose down
docker compose up --build -d
```

### "Not authenticated. Please log in with Google"
Your session expired or wasn't created. Try logging in again.

### CORS errors
Make sure `CORS_ORIGINS` in `.env` includes both your frontend and API domains:
```bash
CORS_ORIGINS=https://iam-copilot.com,https://api.iam-copilot.com
```

### Login works but redirects to wrong URL
Check that `VITE_API_URL` points to your API domain:
```bash
VITE_API_URL=https://api.iam-copilot.com
```

## Next Steps

1. Set up Google OAuth (see GOOGLE_OAUTH_DEPLOYMENT_GUIDE.md)
2. Update `.env` with Google credentials
3. Rebuild containers
4. Run migrations
5. Test login at https://iam-copilot.com/login

Your app is now a fully authenticated multi-tenant SaaS platform!
