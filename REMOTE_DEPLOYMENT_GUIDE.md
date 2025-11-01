# Remote Host Deployment Guide

## Deploying Multi-Tenant Updates to Remote Host

This guide walks you through deploying the multi-tenant authentication updates to your remote VM.

## Prerequisites

- SSH access to your remote VM
- Docker and Docker Compose installed on remote VM
- Cloudflare Tunnel configured (if using)

## Step-by-Step Deployment

### Step 1: Copy Files to Remote Host

From your local machine, sync all files to the remote host:

```bash
# Option A: Using rsync (recommended)
rsync -avz --exclude 'node_modules' --exclude '.git' --exclude '__pycache__' \
  /Users/joeleboube/Development/IAM-Copilot/ \
  user@your-remote-host:/path/to/IAM-Copilot/

# Option B: Using scp
scp -r /Users/joeleboube/Development/IAM-Copilot/ \
  user@your-remote-host:/path/to/IAM-Copilot/
```

**Important files to verify are copied:**
- `api/alembic.ini`
- `api/alembic/env.py`
- `api/app/models/user.py`
- `api/app/models/__init__.py`
- `api/app/services/auth_service.py`
- `api/app/schemas/auth.py`
- `api/app/routers/auth.py`
- `api/app/dependencies.py`
- `api/requirements.txt`
- `api/app/main.py`

### Step 2: SSH into Remote Host

```bash
ssh user@your-remote-host
cd /path/to/IAM-Copilot
```

### Step 3: Update Environment Variables

Generate a secure SECRET_KEY:

```bash
# Generate 32-byte random key
openssl rand -hex 32
```

Edit your `.env` file on the remote host:

```bash
nano .env
```

Add/update these variables:

```bash
# Authentication (REQUIRED - ADD THESE)
SECRET_KEY=paste_your_generated_key_here
ACCESS_TOKEN_EXPIRE_MINUTES=15

# Database (should already exist)
DATABASE_URL=postgresql://admin:your_db_password@db:5432/iam_copilot
DB_PASSWORD=your_db_password

# CORS - Update with your domain
CORS_ORIGINS=https://iam-copilot.yourdomain.com,https://api.iam-copilot.yourdomain.com

# Frontend API URL
VITE_API_URL=https://api.iam-copilot.yourdomain.com

# Environment
ENVIRONMENT=production
DEBUG=false

# Keep other existing variables (AWS region, Bedrock, etc.)
```

Save and exit (`Ctrl+X`, then `Y`, then `Enter`).

### Step 4: Stop Running Containers

```bash
docker compose down
```

### Step 5: Rebuild Containers

This step rebuilds the API container with the new authentication code:

```bash
docker compose build api
```

**Expected output:**
```
[+] Building 45.2s (13/13) FINISHED
...
 => => naming to docker.io/library/iam-copilot-api:latest
```

### Step 6: Start Containers

```bash
docker compose up -d
```

**Verify all containers are running:**

```bash
docker compose ps
```

You should see:
- iam-copilot-db-1 (healthy)
- iam-copilot-redis-1 (running)
- iam-copilot-api-1 (running)
- iam-copilot-web-1 (running)
- iam-copilot-worker-1 (running)

### Step 7: Run Database Migrations

**Check database connection first:**

```bash
docker compose exec db pg_isready -U admin
```

Expected: `postgresql://admin@db:5432/iam_copilot - accepting connections`

**Generate migration for new auth tables:**

```bash
docker compose exec api alembic revision --autogenerate -m "add multi-tenant auth tables"
```

**Expected output:**
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.autogenerate.compare] Detected added table 'users'
INFO  [alembic.autogenerate.compare] Detected added table 'refresh_tokens'
INFO  [alembic.autogenerate.compare] Detected added table 'user_aws_credentials'
INFO  [alembic.autogenerate.compare] Detected added table 'audit_logs'
  Generating /app/alembic/versions/2025_11_01_xxxx-add_multi_tenant_auth_tables.py ... done
```

**Apply the migration:**

```bash
docker compose exec api alembic upgrade head
```

**Expected output:**
```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade xxx -> yyy, add multi-tenant auth tables
```

### Step 8: Verify Database Tables

```bash
docker compose exec db psql -U admin -d iam_copilot -c "\dt"
```

**You should see the new tables:**
```
                   List of relations
 Schema |          Name           | Type  | Owner
--------+-------------------------+-------+-------
 public | alembic_version         | table | admin
 public | audit_logs              | table | admin
 public | policies                | table | admin
 public | refresh_tokens          | table | admin
 public | user_aws_credentials    | table | admin
 public | users                   | table | admin
 ...
```

### Step 9: Test Authentication Endpoints

**Test health check:**

```bash
curl -s https://api.iam-copilot.yourdomain.com/health | jq
```

**Test auth health:**

```bash
curl -s https://api.iam-copilot.yourdomain.com/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"email":"test@example.com","password":"TestPass123","full_name":"Test User"}' | jq
```

**Expected response:**
```json
{
  "id": 1,
  "email": "test@example.com",
  "full_name": "Test User",
  "is_active": true,
  "is_verified": false,
  "created_at": "2025-11-01T12:00:00.000000",
  "last_login": null
}
```

**Test login:**

```bash
curl -s https://api.iam-copilot.yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"email":"test@example.com","password":"TestPass123"}' | jq
```

**Expected response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "dGhpc2lzYXJlZnJlc2h0...",
  "token_type": "bearer",
  "expires_in": 900
}
```

### Step 10: Check Logs

If anything fails, check the logs:

```bash
# API logs
docker compose logs -f api

# Database logs
docker compose logs db

# All logs
docker compose logs --tail=100
```

## Troubleshooting

### Issue: "No config file 'alembic.ini' found"

**Solution:**
```bash
# Verify file exists in container
docker compose exec api ls -la /app/alembic.ini

# If missing, the file wasn't copied properly
# Re-copy from local machine
scp /Users/joeleboube/Development/IAM-Copilot/api/alembic.ini \
  user@remote:/path/to/IAM-Copilot/api/alembic.ini

# Rebuild and restart
docker compose down
docker compose up --build -d
```

### Issue: "ImportError: cannot import name 'User'"

**Solution:**
```bash
# Verify user.py exists
docker compose exec api ls -la /app/app/models/user.py

# Verify __init__.py imports it
docker compose exec api cat /app/app/models/__init__.py | grep "from app.models.user"

# If missing, rebuild
docker compose down
docker compose build api
docker compose up -d
```

### Issue: Database migration fails

**Solution:**
```bash
# Check database is running
docker compose exec db pg_isready -U admin

# Check DATABASE_URL is set
docker compose exec api env | grep DATABASE_URL

# Try migration again with verbose output
docker compose exec api alembic upgrade head --verbose
```

### Issue: "Table 'users' already exists"

If you run the migration twice:

```bash
# Mark current migration as applied without running it
docker compose exec api alembic stamp head

# Or drop and recreate (WARNING: loses data)
docker compose exec db psql -U admin -d iam_copilot -c "DROP TABLE IF EXISTS users CASCADE;"
docker compose exec api alembic upgrade head
```

### Issue: 401 Unauthorized on all endpoints

This is expected! After deployment, all endpoints require authentication.

**Solution:**
1. Users must register: `POST /api/v1/auth/register`
2. Users must login: `POST /api/v1/auth/login`
3. Include JWT token in requests: `Authorization: Bearer <token>`

## Post-Deployment Checklist

- [ ] All containers running: `docker compose ps`
- [ ] Database tables created: `\dt` in psql
- [ ] Health check works: `curl https://api.yourdomain.com/health`
- [ ] Can register user: `POST /api/v1/auth/register`
- [ ] Can login: `POST /api/v1/auth/login`
- [ ] JWT token received
- [ ] Can add AWS credentials: `POST /api/v1/auth/aws-credentials`
- [ ] Frontend loads at your domain
- [ ] Cloudflare Tunnel routing works (if applicable)

## Security Notes

**IMPORTANT:**

1. **Never commit SECRET_KEY** - Keep it in .env only
2. **Use strong DB_PASSWORD** - Generate with `openssl rand -base64 32`
3. **HTTPS only** - Ensure Cloudflare SSL/TLS is enabled
4. **Backup database** before running migrations:
   ```bash
   docker compose exec db pg_dump -U admin iam_copilot > backup.sql
   ```

## Rollback Procedure

If something goes wrong:

```bash
# Stop containers
docker compose down

# Restore from backup
docker compose exec -T db psql -U admin iam_copilot < backup.sql

# Rollback migration
docker compose exec api alembic downgrade -1

# Restart old version
git checkout previous-commit
docker compose up -d
```

## Need Help?

Check logs:
```bash
docker compose logs -f api
```

Check database:
```bash
docker compose exec db psql -U admin -d iam_copilot
```

Restart everything:
```bash
docker compose down
docker compose up -d
```

## Summary

After successful deployment:

✅ Multi-tenant authentication is live
✅ Users can register and login
✅ Users can add their own AWS credentials (encrypted)
✅ All API requests require JWT authentication
✅ Audit logging tracks all actions

Your IAM Copilot instance is now a fully multi-tenant SaaS platform!
