# IAM Copilot - Complete IAM Management Guide

## Overview

IAM Copilot now provides comprehensive AWS IAM auditing AND full IAM management capabilities. You can audit your entire IAM configuration and manage all IAM resources directly from the web application.

## Features

### 🔍 Comprehensive IAM Auditing

The application can now audit every aspect of IAM:

- **Users**: Access keys, passwords, MFA status, permissions, unused credentials
- **Groups**: Membership, policies, empty groups
- **Roles**: Trust policies, permissions, service-linked roles
- **Policies**: Managed and inline policies, unused policies, wildcard permissions
- **Account Settings**: Password policy strength, MFA requirements
- **Identity Providers**: SAML and OIDC providers

### ⚙️ Full IAM Management

Manage your entire AWS IAM infrastructure:

#### User Management
- Create/Update/Delete IAM users
- Set/Reset user passwords (with auto-generation)
- Manage access keys (create, rotate, delete)
- Manage user group membership
- Attach/Detach policies to users

#### Group Management
- Create/Update/Delete IAM groups
- Add/Remove users from groups
- Attach/Detach policies to groups

#### Role Management
- Create/Update/Delete IAM roles
- Update role trust policies
- Manage role permissions
- Set permissions boundaries

#### Policy Management
- Create/Update/Delete managed policies
- Attach/Detach policies to any principal
- Validate policy documents before creation
- View policy usage across all resources

#### Account Settings
- Configure account password policy
- Set password complexity requirements
- Configure password expiration

## Permissions Required

### For Audit-Only (Read-Only)

Use `iam-copilot-permissions.json` for read-only auditing:

```bash
aws iam create-policy \
  --policy-name IAMCopilotAuditPolicy \
  --policy-document file://iam-copilot-permissions.json

aws iam attach-user-policy \
  --user-name YOUR_IAM_USER \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/IAMCopilotAuditPolicy
```

### For Full Management

Use `iam-copilot-full-permissions.json` for complete IAM management:

```bash
aws iam create-policy \
  --policy-name IAMCopilotFullManagementPolicy \
  --policy-document file://iam-copilot-full-permissions.json

aws iam attach-user-policy \
  --user-name YOUR_IAM_USER \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/IAMCopilotFullManagementPolicy
```

**⚠️ Security Note**: The full management policy grants significant IAM permissions. Only attach this to trusted users/roles. Consider using:
- Permissions boundaries
- Service control policies (SCPs)
- Conditional policies based on IP/MFA
- Regular access reviews

## API Endpoints

### User Management

```bash
# Create user
POST /api/v1/iam/users
{
  "user_name": "john.doe",
  "path": "/",
  "tags": {"Department": "Engineering"}
}

# Update user
PUT /api/v1/iam/users/john.doe
{
  "new_user_name": "john.smith",
  "new_path": "/engineering/"
}

# Delete user (force delete removes all dependencies)
DELETE /api/v1/iam/users/john.doe?force=true

# Set/Reset password
POST /api/v1/iam/users/john.doe/password
{
  "user_name": "john.doe",
  "require_reset": true
}
```

### Access Key Management

```bash
# Create access key
POST /api/v1/iam/users/john.doe/access-keys

# List access keys
GET /api/v1/iam/users/john.doe/access-keys

# Rotate access key
POST /api/v1/iam/users/john.doe/access-keys/AKIAIOSFODNN7EXAMPLE/rotate?delete_old=false

# Delete access key
DELETE /api/v1/iam/users/john.doe/access-keys/AKIAIOSFODNN7EXAMPLE
```

### Group Management

```bash
# Create group
POST /api/v1/iam/groups
{
  "group_name": "Developers",
  "path": "/engineering/"
}

# Add user to group
POST /api/v1/iam/groups/Developers/members
{
  "group_name": "Developers",
  "user_name": "john.doe"
}

# Remove user from group
DELETE /api/v1/iam/groups/Developers/members/john.doe

# Delete group
DELETE /api/v1/iam/groups/Developers?force=true
```

### Role Management

```bash
# Create role
POST /api/v1/iam/roles
{
  "role_name": "AppServerRole",
  "assume_role_policy": {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  },
  "description": "Role for application servers",
  "max_session_duration": 3600
}

# Update role trust policy
PUT /api/v1/iam/roles/AppServerRole/trust-policy
{
  "role_name": "AppServerRole",
  "assume_role_policy": { ... }
}

# Delete role
DELETE /api/v1/iam/roles/AppServerRole?force=true
```

### Policy Management

```bash
# Create policy
POST /api/v1/iam/policies
{
  "policy_name": "S3ReadOnlyPolicy",
  "policy_document": {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": "*"
    }]
  },
  "description": "Read-only access to S3"
}

# Attach policy to user/group/role
POST /api/v1/iam/policies/attach
{
  "policy_arn": "arn:aws:iam::123456789012:policy/S3ReadOnlyPolicy",
  "principal_type": "user",
  "principal_name": "john.doe"
}

# Detach policy
POST /api/v1/iam/policies/detach
{
  "policy_arn": "arn:aws:iam::123456789012:policy/S3ReadOnlyPolicy",
  "principal_type": "user",
  "principal_name": "john.doe"
}

# Delete policy
DELETE /api/v1/iam/policies?policy_arn=arn:aws:iam::123456789012:policy/S3ReadOnlyPolicy&force=true
```

### Account Settings

```bash
# Update password policy
PUT /api/v1/iam/account/password-policy
{
  "minimum_password_length": 14,
  "require_symbols": true,
  "require_numbers": true,
  "require_uppercase_characters": true,
  "require_lowercase_characters": true,
  "allow_users_to_change_password": true,
  "expire_passwords": true,
  "max_password_age": 90,
  "password_reuse_prevention": 24
}

# Get current password policy
GET /api/v1/iam/account/password-policy
```

### Comprehensive Audit

```bash
# Run comprehensive audit (all IAM resources)
POST /api/v1/policies/audit
{
  "aws_account_id": "123456789012",
  "audit_scope": "all"
}

# Audit specific resource types
POST /api/v1/policies/audit
{
  "aws_account_id": "123456789012",
  "audit_scope": "users"  # or "groups", "policies", "roles", "account_settings", "identity_providers"
}

# Get audit results
GET /api/v1/policies/audit/{audit_id}
```

## AWS Restrictions

Some IAM features are restricted to AWS Console or CLI only and cannot be managed via API:

### Console-Only Features
- **Root User Management**: Root credentials and MFA
- **Account Closure**: AWS account termination
- **Hardware MFA Devices**: Physical MFA device association
- **Billing IAM Features**: Some billing-related permissions

### Workarounds
- Use IAM users with appropriate permissions instead of root user
- Virtual MFA can be managed via API
- AWS Organizations can handle delegated billing

To view all restrictions:
```bash
GET /api/v1/iam/restrictions
```

## Security Best Practices

1. **Use Permissions Boundaries**
   - Limit maximum permissions for users/roles
   - Prevent privilege escalation

2. **Enable MFA**
   - Require MFA for all IAM users
   - Especially for users with elevated permissions

3. **Principle of Least Privilege**
   - Grant only necessary permissions
   - Use the audit feature to identify excessive permissions
   - Regularly review and tighten policies

4. **Access Key Rotation**
   - Rotate access keys every 90 days
   - Use the audit feature to identify old keys
   - Use the rotation endpoint for safe key rotation

5. **Password Policy**
   - Minimum 14 characters
   - Require all character types
   - Enable expiration (90 days recommended)
   - Prevent reuse of last 24 passwords

6. **Monitor and Audit**
   - Run comprehensive audits regularly
   - Review high-risk findings immediately
   - Track changes with CloudTrail

7. **Use Groups for Permissions**
   - Attach policies to groups, not individual users
   - Manage permissions at the group level
   - Use naming conventions (e.g., /department/team/)

## Examples

### Example 1: Onboard New Employee

```bash
# 1. Create user
curl -X POST http://localhost:8000/api/v1/iam/users \
  -H "Content-Type: application/json" \
  -d '{
    "user_name": "jane.smith",
    "path": "/engineering/",
    "tags": {"Department": "Engineering", "Team": "Backend"}
  }'

# 2. Set password
curl -X POST http://localhost:8000/api/v1/iam/users/jane.smith/password \
  -H "Content-Type: application/json" \
  -d '{
    "user_name": "jane.smith",
    "require_reset": true
  }'

# 3. Add to group
curl -X POST http://localhost:8000/api/v1/iam/groups/Engineers/members \
  -H "Content-Type: application/json" \
  -d '{
    "group_name": "Engineers",
    "user_name": "jane.smith"
  }'

# 4. Create access keys
curl -X POST http://localhost:8000/api/v1/iam/users/jane.smith/access-keys
```

### Example 2: Create Application Role

```bash
# 1. Create role with EC2 trust policy
curl -X POST http://localhost:8000/api/v1/iam/roles \
  -H "Content-Type: application/json" \
  -d '{
    "role_name": "WebAppRole",
    "assume_role_policy": {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole"
      }]
    },
    "description": "Role for web application servers",
    "max_session_duration": 7200
  }'

# 2. Create and attach policy
curl -X POST http://localhost:8000/api/v1/iam/policies \
  -H "Content-Type: application/json" \
  -d '{
    "policy_name": "WebAppPolicy",
    "policy_document": {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": ["s3:GetObject", "dynamodb:Query"],
        "Resource": ["arn:aws:s3:::webapp-bucket/*", "arn:aws:dynamodb:*:*:table/webapp-*"]
      }]
    }
  }'

curl -X POST http://localhost:8000/api/v1/iam/policies/attach \
  -H "Content-Type: application/json" \
  -d '{
    "policy_arn": "arn:aws:iam::123456789012:policy/WebAppPolicy",
    "principal_type": "role",
    "principal_name": "WebAppRole"
  }'
```

### Example 3: Rotate All Old Access Keys

```bash
# 1. Run audit to find old keys
curl -X POST http://localhost:8000/api/v1/policies/audit \
  -H "Content-Type: application/json" \
  -d '{
    "aws_account_id": "123456789012",
    "audit_scope": "users"
  }'

# 2. For each user with old keys, rotate
curl -X POST http://localhost:8000/api/v1/iam/users/USER_NAME/access-keys/OLD_KEY_ID/rotate?delete_old=false

# 3. Notify user of new credentials, then delete old key after transition
curl -X DELETE http://localhost:8000/api/v1/iam/users/USER_NAME/access-keys/OLD_KEY_ID
```

## Deployment

The application continues to run with Docker Compose. No changes needed to your deployment:

```bash
# Start the application
docker compose up --build -d

# View logs
docker compose logs -f api

# Access the application
# Web UI: http://localhost:3000
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

## Troubleshooting

### Permission Denied Errors

If you see permission errors:

1. Check which policy is attached:
   ```bash
   aws iam list-attached-user-policies --user-name YOUR_USER
   ```

2. For audit-only: Use `iam-copilot-permissions.json`
3. For full management: Use `iam-copilot-full-permissions.json`

### API 500 Errors

Check API logs:
```bash
docker compose logs -f api
```

Common issues:
- AWS credentials not configured correctly
- Insufficient IAM permissions
- Invalid policy documents (use validation)

### Cannot Delete Resources

Resources with dependencies cannot be deleted without `force=true`:

```bash
# This fails if user has access keys, policies, or group memberships
DELETE /api/v1/iam/users/john.doe

# This succeeds - removes all dependencies first
DELETE /api/v1/iam/users/john.doe?force=true
```

## Support

For issues, feature requests, or questions:
- Check the API documentation: http://localhost:8000/docs
- Review the PRD: `AWS-IAM-CoPilot-PRD.md`
- Check logs: `docker compose logs -f`

## Security Considerations

**IMPORTANT**: This application provides powerful IAM management capabilities. Consider:

1. **Network Security**: Deploy behind a VPN or use AWS PrivateLink
2. **Authentication**: Implement authentication/authorization before production use
3. **Audit Logging**: Enable CloudTrail to log all IAM changes
4. **Least Privilege**: Only grant full management permissions to administrators
5. **MFA**: Require MFA for users with IAM management access
6. **Regular Reviews**: Audit who has access to this application regularly

## Future Enhancements

Planned features:
- UI components for all management operations
- Bulk operations (create multiple users, rotate all keys)
- IAM policy recommendations using AI
- Compliance reporting (CIS, PCI-DSS, SOC 2)
- Cross-account management dashboard
- Automated remediation workflows
