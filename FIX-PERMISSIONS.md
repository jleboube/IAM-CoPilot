# Fix AWS IAM Permissions for IAM Copilot

## Current Issue

You're seeing this error when trying to run an IAM audit:

```
Audit failed: RetryError[<Future at 0xffff8f977210 state=finished raised ClientError>]
```

**Root Cause:** Your AWS user `BedrockAPIKey-04vb` has Bedrock permissions but lacks the IAM read permissions needed for security audits.

## Solution: Add IAM Permissions

You need to attach an IAM policy to your AWS user that grants read-only access to IAM resources.

### Option 1: Use the AWS Console (Easiest)

1. **Go to IAM Console:**
   - Navigate to: https://console.aws.amazon.com/iam/
   - Click **Users** → `BedrockAPIKey-04vb`

2. **Attach the Policy:**
   - Click **Add permissions** → **Attach policies directly**
   - Click **Create policy**
   - Click the **JSON** tab
   - Copy and paste the contents of `iam-copilot-permissions.json` from this directory
   - Click **Next**
   - Name it: `IAMCopilotAuditPolicy`
   - Click **Create policy**

3. **Attach to User:**
   - Go back to your user `BedrockAPIKey-04vb`
   - Click **Add permissions** → **Attach policies directly**
   - Search for `IAMCopilotAuditPolicy`
   - Select it and click **Add permissions**

### Option 2: Use AWS CLI (Fastest)

```bash
# Navigate to the project directory
cd /Users/joeleboube/Development/IAM-Copilot

# Create the policy
aws iam create-policy \
  --policy-name IAMCopilotAuditPolicy \
  --policy-document file://iam-copilot-permissions.json

# Attach it to your user
aws iam attach-user-policy \
  --user-name BedrockAPIKey-04vb \
  --policy-arn arn:aws:iam::655870278184:policy/IAMCopilotAuditPolicy
```

### Option 3: Use AWS Managed Policy (Quick but Broad)

If you want a quick solution, attach the AWS managed `SecurityAudit` policy:

**AWS Console:**
1. Go to IAM → Users → `BedrockAPIKey-04vb`
2. Add permissions → Attach policies directly
3. Search for `SecurityAudit`
4. Select and attach

**AWS CLI:**
```bash
aws iam attach-user-policy \
  --user-name BedrockAPIKey-04vb \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

## What Permissions Are Needed?

The IAM Copilot needs these **read-only** permissions to perform audits:

- **IAM Read Access:**
  - `iam:GetAccountAuthorizationDetails` - Get comprehensive IAM details
  - `iam:ListRoles`, `iam:ListUsers`, `iam:ListPolicies` - List IAM resources
  - `iam:GetRole`, `iam:GetRolePolicy` - Get role details
  - `iam:SimulatePrincipalPolicy` - Test policies

- **CloudTrail Read Access:**
  - `cloudtrail:LookupEvents` - Analyze unused permissions

- **Organizations Read Access:**
  - `organizations:ListAccounts` - Multi-account support

- **STS:**
  - `sts:AssumeRole` - Cross-account audits

**Note:** All permissions are read-only. IAM Copilot cannot modify your AWS resources.

## After Adding Permissions

1. **No need to restart the app** - the permissions take effect immediately
2. **Try the audit again** in the web interface
3. You should now see security findings and recommendations

## Verify Permissions

Test if the permissions are working:

```bash
aws iam get-account-authorization-details \
  --profile your-profile-name
```

If this command works, your permissions are correct!

## Improved Error Messages

The app now shows clearer error messages:
- ✅ Before: `RetryError[<Future at 0xffff8f977210 state=finished raised ClientError>]`
- ✅ After: `AWS IAM permissions required. Please ensure your AWS credentials have the following permissions: iam:GetAccountAuthorizationDetails, iam:ListRoles, iam:ListUsers...`

## Need Help?

- Check the `README.md` for full deployment instructions
- See `iam-copilot-permissions.json` for the exact policy
- Review the PRD at `AWS-IAM-CoPilot-PRD.md` for architecture details

## Security Note

The permissions in `iam-copilot-permissions.json` are:
- ✅ **Read-only** - Cannot create, update, or delete resources
- ✅ **Minimal** - Only what's needed for audits
- ✅ **AWS Best Practice** - Follows least-privilege principle
