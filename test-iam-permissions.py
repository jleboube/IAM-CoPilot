#!/usr/bin/env python3
"""
Test script to verify AWS IAM permissions for IAM Copilot
This will check each required permission individually
"""

import boto3
import json
from botocore.exceptions import ClientError


def test_permission(client, action_name, test_func):
    """Test a specific IAM permission"""
    try:
        test_func()
        print(f"✅ {action_name}: SUCCESS")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print(f"❌ {action_name}: ACCESS DENIED")
            print(f"   Error: {e.response['Error']['Message']}")
        else:
            print(f"⚠️  {action_name}: ERROR - {error_code}")
        return False
    except Exception as e:
        print(f"⚠️  {action_name}: UNEXPECTED ERROR - {str(e)}")
        return False


def main():
    print("=" * 70)
    print("IAM Copilot - AWS Permissions Diagnostic Tool")
    print("=" * 70)
    print()

    # Initialize clients
    try:
        iam = boto3.client('iam')
        sts = boto3.client('sts')
        cloudtrail = boto3.client('cloudtrail')
    except Exception as e:
        print(f"❌ Failed to initialize AWS clients: {e}")
        print("\nMake sure your AWS credentials are configured:")
        print("  - AWS_ACCESS_KEY_ID")
        print("  - AWS_SECRET_ACCESS_KEY")
        print("  - AWS_REGION (optional, defaults to us-east-1)")
        return

    # Get current identity
    print("Current AWS Identity:")
    print("-" * 70)
    try:
        identity = sts.get_caller_identity()
        print(f"Account: {identity['Account']}")
        print(f"User ARN: {identity['Arn']}")
        print(f"User ID: {identity['UserId']}")
        print()
    except Exception as e:
        print(f"❌ Cannot get caller identity: {e}")
        return

    # Test permissions
    print("Testing Required Permissions:")
    print("-" * 70)

    results = {}

    # Critical permission for audits
    results['GetAccountAuthorizationDetails'] = test_permission(
        iam,
        'iam:GetAccountAuthorizationDetails',
        lambda: iam.get_account_authorization_details(Filter=['Role'], MaxItems=1)
    )

    # IAM List permissions
    results['ListRoles'] = test_permission(
        iam,
        'iam:ListRoles',
        lambda: iam.list_roles(MaxItems=1)
    )

    results['ListUsers'] = test_permission(
        iam,
        'iam:ListUsers',
        lambda: iam.list_users(MaxItems=1)
    )

    results['ListPolicies'] = test_permission(
        iam,
        'iam:ListPolicies',
        lambda: iam.list_policies(Scope='Local', MaxItems=1)
    )

    # CloudTrail permission
    results['CloudTrailLookupEvents'] = test_permission(
        cloudtrail,
        'cloudtrail:LookupEvents',
        lambda: cloudtrail.lookup_events(MaxResults=1)
    )

    print()
    print("=" * 70)
    print("Summary:")
    print("-" * 70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    print(f"Passed: {passed}/{total}")
    print()

    if results.get('GetAccountAuthorizationDetails'):
        print("✅ GREAT! You have the critical permission needed for audits.")
    else:
        print("❌ MISSING CRITICAL PERMISSION: iam:GetAccountAuthorizationDetails")
        print("   This is the #1 permission needed for IAM Copilot audits.")
        print()

    if passed == total:
        print("🎉 All permissions are working! IAM Copilot should work correctly.")
    else:
        print("⚠️  Some permissions are missing. See recommendations below.")
        print()
        print("Recommended Actions:")
        print("-" * 70)
        print("1. Attach the IAM policy from 'iam-copilot-permissions.json'")
        print()
        print("   Using AWS CLI:")
        print("   $ aws iam create-policy --policy-name IAMCopilotAuditPolicy \\")
        print("       --policy-document file://iam-copilot-permissions.json")
        print()
        print("   $ aws iam attach-user-policy \\")
        print(f"       --user-name {identity['Arn'].split('/')[-1]} \\")
        print(f"       --policy-arn arn:aws:iam::{identity['Account']}:policy/IAMCopilotAuditPolicy")
        print()
        print("2. OR attach AWS managed policy 'SecurityAudit':")
        print("   $ aws iam attach-user-policy \\")
        print(f"       --user-name {identity['Arn'].split('/')[-1]} \\")
        print("       --policy-arn arn:aws:iam::aws:policy/SecurityAudit")

    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
