"""
AWS IAM Identity Center Service

Handles operations for AWS IAM Identity Center (formerly AWS SSO), including:
- Permission Sets management
- Account assignments
- Identity Store users and groups
- SSO configuration
"""

import boto3
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class IdentityCenterService:
    """Service for managing AWS IAM Identity Center resources."""

    def __init__(self, aws_account_id: str, role_arn: Optional[str] = None, region: str = 'us-east-1'):
        """
        Initialize Identity Center service.

        Args:
            aws_account_id: AWS account ID
            role_arn: Optional cross-account role ARN for assume role
            region: AWS region (Identity Center is region-specific)
        """
        self.aws_account_id = aws_account_id
        self.role_arn = role_arn
        self.region = region

        if role_arn:
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='IAMCopilotIdentityCenterSession'
            )
            credentials = assumed_role['Credentials']

            self.sso_admin_client = boto3.client(
                'sso-admin',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            self.identitystore_client = boto3.client(
                'identitystore',
                region_name=region,
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            self.organizations_client = boto3.client(
                'organizations',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        else:
            self.sso_admin_client = boto3.client('sso-admin', region_name=region)
            self.identitystore_client = boto3.client('identitystore', region_name=region)
            self.organizations_client = boto3.client('organizations')

    # ========== SSO Instance Methods ==========

    def list_sso_instances(self) -> List[Dict[str, Any]]:
        """
        List all SSO instances.

        Returns:
            List of SSO instance details
        """
        try:
            response = self.sso_admin_client.list_instances()
            instances = []

            for instance in response.get('Instances', []):
                instance_data = {
                    'instance_arn': instance.get('InstanceArn'),
                    'identity_store_id': instance.get('IdentityStoreId'),
                    'name': instance.get('Name', 'N/A'),
                    'status': instance.get('Status', 'ACTIVE')
                }
                instances.append(instance_data)

            return instances
        except Exception as e:
            logger.error(f"Failed to list SSO instances: {str(e)}")
            raise

    def get_sso_instance(self) -> Optional[Dict[str, Any]]:
        """
        Get the primary SSO instance (there's typically only one per region).

        Returns:
            SSO instance details or None if not found
        """
        instances = self.list_sso_instances()
        return instances[0] if instances else None

    # ========== Permission Set Methods ==========

    def list_permission_sets(self, instance_arn: str) -> List[Dict[str, Any]]:
        """
        List all permission sets in the SSO instance.

        Args:
            instance_arn: ARN of the SSO instance

        Returns:
            List of permission set details
        """
        try:
            permission_sets = []
            paginator = self.sso_admin_client.get_paginator('list_permission_sets')

            for page in paginator.paginate(InstanceArn=instance_arn):
                for ps_arn in page.get('PermissionSets', []):
                    ps_details = self.describe_permission_set(instance_arn, ps_arn)
                    if ps_details:
                        permission_sets.append(ps_details)

            return permission_sets
        except Exception as e:
            logger.error(f"Failed to list permission sets: {str(e)}")
            raise

    def describe_permission_set(self, instance_arn: str, permission_set_arn: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a permission set.

        Args:
            instance_arn: ARN of the SSO instance
            permission_set_arn: ARN of the permission set

        Returns:
            Permission set details
        """
        try:
            response = self.sso_admin_client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            )

            permission_set = response.get('PermissionSet', {})

            # Get inline policy if exists
            inline_policy = None
            try:
                policy_response = self.sso_admin_client.get_inline_policy_for_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                )
                inline_policy = policy_response.get('InlinePolicy')
            except self.sso_admin_client.exceptions.ResourceNotFoundException:
                pass

            # Get managed policies
            managed_policies = []
            try:
                policies_paginator = self.sso_admin_client.get_paginator('list_managed_policies_in_permission_set')
                for page in policies_paginator.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ):
                    managed_policies.extend(page.get('AttachedManagedPolicies', []))
            except Exception as e:
                logger.warning(f"Failed to get managed policies: {str(e)}")

            # Get customer managed policies
            customer_managed_policies = []
            try:
                customer_paginator = self.sso_admin_client.get_paginator('list_customer_managed_policy_references_in_permission_set')
                for page in customer_paginator.paginate(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ):
                    customer_managed_policies.extend(page.get('CustomerManagedPolicyReferences', []))
            except Exception as e:
                logger.warning(f"Failed to get customer managed policies: {str(e)}")

            return {
                'name': permission_set.get('Name'),
                'arn': permission_set_arn,
                'description': permission_set.get('Description', ''),
                'session_duration': permission_set.get('SessionDuration', 'PT1H'),
                'relay_state': permission_set.get('RelayState', ''),
                'created_date': permission_set.get('CreatedDate'),
                'inline_policy': inline_policy,
                'managed_policies': managed_policies,
                'customer_managed_policies': customer_managed_policies
            }
        except Exception as e:
            logger.error(f"Failed to describe permission set {permission_set_arn}: {str(e)}")
            return None

    # ========== Account Assignment Methods ==========

    def list_account_assignments(self, instance_arn: str, account_id: str, permission_set_arn: str) -> List[Dict[str, Any]]:
        """
        List all account assignments for a permission set.

        Args:
            instance_arn: ARN of the SSO instance
            account_id: AWS account ID
            permission_set_arn: ARN of the permission set

        Returns:
            List of account assignments
        """
        try:
            assignments = []
            paginator = self.sso_admin_client.get_paginator('list_account_assignments')

            for page in paginator.paginate(
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=permission_set_arn
            ):
                for assignment in page.get('AccountAssignments', []):
                    assignments.append({
                        'principal_type': assignment.get('PrincipalType'),
                        'principal_id': assignment.get('PrincipalId'),
                        'permission_set_arn': assignment.get('PermissionSetArn'),
                        'account_id': assignment.get('AccountId')
                    })

            return assignments
        except Exception as e:
            logger.error(f"Failed to list account assignments: {str(e)}")
            raise

    def list_accounts_for_provisioned_permission_set(self, instance_arn: str, permission_set_arn: str) -> List[str]:
        """
        List all accounts where a permission set is provisioned.

        Args:
            instance_arn: ARN of the SSO instance
            permission_set_arn: ARN of the permission set

        Returns:
            List of account IDs
        """
        try:
            accounts = []
            paginator = self.sso_admin_client.get_paginator('list_accounts_for_provisioned_permission_set')

            for page in paginator.paginate(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            ):
                accounts.extend(page.get('AccountIds', []))

            return accounts
        except Exception as e:
            logger.error(f"Failed to list accounts for permission set: {str(e)}")
            raise

    # ========== Identity Store Methods ==========

    def list_identity_store_users(self, identity_store_id: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        List users from the Identity Store.

        Args:
            identity_store_id: ID of the Identity Store
            max_results: Maximum number of results to return

        Returns:
            List of user details
        """
        try:
            users = []
            paginator = self.identitystore_client.get_paginator('list_users')

            for page in paginator.paginate(
                IdentityStoreId=identity_store_id,
                PaginationConfig={'MaxItems': max_results}
            ):
                for user in page.get('Users', []):
                    users.append({
                        'user_id': user.get('UserId'),
                        'user_name': user.get('UserName'),
                        'display_name': user.get('DisplayName', ''),
                        'name': user.get('Name', {}),
                        'emails': user.get('Emails', []),
                        'identity_store_id': identity_store_id
                    })

            return users
        except Exception as e:
            logger.error(f"Failed to list Identity Store users: {str(e)}")
            raise

    def list_identity_store_groups(self, identity_store_id: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        List groups from the Identity Store.

        Args:
            identity_store_id: ID of the Identity Store
            max_results: Maximum number of results to return

        Returns:
            List of group details
        """
        try:
            groups = []
            paginator = self.identitystore_client.get_paginator('list_groups')

            for page in paginator.paginate(
                IdentityStoreId=identity_store_id,
                PaginationConfig={'MaxItems': max_results}
            ):
                for group in page.get('Groups', []):
                    groups.append({
                        'group_id': group.get('GroupId'),
                        'display_name': group.get('DisplayName'),
                        'description': group.get('Description', ''),
                        'identity_store_id': identity_store_id
                    })

            return groups
        except Exception as e:
            logger.error(f"Failed to list Identity Store groups: {str(e)}")
            raise

    def list_group_memberships(self, identity_store_id: str, group_id: str) -> List[Dict[str, Any]]:
        """
        List members of a group.

        Args:
            identity_store_id: ID of the Identity Store
            group_id: ID of the group

        Returns:
            List of group members
        """
        try:
            members = []
            paginator = self.identitystore_client.get_paginator('list_group_memberships')

            for page in paginator.paginate(
                IdentityStoreId=identity_store_id,
                GroupId=group_id
            ):
                for membership in page.get('GroupMemberships', []):
                    members.append({
                        'membership_id': membership.get('MembershipId'),
                        'member_id': membership.get('MemberId', {}).get('UserId'),
                        'identity_store_id': identity_store_id
                    })

            return members
        except Exception as e:
            logger.error(f"Failed to list group memberships: {str(e)}")
            raise

    # ========== Organization Methods ==========

    def list_organization_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the AWS Organization.

        Returns:
            List of account details
        """
        try:
            accounts = []
            paginator = self.organizations_client.get_paginator('list_accounts')

            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    accounts.append({
                        'id': account.get('Id'),
                        'name': account.get('Name'),
                        'email': account.get('Email'),
                        'status': account.get('Status'),
                        'joined_method': account.get('JoinedMethod'),
                        'joined_timestamp': account.get('JoinedTimestamp')
                    })

            return accounts
        except Exception as e:
            logger.error(f"Failed to list organization accounts: {str(e)}")
            raise

    # ========== Comprehensive Data Methods ==========

    def get_identity_center_overview(self) -> Dict[str, Any]:
        """
        Get a comprehensive overview of Identity Center configuration.

        Returns:
            Complete overview including instances, permission sets, users, groups, and assignments
        """
        try:
            # Get SSO instance
            instance = self.get_sso_instance()
            if not instance:
                return {
                    'enabled': False,
                    'message': 'IAM Identity Center is not enabled in this region'
                }

            instance_arn = instance['instance_arn']
            identity_store_id = instance['identity_store_id']

            # Get permission sets
            permission_sets = self.list_permission_sets(instance_arn)

            # Get users and groups
            users = self.list_identity_store_users(identity_store_id)
            groups = self.list_identity_store_groups(identity_store_id)

            # Get organization accounts
            try:
                org_accounts = self.list_organization_accounts()
            except Exception as e:
                logger.warning(f"Failed to list organization accounts: {str(e)}")
                org_accounts = []

            # Get all assignments for each permission set
            all_assignments = []
            for ps in permission_sets:
                ps_arn = ps['arn']
                try:
                    accounts_for_ps = self.list_accounts_for_provisioned_permission_set(instance_arn, ps_arn)
                    for account_id in accounts_for_ps:
                        assignments = self.list_account_assignments(instance_arn, account_id, ps_arn)
                        all_assignments.extend(assignments)
                except Exception as e:
                    logger.warning(f"Failed to get assignments for {ps['name']}: {str(e)}")

            return {
                'enabled': True,
                'instance': instance,
                'permission_sets': permission_sets,
                'users': users,
                'groups': groups,
                'assignments': all_assignments,
                'organization_accounts': org_accounts,
                'stats': {
                    'total_permission_sets': len(permission_sets),
                    'total_users': len(users),
                    'total_groups': len(groups),
                    'total_assignments': len(all_assignments),
                    'total_org_accounts': len(org_accounts)
                }
            }
        except Exception as e:
            logger.error(f"Failed to get Identity Center overview: {str(e)}")
            raise
