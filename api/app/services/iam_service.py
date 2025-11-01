"""
AWS IAM service for policy operations
"""
import json
from typing import Any
import boto3
from botocore.exceptions import ClientError
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

from app.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


class IAMService:
    """Service for AWS IAM operations"""

    def __init__(self, aws_access_key_id: str | None = None, aws_secret_access_key: str | None = None, role_arn: str | None = None):
        """Initialize IAM service with optional credentials or role assumption"""
        self.settings = settings

        if role_arn:
            # Assume cross-account role
            sts_client = boto3.client('sts', region_name=settings.aws_region)
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='iam-copilot-session'
            )
            credentials = response['Credentials']
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=settings.aws_region
            )
        elif aws_access_key_id and aws_secret_access_key:
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=settings.aws_region
            )
        else:
            # Use default credentials (IAM role, environment, or config file)
            self.iam_client = boto3.client('iam', region_name=settings.aws_region)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def create_policy(self, policy_name: str, policy_document: dict[str, Any], description: str = "") -> dict[str, Any]:
        """Create a new IAM policy"""
        try:
            response = self.iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
                Description=description
            )
            logger.info("policy_created", policy_arn=response['Policy']['Arn'])
            return response['Policy']
        except ClientError as e:
            logger.error("policy_creation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def simulate_principal_policy(
        self,
        principal_arn: str,
        action_names: list[str],
        resource_arns: list[str] | None = None
    ) -> dict[str, Any]:
        """Simulate IAM policy for a principal"""
        try:
            params = {
                'PolicySourceArn': principal_arn,
                'ActionNames': action_names,
            }
            if resource_arns:
                params['ResourceArns'] = resource_arns

            response = self.iam_client.simulate_principal_policy(**params)
            logger.info("policy_simulation_completed", principal_arn=principal_arn)
            return self._process_simulation_results(response)
        except ClientError as e:
            logger.error("policy_simulation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def simulate_custom_policy(
        self,
        policy_document: dict[str, Any],
        action_names: list[str],
        resource_arns: list[str] | None = None
    ) -> dict[str, Any]:
        """Simulate a custom IAM policy"""
        try:
            params = {
                'PolicyInputList': [json.dumps(policy_document)],
                'ActionNames': action_names,
            }
            if resource_arns:
                params['ResourceArns'] = resource_arns

            response = self.iam_client.simulate_custom_policy(**params)
            logger.info("custom_policy_simulation_completed")
            return self._process_simulation_results(response)
        except ClientError as e:
            logger.error("custom_policy_simulation_failed", error=str(e))
            raise

    def _process_simulation_results(self, response: dict[str, Any]) -> dict[str, Any]:
        """Process simulation results into a structured format"""
        evaluation_results = response.get('EvaluationResults', [])

        allowed_actions = []
        denied_actions = []
        matched_statements = []

        for result in evaluation_results:
            action = result['EvalActionName']
            decision = result['EvalDecision']

            if decision == 'allowed':
                allowed_actions.append(action)
                if 'MatchedStatements' in result:
                    matched_statements.extend([stmt.get('SourcePolicyId', 'unknown') for stmt in result['MatchedStatements']])
            else:
                denied_actions.append(action)

        return {
            'evaluation_results': evaluation_results,
            'allowed_actions': allowed_actions,
            'denied_actions': denied_actions,
            'matched_statements': list(set(matched_statements)),
            'summary': f"Allowed: {len(allowed_actions)}, Denied: {len(denied_actions)}"
        }

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def list_roles(self) -> list[dict[str, Any]]:
        """List all IAM roles"""
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            roles = []
            for page in paginator.paginate():
                roles.extend(page['Roles'])
            logger.info("roles_listed", count=len(roles))
            return roles
        except ClientError as e:
            logger.error("list_roles_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_role_policies(self, role_name: str) -> dict[str, Any]:
        """Get all policies attached to a role"""
        try:
            # Inline policies
            inline_response = self.iam_client.list_role_policies(RoleName=role_name)
            inline_policies = []
            for policy_name in inline_response.get('PolicyNames', []):
                policy_response = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                inline_policies.append({
                    'PolicyName': policy_name,
                    'PolicyDocument': policy_response['PolicyDocument']
                })

            # Attached managed policies
            attached_response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = attached_response.get('AttachedPolicies', [])

            logger.info("role_policies_retrieved", role_name=role_name)
            return {
                'inline_policies': inline_policies,
                'attached_policies': attached_policies
            }
        except ClientError as e:
            logger.error("get_role_policies_failed", role_name=role_name, error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def get_account_authorization_details(self) -> dict[str, Any]:
        """Get comprehensive IAM details for the account"""
        try:
            paginator = self.iam_client.get_paginator('get_account_authorization_details')

            users = []
            roles = []
            groups = []
            policies = []

            for page in paginator.paginate():
                users.extend(page.get('UserDetailList', []))
                roles.extend(page.get('RoleDetailList', []))
                groups.extend(page.get('GroupDetailList', []))
                policies.extend(page.get('Policies', []))

            logger.info("account_authorization_details_retrieved",
                       users_count=len(users),
                       roles_count=len(roles),
                       groups_count=len(groups),
                       policies_count=len(policies))

            return {
                'users': users,
                'roles': roles,
                'groups': groups,
                'policies': policies
            }
        except ClientError as e:
            logger.error("get_account_authorization_details_failed", error=str(e))
            raise

    # ==================== IAM User Management ====================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def create_user(self, user_name: str, path: str = "/", permissions_boundary: str | None = None, tags: list[dict[str, str]] | None = None) -> dict[str, Any]:
        """Create a new IAM user"""
        try:
            params = {'UserName': user_name, 'Path': path}
            if permissions_boundary:
                params['PermissionsBoundary'] = permissions_boundary
            if tags:
                params['Tags'] = tags

            response = self.iam_client.create_user(**params)
            logger.info("user_created", user_name=user_name)
            return response['User']
        except ClientError as e:
            logger.error("user_creation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def delete_user(self, user_name: str, force: bool = False) -> dict[str, str]:
        """Delete an IAM user"""
        try:
            if force:
                # Remove all attached policies, access keys, inline policies, etc.
                self._cleanup_user_dependencies(user_name)

            self.iam_client.delete_user(UserName=user_name)
            logger.info("user_deleted", user_name=user_name)
            return {'message': f'User {user_name} deleted successfully'}
        except ClientError as e:
            logger.error("user_deletion_failed", error=str(e))
            raise

    def _cleanup_user_dependencies(self, user_name: str):
        """Remove all user dependencies before deletion"""
        # Remove access keys
        try:
            keys = self.iam_client.list_access_keys(UserName=user_name)
            for key in keys['AccessKeyMetadata']:
                self.iam_client.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
        except ClientError:
            pass

        # Detach managed policies
        try:
            policies = self.iam_client.list_attached_user_policies(UserName=user_name)
            for policy in policies['AttachedPolicies']:
                self.iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
        except ClientError:
            pass

        # Delete inline policies
        try:
            policies = self.iam_client.list_user_policies(UserName=user_name)
            for policy_name in policies['PolicyNames']:
                self.iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        except ClientError:
            pass

        # Remove from groups
        try:
            groups = self.iam_client.list_groups_for_user(UserName=user_name)
            for group in groups['Groups']:
                self.iam_client.remove_user_from_group(UserName=user_name, GroupName=group['GroupName'])
        except ClientError:
            pass

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def update_user(self, user_name: str, new_user_name: str | None = None, new_path: str | None = None) -> dict[str, str]:
        """Update an IAM user"""
        try:
            params = {'UserName': user_name}
            if new_user_name:
                params['NewUserName'] = new_user_name
            if new_path:
                params['NewPath'] = new_path

            self.iam_client.update_user(**params)
            logger.info("user_updated", user_name=user_name)
            return {'message': f'User {user_name} updated successfully'}
        except ClientError as e:
            logger.error("user_update_failed", error=str(e))
            raise

    # ==================== Access Key Management ====================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def create_access_key(self, user_name: str) -> dict[str, Any]:
        """Create access key for user"""
        try:
            response = self.iam_client.create_access_key(UserName=user_name)
            logger.info("access_key_created", user_name=user_name)
            return response['AccessKey']
        except ClientError as e:
            logger.error("access_key_creation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def delete_access_key(self, user_name: str, access_key_id: str) -> dict[str, str]:
        """Delete an access key"""
        try:
            self.iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            logger.info("access_key_deleted", user_name=user_name, access_key_id=access_key_id)
            return {'message': f'Access key {access_key_id} deleted successfully'}
        except ClientError as e:
            logger.error("access_key_deletion_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def list_access_keys(self, user_name: str) -> list[dict[str, Any]]:
        """List access keys for a user"""
        try:
            response = self.iam_client.list_access_keys(UserName=user_name)
            return response['AccessKeyMetadata']
        except ClientError as e:
            logger.error("list_access_keys_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def update_access_key(self, user_name: str, access_key_id: str, status: str) -> dict[str, str]:
        """Update access key status (Active/Inactive)"""
        try:
            self.iam_client.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status=status)
            logger.info("access_key_updated", user_name=user_name, access_key_id=access_key_id, status=status)
            return {'message': f'Access key {access_key_id} status updated to {status}'}
        except ClientError as e:
            logger.error("access_key_update_failed", error=str(e))
            raise

    # ==================== Group Management ====================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def create_group(self, group_name: str, path: str = "/") -> dict[str, Any]:
        """Create a new IAM group"""
        try:
            response = self.iam_client.create_group(GroupName=group_name, Path=path)
            logger.info("group_created", group_name=group_name)
            return response['Group']
        except ClientError as e:
            logger.error("group_creation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def delete_group(self, group_name: str, force: bool = False) -> dict[str, str]:
        """Delete an IAM group"""
        try:
            if force:
                self._cleanup_group_dependencies(group_name)

            self.iam_client.delete_group(GroupName=group_name)
            logger.info("group_deleted", group_name=group_name)
            return {'message': f'Group {group_name} deleted successfully'}
        except ClientError as e:
            logger.error("group_deletion_failed", error=str(e))
            raise

    def _cleanup_group_dependencies(self, group_name: str):
        """Remove all group dependencies before deletion"""
        # Detach managed policies
        try:
            policies = self.iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in policies['AttachedPolicies']:
                self.iam_client.detach_group_policy(GroupName=group_name, PolicyArn=policy['PolicyArn'])
        except ClientError:
            pass

        # Delete inline policies
        try:
            policies = self.iam_client.list_group_policies(GroupName=group_name)
            for policy_name in policies['PolicyNames']:
                self.iam_client.delete_group_policy(GroupName=group_name, PolicyName=policy_name)
        except ClientError:
            pass

        # Remove users from group
        try:
            response = self.iam_client.get_group(GroupName=group_name)
            for user in response.get('Users', []):
                self.iam_client.remove_user_from_group(GroupName=group_name, UserName=user['UserName'])
        except ClientError:
            pass

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def add_user_to_group(self, group_name: str, user_name: str) -> dict[str, str]:
        """Add user to group"""
        try:
            self.iam_client.add_user_to_group(GroupName=group_name, UserName=user_name)
            logger.info("user_added_to_group", group_name=group_name, user_name=user_name)
            return {'message': f'User {user_name} added to group {group_name}'}
        except ClientError as e:
            logger.error("add_user_to_group_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def remove_user_from_group(self, group_name: str, user_name: str) -> dict[str, str]:
        """Remove user from group"""
        try:
            self.iam_client.remove_user_from_group(GroupName=group_name, UserName=user_name)
            logger.info("user_removed_from_group", group_name=group_name, user_name=user_name)
            return {'message': f'User {user_name} removed from group {group_name}'}
        except ClientError as e:
            logger.error("remove_user_from_group_failed", error=str(e))
            raise

    # ==================== Role Management ====================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def create_role(self, role_name: str, assume_role_policy: dict[str, Any], description: str = "", max_session_duration: int = 3600, path: str = "/", permissions_boundary: str | None = None, tags: list[dict[str, str]] | None = None) -> dict[str, Any]:
        """Create a new IAM role"""
        try:
            params = {
                'RoleName': role_name,
                'AssumeRolePolicyDocument': json.dumps(assume_role_policy),
                'Path': path,
                'MaxSessionDuration': max_session_duration
            }
            if description:
                params['Description'] = description
            if permissions_boundary:
                params['PermissionsBoundary'] = permissions_boundary
            if tags:
                params['Tags'] = tags

            response = self.iam_client.create_role(**params)
            logger.info("role_created", role_name=role_name)
            return response['Role']
        except ClientError as e:
            logger.error("role_creation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def delete_role(self, role_name: str, force: bool = False) -> dict[str, str]:
        """Delete an IAM role"""
        try:
            if force:
                self._cleanup_role_dependencies(role_name)

            self.iam_client.delete_role(RoleName=role_name)
            logger.info("role_deleted", role_name=role_name)
            return {'message': f'Role {role_name} deleted successfully'}
        except ClientError as e:
            logger.error("role_deletion_failed", error=str(e))
            raise

    def _cleanup_role_dependencies(self, role_name: str):
        """Remove all role dependencies before deletion"""
        # Detach managed policies
        try:
            policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in policies['AttachedPolicies']:
                self.iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
        except ClientError:
            pass

        # Delete inline policies
        try:
            policies = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in policies['PolicyNames']:
                self.iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError:
            pass

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def update_role(self, role_name: str, description: str | None = None, max_session_duration: int | None = None) -> dict[str, str]:
        """Update an IAM role"""
        try:
            if description is not None:
                self.iam_client.update_role_description(RoleName=role_name, Description=description)
            if max_session_duration is not None:
                self.iam_client.update_role(RoleName=role_name, MaxSessionDuration=max_session_duration)

            logger.info("role_updated", role_name=role_name)
            return {'message': f'Role {role_name} updated successfully'}
        except ClientError as e:
            logger.error("role_update_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def update_assume_role_policy(self, role_name: str, assume_role_policy: dict[str, Any]) -> dict[str, str]:
        """Update role trust policy"""
        try:
            self.iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(assume_role_policy)
            )
            logger.info("assume_role_policy_updated", role_name=role_name)
            return {'message': f'Trust policy for role {role_name} updated successfully'}
        except ClientError as e:
            logger.error("assume_role_policy_update_failed", error=str(e))
            raise

    # ==================== Policy Management ====================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def create_managed_policy(self, policy_name: str, policy_document: dict[str, Any], description: str = "", path: str = "/", tags: list[dict[str, str]] | None = None) -> dict[str, Any]:
        """Create a managed policy"""
        try:
            params = {
                'PolicyName': policy_name,
                'PolicyDocument': json.dumps(policy_document),
                'Path': path
            }
            if description:
                params['Description'] = description
            if tags:
                params['Tags'] = tags

            response = self.iam_client.create_policy(**params)
            logger.info("policy_created", policy_arn=response['Policy']['Arn'])
            return response['Policy']
        except ClientError as e:
            logger.error("policy_creation_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def delete_managed_policy(self, policy_arn: str, force: bool = False) -> dict[str, str]:
        """Delete a managed policy"""
        try:
            if force:
                self._cleanup_policy_dependencies(policy_arn)

            # Delete all non-default versions
            versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
            for version in versions['Versions']:
                if not version['IsDefaultVersion']:
                    self.iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=version['VersionId'])

            self.iam_client.delete_policy(PolicyArn=policy_arn)
            logger.info("policy_deleted", policy_arn=policy_arn)
            return {'message': f'Policy {policy_arn} deleted successfully'}
        except ClientError as e:
            logger.error("policy_deletion_failed", error=str(e))
            raise

    def _cleanup_policy_dependencies(self, policy_arn: str):
        """Detach policy from all principals"""
        # Detach from users
        try:
            entities = self.iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='User')
            for user in entities.get('PolicyUsers', []):
                self.iam_client.detach_user_policy(UserName=user['UserName'], PolicyArn=policy_arn)
        except ClientError:
            pass

        # Detach from groups
        try:
            entities = self.iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='Group')
            for group in entities.get('PolicyGroups', []):
                self.iam_client.detach_group_policy(GroupName=group['GroupName'], PolicyArn=policy_arn)
        except ClientError:
            pass

        # Detach from roles
        try:
            entities = self.iam_client.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter='Role')
            for role in entities.get('PolicyRoles', []):
                self.iam_client.detach_role_policy(RoleName=role['RoleName'], PolicyArn=policy_arn)
        except ClientError:
            pass

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def attach_policy_to_user(self, user_name: str, policy_arn: str) -> dict[str, str]:
        """Attach policy to user"""
        try:
            self.iam_client.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            logger.info("policy_attached_to_user", user_name=user_name, policy_arn=policy_arn)
            return {'message': f'Policy attached to user {user_name}'}
        except ClientError as e:
            logger.error("attach_policy_to_user_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def detach_policy_from_user(self, user_name: str, policy_arn: str) -> dict[str, str]:
        """Detach policy from user"""
        try:
            self.iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            logger.info("policy_detached_from_user", user_name=user_name, policy_arn=policy_arn)
            return {'message': f'Policy detached from user {user_name}'}
        except ClientError as e:
            logger.error("detach_policy_from_user_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def attach_policy_to_group(self, group_name: str, policy_arn: str) -> dict[str, str]:
        """Attach policy to group"""
        try:
            self.iam_client.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
            logger.info("policy_attached_to_group", group_name=group_name, policy_arn=policy_arn)
            return {'message': f'Policy attached to group {group_name}'}
        except ClientError as e:
            logger.error("attach_policy_to_group_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def detach_policy_from_group(self, group_name: str, policy_arn: str) -> dict[str, str]:
        """Detach policy from group"""
        try:
            self.iam_client.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
            logger.info("policy_detached_from_group", group_name=group_name, policy_arn=policy_arn)
            return {'message': f'Policy detached from group {group_name}'}
        except ClientError as e:
            logger.error("detach_policy_from_group_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def attach_policy_to_role(self, role_name: str, policy_arn: str) -> dict[str, str]:
        """Attach policy to role"""
        try:
            self.iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            logger.info("policy_attached_to_role", role_name=role_name, policy_arn=policy_arn)
            return {'message': f'Policy attached to role {role_name}'}
        except ClientError as e:
            logger.error("attach_policy_to_role_failed", error=str(e))
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def detach_policy_from_role(self, role_name: str, policy_arn: str) -> dict[str, str]:
        """Detach policy from role"""
        try:
            self.iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            logger.info("policy_detached_from_role", role_name=role_name, policy_arn=policy_arn)
            return {'message': f'Policy detached from role {role_name}'}
        except ClientError as e:
            logger.error("detach_policy_from_role_failed", error=str(e))
            raise

    # ==================== Password & Account Settings ====================

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def update_account_password_policy(self, **policy_settings) -> dict[str, str]:
        """Update account password policy"""
        try:
            self.iam_client.update_account_password_policy(**policy_settings)
            logger.info("password_policy_updated")
            return {'message': 'Account password policy updated successfully'}
        except ClientError as e:
            logger.error("password_policy_update_failed", error=str(e))
            raise

    @property
    def client(self):
        """Get the IAM client"""
        return self.iam_client

    def validate_policy_document(self, policy_document: dict[str, Any]) -> dict[str, Any]:
        """Validate IAM policy document structure"""
        required_fields = ['Version', 'Statement']
        errors = []

        # Check required fields
        for field in required_fields:
            if field not in policy_document:
                errors.append(f"Missing required field: {field}")

        # Validate version
        if 'Version' in policy_document and policy_document['Version'] not in ['2012-10-17', '2008-10-17']:
            errors.append(f"Invalid Version: {policy_document['Version']}")

        # Validate statements
        if 'Statement' in policy_document:
            statements = policy_document['Statement']
            if not isinstance(statements, list):
                errors.append("Statement must be a list")
            else:
                for idx, stmt in enumerate(statements):
                    if 'Effect' not in stmt:
                        errors.append(f"Statement {idx}: Missing Effect")
                    if stmt.get('Effect') not in ['Allow', 'Deny']:
                        errors.append(f"Statement {idx}: Invalid Effect")
                    if 'Action' not in stmt and 'NotAction' not in stmt:
                        errors.append(f"Statement {idx}: Missing Action or NotAction")

        return {
            'valid': len(errors) == 0,
            'errors': errors
        }
