"""
IAM audit service for analyzing permissions and generating recommendations
"""
from datetime import datetime
from typing import Any
import structlog

from app.services.iam_service import IAMService
from app.services.bedrock_service import BedrockService

logger = structlog.get_logger(__name__)


class AuditService:
    """Service for auditing IAM configurations"""

    def __init__(self, iam_service: IAMService, bedrock_service: BedrockService):
        """Initialize audit service"""
        self.iam_service = iam_service
        self.bedrock_service = bedrock_service

    def audit_account(self, aws_account_id: str, audit_scope: str = "all") -> dict[str, Any]:
        """
        Audit IAM configuration for an AWS account

        Args:
            aws_account_id: AWS account ID to audit
            audit_scope: Scope of audit (roles, users, groups, policies, account_settings, identity_providers, or all)

        Returns:
            Dict containing audit findings and recommendations
        """
        logger.info("audit_started", account_id=aws_account_id, scope=audit_scope)

        findings = []
        stats = {
            'total_resources': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'total_excessive_permissions': 0,
            'users_count': 0,
            'roles_count': 0,
            'groups_count': 0,
            'policies_count': 0,
            'unused_credentials': 0,
            'mfa_not_enabled': 0,
            'old_access_keys': 0
        }

        try:
            # Get comprehensive IAM details
            auth_details = self.iam_service.get_account_authorization_details()

            # Audit based on scope
            if audit_scope in ['roles', 'all']:
                role_findings = self._audit_roles(auth_details['roles'])
                findings.extend(role_findings)
                stats['roles_count'] = len(auth_details['roles'])
                stats['total_resources'] += len(auth_details['roles'])

            if audit_scope in ['users', 'all']:
                user_findings = self._audit_users(auth_details['users'])
                findings.extend(user_findings)
                stats['users_count'] = len(auth_details['users'])
                stats['total_resources'] += len(auth_details['users'])

            if audit_scope in ['groups', 'all']:
                group_findings = self._audit_groups(auth_details.get('groups', []))
                findings.extend(group_findings)
                stats['groups_count'] = len(auth_details.get('groups', []))
                stats['total_resources'] += len(auth_details.get('groups', []))

            if audit_scope in ['policies', 'all']:
                policy_findings = self._audit_policies(auth_details.get('policies', []))
                findings.extend(policy_findings)
                stats['policies_count'] = len(auth_details.get('policies', []))
                stats['total_resources'] += len(auth_details.get('policies', []))

            if audit_scope in ['account_settings', 'all']:
                account_findings = self._audit_account_settings()
                findings.extend(account_findings)

            if audit_scope in ['identity_providers', 'all']:
                idp_findings = self._audit_identity_providers()
                findings.extend(idp_findings)

            # Calculate stats from findings
            for finding in findings:
                severity = finding.get('severity', 'low')
                if severity == 'high':
                    stats['high_risk'] += 1
                elif severity == 'medium':
                    stats['medium_risk'] += 1
                else:
                    stats['low_risk'] += 1

                if finding.get('permission_reduction_percent'):
                    stats['total_excessive_permissions'] += finding['permission_reduction_percent']

                # Track specific issue types
                finding_type = finding.get('finding_type', '')
                if 'unused_credential' in finding_type:
                    stats['unused_credentials'] += 1
                if 'mfa_not_enabled' in finding_type:
                    stats['mfa_not_enabled'] += 1
                if 'old_access_key' in finding_type:
                    stats['old_access_keys'] += 1

            logger.info("audit_completed", account_id=aws_account_id, findings_count=len(findings))

            return {
                'findings': findings,
                'stats': stats,
                'audited_at': datetime.utcnow().isoformat(),
                'account_id': aws_account_id
            }

        except Exception as e:
            logger.error("audit_failed", account_id=aws_account_id, error=str(e))
            raise

    def _audit_roles(self, roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Audit IAM roles for excessive permissions"""
        findings = []

        for role in roles:
            role_name = role['RoleName']
            role_arn = role['Arn']

            logger.debug("auditing_role", role_name=role_name)

            # Check for overly permissive policies
            attached_policies = role.get('AttachedManagedPolicies', [])
            inline_policies = role.get('RolePolicyList', [])

            # Check for AdministratorAccess
            if any(p['PolicyName'] == 'AdministratorAccess' for p in attached_policies):
                findings.append({
                    'resource_type': 'role',
                    'resource_name': role_name,
                    'resource_arn': role_arn,
                    'severity': 'high',
                    'finding': 'Role has AdministratorAccess policy attached',
                    'recommendation': 'Replace with least-privilege policy specific to role requirements',
                    'permission_reduction_percent': 90
                })

            # Check for wildcard actions in inline policies
            for inline_policy in inline_policies:
                policy_doc = inline_policy.get('PolicyDocument', {})
                if self._has_wildcard_actions(policy_doc):
                    findings.append({
                        'resource_type': 'role',
                        'resource_name': role_name,
                        'resource_arn': role_arn,
                        'severity': 'high',
                        'finding': f'Inline policy "{inline_policy["PolicyName"]}" contains wildcard actions',
                        'recommendation': 'Replace wildcard actions with specific permissions',
                        'permission_reduction_percent': 70
                    })

            # Check trust policy
            assume_role_policy = role.get('AssumeRolePolicyDocument', {})
            if self._has_overly_permissive_trust(assume_role_policy):
                findings.append({
                    'resource_type': 'role',
                    'resource_name': role_name,
                    'resource_arn': role_arn,
                    'severity': 'high',
                    'finding': 'Role has overly permissive trust policy',
                    'recommendation': 'Restrict trust policy to specific principals',
                    'permission_reduction_percent': 0
                })

        return findings

    def _audit_users(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Audit IAM users for security issues"""
        findings = []
        from datetime import timedelta, timezone

        for user in users:
            user_name = user['UserName']
            user_arn = user['Arn']
            user_create_date = user.get('CreateDate')

            # Check for users with access keys
            access_keys = user.get('AccessKeyMetadata', [])
            if access_keys:
                for key in access_keys:
                    key_create_date = key.get('CreateDate')
                    if key_create_date:
                        # Make sure we have timezone-aware datetime
                        if key_create_date.tzinfo is None:
                            key_create_date = key_create_date.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        key_age_days = (now - key_create_date).days
                    else:
                        key_age_days = 0

                    # Check for old access keys (>90 days)
                    if key_age_days > 90:
                        findings.append({
                            'resource_type': 'user',
                            'resource_name': user_name,
                            'resource_arn': user_arn,
                            'severity': 'high',
                            'finding': f'Access key is {key_age_days} days old (should be rotated every 90 days)',
                            'finding_type': 'old_access_key',
                            'recommendation': 'Rotate access key and implement automated rotation',
                            'permission_reduction_percent': 0,
                            'metadata': {'key_id': key.get('AccessKeyId'), 'age_days': key_age_days}
                        })

                    # General warning about access keys
                    findings.append({
                        'resource_type': 'user',
                        'resource_name': user_name,
                        'resource_arn': user_arn,
                        'severity': 'medium',
                        'finding': 'User has access keys (consider using IAM roles instead)',
                        'finding_type': 'access_key_exists',
                        'recommendation': 'Migrate to IAM roles for applications, use temporary credentials',
                        'permission_reduction_percent': 0
                    })

            # Check for MFA
            if not user.get('MFADevices') or len(user.get('MFADevices', [])) == 0:
                findings.append({
                    'resource_type': 'user',
                    'resource_name': user_name,
                    'resource_arn': user_arn,
                    'severity': 'high',
                    'finding': 'User does not have MFA enabled',
                    'finding_type': 'mfa_not_enabled',
                    'recommendation': 'Enable MFA for all IAM users, especially those with console access',
                    'permission_reduction_percent': 0
                })

            # Check for users with admin access
            attached_policies = user.get('AttachedManagedPolicies', [])
            if any(p['PolicyName'] == 'AdministratorAccess' for p in attached_policies):
                findings.append({
                    'resource_type': 'user',
                    'resource_name': user_name,
                    'resource_arn': user_arn,
                    'severity': 'high',
                    'finding': 'User has AdministratorAccess policy',
                    'finding_type': 'admin_access',
                    'recommendation': 'Remove admin access, grant specific permissions only',
                    'permission_reduction_percent': 90
                })

            # Check for inline policies (should use managed policies)
            inline_policies = user.get('UserPolicyList', [])
            if inline_policies:
                findings.append({
                    'resource_type': 'user',
                    'resource_name': user_name,
                    'resource_arn': user_arn,
                    'severity': 'medium',
                    'finding': f'User has {len(inline_policies)} inline policies (should use managed policies)',
                    'finding_type': 'inline_policy',
                    'recommendation': 'Convert inline policies to managed policies for better reusability and management',
                    'permission_reduction_percent': 0
                })

            # Check for unused users (no password last used, no access key last used)
            password_last_used = user.get('PasswordLastUsed')
            if not password_last_used and not access_keys:
                if user_create_date:
                    # Make sure we have timezone-aware datetime
                    if user_create_date.tzinfo is None:
                        user_create_date = user_create_date.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    user_age_days = (now - user_create_date).days
                else:
                    user_age_days = 0

                if user_age_days > 30:
                    findings.append({
                        'resource_type': 'user',
                        'resource_name': user_name,
                        'resource_arn': user_arn,
                        'severity': 'low',
                        'finding': f'User has not been used in {user_age_days} days',
                        'finding_type': 'unused_credential',
                        'recommendation': 'Consider removing unused IAM user',
                        'permission_reduction_percent': 0
                    })

        return findings

    def _has_wildcard_actions(self, policy_document: dict[str, Any]) -> bool:
        """Check if policy contains wildcard actions"""
        statements = policy_document.get('Statement', [])
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if '*' in actions or any(action.endswith(':*') for action in actions):
                    return True
        return False

    def _has_overly_permissive_trust(self, assume_role_policy: dict[str, Any]) -> bool:
        """Check if trust policy is overly permissive"""
        statements = assume_role_policy.get('Statement', [])
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                # Check for wildcard principals
                if principal == '*' or principal.get('AWS') == '*':
                    return True
        return False

    def _audit_groups(self, groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Audit IAM groups for security issues"""
        findings = []

        for group in groups:
            group_name = group['GroupName']
            group_arn = group['Arn']

            # Check for empty groups
            group_users = group.get('GroupPolicyList', [])
            if not group_users:
                findings.append({
                    'resource_type': 'group',
                    'resource_name': group_name,
                    'resource_arn': group_arn,
                    'severity': 'low',
                    'finding': 'Group has no members',
                    'finding_type': 'empty_group',
                    'recommendation': 'Consider removing unused group',
                    'permission_reduction_percent': 0
                })

            # Check for admin access
            attached_policies = group.get('AttachedManagedPolicies', [])
            if any(p['PolicyName'] == 'AdministratorAccess' for p in attached_policies):
                findings.append({
                    'resource_type': 'group',
                    'resource_name': group_name,
                    'resource_arn': group_arn,
                    'severity': 'high',
                    'finding': 'Group has AdministratorAccess policy',
                    'finding_type': 'admin_access',
                    'recommendation': 'Limit admin access to specific users, not groups',
                    'permission_reduction_percent': 90
                })

            # Check for inline policies
            inline_policies = group.get('GroupPolicyList', [])
            if inline_policies:
                for inline_policy in inline_policies:
                    policy_doc = inline_policy.get('PolicyDocument', {})
                    if self._has_wildcard_actions(policy_doc):
                        findings.append({
                            'resource_type': 'group',
                            'resource_name': group_name,
                            'resource_arn': group_arn,
                            'severity': 'high',
                            'finding': f'Inline policy "{inline_policy["PolicyName"]}" contains wildcard actions',
                            'finding_type': 'wildcard_permission',
                            'recommendation': 'Replace wildcard actions with specific permissions',
                            'permission_reduction_percent': 70
                        })

        return findings

    def _audit_policies(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Audit IAM policies for security issues"""
        findings = []

        for policy in policies:
            policy_name = policy['PolicyName']
            policy_arn = policy['Arn']
            is_attached = policy.get('AttachmentCount', 0) > 0

            # Check for unused policies
            if not is_attached:
                findings.append({
                    'resource_type': 'policy',
                    'resource_name': policy_name,
                    'resource_arn': policy_arn,
                    'severity': 'low',
                    'finding': 'Policy is not attached to any users, groups, or roles',
                    'finding_type': 'unused_policy',
                    'recommendation': 'Consider removing unused policy',
                    'permission_reduction_percent': 0
                })

            # Check for overly permissive actions in policy versions
            default_version = policy.get('DefaultVersionId')
            for policy_version in policy.get('PolicyVersionList', []):
                if policy_version.get('VersionId') == default_version:
                    policy_doc = policy_version.get('Document', {})

                    if self._has_wildcard_actions(policy_doc):
                        findings.append({
                            'resource_type': 'policy',
                            'resource_name': policy_name,
                            'resource_arn': policy_arn,
                            'severity': 'high',
                            'finding': 'Policy contains wildcard actions (*:* or service:*)',
                            'finding_type': 'wildcard_permission',
                            'recommendation': 'Scope down to specific actions needed',
                            'permission_reduction_percent': 70
                        })

                    # Check for full resource access
                    if self._has_wildcard_resources(policy_doc):
                        findings.append({
                            'resource_type': 'policy',
                            'resource_name': policy_name,
                            'resource_arn': policy_arn,
                            'severity': 'medium',
                            'finding': 'Policy grants access to all resources (*)',
                            'finding_type': 'wildcard_resource',
                            'recommendation': 'Scope down to specific resources',
                            'permission_reduction_percent': 50
                        })

        return findings

    def _audit_account_settings(self) -> list[dict[str, Any]]:
        """Audit account-level IAM settings"""
        findings = []

        try:
            # Check password policy
            password_policy = self.iam_service.client.get_account_password_policy()
            policy = password_policy.get('PasswordPolicy', {})

            if not policy.get('RequireUppercaseCharacters'):
                findings.append({
                    'resource_type': 'account_setting',
                    'resource_name': 'PasswordPolicy',
                    'resource_arn': 'N/A',
                    'severity': 'medium',
                    'finding': 'Password policy does not require uppercase characters',
                    'finding_type': 'weak_password_policy',
                    'recommendation': 'Enable uppercase character requirement',
                    'permission_reduction_percent': 0
                })

            if not policy.get('RequireLowercaseCharacters'):
                findings.append({
                    'resource_type': 'account_setting',
                    'resource_name': 'PasswordPolicy',
                    'resource_arn': 'N/A',
                    'severity': 'medium',
                    'finding': 'Password policy does not require lowercase characters',
                    'finding_type': 'weak_password_policy',
                    'recommendation': 'Enable lowercase character requirement',
                    'permission_reduction_percent': 0
                })

            if not policy.get('RequireNumbers'):
                findings.append({
                    'resource_type': 'account_setting',
                    'resource_name': 'PasswordPolicy',
                    'resource_arn': 'N/A',
                    'severity': 'medium',
                    'finding': 'Password policy does not require numbers',
                    'finding_type': 'weak_password_policy',
                    'recommendation': 'Enable number requirement',
                    'permission_reduction_percent': 0
                })

            if not policy.get('RequireSymbols'):
                findings.append({
                    'resource_type': 'account_setting',
                    'resource_name': 'PasswordPolicy',
                    'resource_arn': 'N/A',
                    'severity': 'medium',
                    'finding': 'Password policy does not require symbols',
                    'finding_type': 'weak_password_policy',
                    'recommendation': 'Enable symbol requirement',
                    'permission_reduction_percent': 0
                })

            min_length = policy.get('MinimumPasswordLength', 0)
            if min_length < 14:
                findings.append({
                    'resource_type': 'account_setting',
                    'resource_name': 'PasswordPolicy',
                    'resource_arn': 'N/A',
                    'severity': 'high',
                    'finding': f'Password minimum length is {min_length} (should be at least 14)',
                    'finding_type': 'weak_password_policy',
                    'recommendation': 'Increase minimum password length to 14 or more',
                    'permission_reduction_percent': 0
                })

            if not policy.get('ExpirePasswords'):
                findings.append({
                    'resource_type': 'account_setting',
                    'resource_name': 'PasswordPolicy',
                    'resource_arn': 'N/A',
                    'severity': 'medium',
                    'finding': 'Passwords do not expire',
                    'finding_type': 'weak_password_policy',
                    'recommendation': 'Enable password expiration (recommend 90 days)',
                    'permission_reduction_percent': 0
                })

        except self.iam_service.client.exceptions.NoSuchEntityException:
            findings.append({
                'resource_type': 'account_setting',
                'resource_name': 'PasswordPolicy',
                'resource_arn': 'N/A',
                'severity': 'high',
                'finding': 'No password policy configured',
                'finding_type': 'missing_password_policy',
                'recommendation': 'Configure a strong password policy',
                'permission_reduction_percent': 0
            })
        except Exception as e:
            logger.warning("password_policy_check_failed", error=str(e))

        return findings

    def _audit_identity_providers(self) -> list[dict[str, Any]]:
        """Audit SAML and OIDC identity providers"""
        findings = []
        from datetime import timezone

        try:
            # List SAML providers
            saml_providers = self.iam_service.client.list_saml_providers()
            for provider in saml_providers.get('SAMLProviderList', []):
                # Get provider details
                provider_arn = provider['Arn']
                provider_response = self.iam_service.client.get_saml_provider(SAMLProviderArn=provider_arn)

                create_date = provider_response.get('CreateDate')
                if create_date:
                    # Make sure we have timezone-aware datetime
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    age_days = (now - create_date).days

                    if age_days > 365:
                        findings.append({
                            'resource_type': 'identity_provider',
                            'resource_name': provider_arn.split('/')[-1],
                            'resource_arn': provider_arn,
                            'severity': 'medium',
                            'finding': f'SAML provider metadata is {age_days} days old',
                            'finding_type': 'old_saml_metadata',
                            'recommendation': 'Review and update SAML provider metadata regularly',
                            'permission_reduction_percent': 0
                        })

        except Exception as e:
            logger.warning("saml_provider_check_failed", error=str(e))

        try:
            # List OIDC providers
            oidc_providers = self.iam_service.client.list_open_id_connect_providers()
            for provider in oidc_providers.get('OpenIDConnectProviderList', []):
                provider_arn = provider['Arn']
                # Additional checks can be added here
                logger.debug("oidc_provider_found", arn=provider_arn)

        except Exception as e:
            logger.warning("oidc_provider_check_failed", error=str(e))

        return findings

    def _has_wildcard_resources(self, policy_document: dict[str, Any]) -> bool:
        """Check if policy grants access to all resources"""
        statements = policy_document.get('Statement', [])
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                if '*' in resources:
                    return True
        return False

    def generate_access_graph(self, aws_account_id: str) -> dict[str, Any]:
        """
        Generate an access graph showing relationships between IAM entities

        Returns:
            Dict with nodes and edges for visualization
        """
        logger.info("generating_access_graph", account_id=aws_account_id)

        try:
            auth_details = self.iam_service.get_account_authorization_details()

            nodes = []
            edges = []

            # Create nodes for roles
            for role in auth_details['roles']:
                nodes.append({
                    'id': role['Arn'],
                    'type': 'role',
                    'name': role['RoleName'],
                    'arn': role['Arn']
                })

                # Create edges for attached policies
                for policy in role.get('AttachedManagedPolicies', []):
                    nodes.append({
                        'id': policy['PolicyArn'],
                        'type': 'policy',
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn']
                    })
                    edges.append({
                        'source': role['Arn'],
                        'target': policy['PolicyArn'],
                        'relationship': 'attached'
                    })

            # Create nodes for users
            for user in auth_details['users']:
                nodes.append({
                    'id': user['Arn'],
                    'type': 'user',
                    'name': user['UserName'],
                    'arn': user['Arn']
                })

                # Create edges for attached policies
                for policy in user.get('AttachedManagedPolicies', []):
                    if not any(n['id'] == policy['PolicyArn'] for n in nodes):
                        nodes.append({
                            'id': policy['PolicyArn'],
                            'type': 'policy',
                            'name': policy['PolicyName'],
                            'arn': policy['PolicyArn']
                        })
                    edges.append({
                        'source': user['Arn'],
                        'target': policy['PolicyArn'],
                        'relationship': 'attached'
                    })

            # Deduplicate nodes
            unique_nodes = {node['id']: node for node in nodes}.values()

            logger.info("access_graph_generated", nodes_count=len(unique_nodes), edges_count=len(edges))

            return {
                'nodes': list(unique_nodes),
                'edges': edges,
                'stats': {
                    'total_nodes': len(unique_nodes),
                    'total_edges': len(edges),
                    'roles': len([n for n in unique_nodes if n['type'] == 'role']),
                    'users': len([n for n in unique_nodes if n['type'] == 'user']),
                    'policies': len([n for n in unique_nodes if n['type'] == 'policy'])
                }
            }

        except Exception as e:
            logger.error("access_graph_generation_failed", error=str(e))
            raise
