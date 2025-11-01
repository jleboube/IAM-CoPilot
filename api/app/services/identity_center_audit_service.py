"""
AWS IAM Identity Center Audit Service

Performs security audits on IAM Identity Center (formerly AWS SSO) configuration, including:
- Permission Set analysis
- Account assignment review
- Identity Store user/group analysis
- Security best practices validation
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
import logging
from .identity_center_service import IdentityCenterService

logger = logging.getLogger(__name__)


class IdentityCenterAuditService:
    """Service for auditing AWS IAM Identity Center configuration."""

    # High-risk managed policies
    HIGH_RISK_POLICIES = [
        'AdministratorAccess',
        'PowerUserAccess',
        'IAMFullAccess',
        'SecurityAudit',
        'SystemAdministrator'
    ]

    # Recommended maximum session duration (8 hours)
    MAX_RECOMMENDED_SESSION_DURATION = 'PT8H'

    def __init__(self, aws_account_id: str, role_arn: Optional[str] = None, region: str = 'us-east-1'):
        """
        Initialize Identity Center audit service.

        Args:
            aws_account_id: AWS account ID
            role_arn: Optional cross-account role ARN
            region: AWS region
        """
        self.ic_service = IdentityCenterService(aws_account_id, role_arn, region)
        self.findings = []
        self.resources_audited = 0

    def run_comprehensive_audit(self) -> Dict[str, Any]:
        """
        Run a comprehensive audit of IAM Identity Center.

        Returns:
            Audit results with findings and statistics
        """
        self.findings = []
        self.resources_audited = 0

        try:
            # Get Identity Center overview
            overview = self.ic_service.get_identity_center_overview()

            if not overview.get('enabled'):
                return {
                    'enabled': False,
                    'message': overview.get('message', 'Identity Center not enabled'),
                    'findings': [],
                    'resources_audited': 0
                }

            instance = overview['instance']
            instance_arn = instance['instance_arn']
            identity_store_id = instance['identity_store_id']

            # Audit permission sets
            permission_set_findings = self._audit_permission_sets(
                instance_arn,
                overview['permission_sets'],
                overview['assignments']
            )
            self.findings.extend(permission_set_findings)

            # Audit assignments
            assignment_findings = self._audit_assignments(
                overview['assignments'],
                overview['permission_sets'],
                overview['users'],
                overview['groups']
            )
            self.findings.extend(assignment_findings)

            # Audit Identity Store users
            user_findings = self._audit_identity_store_users(
                identity_store_id,
                overview['users'],
                overview['assignments']
            )
            self.findings.extend(user_findings)

            # Audit Identity Store groups
            group_findings = self._audit_identity_store_groups(
                identity_store_id,
                overview['groups'],
                overview['assignments']
            )
            self.findings.extend(group_findings)

            # Audit organization accounts
            account_findings = self._audit_organization_accounts(
                overview['organization_accounts'],
                overview['assignments']
            )
            self.findings.extend(account_findings)

            # Calculate statistics
            stats = self._calculate_statistics(overview)

            return {
                'enabled': True,
                'instance': instance,
                'findings': self.findings,
                'resources_audited': self.resources_audited,
                'stats': stats,
                'summary': {
                    'total_findings': len(self.findings),
                    'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                    'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                    'medium': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                    'low': len([f for f in self.findings if f['severity'] == 'LOW']),
                    'info': len([f for f in self.findings if f['severity'] == 'INFO'])
                }
            }

        except Exception as e:
            logger.error(f"Failed to run Identity Center audit: {str(e)}")
            raise

    def _audit_permission_sets(
        self,
        instance_arn: str,
        permission_sets: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Audit permission sets for security issues."""
        findings = []

        for ps in permission_sets:
            self.resources_audited += 1
            ps_name = ps['name']
            ps_arn = ps['arn']

            # Check for high-risk managed policies
            for managed_policy in ps.get('managed_policies', []):
                policy_name = managed_policy.get('Name', '')
                if any(risky in policy_name for risky in self.HIGH_RISK_POLICIES):
                    findings.append({
                        'severity': 'HIGH',
                        'resource_type': 'PermissionSet',
                        'resource_id': ps_name,
                        'finding_type': 'HighRiskManagedPolicy',
                        'description': f"Permission set '{ps_name}' uses high-risk managed policy '{policy_name}'",
                        'recommendation': f"Review necessity of '{policy_name}' and consider using least-privilege custom policies",
                        'details': {
                            'permission_set_arn': ps_arn,
                            'policy_name': policy_name
                        }
                    })

            # Check for inline policies (should prefer managed policies)
            if ps.get('inline_policy'):
                inline_policy = json.loads(ps['inline_policy']) if isinstance(ps['inline_policy'], str) else ps['inline_policy']

                # Analyze inline policy for overly permissive actions
                if self._has_wildcard_permissions(inline_policy):
                    findings.append({
                        'severity': 'HIGH',
                        'resource_type': 'PermissionSet',
                        'resource_id': ps_name,
                        'finding_type': 'WildcardInlinePolicy',
                        'description': f"Permission set '{ps_name}' has inline policy with wildcard (*) permissions",
                        'recommendation': 'Replace wildcard permissions with specific actions following least privilege principle',
                        'details': {
                            'permission_set_arn': ps_arn,
                            'inline_policy': inline_policy
                        }
                    })
                else:
                    findings.append({
                        'severity': 'MEDIUM',
                        'resource_type': 'PermissionSet',
                        'resource_id': ps_name,
                        'finding_type': 'InlinePolicyUsage',
                        'description': f"Permission set '{ps_name}' uses inline policy instead of managed policies",
                        'recommendation': 'Consider using AWS managed policies or customer managed policies for better reusability',
                        'details': {
                            'permission_set_arn': ps_arn
                        }
                    })

            # Check for long session durations
            session_duration = ps.get('session_duration', 'PT1H')
            if self._compare_session_durations(session_duration, self.MAX_RECOMMENDED_SESSION_DURATION) > 0:
                findings.append({
                    'severity': 'MEDIUM',
                    'resource_type': 'PermissionSet',
                    'resource_id': ps_name,
                    'finding_type': 'LongSessionDuration',
                    'description': f"Permission set '{ps_name}' has session duration of {session_duration}, exceeding recommended maximum",
                    'recommendation': f"Reduce session duration to {self.MAX_RECOMMENDED_SESSION_DURATION} or less",
                    'details': {
                        'permission_set_arn': ps_arn,
                        'session_duration': session_duration,
                        'recommended_max': self.MAX_RECOMMENDED_SESSION_DURATION
                    }
                })

            # Check for unused permission sets
            ps_assignments = [a for a in assignments if a['permission_set_arn'] == ps_arn]
            if not ps_assignments:
                findings.append({
                    'severity': 'LOW',
                    'resource_type': 'PermissionSet',
                    'resource_id': ps_name,
                    'finding_type': 'UnusedPermissionSet',
                    'description': f"Permission set '{ps_name}' has no account assignments",
                    'recommendation': 'Remove unused permission sets to reduce attack surface',
                    'details': {
                        'permission_set_arn': ps_arn
                    }
                })

            # Check for permission sets with no policies
            has_policies = (
                ps.get('managed_policies') or
                ps.get('customer_managed_policies') or
                ps.get('inline_policy')
            )
            if not has_policies:
                findings.append({
                    'severity': 'INFO',
                    'resource_type': 'PermissionSet',
                    'resource_id': ps_name,
                    'finding_type': 'EmptyPermissionSet',
                    'description': f"Permission set '{ps_name}' has no attached policies",
                    'recommendation': 'Attach policies or remove this permission set',
                    'details': {
                        'permission_set_arn': ps_arn
                    }
                })

        return findings

    def _audit_assignments(
        self,
        assignments: List[Dict[str, Any]],
        permission_sets: List[Dict[str, Any]],
        users: List[Dict[str, Any]],
        groups: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Audit account assignments for security issues."""
        findings = []

        # Build lookup maps
        ps_map = {ps['arn']: ps for ps in permission_sets}

        # Track assignments per permission set
        ps_assignment_counts = {}
        for assignment in assignments:
            ps_arn = assignment['permission_set_arn']
            ps_assignment_counts[ps_arn] = ps_assignment_counts.get(ps_arn, 0) + 1

        # Check for permission sets assigned to many accounts
        for ps_arn, count in ps_assignment_counts.items():
            if count > 10:  # Threshold for "many accounts"
                ps = ps_map.get(ps_arn, {})
                ps_name = ps.get('name', ps_arn)
                findings.append({
                    'severity': 'MEDIUM',
                    'resource_type': 'PermissionSet',
                    'resource_id': ps_name,
                    'finding_type': 'WidelyAssignedPermissionSet',
                    'description': f"Permission set '{ps_name}' is assigned to {count} accounts/principals",
                    'recommendation': 'Review assignments to ensure least privilege across accounts',
                    'details': {
                        'permission_set_arn': ps_arn,
                        'assignment_count': count
                    }
                })

        # Check for high-risk permission sets with direct user assignments (should use groups)
        for assignment in assignments:
            if assignment['principal_type'] == 'USER':
                ps_arn = assignment['permission_set_arn']
                ps = ps_map.get(ps_arn, {})
                ps_name = ps.get('name', ps_arn)

                # Check if this is a high-risk permission set
                managed_policies = ps.get('managed_policies', [])
                is_high_risk = any(
                    any(risky in mp.get('Name', '') for risky in self.HIGH_RISK_POLICIES)
                    for mp in managed_policies
                )

                if is_high_risk:
                    findings.append({
                        'severity': 'HIGH',
                        'resource_type': 'AccountAssignment',
                        'resource_id': f"{ps_name}-{assignment['principal_id']}",
                        'finding_type': 'HighRiskDirectUserAssignment',
                        'description': f"High-risk permission set '{ps_name}' assigned directly to user instead of group",
                        'recommendation': 'Use group-based assignments for better access management',
                        'details': {
                            'permission_set_arn': ps_arn,
                            'principal_id': assignment['principal_id'],
                            'account_id': assignment['account_id']
                        }
                    })

        return findings

    def _audit_identity_store_users(
        self,
        identity_store_id: str,
        users: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Audit Identity Store users."""
        findings = []

        # Get all user IDs that have assignments
        assigned_user_ids = set(
            a['principal_id'] for a in assignments
            if a['principal_type'] == 'USER'
        )

        for user in users:
            self.resources_audited += 1
            user_id = user['user_id']
            user_name = user.get('user_name', user_id)

            # Check for users with no assignments
            if user_id not in assigned_user_ids:
                findings.append({
                    'severity': 'LOW',
                    'resource_type': 'IdentityStoreUser',
                    'resource_id': user_name,
                    'finding_type': 'UnusedUser',
                    'description': f"User '{user_name}' has no permission set assignments",
                    'recommendation': 'Review if this user account is still needed, or assign appropriate permissions',
                    'details': {
                        'user_id': user_id,
                        'identity_store_id': identity_store_id
                    }
                })

            # Check for users with no email
            emails = user.get('emails', [])
            if not emails:
                findings.append({
                    'severity': 'INFO',
                    'resource_type': 'IdentityStoreUser',
                    'resource_id': user_name,
                    'finding_type': 'MissingEmail',
                    'description': f"User '{user_name}' has no email address configured",
                    'recommendation': 'Add email address for user notifications and MFA',
                    'details': {
                        'user_id': user_id,
                        'identity_store_id': identity_store_id
                    }
                })

        return findings

    def _audit_identity_store_groups(
        self,
        identity_store_id: str,
        groups: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Audit Identity Store groups."""
        findings = []

        # Get all group IDs that have assignments
        assigned_group_ids = set(
            a['principal_id'] for a in assignments
            if a['principal_type'] == 'GROUP'
        )

        for group in groups:
            self.resources_audited += 1
            group_id = group['group_id']
            group_name = group.get('display_name', group_id)

            # Check for groups with no assignments
            if group_id not in assigned_group_ids:
                findings.append({
                    'severity': 'LOW',
                    'resource_type': 'IdentityStoreGroup',
                    'resource_id': group_name,
                    'finding_type': 'UnusedGroup',
                    'description': f"Group '{group_name}' has no permission set assignments",
                    'recommendation': 'Review if this group is still needed, or assign appropriate permissions',
                    'details': {
                        'group_id': group_id,
                        'identity_store_id': identity_store_id
                    }
                })

        return findings

    def _audit_organization_accounts(
        self,
        org_accounts: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Audit organization accounts for access patterns."""
        findings = []

        # Get all account IDs that have assignments
        assigned_account_ids = set(a['account_id'] for a in assignments)

        for account in org_accounts:
            self.resources_audited += 1
            account_id = account['id']
            account_name = account.get('name', account_id)
            account_status = account.get('status', 'UNKNOWN')

            # Check for active accounts with no assignments
            if account_status == 'ACTIVE' and account_id not in assigned_account_ids:
                findings.append({
                    'severity': 'INFO',
                    'resource_type': 'OrganizationAccount',
                    'resource_id': account_name,
                    'finding_type': 'NoIdentityCenterAccess',
                    'description': f"Active account '{account_name}' has no Identity Center assignments",
                    'recommendation': 'Review if this account should have Identity Center access configured',
                    'details': {
                        'account_id': account_id,
                        'account_status': account_status
                    }
                })

        return findings

    def _has_wildcard_permissions(self, policy: Dict[str, Any]) -> bool:
        """Check if a policy document contains wildcard (*) permissions."""
        if not policy or 'Statement' not in policy:
            return False

        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]

                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]

                # Check for wildcard in actions or resources
                if '*' in actions or '*' in resources:
                    return True

                # Check for broad actions like "s3:*" or "ec2:*"
                if any(':*' in action for action in actions):
                    return True

        return False

    def _compare_session_durations(self, duration1: str, duration2: str) -> int:
        """
        Compare two ISO 8601 duration strings.

        Returns:
            Negative if duration1 < duration2
            Zero if duration1 == duration2
            Positive if duration1 > duration2
        """
        def parse_duration(duration_str: str) -> int:
            """Convert ISO 8601 duration to seconds."""
            # Simple parser for PT#H format (e.g., PT1H, PT8H)
            if duration_str.startswith('PT') and duration_str.endswith('H'):
                hours = int(duration_str[2:-1])
                return hours * 3600
            # Handle PT#M format
            elif duration_str.startswith('PT') and duration_str.endswith('M'):
                minutes = int(duration_str[2:-1])
                return minutes * 60
            return 0

        seconds1 = parse_duration(duration1)
        seconds2 = parse_duration(duration2)

        return seconds1 - seconds2

    def _calculate_statistics(self, overview: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate audit statistics."""
        permission_sets = overview['permission_sets']
        assignments = overview['assignments']

        # Count permission sets by policy type
        ps_with_inline = sum(1 for ps in permission_sets if ps.get('inline_policy'))
        ps_with_managed = sum(1 for ps in permission_sets if ps.get('managed_policies'))
        ps_with_customer = sum(1 for ps in permission_sets if ps.get('customer_managed_policies'))

        # Count assignments by principal type
        user_assignments = sum(1 for a in assignments if a['principal_type'] == 'USER')
        group_assignments = sum(1 for a in assignments if a['principal_type'] == 'GROUP')

        # Count unique accounts with assignments
        unique_accounts = len(set(a['account_id'] for a in assignments))

        return {
            'permission_sets': {
                'total': len(permission_sets),
                'with_inline_policy': ps_with_inline,
                'with_managed_policies': ps_with_managed,
                'with_customer_managed_policies': ps_with_customer
            },
            'assignments': {
                'total': len(assignments),
                'user_assignments': user_assignments,
                'group_assignments': group_assignments,
                'unique_accounts': unique_accounts
            },
            'identity_store': {
                'total_users': len(overview['users']),
                'total_groups': len(overview['groups'])
            },
            'organization': {
                'total_accounts': len(overview['organization_accounts'])
            }
        }
