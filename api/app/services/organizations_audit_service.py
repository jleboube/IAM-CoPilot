"""
AWS Organizations Audit Service

Performs security audits on AWS Organizations configuration, including:
- Service Control Policy (SCP) analysis
- Account organization and structure
- Policy attachment review
- Security best practices validation
"""

import json
from typing import Dict, List, Any, Optional
import logging
from .organizations_service import OrganizationsService

logger = logging.getLogger(__name__)


class OrganizationsAuditService:
    """Service for auditing AWS Organizations configuration."""

    # High-risk SCP patterns
    RISKY_SCP_PATTERNS = [
        '*:*',  # All actions on all resources
        'iam:*',  # All IAM actions
        'organizations:*',  # All Organizations actions
        'sts:AssumeRole'  # Unrestricted role assumption
    ]

    def __init__(self, role_arn: Optional[str] = None):
        """
        Initialize Organizations audit service.

        Args:
            role_arn: Optional cross-account role ARN
        """
        self.org_service = OrganizationsService(role_arn)
        self.findings = []
        self.resources_audited = 0

    def run_comprehensive_audit(self) -> Dict[str, Any]:
        """
        Run a comprehensive audit of AWS Organizations.

        Returns:
            Audit results with findings and statistics
        """
        self.findings = []
        self.resources_audited = 0

        try:
            # Get Organizations overview
            overview = self.org_service.get_organizations_overview()

            if not overview.get('enabled'):
                return {
                    'enabled': False,
                    'message': overview.get('message', 'Organizations not enabled'),
                    'findings': [],
                    'resources_audited': 0
                }

            organization = overview['organization']
            accounts = overview['accounts']
            scps = overview['service_control_policies']
            org_tree = overview['organizational_tree']

            # Audit organization configuration
            org_findings = self._audit_organization(organization)
            self.findings.extend(org_findings)

            # Audit accounts
            account_findings = self._audit_accounts(accounts, org_tree)
            self.findings.extend(account_findings)

            # Audit SCPs
            scp_findings = self._audit_service_control_policies(scps, accounts, org_tree)
            self.findings.extend(scp_findings)

            # Audit organizational structure
            structure_findings = self._audit_organizational_structure(org_tree, accounts)
            self.findings.extend(structure_findings)

            # Calculate statistics
            stats = self._calculate_statistics(overview)

            return {
                'enabled': True,
                'organization': organization,
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
            logger.error(f"Failed to run Organizations audit: {str(e)}")
            raise

    def _audit_organization(self, organization: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit organization-level configuration."""
        findings = []
        self.resources_audited += 1

        # Check feature set
        feature_set = organization.get('feature_set', '')
        if feature_set == 'CONSOLIDATED_BILLING':
            findings.append({
                'severity': 'MEDIUM',
                'resource_type': 'Organization',
                'resource_id': organization.get('id', 'N/A'),
                'finding_type': 'LimitedFeatureSet',
                'description': 'Organization is using CONSOLIDATED_BILLING feature set instead of ALL',
                'recommendation': 'Enable ALL feature set to use Service Control Policies and other advanced features',
                'details': {
                    'current_feature_set': feature_set,
                    'recommended_feature_set': 'ALL'
                }
            })

        # Check available policy types
        available_policies = organization.get('available_policy_types', [])
        policy_type_names = [pt.get('Type') for pt in available_policies]

        if 'SERVICE_CONTROL_POLICY' not in policy_type_names:
            findings.append({
                'severity': 'HIGH',
                'resource_type': 'Organization',
                'resource_id': organization.get('id', 'N/A'),
                'finding_type': 'SCPNotEnabled',
                'description': 'Service Control Policies (SCPs) are not enabled',
                'recommendation': 'Enable SCPs to enforce permissions boundaries across accounts',
                'details': {
                    'available_policy_types': policy_type_names
                }
            })

        return findings

    def _audit_accounts(self, accounts: List[Dict[str, Any]], org_tree: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audit account configurations."""
        findings = []

        for account in accounts:
            self.resources_audited += 1
            account_id = account.get('id')
            account_name = account.get('name', account_id)
            account_status = account.get('status')

            # Check for suspended accounts
            if account_status == 'SUSPENDED':
                findings.append({
                    'severity': 'MEDIUM',
                    'resource_type': 'Account',
                    'resource_id': account_name,
                    'finding_type': 'SuspendedAccount',
                    'description': f"Account '{account_name}' is suspended",
                    'recommendation': 'Review suspended account and either reactivate or close it',
                    'details': {
                        'account_id': account_id,
                        'status': account_status
                    }
                })

            # Check for accounts at root level (not in OUs)
            if self._is_account_at_root(account_id, org_tree):
                findings.append({
                    'severity': 'LOW',
                    'resource_type': 'Account',
                    'resource_id': account_name,
                    'finding_type': 'AccountAtRootLevel',
                    'description': f"Account '{account_name}' is at root level, not organized in an OU",
                    'recommendation': 'Organize accounts into OUs for better management and SCP application',
                    'details': {
                        'account_id': account_id
                    }
                })

        return findings

    def _audit_service_control_policies(
        self,
        scps: List[Dict[str, Any]],
        accounts: List[Dict[str, Any]],
        org_tree: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Audit Service Control Policies."""
        findings = []

        # Check if any SCPs exist beyond AWS managed defaults
        customer_scps = [scp for scp in scps if not scp.get('aws_managed', False)]

        if len(customer_scps) == 0:
            findings.append({
                'severity': 'MEDIUM',
                'resource_type': 'Organization',
                'resource_id': 'SCPs',
                'finding_type': 'NoCustomSCPs',
                'description': 'No custom Service Control Policies defined',
                'recommendation': 'Create SCPs to enforce security boundaries and compliance requirements',
                'details': {
                    'total_scps': len(scps),
                    'customer_scps': 0
                }
            })

        for scp in scps:
            self.resources_audited += 1
            scp_name = scp.get('name', scp.get('id'))
            scp_id = scp.get('id')

            # Skip AWS managed policies from detailed checks
            if scp.get('aws_managed', False):
                continue

            # Check SCP content
            content = scp.get('content', {})

            # Check for overly permissive SCPs
            if self._has_overly_permissive_scp(content):
                findings.append({
                    'severity': 'HIGH',
                    'resource_type': 'ServiceControlPolicy',
                    'resource_id': scp_name,
                    'finding_type': 'OverlyPermissiveSCP',
                    'description': f"SCP '{scp_name}' has overly permissive statements",
                    'recommendation': 'Review and restrict SCP to follow least privilege principle',
                    'details': {
                        'scp_id': scp_id,
                        'policy_content': content
                    }
                })

            # Check for SCPs without deny statements (less effective)
            if not self._has_deny_statements(content):
                findings.append({
                    'severity': 'INFO',
                    'resource_type': 'ServiceControlPolicy',
                    'resource_id': scp_name,
                    'finding_type': 'SCPWithoutDenyStatements',
                    'description': f"SCP '{scp_name}' has no explicit deny statements",
                    'recommendation': 'Consider using deny statements for more effective permission boundaries',
                    'details': {
                        'scp_id': scp_id
                    }
                })

            # Check if SCP is attached to any targets
            targets = scp.get('targets', [])
            if len(targets) == 0:
                findings.append({
                    'severity': 'LOW',
                    'resource_type': 'ServiceControlPolicy',
                    'resource_id': scp_name,
                    'finding_type': 'UnusedSCP',
                    'description': f"SCP '{scp_name}' is not attached to any targets",
                    'recommendation': 'Attach SCP to accounts/OUs or remove if not needed',
                    'details': {
                        'scp_id': scp_id
                    }
                })

            # Check if SCP affects management account
            management_account_in_targets = any(
                target.get('type') == 'ROOT' for target in targets
            )
            if management_account_in_targets:
                findings.append({
                    'severity': 'CRITICAL',
                    'resource_type': 'ServiceControlPolicy',
                    'resource_id': scp_name,
                    'finding_type': 'SCPAffectsManagementAccount',
                    'description': f"SCP '{scp_name}' may affect the management account",
                    'recommendation': 'SCPs do not apply to the management account, but this attachment could be misleading',
                    'details': {
                        'scp_id': scp_id,
                        'targets': targets
                    }
                })

        return findings

    def _audit_organizational_structure(
        self,
        org_tree: Dict[str, Any],
        accounts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Audit organizational structure."""
        findings = []

        # Count total OUs
        def count_ous(structure):
            count = len(structure.get('organizational_units', []))
            for ou in structure.get('organizational_units', []):
                count += count_ous(ou.get('children', {}))
            return count

        total_ous = sum(count_ous(root['structure']) for root in org_tree.get('roots', []))

        # Check if organization has minimal structure
        if total_ous == 0 and len(accounts) > 3:
            findings.append({
                'severity': 'MEDIUM',
                'resource_type': 'Organization',
                'resource_id': 'Structure',
                'finding_type': 'NoOrganizationalUnits',
                'description': f"Organization has {len(accounts)} accounts but no OUs",
                'recommendation': 'Create OUs to organize accounts by environment, team, or function',
                'details': {
                    'total_accounts': len(accounts),
                    'total_ous': 0
                }
            })

        # Check for deep OU nesting
        max_depth = self._get_max_ou_depth(org_tree)
        if max_depth > 5:
            findings.append({
                'severity': 'LOW',
                'resource_type': 'Organization',
                'resource_id': 'Structure',
                'finding_type': 'DeepOUNesting',
                'description': f"OU hierarchy is {max_depth} levels deep",
                'recommendation': 'Consider flattening OU structure for easier management',
                'details': {
                    'max_depth': max_depth
                }
            })

        return findings

    def _has_overly_permissive_scp(self, policy: Dict[str, Any]) -> bool:
        """Check if SCP has overly permissive statements."""
        if not policy or 'Statement' not in policy:
            return False

        for statement in policy.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for risky patterns
            for action in actions:
                if action in self.RISKY_SCP_PATTERNS or action == '*':
                    return True

            # Check for wildcard resources with broad actions
            if '*' in resources and len(actions) > 10:
                return True

        return False

    def _has_deny_statements(self, policy: Dict[str, Any]) -> bool:
        """Check if policy has any deny statements."""
        if not policy or 'Statement' not in policy:
            return False

        return any(
            stmt.get('Effect') == 'Deny'
            for stmt in policy.get('Statement', [])
        )

    def _is_account_at_root(self, account_id: str, org_tree: Dict[str, Any]) -> bool:
        """Check if account is directly under root (not in an OU)."""
        for root in org_tree.get('roots', []):
            root_accounts = root.get('structure', {}).get('accounts', [])
            if any(acc.get('id') == account_id for acc in root_accounts):
                return True
        return False

    def _get_max_ou_depth(self, org_tree: Dict[str, Any], current_depth: int = 0) -> int:
        """Get maximum depth of OU nesting."""
        max_depth = current_depth

        for root in org_tree.get('roots', []):
            structure = root.get('structure', {})
            depth = self._get_structure_depth(structure, 1)
            max_depth = max(max_depth, depth)

        return max_depth

    def _get_structure_depth(self, structure: Dict[str, Any], current_depth: int) -> int:
        """Recursively calculate structure depth."""
        ous = structure.get('organizational_units', [])
        if not ous:
            return current_depth

        max_depth = current_depth
        for ou in ous:
            children = ou.get('children', {})
            depth = self._get_structure_depth(children, current_depth + 1)
            max_depth = max(max_depth, depth)

        return max_depth

    def _calculate_statistics(self, overview: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate audit statistics."""
        scps = overview.get('service_control_policies', [])
        accounts = overview.get('accounts', [])

        customer_scps = [scp for scp in scps if not scp.get('aws_managed', False)]
        active_accounts = [acc for acc in accounts if acc.get('status') == 'ACTIVE']
        suspended_accounts = [acc for acc in accounts if acc.get('status') == 'SUSPENDED']

        # Count total SCP attachments
        total_attachments = sum(len(scp.get('targets', [])) for scp in scps)

        return {
            'organization': {
                'feature_set': overview.get('organization', {}).get('feature_set'),
                'policy_types_enabled': len(overview.get('organization', {}).get('available_policy_types', []))
            },
            'accounts': {
                'total': len(accounts),
                'active': len(active_accounts),
                'suspended': len(suspended_accounts)
            },
            'scps': {
                'total': len(scps),
                'customer_managed': len(customer_scps),
                'aws_managed': len(scps) - len(customer_scps),
                'total_attachments': total_attachments
            },
            'structure': {
                'total_ous': overview.get('stats', {}).get('total_ous', 0)
            }
        }
