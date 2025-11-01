"""
AWS Organizations Service

Handles operations for AWS Organizations, including:
- Organization structure and accounts
- Organizational Units (OUs)
- Service Control Policies (SCPs)
- Policy attachments and inheritance
- Root and account management
"""

import boto3
from typing import Dict, List, Any, Optional
import logging
import json

logger = logging.getLogger(__name__)


class OrganizationsService:
    """Service for managing AWS Organizations resources."""

    def __init__(self, role_arn: Optional[str] = None):
        """
        Initialize Organizations service.

        Args:
            role_arn: Optional cross-account role ARN for assume role
        """
        self.role_arn = role_arn

        if role_arn:
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='IAMCopilotOrganizationsSession'
            )
            credentials = assumed_role['Credentials']

            self.org_client = boto3.client(
                'organizations',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        else:
            self.org_client = boto3.client('organizations')

    # ========== Organization Methods ==========

    def describe_organization(self) -> Optional[Dict[str, Any]]:
        """
        Get organization details.

        Returns:
            Organization details or None if not in an organization
        """
        try:
            response = self.org_client.describe_organization()
            org = response.get('Organization', {})

            return {
                'id': org.get('Id'),
                'arn': org.get('Arn'),
                'master_account_arn': org.get('MasterAccountArn'),
                'master_account_id': org.get('MasterAccountId'),
                'master_account_email': org.get('MasterAccountEmail'),
                'feature_set': org.get('FeatureSet'),
                'available_policy_types': org.get('AvailablePolicyTypes', [])
            }
        except self.org_client.exceptions.AWSOrganizationsNotInUseException:
            logger.info("Account is not part of an AWS Organization")
            return None
        except Exception as e:
            logger.error(f"Failed to describe organization: {str(e)}")
            raise

    # ========== Account Methods ==========

    def list_accounts(self) -> List[Dict[str, Any]]:
        """
        List all accounts in the organization.

        Returns:
            List of account details
        """
        try:
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts')

            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    accounts.append({
                        'id': account.get('Id'),
                        'arn': account.get('Arn'),
                        'name': account.get('Name'),
                        'email': account.get('Email'),
                        'status': account.get('Status'),
                        'joined_method': account.get('JoinedMethod'),
                        'joined_timestamp': account.get('JoinedTimestamp')
                    })

            return accounts
        except Exception as e:
            logger.error(f"Failed to list accounts: {str(e)}")
            raise

    def describe_account(self, account_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific account.

        Args:
            account_id: AWS account ID

        Returns:
            Account details
        """
        try:
            response = self.org_client.describe_account(AccountId=account_id)
            account = response.get('Account', {})

            return {
                'id': account.get('Id'),
                'arn': account.get('Arn'),
                'name': account.get('Name'),
                'email': account.get('Email'),
                'status': account.get('Status'),
                'joined_method': account.get('JoinedMethod'),
                'joined_timestamp': account.get('JoinedTimestamp')
            }
        except Exception as e:
            logger.error(f"Failed to describe account {account_id}: {str(e)}")
            return None

    # ========== Organizational Unit Methods ==========

    def list_roots(self) -> List[Dict[str, Any]]:
        """
        List all roots in the organization.

        Returns:
            List of root details
        """
        try:
            response = self.org_client.list_roots()
            roots = []

            for root in response.get('Roots', []):
                roots.append({
                    'id': root.get('Id'),
                    'arn': root.get('Arn'),
                    'name': root.get('Name'),
                    'policy_types': root.get('PolicyTypes', [])
                })

            return roots
        except Exception as e:
            logger.error(f"Failed to list roots: {str(e)}")
            raise

    def list_organizational_units_for_parent(self, parent_id: str) -> List[Dict[str, Any]]:
        """
        List organizational units under a parent.

        Args:
            parent_id: Parent ID (root or OU)

        Returns:
            List of OU details
        """
        try:
            ous = []
            paginator = self.org_client.get_paginator('list_organizational_units_for_parent')

            for page in paginator.paginate(ParentId=parent_id):
                for ou in page.get('OrganizationalUnits', []):
                    ous.append({
                        'id': ou.get('Id'),
                        'arn': ou.get('Arn'),
                        'name': ou.get('Name')
                    })

            return ous
        except Exception as e:
            logger.error(f"Failed to list OUs for parent {parent_id}: {str(e)}")
            raise

    def list_accounts_for_parent(self, parent_id: str) -> List[Dict[str, Any]]:
        """
        List accounts directly under a parent.

        Args:
            parent_id: Parent ID (root or OU)

        Returns:
            List of account details
        """
        try:
            accounts = []
            paginator = self.org_client.get_paginator('list_accounts_for_parent')

            for page in paginator.paginate(ParentId=parent_id):
                for account in page.get('Accounts', []):
                    accounts.append({
                        'id': account.get('Id'),
                        'arn': account.get('Arn'),
                        'name': account.get('Name'),
                        'email': account.get('Email'),
                        'status': account.get('Status')
                    })

            return accounts
        except Exception as e:
            logger.error(f"Failed to list accounts for parent {parent_id}: {str(e)}")
            raise

    def get_organizational_tree(self) -> Dict[str, Any]:
        """
        Build complete organizational tree structure.

        Returns:
            Hierarchical tree of roots, OUs, and accounts
        """
        def build_ou_tree(parent_id: str) -> Dict[str, Any]:
            """Recursively build OU tree."""
            node = {
                'id': parent_id,
                'organizational_units': [],
                'accounts': []
            }

            # Get OUs under this parent
            ous = self.list_organizational_units_for_parent(parent_id)
            for ou in ous:
                ou_node = {
                    'id': ou['id'],
                    'arn': ou['arn'],
                    'name': ou['name'],
                    'children': build_ou_tree(ou['id'])
                }
                node['organizational_units'].append(ou_node)

            # Get accounts under this parent
            accounts = self.list_accounts_for_parent(parent_id)
            node['accounts'] = accounts

            return node

        try:
            roots = self.list_roots()
            tree = {
                'roots': []
            }

            for root in roots:
                root_node = {
                    'id': root['id'],
                    'arn': root['arn'],
                    'name': root['name'],
                    'policy_types': root['policy_types'],
                    'structure': build_ou_tree(root['id'])
                }
                tree['roots'].append(root_node)

            return tree
        except Exception as e:
            logger.error(f"Failed to build organizational tree: {str(e)}")
            raise

    # ========== Policy Methods ==========

    def list_policies(self, policy_type: str = 'SERVICE_CONTROL_POLICY') -> List[Dict[str, Any]]:
        """
        List policies of a specific type.

        Args:
            policy_type: Type of policy (SERVICE_CONTROL_POLICY, TAG_POLICY, etc.)

        Returns:
            List of policy summaries
        """
        try:
            policies = []
            paginator = self.org_client.get_paginator('list_policies')

            for page in paginator.paginate(Filter=policy_type):
                for policy in page.get('Policies', []):
                    policies.append({
                        'id': policy.get('Id'),
                        'arn': policy.get('Arn'),
                        'name': policy.get('Name'),
                        'description': policy.get('Description', ''),
                        'type': policy.get('Type'),
                        'aws_managed': policy.get('AwsManaged', False)
                    })

            return policies
        except Exception as e:
            logger.error(f"Failed to list policies of type {policy_type}: {str(e)}")
            raise

    def describe_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a policy.

        Args:
            policy_id: Policy ID

        Returns:
            Policy details including content
        """
        try:
            response = self.org_client.describe_policy(PolicyId=policy_id)
            policy = response.get('Policy', {})
            policy_summary = policy.get('PolicySummary', {})

            # Parse policy content
            content = policy.get('Content', '{}')
            try:
                content_json = json.loads(content)
            except json.JSONDecodeError:
                content_json = {}

            return {
                'id': policy_summary.get('Id'),
                'arn': policy_summary.get('Arn'),
                'name': policy_summary.get('Name'),
                'description': policy_summary.get('Description', ''),
                'type': policy_summary.get('Type'),
                'aws_managed': policy_summary.get('AwsManaged', False),
                'content': content_json
            }
        except Exception as e:
            logger.error(f"Failed to describe policy {policy_id}: {str(e)}")
            return None

    def list_policies_for_target(self, target_id: str, policy_type: str = 'SERVICE_CONTROL_POLICY') -> List[Dict[str, Any]]:
        """
        List policies attached to a target (account, OU, or root).

        Args:
            target_id: Target ID
            policy_type: Type of policy

        Returns:
            List of attached policies
        """
        try:
            policies = []
            paginator = self.org_client.get_paginator('list_policies_for_target')

            for page in paginator.paginate(TargetId=target_id, Filter=policy_type):
                for policy in page.get('Policies', []):
                    policies.append({
                        'id': policy.get('Id'),
                        'arn': policy.get('Arn'),
                        'name': policy.get('Name'),
                        'description': policy.get('Description', ''),
                        'type': policy.get('Type'),
                        'aws_managed': policy.get('AwsManaged', False)
                    })

            return policies
        except Exception as e:
            logger.error(f"Failed to list policies for target {target_id}: {str(e)}")
            raise

    def list_targets_for_policy(self, policy_id: str) -> List[Dict[str, Any]]:
        """
        List all targets a policy is attached to.

        Args:
            policy_id: Policy ID

        Returns:
            List of targets
        """
        try:
            targets = []
            paginator = self.org_client.get_paginator('list_targets_for_policy')

            for page in paginator.paginate(PolicyId=policy_id):
                for target in page.get('Targets', []):
                    targets.append({
                        'target_id': target.get('TargetId'),
                        'arn': target.get('Arn'),
                        'name': target.get('Name'),
                        'type': target.get('Type')
                    })

            return targets
        except Exception as e:
            logger.error(f"Failed to list targets for policy {policy_id}: {str(e)}")
            raise

    # ========== Comprehensive Overview ==========

    def get_organizations_overview(self) -> Dict[str, Any]:
        """
        Get comprehensive overview of AWS Organizations.

        Returns:
            Complete overview including org details, accounts, OUs, and policies
        """
        try:
            # Check if organization exists
            org = self.describe_organization()
            if not org:
                return {
                    'enabled': False,
                    'message': 'This account is not part of an AWS Organization'
                }

            # Get all accounts
            accounts = self.list_accounts()

            # Get organizational tree
            tree = self.get_organizational_tree()

            # Get all SCPs
            scps = self.list_policies('SERVICE_CONTROL_POLICY')

            # Get SCP details
            scp_details = []
            for scp in scps:
                details = self.describe_policy(scp['id'])
                if details:
                    # Get targets for this policy
                    targets = self.list_targets_for_policy(scp['id'])
                    details['targets'] = targets
                    scp_details.append(details)

            # Count OUs recursively
            def count_ous(structure):
                count = len(structure.get('organizational_units', []))
                for ou in structure.get('organizational_units', []):
                    count += count_ous(ou.get('children', {}))
                return count

            total_ous = sum(count_ous(root['structure']) for root in tree.get('roots', []))

            return {
                'enabled': True,
                'organization': org,
                'accounts': accounts,
                'organizational_tree': tree,
                'service_control_policies': scp_details,
                'stats': {
                    'total_accounts': len(accounts),
                    'total_ous': total_ous,
                    'total_scps': len(scps),
                    'feature_set': org.get('feature_set', 'CONSOLIDATED_BILLING')
                }
            }
        except Exception as e:
            logger.error(f"Failed to get organizations overview: {str(e)}")
            raise
