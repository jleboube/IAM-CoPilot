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
