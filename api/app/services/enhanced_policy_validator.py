"""
Enhanced IAM Policy Validator

Provides comprehensive validation including condition keys, operators,
action names, resource ARNs, and security best practices.
"""

import logging
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from app.services.condition_key_catalog import ConditionKeyCatalog

logger = logging.getLogger(__name__)


class EnhancedPolicyValidator:
    """
    Enhanced IAM policy validator with comprehensive checks.

    Validates:
    - Policy structure
    - Condition keys and operators
    - Action names
    - Resource ARNs
    - Security best practices
    """

    def __init__(self):
        """Initialize the enhanced validator."""
        self.catalog = ConditionKeyCatalog()

    def validate_policy(
        self,
        policy_document: Dict[str, Any],
        validation_level: str = 'comprehensive'
    ) -> Dict[str, Any]:
        """
        Perform comprehensive policy validation.

        Args:
            policy_document: IAM policy document
            validation_level: Level of validation ('basic', 'standard', 'comprehensive')

        Returns:
            Validation results with errors, warnings, and suggestions
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': [],
            'info': [],
            'validation_level': validation_level
        }

        # Basic structure validation
        structural_errors = self._validate_structure(policy_document)
        results['errors'].extend(structural_errors)

        if structural_errors:
            results['valid'] = False
            return results

        # Validate statements
        statements = policy_document.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]

        for idx, statement in enumerate(statements):
            statement_results = self._validate_statement(
                statement,
                idx,
                validation_level
            )

            results['errors'].extend(statement_results['errors'])
            results['warnings'].extend(statement_results['warnings'])
            results['suggestions'].extend(statement_results['suggestions'])
            results['info'].extend(statement_results['info'])

        # Set overall validity
        if results['errors']:
            results['valid'] = False

        return results

    def _validate_structure(self, policy: Dict[str, Any]) -> List[str]:
        """Validate basic policy structure."""
        errors = []

        # Check required fields
        if 'Version' not in policy:
            errors.append("Policy must have a 'Version' field")
        elif policy['Version'] not in ['2012-10-17', '2008-10-17']:
            errors.append(f"Invalid version: {policy['Version']}. Use '2012-10-17'")

        if 'Statement' not in policy:
            errors.append("Policy must have a 'Statement' field")
        elif not policy['Statement']:
            errors.append("Statement cannot be empty")

        return errors

    def _validate_statement(
        self,
        statement: Dict[str, Any],
        index: int,
        validation_level: str
    ) -> Dict[str, List[str]]:
        """Validate a single policy statement."""
        results = {
            'errors': [],
            'warnings': [],
            'suggestions': [],
            'info': []
        }

        statement_id = statement.get('Sid', f'Statement{index}')

        # Validate Effect
        if 'Effect' not in statement:
            results['errors'].append(f"{statement_id}: Missing 'Effect'")
        elif statement['Effect'] not in ['Allow', 'Deny']:
            results['errors'].append(f"{statement_id}: Effect must be 'Allow' or 'Deny'")

        # Validate Action/NotAction
        has_action = 'Action' in statement
        has_not_action = 'NotAction' in statement

        if not has_action and not has_not_action:
            results['errors'].append(f"{statement_id}: Must have 'Action' or 'NotAction'")
        elif has_action and has_not_action:
            results['errors'].append(f"{statement_id}: Cannot have both 'Action' and 'NotAction'")

        # Validate actions if present
        if has_action:
            action_results = self._validate_actions(
                statement.get('Action'),
                statement_id,
                validation_level
            )
            results['errors'].extend(action_results['errors'])
            results['warnings'].extend(action_results['warnings'])

        # Validate Resource/NotResource
        has_resource = 'Resource' in statement
        has_not_resource = 'NotResource' in statement

        if not has_resource and not has_not_resource:
            results['errors'].append(f"{statement_id}: Must have 'Resource' or 'NotResource'")

        # Validate resources if present
        if has_resource:
            resource_results = self._validate_resources(
                statement.get('Resource'),
                statement_id,
                validation_level
            )
            results['errors'].extend(resource_results['errors'])
            results['warnings'].extend(resource_results['warnings'])

        # Validate Condition if present
        if 'Condition' in statement:
            condition_results = self._validate_conditions(
                statement.get('Condition'),
                statement.get('Action', []),
                statement_id,
                validation_level
            )
            results['errors'].extend(condition_results['errors'])
            results['warnings'].extend(condition_results['warnings'])
            results['suggestions'].extend(condition_results['suggestions'])
            results['info'].extend(condition_results['info'])

        # Security best practice checks
        if validation_level in ['standard', 'comprehensive']:
            bp_results = self._check_security_best_practices(statement, statement_id)
            results['warnings'].extend(bp_results['warnings'])
            results['suggestions'].extend(bp_results['suggestions'])

        return results

    def _validate_actions(
        self,
        actions: Any,
        statement_id: str,
        validation_level: str
    ) -> Dict[str, List[str]]:
        """Validate action names."""
        results = {'errors': [], 'warnings': []}

        if isinstance(actions, str):
            actions = [actions]

        for action in actions:
            # Check wildcard usage
            if action == '*':
                results['warnings'].append(
                    f"{statement_id}: Using wildcard '*' for actions grants all permissions"
                )
                continue

            # Validate action format (service:Action)
            if ':' not in action and '*' not in action:
                results['errors'].append(
                    f"{statement_id}: Invalid action format '{action}'. Should be 'service:Action'"
                )

            # Check for overly broad wildcards
            if action.endswith(':*'):
                results['warnings'].append(
                    f"{statement_id}: Action '{action}' grants all operations for the service"
                )

        return results

    def _validate_resources(
        self,
        resources: Any,
        statement_id: str,
        validation_level: str
    ) -> Dict[str, List[str]]:
        """Validate resource ARNs."""
        results = {'errors': [], 'warnings': []}

        if isinstance(resources, str):
            resources = [resources]

        for resource in resources:
            # Check wildcard usage
            if resource == '*':
                results['warnings'].append(
                    f"{statement_id}: Using wildcard '*' for resources applies to all resources"
                )
                continue

            # Validate ARN format
            if not resource.startswith('arn:') and '*' not in resource:
                results['warnings'].append(
                    f"{statement_id}: Resource '{resource}' should be an ARN or wildcard"
                )

            # Basic ARN structure: arn:partition:service:region:account-id:resource
            if resource.startswith('arn:'):
                parts = resource.split(':')
                if len(parts) < 6:
                    results['warnings'].append(
                        f"{statement_id}: ARN '{resource}' may be incomplete"
                    )

        return results

    def _validate_conditions(
        self,
        conditions: Dict[str, Any],
        actions: Any,
        statement_id: str,
        validation_level: str
    ) -> Dict[str, List[str]]:
        """
        Validate condition block comprehensively.

        This is the key enhancement - validates condition keys and operators.
        """
        results = {
            'errors': [],
            'warnings': [],
            'suggestions': [],
            'info': []
        }

        if not isinstance(conditions, dict):
            results['errors'].append(f"{statement_id}: Condition must be an object")
            return results

        # Extract service from actions for context
        service = None
        if actions:
            if isinstance(actions, str):
                service = self.catalog.get_service_from_action(actions)
            elif isinstance(actions, list) and actions:
                service = self.catalog.get_service_from_action(actions[0])

        # Validate each condition operator
        for operator, condition_block in conditions.items():
            # Validate operator
            if not self.catalog.is_valid_operator(operator):
                results['errors'].append(
                    f"{statement_id}: Invalid condition operator '{operator}'"
                )
                continue

            if not isinstance(condition_block, dict):
                results['errors'].append(
                    f"{statement_id}: Condition block for '{operator}' must be an object"
                )
                continue

            # Validate each condition key
            for condition_key, condition_value in condition_block.items():
                # Check if condition key is valid
                if not self.catalog.is_valid_condition_key(condition_key, service):
                    results['errors'].append(
                        f"{statement_id}: Invalid condition key '{condition_key}'"
                    )
                    # Provide suggestions
                    suggestions = self._suggest_similar_keys(condition_key, service)
                    if suggestions:
                        results['suggestions'].append(
                            f"{statement_id}: Did you mean one of: {', '.join(suggestions[:3])}"
                        )
                    continue

                # Validate operator is appropriate for key type
                if not self.catalog.validate_operator_for_key(operator, condition_key):
                    key_info = self.catalog.get_all_condition_keys(service).get(condition_key)
                    expected_type = key_info.get('type') if key_info else 'Unknown'
                    operator_type = self.catalog.get_operator_type(operator)

                    results['errors'].append(
                        f"{statement_id}: Operator '{operator}' (type: {operator_type}) "
                        f"is not compatible with condition key '{condition_key}' (type: {expected_type})"
                    )

                # Validate condition value format
                value_results = self._validate_condition_value(
                    operator,
                    condition_key,
                    condition_value,
                    statement_id
                )
                results['errors'].extend(value_results['errors'])
                results['warnings'].extend(value_results['warnings'])

                # Add info about the condition key
                if validation_level == 'comprehensive':
                    key_info = self.catalog.get_all_condition_keys(service).get(condition_key)
                    if key_info:
                        results['info'].append(
                            f"{statement_id}: {condition_key} - {key_info['description']}"
                        )

        return results

    def _validate_condition_value(
        self,
        operator: str,
        condition_key: str,
        value: Any,
        statement_id: str
    ) -> Dict[str, List[str]]:
        """Validate condition value format based on operator type."""
        results = {'errors': [], 'warnings': []}

        operator_type = self.catalog.get_operator_type(operator)

        if operator_type == 'IpAddress':
            # Validate IP address or CIDR
            if isinstance(value, list):
                values = value
            else:
                values = [value]

            for ip_value in values:
                if not self._is_valid_ip_or_cidr(ip_value):
                    results['errors'].append(
                        f"{statement_id}: Invalid IP address or CIDR '{ip_value}' for {condition_key}"
                    )

        elif operator_type == 'Date':
            # Validate date format (ISO 8601)
            if isinstance(value, list):
                values = value
            else:
                values = [value]

            for date_value in values:
                if not self._is_valid_iso_date(date_value):
                    results['warnings'].append(
                        f"{statement_id}: Date '{date_value}' should be in ISO 8601 format"
                    )

        elif operator_type == 'Numeric':
            # Validate numeric value
            if isinstance(value, list):
                values = value
            else:
                values = [value]

            for num_value in values:
                if not isinstance(num_value, (int, float, str)):
                    results['errors'].append(
                        f"{statement_id}: Numeric condition requires number, got {type(num_value)}"
                    )

        elif operator_type == 'Boolean':
            # Validate boolean
            if isinstance(value, str):
                if value.lower() not in ['true', 'false']:
                    results['errors'].append(
                        f"{statement_id}: Boolean condition must be 'true' or 'false'"
                    )
            elif not isinstance(value, bool):
                results['errors'].append(
                    f"{statement_id}: Boolean condition must be boolean or 'true'/'false' string"
                )

        return results

    def _is_valid_ip_or_cidr(self, value: str) -> bool:
        """Check if value is valid IP or CIDR notation."""
        # Simple regex for IP/CIDR validation
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
        return re.match(ip_pattern, str(value)) is not None

    def _is_valid_iso_date(self, value: str) -> bool:
        """Check if value is valid ISO 8601 date."""
        try:
            datetime.fromisoformat(str(value).replace('Z', '+00:00'))
            return True
        except (ValueError, AttributeError):
            return False

    def _suggest_similar_keys(self, invalid_key: str, service: Optional[str]) -> List[str]:
        """Suggest similar valid condition keys."""
        all_keys = self.catalog.get_all_condition_keys(service)

        # Simple similarity: starts with same prefix or contains similar parts
        suggestions = []

        # Extract prefix
        if ':' in invalid_key:
            prefix = invalid_key.split(':')[0]
            for key in all_keys.keys():
                if key.startswith(prefix + ':'):
                    suggestions.append(key)
        else:
            # Look for partial matches
            for key in all_keys.keys():
                if invalid_key.lower() in key.lower():
                    suggestions.append(key)

        return suggestions[:5]

    def _check_security_best_practices(
        self,
        statement: Dict[str, Any],
        statement_id: str
    ) -> Dict[str, List[str]]:
        """Check security best practices."""
        results = {'warnings': [], 'suggestions': []}

        effect = statement.get('Effect')
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        conditions = statement.get('Condition', {})

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Check for overly permissive Allow statements
        if effect == 'Allow':
            if '*' in actions and '*' in resources:
                results['warnings'].append(
                    f"{statement_id}: Grants all actions (*) on all resources (*). "
                    "This is very permissive and should be avoided."
                )

            # Check for admin-level permissions
            admin_actions = ['iam:*', '*']
            if any(action in actions for action in admin_actions):
                results['warnings'].append(
                    f"{statement_id}: Grants administrative permissions. "
                    "Consider using least privilege principle."
                )

        # Suggest adding conditions for enhanced security
        if effect == 'Allow' and not conditions:
            if any('*' in action for action in actions):
                results['suggestions'].append(
                    f"{statement_id}: Consider adding conditions to restrict when/where "
                    "this policy applies (e.g., source IP, MFA, time-based)"
                )

        # Check for MFA requirement on sensitive actions
        sensitive_patterns = ['Delete', 'Terminate', 'Remove', 'Revoke']
        has_sensitive = any(
            any(pattern in action for pattern in sensitive_patterns)
            for action in actions
        )

        if has_sensitive and effect == 'Allow':
            has_mfa_condition = any(
                'MultiFactorAuthPresent' in str(conditions)
                for conditions in conditions.values()
            ) if conditions else False

            if not has_mfa_condition:
                results['suggestions'].append(
                    f"{statement_id}: Sensitive actions detected. "
                    "Consider requiring MFA with aws:MultiFactorAuthPresent condition"
                )

        return results

    def get_validation_summary(self, validation_results: Dict[str, Any]) -> str:
        """Generate a human-readable summary of validation results."""
        lines = []

        if validation_results['valid']:
            lines.append("✓ Policy is valid")
        else:
            lines.append("✗ Policy has errors")

        if validation_results['errors']:
            lines.append(f"\nErrors ({len(validation_results['errors'])}):")
            for error in validation_results['errors']:
                lines.append(f"  - {error}")

        if validation_results['warnings']:
            lines.append(f"\nWarnings ({len(validation_results['warnings'])}):")
            for warning in validation_results['warnings']:
                lines.append(f"  - {warning}")

        if validation_results['suggestions']:
            lines.append(f"\nSuggestions ({len(validation_results['suggestions'])}):")
            for suggestion in validation_results['suggestions']:
                lines.append(f"  - {suggestion}")

        return "\n".join(lines)
