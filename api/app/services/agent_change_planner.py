"""
IAM API Update Agent - Change Planner Service

Plans code changes based on API monitoring reports and codebase analysis.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.services.agent_report_parser import AgentReportParser
from app.services.agent_codebase_analyzer import AgentCodebaseAnalyzer

logger = logging.getLogger(__name__)


class AgentChangePlanner:
    """Plans code changes needed to keep IAM Copilot in sync with AWS APIs."""

    def __init__(self):
        """Initialize the change planner."""
        self.parser = AgentReportParser()
        self.analyzer = AgentCodebaseAnalyzer()

    def create_change_plan(
        self,
        monitoring_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a comprehensive plan for updating the codebase.

        Args:
            monitoring_report: The monitoring report from API monitoring agent

        Returns:
            Complete change plan with all planned modifications
        """
        logger.info(f"Creating change plan for report {monitoring_report.get('id')}")

        # Parse the report
        parsed_report = self.parser.parse_report(monitoring_report)

        # Get actionable changes
        actionable_changes = parsed_report['actionable_changes']

        if not actionable_changes:
            logger.info("No actionable changes found")
            return {
                'report_id': monitoring_report.get('id'),
                'actionable_changes': 0,
                'planned_changes': [],
                'summary': 'No changes required'
            }

        # Plan changes for each actionable item
        planned_changes = []
        for change in actionable_changes:
            plans = self._plan_change(change)
            planned_changes.extend(plans)

        # Sort by priority
        planned_changes.sort(key=lambda x: x.get('priority', 5))

        plan = {
            'report_id': monitoring_report.get('id'),
            'report_date': parsed_report['report_date'],
            'actionable_changes': len(actionable_changes),
            'planned_changes': planned_changes,
            'total_planned': len(planned_changes),
            'summary': self._generate_plan_summary(planned_changes),
            'categorized': self._categorize_planned_changes(planned_changes)
        }

        logger.info(f"Created plan with {len(planned_changes)} changes")
        return plan

    def _plan_change(self, change: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Plan specific code changes for a single API change.

        Args:
            change: A single change from the monitoring report

        Returns:
            List of planned changes (may be multiple per API change)
        """
        change_type = change.get('change_type')
        service = change.get('service')
        operation_name = change.get('operation_name')

        plans = []

        if change_type == 'new_operation':
            plans.extend(self._plan_new_operation(change))

        elif change_type == 'removed_operation':
            plans.extend(self._plan_remove_operation(change))

        elif change_type == 'deprecated_operation':
            plans.extend(self._plan_deprecate_operation(change))

        elif change_type in ['new_parameter', 'removed_parameter', 'modified_parameter']:
            plans.extend(self._plan_parameter_change(change))

        return plans

    def _plan_new_operation(self, change: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Plan addition of a new operation.

        Args:
            change: Change details

        Returns:
            List of planned changes
        """
        service = change.get('service')
        operation_name = change.get('operation_name')

        # Check if operation already exists
        check = self.analyzer.check_operation_exists(service, operation_name)

        if check['exists']:
            logger.info(f"Operation {operation_name} already exists in {service}")
            return [{
                'change_type': 'skip',
                'service_type': service,
                'operation_name': operation_name,
                'description': f"Operation already exists in codebase",
                'reasoning': f"Skipping {operation_name} as it's already implemented",
                'priority': 5,
                'requires_action': False
            }]

        # Get service file path
        service_file_map = {
            'IAM': 'api/app/services/iam_service.py',
            'IdentityCenter': 'api/app/services/identity_center_service.py',
            'Organizations': 'api/app/services/organizations_service.py'
        }

        target_file = service_file_map.get(service, '')

        plans = []

        # Plan 1: Add method to service
        plans.append({
            'change_type': 'add_operation',
            'service_type': service,
            'operation_name': operation_name,
            'target_file': target_file,
            'description': f"Add {operation_name} method to {service} service",
            'reasoning': f"New AWS API operation detected. Need to add support in service layer.",
            'priority': change.get('priority', 2),
            'requires_service_update': True,
            'requires_schema_update': True,
            'requires_router_update': True,
            'aws_operation_details': change.get('current_value', {}),
            'implementation_plan': {
                'step': 'add_service_method',
                'method_name': self.analyzer._aws_operation_to_method_name(operation_name),
                'service_class': f"{service}Service",
                'boto3_client': self._get_boto3_client_name(service),
                'operation': operation_name
            }
        })

        # Plan 2: Add Pydantic schemas if needed
        schema_file_map = {
            'IAM': 'api/app/schemas/iam.py',
            'IdentityCenter': 'api/app/schemas/identity_center.py',
            'Organizations': 'api/app/schemas/organizations.py'
        }

        plans.append({
            'change_type': 'update_schema',
            'service_type': service,
            'operation_name': operation_name,
            'target_file': schema_file_map.get(service, ''),
            'description': f"Add request/response schemas for {operation_name}",
            'reasoning': f"New operation requires Pydantic schemas for request validation and response serialization",
            'priority': change.get('priority', 2),
            'requires_schema_update': True,
            'implementation_plan': {
                'step': 'add_schemas',
                'operation': operation_name,
                'schema_types': ['request', 'response']
            }
        })

        # Plan 3: Add router endpoint if it's a user-facing operation
        if self._should_add_endpoint(operation_name):
            router_file_map = {
                'IAM': 'api/app/routers/iam_management.py',
                'IdentityCenter': 'api/app/routers/identity_center.py',
                'Organizations': 'api/app/routers/organizations.py'
            }

            plans.append({
                'change_type': 'add_endpoint',
                'service_type': service,
                'operation_name': operation_name,
                'target_file': router_file_map.get(service, ''),
                'description': f"Add API endpoint for {operation_name}",
                'reasoning': f"User-facing operation requires REST API endpoint",
                'priority': change.get('priority', 2),
                'requires_router_update': True,
                'implementation_plan': {
                    'step': 'add_router_endpoint',
                    'operation': operation_name,
                    'http_method': self._infer_http_method(operation_name),
                    'path': self._infer_endpoint_path(operation_name)
                }
            })

        return plans

    def _plan_remove_operation(self, change: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Plan removal of a deprecated operation.

        Args:
            change: Change details

        Returns:
            List of planned changes
        """
        service = change.get('service')
        operation_name = change.get('operation_name')

        # Check if operation exists in our code
        check = self.analyzer.check_operation_exists(service, operation_name)

        if not check['exists']:
            logger.info(f"Operation {operation_name} doesn't exist in {service}, skipping removal")
            return []

        service_file_map = {
            'IAM': 'api/app/services/iam_service.py',
            'IdentityCenter': 'api/app/services/identity_center_service.py',
            'Organizations': 'api/app/services/organizations_service.py'
        }

        return [{
            'change_type': 'remove_operation',
            'service_type': service,
            'operation_name': operation_name,
            'target_file': service_file_map.get(service, ''),
            'description': f"Remove {operation_name} from {service} service",
            'reasoning': f"AWS has removed this operation. Should be removed from our codebase.",
            'priority': 1,  # High priority for breaking changes
            'requires_service_update': True,
            'implementation_plan': {
                'step': 'remove_method',
                'method_name': check['method_name'],
                'add_deprecation_notice': True
            }
        }]

    def _plan_deprecate_operation(self, change: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Plan deprecation marking for an operation.

        Args:
            change: Change details

        Returns:
            List of planned changes
        """
        service = change.get('service')
        operation_name = change.get('operation_name')

        check = self.analyzer.check_operation_exists(service, operation_name)

        if not check['exists']:
            logger.info(f"Operation {operation_name} doesn't exist, skipping deprecation")
            return []

        service_file_map = {
            'IAM': 'api/app/services/iam_service.py',
            'IdentityCenter': 'api/app/services/identity_center_service.py',
            'Organizations': 'api/app/services/organizations_service.py'
        }

        return [{
            'change_type': 'deprecate_operation',
            'service_type': service,
            'operation_name': operation_name,
            'target_file': service_file_map.get(service, ''),
            'description': f"Mark {operation_name} as deprecated",
            'reasoning': f"AWS has deprecated this operation. Add deprecation warning.",
            'priority': 3,  # Medium priority
            'requires_service_update': True,
            'implementation_plan': {
                'step': 'add_deprecation_decorator',
                'method_name': check['method_name'],
                'deprecation_message': change.get('description', '')
            }
        }]

    def _plan_parameter_change(self, change: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Plan changes for parameter modifications.

        Args:
            change: Change details

        Returns:
            List of planned changes
        """
        service = change.get('service')
        operation_name = change.get('operation_name')

        schema_file_map = {
            'IAM': 'api/app/schemas/iam.py',
            'IdentityCenter': 'api/app/schemas/identity_center.py',
            'Organizations': 'api/app/schemas/organizations.py'
        }

        return [{
            'change_type': 'update_parameter',
            'service_type': service,
            'operation_name': operation_name,
            'target_file': schema_file_map.get(service, ''),
            'description': f"Update parameters for {operation_name}",
            'reasoning': f"Parameter change detected: {change.get('description')}",
            'priority': change.get('priority', 3),
            'requires_schema_update': True,
            'implementation_plan': {
                'step': 'update_schema',
                'operation': operation_name,
                'parameter_change': change.get('change_type'),
                'parameter_details': {
                    'previous': change.get('previous_value'),
                    'current': change.get('current_value')
                }
            }
        }]

    def _get_boto3_client_name(self, service: str) -> str:
        """Get the boto3 client name for a service."""
        client_map = {
            'IAM': 'iam',
            'IdentityCenter': 'sso-admin',
            'Organizations': 'organizations'
        }
        return client_map.get(service, service.lower())

    def _should_add_endpoint(self, operation_name: str) -> bool:
        """Determine if an operation should have a REST endpoint."""
        # List operations typically don't need individual endpoints
        if operation_name.startswith('List'):
            return False
        # Describe/Get operations might be useful as endpoints
        # Create/Update/Delete definitely need endpoints
        user_facing_prefixes = ['Create', 'Update', 'Delete', 'Put', 'Attach', 'Detach']
        return any(operation_name.startswith(prefix) for prefix in user_facing_prefixes)

    def _infer_http_method(self, operation_name: str) -> str:
        """Infer HTTP method from operation name."""
        if operation_name.startswith('Create') or operation_name.startswith('Put'):
            return 'POST'
        elif operation_name.startswith('Update'):
            return 'PUT'
        elif operation_name.startswith('Delete') or operation_name.startswith('Remove'):
            return 'DELETE'
        elif operation_name.startswith('List') or operation_name.startswith('Get') or operation_name.startswith('Describe'):
            return 'GET'
        return 'POST'

    def _infer_endpoint_path(self, operation_name: str) -> str:
        """Infer REST endpoint path from operation name."""
        # Convert CreateUser -> /users
        # CreateRole -> /roles
        # Simple heuristic
        import re
        # Remove common prefixes
        name = re.sub(r'^(Create|Update|Delete|Get|List|Describe|Put)', '', operation_name)
        # Convert to lowercase with hyphens
        path = re.sub('([a-z0-9])([A-Z])', r'\1-\2', name).lower()
        return f"/{path}"

    def _generate_plan_summary(self, planned_changes: List[Dict[str, Any]]) -> str:
        """Generate a summary of the change plan."""
        if not planned_changes:
            return "No changes planned"

        by_type = {}
        for change in planned_changes:
            change_type = change.get('change_type', 'unknown')
            by_type[change_type] = by_type.get(change_type, 0) + 1

        lines = [f"Total planned changes: {len(planned_changes)}"]
        for change_type, count in by_type.items():
            lines.append(f"  - {change_type}: {count}")

        return "\n".join(lines)

    def _categorize_planned_changes(
        self,
        planned_changes: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize planned changes by type."""
        categorized = {
            'service_updates': [],
            'schema_updates': [],
            'router_updates': [],
            'removals': [],
            'deprecations': []
        }

        for change in planned_changes:
            change_type = change.get('change_type')

            if change_type in ['add_operation', 'update_parameter']:
                categorized['service_updates'].append(change)
            elif change_type == 'update_schema':
                categorized['schema_updates'].append(change)
            elif change_type == 'add_endpoint':
                categorized['router_updates'].append(change)
            elif change_type == 'remove_operation':
                categorized['removals'].append(change)
            elif change_type == 'deprecate_operation':
                categorized['deprecations'].append(change)

        return categorized
