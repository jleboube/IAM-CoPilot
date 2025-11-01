"""
IAM API Update Agent - Report Parser Service

Parses monitoring reports and extracts actionable changes.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class AgentReportParser:
    """Parses API monitoring reports to extract actionable changes."""

    def __init__(self):
        """Initialize the report parser."""
        pass

    def parse_report(self, monitoring_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a monitoring report and extract changes that require action.

        Args:
            monitoring_report: The monitoring report from APIMonitoringService

        Returns:
            Parsed report with categorized changes
        """
        logger.info(f"Parsing monitoring report ID: {monitoring_report.get('id')}")

        parsed = {
            'report_id': monitoring_report.get('id'),
            'report_date': monitoring_report.get('report_date'),
            'total_changes': monitoring_report.get('total_changes', 0),
            'services_monitored': monitoring_report.get('services_monitored', []),
            'actionable_changes': self._extract_actionable_changes(monitoring_report),
            'summary': monitoring_report.get('summary', {})
        }

        logger.info(f"Parsed {len(parsed['actionable_changes'])} actionable changes")
        return parsed

    def _extract_actionable_changes(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract changes that require code modifications.

        Returns:
            List of actionable changes with context
        """
        actionable = []
        changes_by_service = report.get('changes_by_service', {})

        if not changes_by_service:
            return actionable

        # Process changes from the 'by_service' structure
        if isinstance(changes_by_service, dict):
            for service, service_changes in changes_by_service.items():
                if isinstance(service_changes, list):
                    for change in service_changes:
                        if self._is_actionable(change):
                            actionable.append(self._enrich_change(change, service))

        return actionable

    def _is_actionable(self, change: Dict[str, Any]) -> bool:
        """
        Determine if a change requires code modification.

        Args:
            change: A change from the monitoring report

        Returns:
            True if the change requires action
        """
        change_type = change.get('change_type', '')

        # These change types require code updates
        actionable_types = [
            'new_operation',       # Add new API operation
            'removed_operation',   # Remove deprecated operation
            'deprecated_operation', # Mark as deprecated
            'new_parameter',       # Add new parameter to operation
            'removed_parameter',   # Handle removed parameter
            'modified_parameter'   # Update parameter handling
        ]

        if change_type not in actionable_types:
            return False

        # Skip low-priority changes for now (can be configured)
        impact_level = change.get('impact_level', '')

        # We want to act on breaking changes and enhancements
        # Non-breaking changes can be handled in batch updates
        if impact_level in ['breaking', 'enhancement']:
            return True

        return False

    def _enrich_change(self, change: Dict[str, Any], service: str) -> Dict[str, Any]:
        """
        Add context and metadata to a change.

        Args:
            change: The change dictionary
            service: The service name

        Returns:
            Enriched change with additional context
        """
        enriched = change.copy()
        enriched['service'] = service
        enriched['requires_service_update'] = self._requires_service_update(change)
        enriched['requires_schema_update'] = self._requires_schema_update(change)
        enriched['requires_router_update'] = self._requires_router_update(change)
        enriched['priority'] = self._calculate_priority(change)

        return enriched

    def _requires_service_update(self, change: Dict[str, Any]) -> bool:
        """Check if the service layer needs updating."""
        change_type = change.get('change_type', '')
        return change_type in [
            'new_operation',
            'removed_operation',
            'deprecated_operation',
            'modified_parameter'
        ]

    def _requires_schema_update(self, change: Dict[str, Any]) -> bool:
        """Check if Pydantic schemas need updating."""
        change_type = change.get('change_type', '')
        return change_type in [
            'new_operation',
            'new_parameter',
            'removed_parameter',
            'modified_parameter'
        ]

    def _requires_router_update(self, change: Dict[str, Any]) -> bool:
        """Check if API router endpoints need updating."""
        change_type = change.get('change_type', '')
        # New operations usually need new endpoints
        return change_type in ['new_operation']

    def _calculate_priority(self, change: Dict[str, Any]) -> int:
        """
        Calculate priority for a change (1=highest, 5=lowest).

        Args:
            change: The change dictionary

        Returns:
            Priority score
        """
        impact_level = change.get('impact_level', '')
        change_type = change.get('change_type', '')

        # Breaking changes are highest priority
        if impact_level == 'breaking':
            return 1

        # New features (enhancements) are medium-high priority
        if impact_level == 'enhancement':
            if change_type == 'new_operation':
                return 2
            return 3

        # Non-breaking changes are lower priority
        return 4

    def categorize_changes_by_action(
        self,
        actionable_changes: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group changes by the type of action needed.

        Args:
            actionable_changes: List of actionable changes

        Returns:
            Changes grouped by action type
        """
        categorized = {
            'add_operations': [],
            'remove_operations': [],
            'deprecate_operations': [],
            'update_parameters': [],
            'update_schemas': []
        }

        for change in actionable_changes:
            change_type = change.get('change_type', '')

            if change_type == 'new_operation':
                categorized['add_operations'].append(change)
            elif change_type == 'removed_operation':
                categorized['remove_operations'].append(change)
            elif change_type == 'deprecated_operation':
                categorized['deprecate_operations'].append(change)
            elif change_type in ['new_parameter', 'removed_parameter', 'modified_parameter']:
                categorized['update_parameters'].append(change)

        return categorized

    def generate_summary(self, parsed_report: Dict[str, Any]) -> str:
        """
        Generate a human-readable summary of actionable changes.

        Args:
            parsed_report: Parsed monitoring report

        Returns:
            Summary text
        """
        actionable = parsed_report.get('actionable_changes', [])

        if not actionable:
            return "No actionable changes detected in this monitoring report."

        categorized = self.categorize_changes_by_action(actionable)

        lines = [
            f"API Monitoring Report Summary (Report ID: {parsed_report['report_id']})",
            f"Report Date: {parsed_report['report_date']}",
            "",
            f"Total Changes Detected: {parsed_report['total_changes']}",
            f"Actionable Changes: {len(actionable)}",
            ""
        ]

        if categorized['add_operations']:
            lines.append(f"New Operations to Add: {len(categorized['add_operations'])}")
            for change in categorized['add_operations']:
                lines.append(f"  - {change.get('operation_name')} ({change.get('service')})")

        if categorized['remove_operations']:
            lines.append(f"Operations to Remove: {len(categorized['remove_operations'])}")
            for change in categorized['remove_operations']:
                lines.append(f"  - {change.get('operation_name')} ({change.get('service')})")

        if categorized['deprecate_operations']:
            lines.append(f"Operations to Deprecate: {len(categorized['deprecate_operations'])}")
            for change in categorized['deprecate_operations']:
                lines.append(f"  - {change.get('operation_name')} ({change.get('service')})")

        if categorized['update_parameters']:
            lines.append(f"Parameter Updates: {len(categorized['update_parameters'])}")

        return "\n".join(lines)
