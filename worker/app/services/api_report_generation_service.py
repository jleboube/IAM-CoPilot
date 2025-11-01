"""
AWS API Monitoring Report Generation Service

Generates both human-readable and AI-consumable reports for API changes.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)


class APIReportGenerationService:
    """Service for generating API monitoring reports."""

    def __init__(self):
        """Initialize the report generation service."""
        pass

    def generate_ai_report(
        self,
        changes_by_service: Dict[str, List[Dict[str, Any]]],
        report_date: datetime
    ) -> str:
        """
        Generate AI-consumable report in structured text format.

        This format is designed to be easily parsed by AI agents and includes:
        - Clear sections and structure
        - Machine-readable timestamps
        - Categorized changes
        - Impact assessments

        Args:
            changes_by_service: Dictionary mapping service names to lists of changes
            report_date: Date of the report

        Returns:
            Structured text report optimized for AI consumption
        """
        report_lines = []

        # Header
        report_lines.append("=" * 80)
        report_lines.append("AWS IAM API MONITORING REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Report Date: {report_date.isoformat()}")
        report_lines.append(f"Report Generated: {datetime.now(timezone.utc).isoformat()}")
        report_lines.append("")

        # Executive Summary
        total_changes = sum(len(changes) for changes in changes_by_service.values())
        report_lines.append("EXECUTIVE SUMMARY")
        report_lines.append("-" * 80)
        report_lines.append(f"Total Changes Detected: {total_changes}")
        report_lines.append(f"Services Monitored: {', '.join(changes_by_service.keys())}")
        report_lines.append("")

        # Changes per service
        for service, changes in changes_by_service.items():
            if not changes:
                report_lines.append(f"{service}: No changes detected")
                continue

            report_lines.append(f"{service}: {len(changes)} change(s) detected")

        report_lines.append("")

        # Detailed Changes by Service
        for service, changes in changes_by_service.items():
            if not changes:
                continue

            report_lines.append("=" * 80)
            report_lines.append(f"SERVICE: {service}")
            report_lines.append("=" * 80)
            report_lines.append("")

            # Categorize by impact
            breaking_changes = [c for c in changes if c['impact_level'] == 'breaking']
            enhancements = [c for c in changes if c['impact_level'] == 'enhancement']
            non_breaking = [c for c in changes if c['impact_level'] == 'non-breaking']

            # Breaking changes (highest priority)
            if breaking_changes:
                report_lines.append("BREAKING CHANGES (Immediate Attention Required)")
                report_lines.append("-" * 80)
                for idx, change in enumerate(breaking_changes, 1):
                    report_lines.extend(self._format_change_for_ai(change, idx))
                report_lines.append("")

            # Enhancements (new features)
            if enhancements:
                report_lines.append("ENHANCEMENTS (New Capabilities)")
                report_lines.append("-" * 80)
                for idx, change in enumerate(enhancements, 1):
                    report_lines.extend(self._format_change_for_ai(change, idx))
                report_lines.append("")

            # Non-breaking changes
            if non_breaking:
                report_lines.append("NON-BREAKING CHANGES (Low Priority)")
                report_lines.append("-" * 80)
                for idx, change in enumerate(non_breaking, 1):
                    report_lines.extend(self._format_change_for_ai(change, idx))
                report_lines.append("")

        # Footer with parsing instructions for AI
        report_lines.append("=" * 80)
        report_lines.append("AI PARSING INSTRUCTIONS")
        report_lines.append("=" * 80)
        report_lines.append("This report uses structured sections:")
        report_lines.append("- Lines with '=' are major section dividers")
        report_lines.append("- Lines with '-' are subsection dividers")
        report_lines.append("- CHANGE #N indicates individual change records")
        report_lines.append("- Each change includes: Type, Operation, Impact, Description")
        report_lines.append("- Impact levels: breaking > enhancement > non-breaking")
        report_lines.append("")
        report_lines.append("For automated processing, see companion JSON report.")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def _format_change_for_ai(self, change: Dict[str, Any], index: int) -> List[str]:
        """Format a single change for AI consumption."""
        lines = []

        lines.append(f"CHANGE #{index}")
        lines.append(f"  Type: {change['change_type']}")
        lines.append(f"  Service: {change['service_type']}")

        if change.get('operation_name'):
            lines.append(f"  Operation: {change['operation_name']}")

        lines.append(f"  Impact: {change['impact_level']}")
        lines.append(f"  Path: {change.get('change_path', 'N/A')}")
        lines.append(f"  Description: {change['description']}")

        if change.get('previous_value') is not None:
            prev_str = json.dumps(change['previous_value']) if isinstance(change['previous_value'], (dict, list)) else str(change['previous_value'])
            lines.append(f"  Previous: {prev_str[:200]}{'...' if len(prev_str) > 200 else ''}")

        if change.get('current_value') is not None:
            curr_str = json.dumps(change['current_value']) if isinstance(change['current_value'], (dict, list)) else str(change['current_value'])
            lines.append(f"  Current: {curr_str[:200]}{'...' if len(curr_str) > 200 else ''}")

        lines.append(f"  Detected: {change.get('detected_at', datetime.now(timezone.utc)).isoformat()}")
        lines.append("")

        return lines

    def generate_json_report(
        self,
        changes_by_service: Dict[str, List[Dict[str, Any]]],
        report_date: datetime,
        snapshots_info: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate complete JSON report for programmatic consumption.

        Args:
            changes_by_service: Dictionary mapping service names to changes
            report_date: Date of the report
            snapshots_info: Information about current API snapshots

        Returns:
            Complete structured JSON report
        """
        total_changes = sum(len(changes) for changes in changes_by_service.values())

        # Categorize all changes
        all_changes_categorized = {
            'breaking': [],
            'enhancement': [],
            'non-breaking': []
        }

        for service, changes in changes_by_service.items():
            for change in changes:
                impact = change.get('impact_level', 'non-breaking')
                all_changes_categorized[impact].append(change)

        # Build summary
        summary = {
            'report_date': report_date.isoformat(),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_changes': total_changes,
            'services_monitored': list(changes_by_service.keys()),
            'changes_by_impact': {
                'breaking': len(all_changes_categorized['breaking']),
                'enhancement': len(all_changes_categorized['enhancement']),
                'non-breaking': len(all_changes_categorized['non-breaking'])
            },
            'changes_by_service': {
                service: len(changes)
                for service, changes in changes_by_service.items()
            }
        }

        # Build detailed report
        report = {
            'version': '1.0',
            'report_type': 'aws_iam_api_monitoring',
            'summary': summary,
            'snapshots': snapshots_info,
            'changes': {
                'by_service': changes_by_service,
                'by_impact': all_changes_categorized
            },
            'metadata': {
                'format_version': '1.0',
                'ai_consumable': True,
                'schema_url': 'https://iam-copilot/schemas/api-monitoring-report.json'
            }
        }

        return report

    def generate_summary_statistics(
        self,
        changes_by_service: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """
        Generate summary statistics for changes.

        Args:
            changes_by_service: Dictionary mapping service names to changes

        Returns:
            Summary statistics
        """
        stats = {
            'total_changes': 0,
            'by_type': {},
            'by_service': {},
            'by_impact': {
                'breaking': 0,
                'enhancement': 0,
                'non-breaking': 0
            }
        }

        for service, changes in changes_by_service.items():
            stats['total_changes'] += len(changes)
            stats['by_service'][service] = len(changes)

            for change in changes:
                # Count by type
                change_type = change.get('change_type', 'unknown')
                stats['by_type'][change_type] = stats['by_type'].get(change_type, 0) + 1

                # Count by impact
                impact = change.get('impact_level', 'non-breaking')
                stats['by_impact'][impact] += 1

        return stats

    def generate_operations_diff_report(
        self,
        previous_operations: List[str],
        current_operations: List[str],
        service_name: str
    ) -> Dict[str, Any]:
        """
        Generate a diff report for operations between two snapshots.

        Args:
            previous_operations: List of operation names from previous snapshot
            current_operations: List of operation names from current snapshot
            service_name: Name of the service

        Returns:
            Operations diff report
        """
        prev_set = set(previous_operations)
        curr_set = set(current_operations)

        return {
            'service': service_name,
            'previous_count': len(prev_set),
            'current_count': len(curr_set),
            'added': sorted(list(curr_set - prev_set)),
            'removed': sorted(list(prev_set - curr_set)),
            'unchanged': sorted(list(prev_set & curr_set)),
            'summary': {
                'added_count': len(curr_set - prev_set),
                'removed_count': len(prev_set - curr_set),
                'unchanged_count': len(prev_set & curr_set)
            }
        }
