"""
AWS API Change Detection Service

Compares API snapshots to detect changes, additions, removals, and modifications.
"""

import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)


class APIChangeDetectionService:
    """Service for detecting changes between API snapshots."""

    def __init__(self):
        """Initialize the change detection service."""
        pass

    def detect_changes(
        self,
        previous_api: Dict[str, Any],
        current_api: Dict[str, Any],
        service_type: str
    ) -> List[Dict[str, Any]]:
        """
        Detect all changes between two API snapshots.

        Args:
            previous_api: Previous API definition
            current_api: Current API definition
            service_type: Service being compared (IAM, IdentityCenter, Organizations)

        Returns:
            List of detected changes with details
        """
        changes = []

        # Detect operation changes
        operation_changes = self._detect_operation_changes(
            previous_api.get('operations', {}),
            current_api.get('operations', {}),
            service_type
        )
        changes.extend(operation_changes)

        # Detect shape changes
        shape_changes = self._detect_shape_changes(
            previous_api.get('shapes', {}),
            current_api.get('shapes', {}),
            service_type
        )
        changes.extend(shape_changes)

        # Detect metadata changes
        metadata_changes = self._detect_metadata_changes(
            previous_api.get('metadata', {}),
            current_api.get('metadata', {}),
            service_type
        )
        changes.extend(metadata_changes)

        logger.info(f"Detected {len(changes)} changes for {service_type}")
        return changes

    def _detect_operation_changes(
        self,
        previous_ops: Dict[str, Any],
        current_ops: Dict[str, Any],
        service_type: str
    ) -> List[Dict[str, Any]]:
        """Detect changes in operations."""
        changes = []

        previous_op_names = set(previous_ops.keys())
        current_op_names = set(current_ops.keys())

        # New operations
        new_operations = current_op_names - previous_op_names
        for op_name in new_operations:
            changes.append({
                'service_type': service_type,
                'change_type': 'new_operation',
                'operation_name': op_name,
                'change_path': f'operations.{op_name}',
                'previous_value': None,
                'current_value': current_ops[op_name],
                'description': f"New operation '{op_name}' added to {service_type} API",
                'impact_level': 'enhancement',
                'detected_at': datetime.now(timezone.utc)
            })

        # Removed operations
        removed_operations = previous_op_names - current_op_names
        for op_name in removed_operations:
            changes.append({
                'service_type': service_type,
                'change_type': 'removed_operation',
                'operation_name': op_name,
                'change_path': f'operations.{op_name}',
                'previous_value': previous_ops[op_name],
                'current_value': None,
                'description': f"Operation '{op_name}' removed from {service_type} API",
                'impact_level': 'breaking',
                'detected_at': datetime.now(timezone.utc)
            })

        # Modified operations
        common_operations = previous_op_names & current_op_names
        for op_name in common_operations:
            prev_op = previous_ops[op_name]
            curr_op = current_ops[op_name]

            # Check for deprecation
            if not prev_op.get('deprecated', False) and curr_op.get('deprecated', False):
                changes.append({
                    'service_type': service_type,
                    'change_type': 'deprecated_operation',
                    'operation_name': op_name,
                    'change_path': f'operations.{op_name}.deprecated',
                    'previous_value': False,
                    'current_value': True,
                    'description': f"Operation '{op_name}' marked as deprecated in {service_type} API. {curr_op.get('deprecatedMessage', '')}",
                    'impact_level': 'non-breaking',
                    'detected_at': datetime.now(timezone.utc)
                })

            # Check for input changes
            input_changes = self._detect_parameter_changes(
                prev_op.get('input'),
                curr_op.get('input'),
                op_name,
                'input',
                service_type
            )
            changes.extend(input_changes)

            # Check for output changes
            output_changes = self._detect_parameter_changes(
                prev_op.get('output'),
                curr_op.get('output'),
                op_name,
                'output',
                service_type
            )
            changes.extend(output_changes)

            # Check for new errors
            prev_errors = set(e.get('name', '') for e in prev_op.get('errors', []))
            curr_errors = set(e.get('name', '') for e in curr_op.get('errors', []))

            new_errors = curr_errors - prev_errors
            for error in new_errors:
                changes.append({
                    'service_type': service_type,
                    'change_type': 'new_error',
                    'operation_name': op_name,
                    'change_path': f'operations.{op_name}.errors',
                    'previous_value': list(prev_errors),
                    'current_value': list(curr_errors),
                    'description': f"New error type '{error}' added to operation '{op_name}' in {service_type} API",
                    'impact_level': 'non-breaking',
                    'detected_at': datetime.now(timezone.utc)
                })

        return changes

    def _detect_parameter_changes(
        self,
        previous_param: Dict[str, Any],
        current_param: Dict[str, Any],
        operation_name: str,
        param_type: str,  # 'input' or 'output'
        service_type: str
    ) -> List[Dict[str, Any]]:
        """Detect changes in operation parameters (input/output)."""
        changes = []

        if not previous_param and current_param:
            changes.append({
                'service_type': service_type,
                'change_type': 'new_parameter',
                'operation_name': operation_name,
                'change_path': f'operations.{operation_name}.{param_type}',
                'previous_value': None,
                'current_value': current_param,
                'description': f"New {param_type} parameter added to operation '{operation_name}' in {service_type} API",
                'impact_level': 'non-breaking' if param_type == 'output' else 'enhancement',
                'detected_at': datetime.now(timezone.utc)
            })
            return changes

        if previous_param and not current_param:
            changes.append({
                'service_type': service_type,
                'change_type': 'removed_parameter',
                'operation_name': operation_name,
                'change_path': f'operations.{operation_name}.{param_type}',
                'previous_value': previous_param,
                'current_value': None,
                'description': f"{param_type.capitalize()} parameter removed from operation '{operation_name}' in {service_type} API",
                'impact_level': 'breaking',
                'detected_at': datetime.now(timezone.utc)
            })
            return changes

        if not previous_param or not current_param:
            return changes

        # Compare members if this is a structure
        prev_members = previous_param.get('members', {})
        curr_members = current_param.get('members', {})

        prev_member_names = set(prev_members.keys())
        curr_member_names = set(curr_members.keys())

        # New members
        new_members = curr_member_names - prev_member_names
        for member in new_members:
            changes.append({
                'service_type': service_type,
                'change_type': 'new_parameter',
                'operation_name': operation_name,
                'change_path': f'operations.{operation_name}.{param_type}.members.{member}',
                'previous_value': None,
                'current_value': curr_members[member],
                'description': f"New {param_type} field '{member}' added to operation '{operation_name}' in {service_type} API",
                'impact_level': 'non-breaking' if param_type == 'output' else 'enhancement',
                'detected_at': datetime.now(timezone.utc)
            })

        # Removed members
        removed_members = prev_member_names - curr_member_names
        for member in removed_members:
            changes.append({
                'service_type': service_type,
                'change_type': 'removed_parameter',
                'operation_name': operation_name,
                'change_path': f'operations.{operation_name}.{param_type}.members.{member}',
                'previous_value': prev_members[member],
                'current_value': None,
                'description': f"{param_type.capitalize()} field '{member}' removed from operation '{operation_name}' in {service_type} API",
                'impact_level': 'breaking' if prev_members[member].get('required') else 'non-breaking',
                'detected_at': datetime.now(timezone.utc)
            })

        # Check for required field changes
        prev_required = set(previous_param.get('required', []))
        curr_required = set(current_param.get('required', []))

        newly_required = curr_required - prev_required
        for field in newly_required:
            changes.append({
                'service_type': service_type,
                'change_type': 'modified_parameter',
                'operation_name': operation_name,
                'change_path': f'operations.{operation_name}.{param_type}.required',
                'previous_value': {'field': field, 'required': False},
                'current_value': {'field': field, 'required': True},
                'description': f"Field '{field}' is now required in {param_type} for operation '{operation_name}' in {service_type} API",
                'impact_level': 'breaking' if param_type == 'input' else 'non-breaking',
                'detected_at': datetime.now(timezone.utc)
            })

        return changes

    def _detect_shape_changes(
        self,
        previous_shapes: Dict[str, Any],
        current_shapes: Dict[str, Any],
        service_type: str
    ) -> List[Dict[str, Any]]:
        """Detect changes in shape definitions."""
        changes = []

        previous_shape_names = set(previous_shapes.keys())
        current_shape_names = set(current_shapes.keys())

        # New shapes (usually not critical but good to know)
        new_shapes = current_shape_names - previous_shape_names
        if new_shapes:
            changes.append({
                'service_type': service_type,
                'change_type': 'modified_shape',
                'operation_name': None,
                'change_path': 'shapes',
                'previous_value': None,
                'current_value': list(new_shapes),
                'description': f"{len(new_shapes)} new data shapes added to {service_type} API",
                'impact_level': 'enhancement',
                'detected_at': datetime.now(timezone.utc)
            })

        # Removed shapes
        removed_shapes = previous_shape_names - current_shape_names
        if removed_shapes:
            changes.append({
                'service_type': service_type,
                'change_type': 'modified_shape',
                'operation_name': None,
                'change_path': 'shapes',
                'previous_value': list(removed_shapes),
                'current_value': None,
                'description': f"{len(removed_shapes)} data shapes removed from {service_type} API",
                'impact_level': 'breaking',
                'detected_at': datetime.now(timezone.utc)
            })

        return changes

    def _detect_metadata_changes(
        self,
        previous_metadata: Dict[str, Any],
        current_metadata: Dict[str, Any],
        service_type: str
    ) -> List[Dict[str, Any]]:
        """Detect changes in service metadata."""
        changes = []

        # Check for API version changes
        prev_version = previous_metadata.get('apiVersion')
        curr_version = current_metadata.get('apiVersion')

        if prev_version != curr_version:
            changes.append({
                'service_type': service_type,
                'change_type': 'modified_operation',
                'operation_name': None,
                'change_path': 'metadata.apiVersion',
                'previous_value': prev_version,
                'current_value': curr_version,
                'description': f"API version changed from {prev_version} to {curr_version} for {service_type}",
                'impact_level': 'non-breaking',
                'detected_at': datetime.now(timezone.utc)
            })

        return changes

    def categorize_changes_by_impact(self, changes: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize changes by impact level."""
        categorized = {
            'breaking': [],
            'non-breaking': [],
            'enhancement': []
        }

        for change in changes:
            impact = change.get('impact_level', 'non-breaking')
            categorized[impact].append(change)

        return categorized

    def get_change_summary(self, changes: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get a summary count of changes by type."""
        summary = {}

        for change in changes:
            change_type = change.get('change_type', 'unknown')
            summary[change_type] = summary.get(change_type, 0) + 1

        return summary
