"""
AWS API Discovery Service

Discovers and extracts API definitions for AWS services using boto3's service models.
"""

import boto3
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)


class APIDiscoveryService:
    """Service for discovering AWS service API definitions."""

    # Services we're monitoring
    MONITORED_SERVICES = {
        'iam': 'IAM',
        'sso-admin': 'IdentityCenter',
        'organizations': 'Organizations'
    }

    def __init__(self):
        """Initialize the API discovery service."""
        self.boto3_session = boto3.Session()

    def discover_service_api(self, service_name: str) -> Dict[str, Any]:
        """
        Discover and extract complete API definition for a service.

        Args:
            service_name: AWS service name (e.g., 'iam', 'sso-admin', 'organizations')

        Returns:
            Complete API definition including operations, shapes, and metadata
        """
        try:
            # Get the service model from boto3
            client = self.boto3_session.client(service_name)
            service_model = client._service_model

            # Extract comprehensive API definition
            api_definition = {
                'service_name': service_name,
                'service_id': service_model.service_id,
                'api_version': service_model.api_version,
                'protocol': service_model.protocol,
                'endpoint_prefix': service_model.endpoint_prefix,
                'signing_name': service_model.signing_name,
                'service_full_name': service_model.service_description.get('serviceFullName', ''),
                'operations': self._extract_operations(service_model),
                'shapes': self._extract_shapes(service_model),
                'metadata': service_model.metadata,
                'discovery_timestamp': datetime.now(timezone.utc).isoformat()
            }

            logger.info(f"Discovered API for {service_name}: {len(api_definition['operations'])} operations")
            return api_definition

        except Exception as e:
            logger.error(f"Failed to discover API for {service_name}: {str(e)}")
            raise

    def _extract_operations(self, service_model) -> Dict[str, Any]:
        """Extract all operations from the service model."""
        operations = {}

        for operation_name in service_model.operation_names:
            operation_model = service_model.operation_model(operation_name)

            operations[operation_name] = {
                'name': operation_name,
                'http': {
                    'method': operation_model.http.get('method', 'POST'),
                    'requestUri': operation_model.http.get('requestUri', '/'),
                },
                'input': self._extract_shape_reference(operation_model.input_shape) if operation_model.input_shape else None,
                'output': self._extract_shape_reference(operation_model.output_shape) if operation_model.output_shape else None,
                'errors': [
                    self._extract_shape_reference(error)
                    for error in operation_model.error_shapes
                ] if operation_model.error_shapes else [],
                'documentation': operation_model.documentation,
                'deprecated': getattr(operation_model, 'deprecated', False),
                'deprecatedMessage': getattr(operation_model, 'deprecatedMessage', None)
            }

        return operations

    def _extract_shape_reference(self, shape) -> Dict[str, Any]:
        """Extract shape reference information."""
        if not shape:
            return None

        shape_info = {
            'name': shape.name,
            'type': shape.type_name,
        }

        # Add type-specific details
        if shape.type_name == 'structure':
            shape_info['members'] = {
                member_name: {
                    'shape': member_shape.name,
                    'required': member_name in shape.required_members,
                    'documentation': getattr(member_shape, 'documentation', None)
                }
                for member_name, member_shape in shape.members.items()
            }
            shape_info['required'] = list(shape.required_members)

        elif shape.type_name == 'list':
            shape_info['member'] = shape.member.name

        elif shape.type_name == 'map':
            shape_info['key'] = shape.key.name
            shape_info['value'] = shape.value.name

        elif shape.type_name in ['string', 'integer', 'boolean', 'long', 'double', 'float']:
            if hasattr(shape, 'enum'):
                shape_info['enum'] = shape.enum
            if hasattr(shape, 'min'):
                shape_info['min'] = shape.min
            if hasattr(shape, 'max'):
                shape_info['max'] = shape.max
            if hasattr(shape, 'pattern'):
                shape_info['pattern'] = shape.pattern

        return shape_info

    def _extract_shapes(self, service_model) -> Dict[str, Any]:
        """Extract all shape definitions from the service model."""
        shapes = {}

        # Get all shapes from the service model
        for shape_name in service_model._shape_resolver._shape_map.keys():
            shape = service_model._shape_resolver.get_shape_by_name(shape_name)

            shapes[shape_name] = {
                'name': shape_name,
                'type': shape.type_name,
                'documentation': getattr(shape, 'documentation', None)
            }

            # Add type-specific details
            if shape.type_name == 'structure':
                shapes[shape_name]['members'] = {
                    member_name: member_shape.name
                    for member_name, member_shape in shape.members.items()
                }
                if shape.required_members:
                    shapes[shape_name]['required'] = list(shape.required_members)

            elif shape.type_name == 'list':
                shapes[shape_name]['member'] = shape.member.name

            elif shape.type_name == 'map':
                shapes[shape_name]['key'] = shape.key.name
                shapes[shape_name]['value'] = shape.value.name

        return shapes

    def discover_all_monitored_services(self) -> Dict[str, Dict[str, Any]]:
        """
        Discover API definitions for all monitored services.

        Returns:
            Dictionary mapping service names to their API definitions
        """
        all_apis = {}

        for boto_service_name, service_type in self.MONITORED_SERVICES.items():
            try:
                api_def = self.discover_service_api(boto_service_name)
                all_apis[service_type] = api_def
            except Exception as e:
                logger.error(f"Failed to discover {service_type}: {str(e)}")
                # Continue with other services even if one fails
                continue

        return all_apis

    def get_operation_count(self, api_definition: Dict[str, Any]) -> int:
        """Get the total number of operations in an API definition."""
        return len(api_definition.get('operations', {}))

    def get_shape_count(self, api_definition: Dict[str, Any]) -> int:
        """Get the total number of shapes in an API definition."""
        return len(api_definition.get('shapes', {}))

    def get_operation_summary(self, api_definition: Dict[str, Any]) -> List[str]:
        """Get a list of all operation names."""
        return list(api_definition.get('operations', {}).keys())
