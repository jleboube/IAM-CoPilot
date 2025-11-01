"""
IAM API Update Agent - Codebase Analyzer Service

Analyzes the current IAM Copilot codebase to understand what's implemented.
"""

import logging
import os
import re
from typing import Dict, Any, List, Set, Optional
from pathlib import Path
import ast

logger = logging.getLogger(__name__)


class AgentCodebaseAnalyzer:
    """Analyzes the IAM Copilot codebase to understand current implementation."""

    def __init__(self, project_root: str = "/app"):
        """
        Initialize the codebase analyzer.

        Args:
            project_root: Root directory of the project
        """
        self.project_root = Path(project_root)
        self.services_dir = self.project_root / "app" / "services"
        self.routers_dir = self.project_root / "app" / "routers"
        self.schemas_dir = self.project_root / "app" / "schemas"

    def analyze_service_implementation(self, service_type: str) -> Dict[str, Any]:
        """
        Analyze what operations are currently implemented for a service.

        Args:
            service_type: Service name (IAM, IdentityCenter, Organizations)

        Returns:
            Analysis of current implementation
        """
        logger.info(f"Analyzing {service_type} service implementation")

        # Map service types to file names
        service_file_map = {
            'IAM': 'iam_service.py',
            'IdentityCenter': 'identity_center_service.py',
            'Organizations': 'organizations_service.py'
        }

        service_file = service_file_map.get(service_type)
        if not service_file:
            logger.warning(f"Unknown service type: {service_type}")
            return {
                'service_type': service_type,
                'implemented_operations': [],
                'file_exists': False
            }

        service_path = self.services_dir / service_file

        if not service_path.exists():
            logger.warning(f"Service file not found: {service_path}")
            return {
                'service_type': service_type,
                'implemented_operations': [],
                'file_exists': False,
                'file_path': str(service_path)
            }

        # Parse the service file
        implemented_operations = self._extract_operations_from_service(service_path)

        return {
            'service_type': service_type,
            'implemented_operations': implemented_operations,
            'file_exists': True,
            'file_path': str(service_path),
            'total_operations': len(implemented_operations)
        }

    def _extract_operations_from_service(self, file_path: Path) -> List[str]:
        """
        Extract operation names from a service file.

        Args:
            file_path: Path to the service file

        Returns:
            List of operation names (method names that match AWS operations)
        """
        operations = []

        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # Parse Python AST
            tree = ast.parse(content)

            # Find all method definitions in classes
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            method_name = item.name

                            # Skip private methods and common utility methods
                            if method_name.startswith('_'):
                                continue
                            if method_name in ['__init__', '__str__', '__repr__']:
                                continue

                            # Look for AWS operation patterns
                            # Common AWS operations: create_, delete_, list_, get_, update_, describe_, put_
                            aws_patterns = [
                                'create_', 'delete_', 'list_', 'get_',
                                'update_', 'describe_', 'put_', 'attach_',
                                'detach_', 'remove_', 'add_', 'enable_',
                                'disable_', 'tag_', 'untag_'
                            ]

                            if any(method_name.startswith(pattern) for pattern in aws_patterns):
                                operations.append(method_name)

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {str(e)}")

        return operations

    def check_operation_exists(
        self,
        service_type: str,
        operation_name: str
    ) -> Dict[str, Any]:
        """
        Check if a specific operation is already implemented.

        Args:
            service_type: Service name
            operation_name: AWS operation name (e.g., "CreateUser")

        Returns:
            Information about whether the operation exists
        """
        analysis = self.analyze_service_implementation(service_type)

        if not analysis['file_exists']:
            return {
                'exists': False,
                'reason': 'Service file does not exist',
                'file_path': analysis.get('file_path')
            }

        # Convert AWS operation name to Python method name
        # CreateUser -> create_user
        method_name = self._aws_operation_to_method_name(operation_name)

        implemented_ops = analysis['implemented_operations']

        exists = method_name in implemented_ops

        return {
            'exists': exists,
            'method_name': method_name,
            'operation_name': operation_name,
            'service_type': service_type,
            'file_path': analysis.get('file_path'),
            'all_operations': implemented_ops
        }

    def _aws_operation_to_method_name(self, operation_name: str) -> str:
        """
        Convert AWS operation name to Python method name.

        Args:
            operation_name: AWS operation name (e.g., "CreateUser")

        Returns:
            Python method name (e.g., "create_user")
        """
        # Convert PascalCase to snake_case
        # Insert underscore before uppercase letters
        method_name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation_name)
        method_name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', method_name)
        return method_name.lower()

    def get_service_file_structure(self, service_type: str) -> Dict[str, Any]:
        """
        Get the structure of a service file for code generation context.

        Args:
            service_type: Service name

        Returns:
            File structure information
        """
        service_file_map = {
            'IAM': 'iam_service.py',
            'IdentityCenter': 'identity_center_service.py',
            'Organizations': 'organizations_service.py'
        }

        service_file = service_file_map.get(service_type)
        if not service_file:
            return {'exists': False}

        service_path = self.services_dir / service_file

        if not service_path.exists():
            return {'exists': False, 'file_path': str(service_path)}

        try:
            with open(service_path, 'r') as f:
                content = f.read()

            tree = ast.parse(content)

            classes = []
            imports = []
            functions = []

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    classes.append({
                        'name': node.name,
                        'methods': [
                            item.name for item in node.body
                            if isinstance(item, ast.FunctionDef)
                        ]
                    })
                elif isinstance(node, ast.Import):
                    imports.extend([alias.name for alias in node.names])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)

            return {
                'exists': True,
                'file_path': str(service_path),
                'classes': classes,
                'imports': list(set(imports)),
                'total_lines': len(content.split('\n'))
            }

        except Exception as e:
            logger.error(f"Error analyzing file structure: {str(e)}")
            return {'exists': True, 'error': str(e)}

    def find_related_files(self, service_type: str) -> Dict[str, List[str]]:
        """
        Find all related files for a service (schemas, routers, etc.).

        Args:
            service_type: Service name

        Returns:
            Dictionary of related file paths by type
        """
        related = {
            'service': [],
            'router': [],
            'schema': [],
            'model': []
        }

        service_name_patterns = {
            'IAM': ['iam'],
            'IdentityCenter': ['identity_center', 'identity-center'],
            'Organizations': ['organizations']
        }

        patterns = service_name_patterns.get(service_type, [])

        # Find service files
        for pattern in patterns:
            for file in self.services_dir.glob(f"*{pattern}*.py"):
                related['service'].append(str(file))

        # Find router files
        for pattern in patterns:
            for file in self.routers_dir.glob(f"*{pattern}*.py"):
                related['router'].append(str(file))

        # Find schema files
        for pattern in patterns:
            for file in self.schemas_dir.glob(f"*{pattern}*.py"):
                related['schema'].append(str(file))

        return related

    def get_code_context(
        self,
        service_type: str,
        context_type: str = 'full'
    ) -> str:
        """
        Get code context for LLM to understand the codebase.

        Args:
            service_type: Service name
            context_type: Type of context (full, summary, structure)

        Returns:
            Formatted context string
        """
        analysis = self.analyze_service_implementation(service_type)
        structure = self.get_service_file_structure(service_type)
        related = self.find_related_files(service_type)

        context_lines = [
            f"# IAM Copilot Codebase Context for {service_type}",
            "",
            f"## Current Implementation Status",
            f"- Service File: {analysis.get('file_path', 'Not found')}",
            f"- File Exists: {analysis.get('file_exists', False)}",
            f"- Implemented Operations: {analysis.get('total_operations', 0)}",
            ""
        ]

        if analysis.get('implemented_operations'):
            context_lines.append("## Currently Implemented Operations:")
            for op in analysis['implemented_operations'][:10]:  # First 10
                context_lines.append(f"  - {op}")
            if len(analysis['implemented_operations']) > 10:
                context_lines.append(f"  ... and {len(analysis['implemented_operations']) - 10} more")
            context_lines.append("")

        if structure.get('classes'):
            context_lines.append("## Service Classes:")
            for cls in structure['classes']:
                context_lines.append(f"  - {cls['name']} ({len(cls['methods'])} methods)")
            context_lines.append("")

        context_lines.append("## Related Files:")
        for file_type, files in related.items():
            if files:
                context_lines.append(f"  {file_type}: {len(files)} file(s)")

        return "\n".join(context_lines)
