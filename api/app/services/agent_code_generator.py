"""
IAM API Update Agent - Code Generator Service

Generates code changes using LLM (Bedrock) based on change plans.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from app.services.bedrock_service import BedrockService
from app.services.agent_codebase_analyzer import AgentCodebaseAnalyzer

logger = logging.getLogger(__name__)


class AgentCodeGenerator:
    """Generates code using LLM to implement planned changes."""

    def __init__(self):
        """Initialize the code generator."""
        self.bedrock = BedrockService()
        self.analyzer = AgentCodebaseAnalyzer()

    def generate_code_for_change(
        self,
        planned_change: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate code for a specific planned change.

        Args:
            planned_change: A planned change from the change planner

        Returns:
            Generated code and implementation details
        """
        change_type = planned_change.get('change_type')

        logger.info(f"Generating code for {change_type}: {planned_change.get('description')}")

        if change_type == 'add_operation':
            return self._generate_new_operation_code(planned_change)
        elif change_type == 'update_schema':
            return self._generate_schema_code(planned_change)
        elif change_type == 'add_endpoint':
            return self._generate_endpoint_code(planned_change)
        elif change_type == 'deprecate_operation':
            return self._generate_deprecation_code(planned_change)
        elif change_type == 'remove_operation':
            return self._generate_removal_plan(planned_change)
        else:
            logger.warning(f"Unknown change type: {change_type}")
            return {
                'success': False,
                'error': f"Unsupported change type: {change_type}"
            }

    def _generate_new_operation_code(self, planned_change: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate code for a new AWS operation.

        Args:
            planned_change: Planned change details

        Returns:
            Generated service method code
        """
        service_type = planned_change.get('service_type')
        operation_name = planned_change.get('operation_name')
        implementation_plan = planned_change.get('implementation_plan', {})

        # Get codebase context
        context = self.analyzer.get_code_context(service_type, context_type='full')

        # Get AWS operation details if available
        aws_operation_details = planned_change.get('aws_operation_details', {})

        # Build LLM prompt
        prompt = self._build_operation_generation_prompt(
            service_type=service_type,
            operation_name=operation_name,
            method_name=implementation_plan.get('method_name', ''),
            boto3_client=implementation_plan.get('boto3_client', ''),
            aws_details=aws_operation_details,
            codebase_context=context
        )

        # Generate code using Bedrock
        try:
            generated_code = self.bedrock.generate_text(
                prompt=prompt,
                max_tokens=2000,
                temperature=0.3  # Lower temperature for more deterministic code
            )

            # Extract just the code from the response
            code = self._extract_code_from_response(generated_code)

            return {
                'success': True,
                'generated_code': code,
                'method_name': implementation_plan.get('method_name'),
                'operation_name': operation_name,
                'target_file': planned_change.get('target_file'),
                'insertion_strategy': 'append_to_class'
            }

        except Exception as e:
            logger.error(f"Failed to generate code: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def _build_operation_generation_prompt(
        self,
        service_type: str,
        operation_name: str,
        method_name: str,
        boto3_client: str,
        aws_details: Dict[str, Any],
        codebase_context: str
    ) -> str:
        """Build the LLM prompt for generating a new operation method."""

        prompt = f"""You are an expert Python developer working on the IAM Copilot project. You need to add a new AWS API operation to the codebase.

## Task
Add support for the AWS {service_type} operation: {operation_name}

## Codebase Context
{codebase_context}

## AWS Operation Details
Operation Name: {operation_name}
Boto3 Client: {boto3_client}
Python Method Name: {method_name}

## Operation Information
{json.dumps(aws_details, indent=2) if aws_details else 'No additional details available'}

## Requirements
1. Generate a Python method that calls the AWS API using boto3
2. Follow the existing code style and patterns in the codebase
3. Include proper error handling with try/except
4. Add logging statements for debugging
5. Include a docstring explaining the method
6. Handle AWS SDK pagination if this is a List operation
7. Return data in a structured format (dict or list)

## Code Style Guidelines
- Use type hints for parameters and return types
- Follow Python naming conventions (snake_case for methods)
- Include comprehensive docstrings
- Log both successful operations and errors
- Handle boto3 exceptions gracefully

## Example Structure
```python
def {method_name}(self, **kwargs) -> Dict[str, Any]:
    \"\"\"
    [Description of what this operation does]

    Args:
        [Parameters]

    Returns:
        [Return value description]
    \"\"\"
    try:
        response = self.client.{self._aws_operation_to_boto3(operation_name)}(**kwargs)
        # Process response
        return response
    except ClientError as e:
        logger.error(f"Error in {method_name}: {{e}}")
        raise
```

Generate ONLY the Python method code, no explanations. The code should be production-ready and follow the patterns used in the existing codebase.
"""
        return prompt

    def _generate_schema_code(self, planned_change: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Pydantic schema code for an operation."""

        service_type = planned_change.get('service_type')
        operation_name = planned_change.get('operation_name')

        prompt = f"""You are an expert Python developer working on the IAM Copilot project. Generate Pydantic schemas for a new AWS API operation.

## Task
Create request and response schemas for the AWS {service_type} operation: {operation_name}

## Requirements
1. Generate two Pydantic BaseModel classes:
   - {operation_name}Request (for request validation)
   - {operation_name}Response (for response serialization)

2. Follow these patterns:
   - Use Optional[] for optional fields
   - Use List[] and Dict[] for collections
   - Include Field() with description for documentation
   - Add class Config with from_attributes = True

## Example Structure
```python
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class {operation_name}Request(BaseModel):
    \"\"\"Request schema for {operation_name} operation.\"\"\"
    # Add relevant fields based on AWS API
    pass

    class Config:
        from_attributes = True

class {operation_name}Response(BaseModel):
    \"\"\"Response schema for {operation_name} operation.\"\"\"
    # Add relevant fields based on AWS API response
    pass

    class Config:
        from_attributes = True
```

Generate ONLY the Python code for both schema classes, no explanations.
"""

        try:
            generated_code = self.bedrock.generate_text(
                prompt=prompt,
                max_tokens=1500,
                temperature=0.3
            )

            code = self._extract_code_from_response(generated_code)

            return {
                'success': True,
                'generated_code': code,
                'operation_name': operation_name,
                'target_file': planned_change.get('target_file'),
                'insertion_strategy': 'append_to_file'
            }

        except Exception as e:
            logger.error(f"Failed to generate schema code: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def _generate_endpoint_code(self, planned_change: Dict[str, Any]) -> Dict[str, Any]:
        """Generate FastAPI endpoint code."""

        service_type = planned_change.get('service_type')
        operation_name = planned_change.get('operation_name')
        implementation_plan = planned_change.get('implementation_plan', {})

        http_method = implementation_plan.get('http_method', 'POST')
        endpoint_path = implementation_plan.get('path', '/unknown')

        prompt = f"""You are an expert Python developer working on the IAM Copilot FastAPI application. Generate a REST API endpoint for a new AWS operation.

## Task
Create a FastAPI endpoint for the AWS {service_type} operation: {operation_name}

## Endpoint Details
- HTTP Method: {http_method}
- Path: {endpoint_path}
- Operation: {operation_name}

## Requirements
1. Use FastAPI's @router.{http_method.lower()}() decorator
2. Include proper dependency injection (Depends)
3. Use appropriate Pydantic schemas for request/response
4. Include error handling with HTTPException
5. Add comprehensive docstring
6. Return appropriate HTTP status codes

## Example Structure
```python
@router.{http_method.lower()}("{endpoint_path}", response_model={operation_name}Response)
def {operation_name.lower()}(
    request: {operation_name}Request,
    db: Session = Depends(get_db)
):
    \"\"\"
    [Description of endpoint]

    Args:
        request: The request payload
        db: Database session

    Returns:
        Operation result
    \"\"\"
    try:
        service = {service_type}Service()
        result = service.{operation_name.lower()}(**request.dict())
        return result
    except Exception as e:
        logger.error(f"Error in {operation_name}: {{str(e)}}")
        raise HTTPException(status_code=500, detail=str(e))
```

Generate ONLY the Python endpoint function code, no explanations.
"""

        try:
            generated_code = self.bedrock.generate_text(
                prompt=prompt,
                max_tokens=1500,
                temperature=0.3
            )

            code = self._extract_code_from_response(generated_code)

            return {
                'success': True,
                'generated_code': code,
                'operation_name': operation_name,
                'target_file': planned_change.get('target_file'),
                'insertion_strategy': 'append_to_router'
            }

        except Exception as e:
            logger.error(f"Failed to generate endpoint code: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def _generate_deprecation_code(self, planned_change: Dict[str, Any]) -> Dict[str, Any]:
        """Generate code to mark an operation as deprecated."""

        method_name = planned_change.get('implementation_plan', {}).get('method_name', '')
        deprecation_message = planned_change.get('implementation_plan', {}).get('deprecation_message', '')

        # Simple deprecation decorator
        deprecation_code = f'''
import warnings

def deprecated(message):
    """Decorator to mark functions as deprecated."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            warnings.warn(f"{{func.__name__}} is deprecated: {{message}}",
                        DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Add this decorator above the {method_name} method:
@deprecated("{deprecation_message}")
'''

        return {
            'success': True,
            'generated_code': deprecation_code,
            'method_name': method_name,
            'target_file': planned_change.get('target_file'),
            'insertion_strategy': 'add_decorator'
        }

    def _generate_removal_plan(self, planned_change: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a plan for removing an operation (not actual code)."""

        method_name = planned_change.get('implementation_plan', {}).get('method_name', '')

        return {
            'success': True,
            'generated_code': f'# TODO: Remove method {method_name} - AWS has removed this operation',
            'method_name': method_name,
            'target_file': planned_change.get('target_file'),
            'insertion_strategy': 'manual_review',
            'requires_manual_review': True,
            'removal_reason': 'AWS API removed this operation'
        }

    def _extract_code_from_response(self, llm_response: str) -> str:
        """
        Extract Python code from LLM response.

        Args:
            llm_response: The full LLM response

        Returns:
            Extracted code
        """
        # Remove markdown code blocks if present
        if '```python' in llm_response:
            start = llm_response.find('```python') + 9
            end = llm_response.find('```', start)
            if end > start:
                return llm_response[start:end].strip()
        elif '```' in llm_response:
            start = llm_response.find('```') + 3
            end = llm_response.find('```', start)
            if end > start:
                return llm_response[start:end].strip()

        # Return the whole response if no code blocks found
        return llm_response.strip()

    def _aws_operation_to_boto3(self, operation_name: str) -> str:
        """Convert AWS operation name to boto3 method name."""
        # PascalCase to snake_case
        import re
        method_name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation_name)
        method_name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', method_name)
        return method_name.lower()
