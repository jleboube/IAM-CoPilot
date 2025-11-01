"""
Policy Validation Router

Provides endpoints for enhanced IAM policy validation with condition key checking,
real-time validation, and permissions boundary management.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import logging

from app.database import get_db
from app.schemas.policy_validation import (
    ValidatePolicyRequest,
    ValidationResult,
    ConditionKeySuggestionsRequest,
    ConditionKeySuggestionsResponse,
    ConditionOperatorsResponse,
    ValidateConditionRequest,
    ValidateConditionResponse,
    PermissionsBoundarySetRequest,
    PermissionsBoundaryDeleteRequest,
    PermissionsBoundaryResponse
)
from app.services.enhanced_policy_validator import EnhancedPolicyValidator
from app.services.condition_key_catalog import ConditionKeyCatalog
from app.services.iam_service import IAMService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/policy-validation", tags=["Policy Validation"])


@router.post("/validate", response_model=ValidationResult)
def validate_policy(
    request: ValidatePolicyRequest,
    db: Session = Depends(get_db)
):
    """
    Perform comprehensive IAM policy validation.

    This endpoint provides enhanced validation including:
    - Structural validation
    - Condition key validation against AWS catalog
    - Condition operator validation
    - Action and resource validation
    - Security best practice checks

    Validation levels:
    - **basic**: Structure and syntax only
    - **standard**: Basic + actions, resources, conditions
    - **comprehensive**: Standard + best practices, detailed suggestions

    Args:
        request: Policy validation request
        db: Database session

    Returns:
        Detailed validation results with errors, warnings, and suggestions
    """
    try:
        validator = EnhancedPolicyValidator()

        # Perform validation
        results = validator.validate_policy(
            request.policy_document,
            request.validation_level
        )

        # Add human-readable summary
        results['summary'] = validator.get_validation_summary(results)

        logger.info(
            f"Policy validated: valid={results['valid']}, "
            f"errors={len(results['errors'])}, warnings={len(results['warnings'])}"
        )

        return results

    except Exception as e:
        logger.error(f"Policy validation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Validation failed: {str(e)}"
        )


@router.post("/condition-keys/suggest", response_model=ConditionKeySuggestionsResponse)
def suggest_condition_keys(
    request: ConditionKeySuggestionsRequest,
    db: Session = Depends(get_db)
):
    """
    Get condition key suggestions for autocomplete.

    This endpoint helps developers discover and use the correct condition keys
    when writing IAM policies.

    Args:
        request: Suggestion request with optional service and prefix
        db: Database session

    Returns:
        List of matching condition keys with descriptions

    Examples:
        - Get all S3 condition keys: `{"service": "s3"}`
        - Autocomplete for IAM: `{"service": "iam", "prefix": "iam:Policy"}`
        - Get all global keys: `{"service": null}`
    """
    try:
        catalog = ConditionKeyCatalog()

        suggestions = catalog.suggest_condition_keys(
            service=request.service,
            prefix=request.prefix or ''
        )

        return {
            'suggestions': suggestions,
            'total': len(suggestions),
            'service': request.service
        }

    except Exception as e:
        logger.error(f"Failed to get suggestions: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get suggestions: {str(e)}"
        )


@router.get("/condition-keys/operators", response_model=ConditionOperatorsResponse)
def get_condition_operators(db: Session = Depends(get_db)):
    """
    Get all available IAM condition operators.

    Returns a map of condition operators to their data types.

    Returns:
        Dictionary of operators (e.g., "StringEquals": "String")
    """
    try:
        catalog = ConditionKeyCatalog()

        return {
            'operators': catalog.CONDITION_OPERATORS
        }

    except Exception as e:
        logger.error(f"Failed to get operators: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get operators: {str(e)}"
        )


@router.post("/validate-condition", response_model=ValidateConditionResponse)
def validate_condition(
    request: ValidateConditionRequest,
    db: Session = Depends(get_db)
):
    """
    Validate a specific condition (real-time validation).

    This is useful for IDE integrations and real-time feedback as users
    type policy conditions.

    Args:
        request: Condition validation request
        db: Database session

    Returns:
        Validation result for the specific condition

    Example:
        ```json
        {
          "operator": "StringEquals",
          "condition_key": "s3:prefix",
          "condition_value": "home/",
          "service": "s3"
        }
        ```
    """
    try:
        catalog = ConditionKeyCatalog()
        validator = EnhancedPolicyValidator()

        results = {'valid': True, 'errors': [], 'warnings': [], 'key_info': None}

        # Validate operator
        if not catalog.is_valid_operator(request.operator):
            results['valid'] = False
            results['errors'].append(f"Invalid condition operator: {request.operator}")
            return results

        # Validate condition key
        if not catalog.is_valid_condition_key(request.condition_key, request.service):
            results['valid'] = False
            results['errors'].append(f"Invalid condition key: {request.condition_key}")

            # Provide suggestions
            suggestions = validator._suggest_similar_keys(
                request.condition_key,
                request.service
            )
            if suggestions:
                results['warnings'].append(f"Did you mean: {', '.join(suggestions[:3])}")

            return results

        # Validate operator matches key type
        if not catalog.validate_operator_for_key(request.operator, request.condition_key):
            results['valid'] = False

            all_keys = catalog.get_all_condition_keys(request.service)
            key_info = all_keys.get(request.condition_key, {})
            expected_type = key_info.get('type', 'Unknown')
            operator_type = catalog.get_operator_type(request.operator)

            results['errors'].append(
                f"Operator '{request.operator}' (type: {operator_type}) is not compatible "
                f"with condition key '{request.condition_key}' (type: {expected_type})"
            )
            return results

        # Validate value format
        value_validation = validator._validate_condition_value(
            request.operator,
            request.condition_key,
            request.condition_value,
            "Condition"
        )

        results['errors'].extend(value_validation['errors'])
        results['warnings'].extend(value_validation['warnings'])

        if results['errors']:
            results['valid'] = False

        # Add key info
        all_keys = catalog.get_all_condition_keys(request.service)
        key_info = all_keys.get(request.condition_key)
        if key_info:
            results['key_info'] = key_info

        return results

    except Exception as e:
        logger.error(f"Condition validation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Validation failed: {str(e)}"
        )


@router.post("/permissions-boundary/set", response_model=PermissionsBoundaryResponse)
def set_permissions_boundary(
    request: PermissionsBoundarySetRequest,
    db: Session = Depends(get_db)
):
    """
    Set permissions boundary on an IAM user or role.

    Permissions boundaries define the maximum permissions that an identity-based
    policy can grant to an IAM entity.

    Args:
        request: Permissions boundary set request
        db: Database session

    Returns:
        Operation result

    Example:
        ```json
        {
          "resource_type": "user",
          "resource_name": "developer-user",
          "boundary_policy_arn": "arn:aws:iam::123456789012:policy/DeveloperBoundary"
        }
        ```
    """
    try:
        # Validate resource type
        if request.resource_type not in ['user', 'role']:
            raise HTTPException(
                status_code=400,
                detail="resource_type must be 'user' or 'role'"
            )

        # Initialize IAM service
        iam_service = IAMService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn
        )

        # Set permissions boundary
        if request.resource_type == 'user':
            iam_service.iam_client.put_user_permissions_boundary(
                UserName=request.resource_name,
                PermissionsBoundary=request.boundary_policy_arn
            )
        else:  # role
            iam_service.iam_client.put_role_permissions_boundary(
                RoleName=request.resource_name,
                PermissionsBoundary=request.boundary_policy_arn
            )

        logger.info(
            f"Set permissions boundary on {request.resource_type} "
            f"{request.resource_name}: {request.boundary_policy_arn}"
        )

        return {
            'success': True,
            'message': f"Permissions boundary set successfully on {request.resource_type} {request.resource_name}",
            'resource_type': request.resource_type,
            'resource_name': request.resource_name,
            'boundary_policy_arn': request.boundary_policy_arn
        }

    except Exception as e:
        logger.error(f"Failed to set permissions boundary: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to set permissions boundary: {str(e)}"
        )


@router.post("/permissions-boundary/delete", response_model=PermissionsBoundaryResponse)
def delete_permissions_boundary(
    request: PermissionsBoundaryDeleteRequest,
    db: Session = Depends(get_db)
):
    """
    Remove permissions boundary from an IAM user or role.

    Args:
        request: Permissions boundary delete request
        db: Database session

    Returns:
        Operation result
    """
    try:
        # Validate resource type
        if request.resource_type not in ['user', 'role']:
            raise HTTPException(
                status_code=400,
                detail="resource_type must be 'user' or 'role'"
            )

        # Initialize IAM service
        iam_service = IAMService(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn
        )

        # Delete permissions boundary
        if request.resource_type == 'user':
            iam_service.iam_client.delete_user_permissions_boundary(
                UserName=request.resource_name
            )
        else:  # role
            iam_service.iam_client.delete_role_permissions_boundary(
                RoleName=request.resource_name
            )

        logger.info(
            f"Deleted permissions boundary from {request.resource_type} "
            f"{request.resource_name}"
        )

        return {
            'success': True,
            'message': f"Permissions boundary removed from {request.resource_type} {request.resource_name}",
            'resource_type': request.resource_type,
            'resource_name': request.resource_name,
            'boundary_policy_arn': None
        }

    except Exception as e:
        logger.error(f"Failed to delete permissions boundary: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete permissions boundary: {str(e)}"
        )


@router.get("/health")
def validation_health():
    """
    Health check for policy validation service.

    Returns:
        Service status and available features
    """
    try:
        catalog = ConditionKeyCatalog()

        total_services = len(catalog.SERVICE_CONDITION_KEYS)
        total_operators = len(catalog.CONDITION_OPERATORS)
        total_global_keys = len(catalog.GLOBAL_CONDITION_KEYS)

        total_service_keys = sum(
            len(keys) for keys in catalog.SERVICE_CONDITION_KEYS.values()
        )

        return {
            'status': 'healthy',
            'features': {
                'enhanced_validation': True,
                'condition_key_validation': True,
                'real_time_validation': True,
                'permissions_boundary_management': True,
                'condition_key_suggestions': True
            },
            'catalog_stats': {
                'services_supported': total_services,
                'global_condition_keys': total_global_keys,
                'service_specific_keys': total_service_keys,
                'total_condition_keys': total_global_keys + total_service_keys,
                'condition_operators': total_operators
            }
        }

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            'status': 'unhealthy',
            'error': str(e)
        }
