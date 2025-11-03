"""
API endpoints for IAM policy operations
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import structlog

from app.database import get_db
from app.models.policy import Policy, PolicyAudit, AuditStatus
from app.models.user_settings import UserSettings
from app.schemas.policy import (
    PolicyGenerateRequest,
    PolicyGenerateResponse,
    PolicySimulateRequest,
    PolicySimulateResponse,
    AuditRequest,
    AuditResponse,
    AccessGraphResponse,
)
from app.services.iam_service import IAMService
from app.services.bedrock_service import BedrockService
from app.services.audit_service import AuditService
from app.dependencies import get_user_settings

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/policies", tags=["policies"])


@router.post("/generate", response_model=PolicyGenerateResponse, status_code=status.HTTP_201_CREATED)
async def generate_policy(
    request: PolicyGenerateRequest,
    db: Session = Depends(get_db),
    user_settings: UserSettings = Depends(get_user_settings)
):
    """
    Generate an IAM policy from natural language description using Amazon Bedrock
    """
    try:
        logger.info("policy_generation_requested", description=request.description[:100])

        # Initialize services with user-specific settings
        bedrock_service = BedrockService(
            model_id=user_settings.bedrock_model_id,
            max_tokens=user_settings.bedrock_max_tokens,
            temperature=user_settings.bedrock_temperature,
            aws_region=user_settings.default_aws_region
        )
        iam_service = IAMService()

        # Generate policy using Bedrock
        generated = bedrock_service.generate_policy_from_nl(
            description=request.description,
            resource_arns=request.resource_arns,
            principal_type=request.principal_type
        )

        policy_json = generated['policy_document']

        # Validate policy structure
        validation = iam_service.validate_policy_document(policy_json)
        if not validation['valid']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Generated policy is invalid: {validation['errors']}"
            )

        # Simulate policy (optional validation)
        simulation_results = None
        try:
            # Extract actions from policy for simulation
            actions = []
            for statement in policy_json.get('Statement', []):
                stmt_actions = statement.get('Action', [])
                if isinstance(stmt_actions, str):
                    stmt_actions = [stmt_actions]
                actions.extend(stmt_actions)

            if actions:
                simulation_results = iam_service.simulate_custom_policy(
                    policy_document=policy_json,
                    action_names=actions[:10],  # Limit to first 10 actions
                    resource_arns=request.resource_arns
                )
        except Exception as e:
            logger.warning("policy_simulation_failed", error=str(e))

        # Save to database
        policy = Policy(
            name=generated['policy_name'],
            description=request.description,
            natural_language_input=request.description,
            policy_json=policy_json,
            aws_account_id=request.aws_account_id
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)

        logger.info("policy_generated_successfully", policy_id=policy.id)

        return PolicyGenerateResponse(
            policy_id=policy.id,
            name=policy.name,
            policy_json=policy_json,
            description=request.description,
            natural_language_input=request.description,
            validation_status="valid",
            simulation_results=simulation_results,
            created_at=policy.created_at
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("policy_generation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy generation failed: {str(e)}"
        )


@router.post("/simulate", response_model=PolicySimulateResponse)
async def simulate_policy(request: PolicySimulateRequest):
    """
    Simulate an IAM policy to test what actions would be allowed or denied
    """
    try:
        logger.info("policy_simulation_requested", actions_count=len(request.action_names))

        iam_service = IAMService()

        # Simulate the policy
        results = iam_service.simulate_custom_policy(
            policy_document=request.policy_document,
            action_names=request.action_names,
            resource_arns=request.resource_arns
        )

        logger.info("policy_simulation_completed")

        return PolicySimulateResponse(
            evaluation_results=results['evaluation_results'],
            matched_statements=results['matched_statements'],
            denied_actions=results['denied_actions'],
            allowed_actions=results['allowed_actions'],
            summary=results['summary']
        )

    except Exception as e:
        logger.error("policy_simulation_failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy simulation failed: {str(e)}"
        )


@router.post("/audit", response_model=AuditResponse, status_code=status.HTTP_202_ACCEPTED)
async def audit_iam(
    request: AuditRequest,
    db: Session = Depends(get_db)
):
    """
    Start an asynchronous audit of IAM configuration
    """
    try:
        logger.info("audit_requested", account_id=request.aws_account_id)

        # Create audit record
        audit = PolicyAudit(
            aws_account_id=request.aws_account_id,
            role_arn=request.role_arn,
            status=AuditStatus.PENDING
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)

        # In a real implementation, this would trigger a Celery task
        # For now, we'll run it synchronously (should be async in production)
        try:
            # Initialize services
            iam_service = IAMService(role_arn=request.role_arn)
            bedrock_service = BedrockService()
            audit_service = AuditService(iam_service, bedrock_service)

            # Update status
            audit.status = AuditStatus.IN_PROGRESS
            db.commit()

            # Run audit
            audit_results = audit_service.audit_account(
                aws_account_id=request.aws_account_id,
                audit_scope=request.audit_scope
            )

            # Update audit with results
            audit.status = AuditStatus.COMPLETED
            audit.findings = audit_results['findings']
            audit.recommendations = audit_results['stats']
            db.commit()

        except Exception as e:
            audit.status = AuditStatus.FAILED
            audit.error_message = str(e)
            db.commit()
            raise

        logger.info("audit_completed", audit_id=audit.id)

        return AuditResponse(
            audit_id=audit.id,
            status=audit.status.value,
            aws_account_id=request.aws_account_id,
            started_at=audit.started_at,
            message="Audit completed successfully" if audit.status == AuditStatus.COMPLETED else "Audit failed"
        )

    except Exception as e:
        logger.error("audit_failed", error=str(e))

        # Extract helpful error message from AWS ClientError
        error_message = str(e)
        if "AccessDenied" in error_message or "not authorized" in error_message:
            error_message = "AWS IAM permissions required. Please ensure your AWS credentials have the following permissions: iam:GetAccountAuthorizationDetails, iam:ListRoles, iam:ListUsers, iam:GetRole, iam:GetRolePolicy, iam:ListAttachedRolePolicies. See the README for full IAM policy requirements."
        elif "RetryError" in error_message:
            error_message = "Unable to complete audit after multiple retries. Please check your AWS credentials and permissions."

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_message
        )


@router.get("/audit/{audit_id}")
async def get_audit_results(audit_id: int, db: Session = Depends(get_db)):
    """
    Get audit results by audit ID
    """
    audit = db.query(PolicyAudit).filter(PolicyAudit.id == audit_id).first()
    if not audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit not found"
        )

    return {
        "audit_id": audit.id,
        "status": audit.status.value,
        "aws_account_id": audit.aws_account_id,
        "findings": audit.findings,
        "recommendations": audit.recommendations,
        "error_message": audit.error_message,
        "created_at": audit.created_at,
        "completed_at": audit.completed_at
    }


@router.get("/access-graph/{aws_account_id}", response_model=AccessGraphResponse)
async def get_access_graph(aws_account_id: str, role_arn: str | None = None):
    """
    Generate an interactive access graph showing IAM relationships
    """
    try:
        logger.info("access_graph_requested", account_id=aws_account_id)

        # Initialize services
        iam_service = IAMService(role_arn=role_arn)
        bedrock_service = BedrockService()
        audit_service = AuditService(iam_service, bedrock_service)

        # Generate graph
        graph = audit_service.generate_access_graph(aws_account_id)

        logger.info("access_graph_generated", account_id=aws_account_id)

        return AccessGraphResponse(
            nodes=graph['nodes'],
            edges=graph['edges'],
            stats=graph['stats']
        )

    except Exception as e:
        logger.error("access_graph_generation_failed", error=str(e))

        # Extract helpful error message from AWS ClientError
        error_message = str(e)
        if "AccessDenied" in error_message or "not authorized" in error_message:
            error_message = "AWS IAM permissions required. Please ensure your AWS credentials have permissions to list IAM resources. See the README for full IAM policy requirements."

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=error_message
        )


@router.get("/{policy_id}")
async def get_policy(policy_id: int, db: Session = Depends(get_db)):
    """
    Get a policy by ID
    """
    policy = db.query(Policy).filter(Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )

    return {
        "id": policy.id,
        "name": policy.name,
        "description": policy.description,
        "natural_language_input": policy.natural_language_input,
        "policy_json": policy.policy_json,
        "aws_policy_arn": policy.aws_policy_arn,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at
    }


@router.get("/")
async def list_policies(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """
    List all generated policies
    """
    policies = db.query(Policy).offset(skip).limit(limit).all()
    return {
        "policies": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "created_at": p.created_at
            }
            for p in policies
        ],
        "total": db.query(Policy).count()
    }
