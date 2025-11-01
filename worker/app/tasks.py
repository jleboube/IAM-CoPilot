"""
Celery tasks for IAM auditing
"""
from datetime import datetime
import structlog
from celery import Task

from app.celery_app import celery_app

logger = structlog.get_logger(__name__)


class IAMAuditTask(Task):
    """Base task for IAM audits with error handling"""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure"""
        logger.error(
            "task_failed",
            task_id=task_id,
            exception=str(exc),
            traceback=str(einfo)
        )

    def on_success(self, retval, task_id, args, kwargs):
        """Handle task success"""
        logger.info("task_completed", task_id=task_id)


@celery_app.task(base=IAMAuditTask, bind=True, max_retries=3)
def audit_iam_account(self, audit_id: int, aws_account_id: str, role_arn: str | None = None, audit_scope: str = "roles"):
    """
    Async task to audit IAM configuration

    Args:
        audit_id: Database ID of the audit record
        aws_account_id: AWS account ID to audit
        role_arn: Optional cross-account role ARN
        audit_scope: Scope of audit (roles, users, policies, or all)
    """
    logger.info(
        "audit_task_started",
        task_id=self.request.id,
        audit_id=audit_id,
        account_id=aws_account_id
    )

    try:
        # Import here to avoid circular dependencies
        from app.services.iam_service import IAMService
        from app.services.bedrock_service import BedrockService
        from app.services.audit_service import AuditService
        from app.database import SessionLocal
        from app.models import PolicyAudit, AuditStatus

        # Create database session
        db = SessionLocal()

        try:
            # Get audit record
            audit = db.query(PolicyAudit).filter(PolicyAudit.id == audit_id).first()
            if not audit:
                raise ValueError(f"Audit {audit_id} not found")

            # Update status
            audit.status = AuditStatus.IN_PROGRESS
            audit.started_at = datetime.utcnow()
            db.commit()

            # Initialize services
            iam_service = IAMService(role_arn=role_arn)
            bedrock_service = BedrockService()
            audit_service = AuditService(iam_service, bedrock_service)

            # Run audit
            results = audit_service.audit_account(
                aws_account_id=aws_account_id,
                audit_scope=audit_scope
            )

            # Update audit record with results
            audit.status = AuditStatus.COMPLETED
            audit.findings = results['findings']
            audit.recommendations = results['stats']
            audit.completed_at = datetime.utcnow()
            db.commit()

            logger.info(
                "audit_task_completed",
                audit_id=audit_id,
                findings_count=len(results['findings'])
            )

            return {
                'audit_id': audit_id,
                'status': 'completed',
                'findings_count': len(results['findings'])
            }

        finally:
            db.close()

    except Exception as exc:
        logger.error(
            "audit_task_failed",
            audit_id=audit_id,
            error=str(exc)
        )

        # Update audit status to failed
        try:
            db = SessionLocal()
            audit = db.query(PolicyAudit).filter(PolicyAudit.id == audit_id).first()
            if audit:
                audit.status = AuditStatus.FAILED
                audit.error_message = str(exc)
                audit.completed_at = datetime.utcnow()
                db.commit()
            db.close()
        except Exception as db_exc:
            logger.error("failed_to_update_audit_status", error=str(db_exc))

        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)


@celery_app.task(base=IAMAuditTask, bind=True)
def analyze_cloudtrail_usage(self, role_arn: str, days: int = 90):
    """
    Analyze CloudTrail logs to identify unused permissions

    Args:
        role_arn: ARN of the role to analyze
        days: Number of days to look back (default 90)
    """
    logger.info("cloudtrail_analysis_started", role_arn=role_arn, days=days)

    try:
        import boto3
        from collections import defaultdict

        cloudtrail = boto3.client('cloudtrail')

        # Look up events for the role
        events = []
        paginator = cloudtrail.get_paginator('lookup_events')

        for page in paginator.paginate(
            LookupAttributes=[
                {
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': role_arn
                }
            ]
        ):
            events.extend(page.get('Events', []))

        # Aggregate actions used
        actions_used = defaultdict(int)
        for event in events:
            event_name = event.get('EventName')
            if event_name:
                actions_used[event_name] += 1

        logger.info(
            "cloudtrail_analysis_completed",
            role_arn=role_arn,
            events_count=len(events),
            unique_actions=len(actions_used)
        )

        return {
            'role_arn': role_arn,
            'events_analyzed': len(events),
            'actions_used': dict(actions_used),
            'unique_actions': len(actions_used)
        }

    except Exception as exc:
        logger.error("cloudtrail_analysis_failed", role_arn=role_arn, error=str(exc))
        raise


@celery_app.task(base=IAMAuditTask)
def generate_compliance_report(aws_account_id: str, report_type: str = "summary"):
    """
    Generate a compliance report for IAM configuration

    Args:
        aws_account_id: AWS account ID
        report_type: Type of report (summary, detailed, executive)
    """
    logger.info("compliance_report_generation_started", account_id=aws_account_id, report_type=report_type)

    try:
        # Placeholder for compliance report generation
        # In production, this would generate detailed compliance reports
        # based on frameworks like CIS AWS Foundations, SOC2, etc.

        report = {
            'account_id': aws_account_id,
            'report_type': report_type,
            'generated_at': datetime.utcnow().isoformat(),
            'compliance_score': 75,  # Placeholder
            'findings': [],
            'recommendations': []
        }

        logger.info("compliance_report_generated", account_id=aws_account_id)
        return report

    except Exception as exc:
        logger.error("compliance_report_generation_failed", error=str(exc))
        raise


@celery_app.task(base=IAMAuditTask, bind=True)
def monitor_api_changes(self):
    """
    Daily task to monitor AWS API changes for IAM, Identity Center, and Organizations.

    This task:
    1. Discovers current API definitions from boto3
    2. Creates snapshots of the APIs
    3. Detects changes compared to previous snapshots
    4. Generates AI-consumable reports
    """
    logger.info("api_monitoring_started", task_id=self.request.id)

    try:
        # Import here to avoid circular dependencies
        from app.services.api_monitoring_service import APIMonitoringService
        from app.database import SessionLocal

        # Create database session
        db = SessionLocal()

        try:
            # Initialize monitoring service
            monitoring_service = APIMonitoringService(db)

            # Run the monitoring workflow
            results = monitoring_service.run_daily_monitoring()

            logger.info(
                "api_monitoring_completed",
                task_id=self.request.id,
                snapshots_created=len(results['snapshots']),
                total_changes=results['total_changes'],
                report_id=results['report_id']
            )

            return {
                'status': 'success',
                'snapshots': results['snapshots'],
                'total_changes': results['total_changes'],
                'changes_by_service': results['changes_by_service'],
                'report_id': results['report_id'],
                'report_date': results['report_date']
            }

        finally:
            db.close()

    except Exception as exc:
        logger.error(
            "api_monitoring_failed",
            task_id=self.request.id,
            error=str(exc)
        )
        raise self.retry(exc=exc, countdown=300, max_retries=3)  # Retry after 5 minutes
