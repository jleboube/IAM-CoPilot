"""
IAM API Update Agent - Main Orchestration Service

Coordinates the entire agent workflow: analyze, plan, generate, and optionally apply changes.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.iam_api_update_agent import (
    AgentRun,
    PlannedChange,
    AppliedChange,
    AgentRunStatus,
    ChangeStatus,
    ChangeType as AgentChangeType
)
from app.models.api_monitoring import MonitoringReport
from app.services.agent_report_parser import AgentReportParser
from app.services.agent_codebase_analyzer import AgentCodebaseAnalyzer
from app.services.agent_change_planner import AgentChangePlanner
from app.services.agent_code_generator import AgentCodeGenerator

logger = logging.getLogger(__name__)


class IAMAPIUpdateAgentService:
    """Main orchestrator for the IAM API Update Agent."""

    def __init__(self, db: Session):
        """
        Initialize the agent service.

        Args:
            db: Database session
        """
        self.db = db
        self.parser = AgentReportParser()
        self.analyzer = AgentCodebaseAnalyzer()
        self.planner = AgentChangePlanner()
        self.generator = AgentCodeGenerator()

    def run_agent(
        self,
        monitoring_report_id: Optional[int] = None,
        auto_apply: bool = False
    ) -> Dict[str, Any]:
        """
        Run the complete agent workflow.

        Args:
            monitoring_report_id: ID of monitoring report to process. If None, uses latest.
            auto_apply: Whether to automatically apply changes (default: False for safety)

        Returns:
            Results of the agent run
        """
        logger.info(f"Starting IAM API Update Agent run (auto_apply={auto_apply})")

        # Step 1: Get monitoring report
        if monitoring_report_id:
            monitoring_report = self.db.query(MonitoringReport).filter(
                MonitoringReport.id == monitoring_report_id
            ).first()
        else:
            monitoring_report = self.db.query(MonitoringReport).order_by(
                MonitoringReport.report_date.desc()
            ).first()

        if not monitoring_report:
            logger.error("No monitoring report found")
            return {
                'success': False,
                'error': 'No monitoring report available'
            }

        # Step 2: Create agent run record
        agent_run = AgentRun(
            monitoring_report_id=monitoring_report.id,
            status=AgentRunStatus.ANALYZING
        )
        self.db.add(agent_run)
        self.db.commit()
        self.db.refresh(agent_run)

        try:
            # Step 3: Parse report and create change plan
            logger.info("Creating change plan...")
            agent_run.status = AgentRunStatus.PLANNING
            self.db.commit()

            report_dict = {
                'id': monitoring_report.id,
                'report_date': monitoring_report.report_date.isoformat(),
                'total_changes': monitoring_report.total_changes,
                'services_monitored': monitoring_report.services_monitored,
                'summary': monitoring_report.summary,
                'changes_by_service': monitoring_report.changes_by_service
            }

            change_plan = self.planner.create_change_plan(report_dict)

            agent_run.total_changes_detected = change_plan.get('actionable_changes', 0)
            agent_run.total_changes_planned = change_plan.get('total_planned', 0)
            agent_run.analysis_summary = change_plan.get('summary', '')
            self.db.commit()

            # Step 4: Store planned changes
            planned_changes_records = []
            for planned_change in change_plan.get('planned_changes', []):
                planned_record = self._create_planned_change_record(
                    agent_run.id,
                    planned_change
                )
                if planned_record:
                    planned_changes_records.append(planned_record)
                    self.db.add(planned_record)

            self.db.commit()

            # Step 5: Generate code for each planned change
            logger.info(f"Generating code for {len(planned_changes_records)} changes...")

            for planned_record in planned_changes_records:
                if planned_record.status == ChangeStatus.PLANNED:
                    self._generate_code_for_planned_change(planned_record)

            self.db.commit()

            # Step 6: Optionally apply changes
            if auto_apply:
                logger.warning("Auto-apply is enabled - this will modify code files!")
                agent_run.status = AgentRunStatus.APPLYING
                self.db.commit()

                # For safety, we'll skip actual application in this version
                # This would require git integration and careful file modification
                logger.info("Auto-apply would happen here (not implemented for safety)")
                applied_count = 0
            else:
                logger.info("Skipping auto-apply (set auto_apply=True to enable)")
                applied_count = 0

            # Step 7: Mark run as completed
            agent_run.status = AgentRunStatus.COMPLETED
            agent_run.completed_at = datetime.now(timezone.utc)
            agent_run.total_changes_applied = applied_count
            self.db.commit()

            logger.info(f"Agent run completed: {agent_run.id}")

            return {
                'success': True,
                'agent_run_id': agent_run.id,
                'monitoring_report_id': monitoring_report.id,
                'changes_detected': agent_run.total_changes_detected,
                'changes_planned': agent_run.total_changes_planned,
                'changes_generated': len([p for p in planned_changes_records if p.generated_code]),
                'changes_applied': applied_count,
                'summary': agent_run.analysis_summary,
                'planned_changes': [
                    self._planned_change_to_dict(p)
                    for p in planned_changes_records
                ]
            }

        except Exception as e:
            logger.error(f"Agent run failed: {str(e)}")
            agent_run.status = AgentRunStatus.FAILED
            agent_run.error_message = str(e)
            agent_run.completed_at = datetime.now(timezone.utc)
            self.db.commit()

            return {
                'success': False,
                'agent_run_id': agent_run.id,
                'error': str(e)
            }

    def _create_planned_change_record(
        self,
        agent_run_id: int,
        planned_change: Dict[str, Any]
    ) -> Optional[PlannedChange]:
        """
        Create a database record for a planned change.

        Args:
            agent_run_id: ID of the agent run
            planned_change: Planned change from planner

        Returns:
            PlannedChange record
        """
        change_type_str = planned_change.get('change_type', '')

        # Map planner change types to database enum
        change_type_map = {
            'add_operation': AgentChangeType.ADD_OPERATION,
            'remove_operation': AgentChangeType.REMOVE_OPERATION,
            'deprecate_operation': AgentChangeType.DEPRECATE_OPERATION,
            'update_parameter': AgentChangeType.UPDATE_PARAMETER,
            'update_schema': AgentChangeType.UPDATE_SCHEMA,
            'add_endpoint': AgentChangeType.ADD_OPERATION,  # Map to ADD_OPERATION
            'skip': None  # Don't create records for skipped changes
        }

        agent_change_type = change_type_map.get(change_type_str)

        if not agent_change_type:
            logger.debug(f"Skipping change type: {change_type_str}")
            return None

        planned_record = PlannedChange(
            agent_run_id=agent_run_id,
            status=ChangeStatus.PLANNED,
            change_type=agent_change_type,
            service_type=planned_change.get('service_type', ''),
            operation_name=planned_change.get('operation_name'),
            target_file=planned_change.get('target_file'),
            description=planned_change.get('description', ''),
            reasoning=planned_change.get('reasoning'),
            implementation_plan=planned_change.get('implementation_plan', {})
        )

        return planned_record

    def _generate_code_for_planned_change(self, planned_record: PlannedChange) -> None:
        """
        Generate code for a planned change and update the record.

        Args:
            planned_record: PlannedChange database record
        """
        logger.info(f"Generating code for: {planned_record.description}")

        planned_dict = {
            'change_type': planned_record.change_type.value,
            'service_type': planned_record.service_type,
            'operation_name': planned_record.operation_name,
            'target_file': planned_record.target_file,
            'description': planned_record.description,
            'implementation_plan': planned_record.implementation_plan
        }

        try:
            result = self.generator.generate_code_for_change(planned_dict)

            if result.get('success'):
                planned_record.generated_code = result.get('generated_code')
                logger.info(f"Successfully generated code for {planned_record.operation_name}")
            else:
                planned_record.error_message = result.get('error', 'Unknown error')
                logger.error(f"Failed to generate code: {planned_record.error_message}")

        except Exception as e:
            logger.error(f"Error generating code: {str(e)}")
            planned_record.error_message = str(e)

    def _planned_change_to_dict(self, planned_change: PlannedChange) -> Dict[str, Any]:
        """Convert PlannedChange to dictionary."""
        return {
            'id': planned_change.id,
            'change_type': planned_change.change_type.value,
            'service_type': planned_change.service_type,
            'operation_name': planned_change.operation_name,
            'target_file': planned_change.target_file,
            'description': planned_change.description,
            'reasoning': planned_change.reasoning,
            'has_generated_code': bool(planned_change.generated_code),
            'code_preview': planned_change.generated_code[:200] + '...' if planned_change.generated_code and len(planned_change.generated_code) > 200 else planned_change.generated_code,
            'status': planned_change.status.value,
            'error_message': planned_change.error_message
        }

    def get_agent_run_details(self, agent_run_id: int) -> Dict[str, Any]:
        """
        Get detailed information about an agent run.

        Args:
            agent_run_id: ID of the agent run

        Returns:
            Detailed run information including all planned changes
        """
        agent_run = self.db.query(AgentRun).filter(
            AgentRun.id == agent_run_id
        ).first()

        if not agent_run:
            return {'error': 'Agent run not found'}

        return {
            'id': agent_run.id,
            'status': agent_run.status.value,
            'monitoring_report_id': agent_run.monitoring_report_id,
            'started_at': agent_run.started_at.isoformat(),
            'completed_at': agent_run.completed_at.isoformat() if agent_run.completed_at else None,
            'total_changes_detected': agent_run.total_changes_detected,
            'total_changes_planned': agent_run.total_changes_planned,
            'total_changes_applied': agent_run.total_changes_applied,
            'total_changes_failed': agent_run.total_changes_failed,
            'analysis_summary': agent_run.analysis_summary,
            'error_message': agent_run.error_message,
            'planned_changes': [
                self._planned_change_to_dict(pc)
                for pc in agent_run.planned_changes
            ]
        }

    def get_recent_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent agent runs.

        Args:
            limit: Maximum number of runs to return

        Returns:
            List of agent run summaries
        """
        runs = self.db.query(AgentRun).order_by(
            AgentRun.started_at.desc()
        ).limit(limit).all()

        return [
            {
                'id': run.id,
                'status': run.status.value,
                'started_at': run.started_at.isoformat(),
                'completed_at': run.completed_at.isoformat() if run.completed_at else None,
                'changes_planned': run.total_changes_planned,
                'changes_applied': run.total_changes_applied
            }
            for run in runs
        ]
