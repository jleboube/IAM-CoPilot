"""
AWS API Monitoring Orchestration Service

Coordinates API discovery, change detection, and report generation.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.api_monitoring import APISnapshot, APIChange, MonitoringReport, ServiceType
from app.services.api_discovery_service import APIDiscoveryService
from app.services.api_change_detection_service import APIChangeDetectionService
from app.services.api_report_generation_service import APIReportGenerationService

logger = logging.getLogger(__name__)


class APIMonitoringService:
    """Orchestrates the complete API monitoring workflow."""

    def __init__(self, db: Session):
        """
        Initialize the monitoring service.

        Args:
            db: Database session
        """
        self.db = db
        self.discovery_service = APIDiscoveryService()
        self.change_detection_service = APIChangeDetectionService()
        self.report_service = APIReportGenerationService()

    def run_daily_monitoring(self) -> Dict[str, Any]:
        """
        Run the complete daily monitoring workflow.

        This is the main entry point for automated monitoring.

        Returns:
            Monitoring results including snapshots, changes, and report
        """
        logger.info("Starting daily API monitoring")

        try:
            # Step 1: Discover current APIs
            current_apis = self.discovery_service.discover_all_monitored_services()
            logger.info(f"Discovered {len(current_apis)} service APIs")

            # Step 2: Create snapshots
            current_snapshots = {}
            for service_type, api_def in current_apis.items():
                snapshot = self._create_snapshot(service_type, api_def)
                current_snapshots[service_type] = snapshot
                logger.info(f"Created snapshot for {service_type}: {snapshot.id}")

            # Step 3: Detect changes
            all_changes = []
            changes_by_service = {}

            for service_type, current_snapshot in current_snapshots.items():
                previous_snapshot = self._get_latest_snapshot(service_type, exclude_id=current_snapshot.id)

                if previous_snapshot:
                    changes = self._detect_and_store_changes(
                        service_type,
                        previous_snapshot,
                        current_snapshot
                    )
                    all_changes.extend(changes)
                    changes_by_service[service_type.value] = [
                        self._change_to_dict(c) for c in changes
                    ]
                    logger.info(f"Detected {len(changes)} changes for {service_type}")
                else:
                    logger.info(f"No previous snapshot for {service_type}, this is the first monitoring")
                    changes_by_service[service_type.value] = []

            # Step 4: Generate reports
            report = self._generate_and_store_report(
                changes_by_service,
                current_snapshots
            )

            logger.info(f"Monitoring complete: {len(all_changes)} total changes detected")

            return {
                'success': True,
                'snapshots': {
                    service_type.value: snapshot.id
                    for service_type, snapshot in current_snapshots.items()
                },
                'total_changes': len(all_changes),
                'changes_by_service': {
                    service: len(changes)
                    for service, changes in changes_by_service.items()
                },
                'report_id': report.id,
                'report_date': report.report_date.isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to run daily monitoring: {str(e)}")
            raise

    def _create_snapshot(self, service_type: str, api_definition: Dict[str, Any]) -> APISnapshot:
        """Create and store an API snapshot."""
        snapshot = APISnapshot(
            service_type=ServiceType[service_type],
            service_version=api_definition.get('api_version'),
            api_definition=api_definition,
            total_operations=self.discovery_service.get_operation_count(api_definition),
            total_shapes=self.discovery_service.get_shape_count(api_definition),
            source='boto3'
        )

        self.db.add(snapshot)
        self.db.commit()
        self.db.refresh(snapshot)

        return snapshot

    def _get_latest_snapshot(
        self,
        service_type: ServiceType,
        exclude_id: Optional[int] = None
    ) -> Optional[APISnapshot]:
        """Get the most recent snapshot for a service."""
        query = self.db.query(APISnapshot).filter(
            APISnapshot.service_type == service_type
        )

        if exclude_id:
            query = query.filter(APISnapshot.id != exclude_id)

        return query.order_by(APISnapshot.snapshot_date.desc()).first()

    def _detect_and_store_changes(
        self,
        service_type: ServiceType,
        previous_snapshot: APISnapshot,
        current_snapshot: APISnapshot
    ) -> List[APIChange]:
        """Detect changes between snapshots and store them."""
        # Detect changes
        changes_data = self.change_detection_service.detect_changes(
            previous_snapshot.api_definition,
            current_snapshot.api_definition,
            service_type.value
        )

        # Store changes
        change_objects = []
        for change_data in changes_data:
            change = APIChange(
                service_type=service_type,
                change_type=change_data['change_type'],
                current_snapshot_id=current_snapshot.id,
                previous_snapshot_id=previous_snapshot.id,
                operation_name=change_data.get('operation_name'),
                change_path=change_data.get('change_path'),
                previous_value=change_data.get('previous_value'),
                current_value=change_data.get('current_value'),
                description=change_data['description'],
                impact_level=change_data['impact_level'],
                detected_at=change_data.get('detected_at', datetime.now(timezone.utc))
            )
            self.db.add(change)
            change_objects.append(change)

        self.db.commit()

        for change in change_objects:
            self.db.refresh(change)

        return change_objects

    def _generate_and_store_report(
        self,
        changes_by_service: Dict[str, List[Dict[str, Any]]],
        current_snapshots: Dict[ServiceType, APISnapshot]
    ) -> MonitoringReport:
        """Generate and store a monitoring report."""
        report_date = datetime.now(timezone.utc)

        # Generate AI report
        ai_report = self.report_service.generate_ai_report(
            changes_by_service,
            report_date
        )

        # Generate JSON report
        snapshots_info = {
            service_type.value: {
                'snapshot_id': snapshot.id,
                'api_version': snapshot.service_version,
                'total_operations': snapshot.total_operations,
                'snapshot_date': snapshot.snapshot_date.isoformat()
            }
            for service_type, snapshot in current_snapshots.items()
        }

        json_report = self.report_service.generate_json_report(
            changes_by_service,
            report_date,
            snapshots_info
        )

        # Generate summary
        summary = self.report_service.generate_summary_statistics(changes_by_service)

        # Create report
        report = MonitoringReport(
            report_date=report_date,
            summary=summary,
            changes_by_service=json_report,
            ai_report=ai_report,
            total_changes=summary['total_changes'],
            services_monitored=list(changes_by_service.keys())
        )

        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)

        return report

    def _change_to_dict(self, change: APIChange) -> Dict[str, Any]:
        """Convert APIChange object to dictionary."""
        return {
            'id': change.id,
            'service_type': change.service_type.value,
            'change_type': change.change_type.value,
            'operation_name': change.operation_name,
            'change_path': change.change_path,
            'previous_value': change.previous_value,
            'current_value': change.current_value,
            'description': change.description,
            'impact_level': change.impact_level,
            'detected_at': change.detected_at.isoformat()
        }

    def get_latest_report(self) -> Optional[MonitoringReport]:
        """Get the most recent monitoring report."""
        return self.db.query(MonitoringReport).order_by(
            MonitoringReport.report_date.desc()
        ).first()

    def get_reports(self, limit: int = 30) -> List[MonitoringReport]:
        """Get recent monitoring reports."""
        return self.db.query(MonitoringReport).order_by(
            MonitoringReport.report_date.desc()
        ).limit(limit).all()

    def get_changes_for_service(
        self,
        service_type: str,
        limit: int = 100
    ) -> List[APIChange]:
        """Get recent changes for a specific service."""
        return self.db.query(APIChange).filter(
            APIChange.service_type == ServiceType[service_type]
        ).order_by(
            APIChange.detected_at.desc()
        ).limit(limit).all()

    def get_breaking_changes(self, days: int = 30) -> List[APIChange]:
        """Get all breaking changes from the last N days."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        return self.db.query(APIChange).filter(
            APIChange.impact_level == 'breaking',
            APIChange.detected_at >= cutoff_date
        ).order_by(
            APIChange.detected_at.desc()
        ).all()


from datetime import timedelta
