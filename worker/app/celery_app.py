"""
Celery application for async IAM audit tasks
"""
from celery import Celery
import structlog

logger = structlog.get_logger(__name__)

# Create Celery app
celery_app = Celery(
    'iam_copilot_worker',
    broker='redis://redis:6379/0',
    backend='redis://redis:6379/0',
    include=['app.tasks']
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3300,  # 55 minutes soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)

logger.info("celery_app_initialized")
