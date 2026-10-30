"""
Cloud integration adapters for Google Cloud Run, Firestore, Cloud Logging, and Cloud Monitoring.
Designed with transparent local fallback adapters adhering to the BMSCE x MindMatrix Environment Caveat:
'Cloud/emulator capabilities vary by service and version. If an operation is unsupported,
document it and use a clearly labelled local adapter or design demonstration; do not claim unverified integration.'
"""

from .cloud_logging import SecurityLogger, structured_security_logger
from .cloud_monitoring import CloudMonitoringAdapter
from .firestore_store import FirestoreStorage

__all__ = [
    "SecurityLogger",
    "structured_security_logger",
    "CloudMonitoringAdapter",
    "FirestoreStorage"
]
