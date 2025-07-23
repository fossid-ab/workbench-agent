"""
Helper modules for the Workbench API client.
"""

# Helper modules for Workbench API operations
from .api_base import APIBase
from .project_scan_checks import check_if_project_exists, check_if_scan_exists

# Helper mixins for API classes (these contain the actual implementations)
from .process_waiters import ProcessWaiters
from .status_checkers import StatusCheckers
from .upload_helpers import UploadHelper

# Exception types
from .exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    AuthenticationError,
    ValidationError,
    ScanNotFoundError,
    ScanExistsError,
    ProjectNotFoundError,
    ProjectExistsError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
)

__all__ = [
    # Base API class
    "APIBase",
    # Helper mixins (contain the enhanced implementations)
    "ProcessWaiters",
    "StatusCheckers",
    "UploadHelper",
    # Project/scan existence checks
    "check_if_project_exists",
    "check_if_scan_exists",
    # Exception types
    "WorkbenchAgentError",
    "ApiError",
    "NetworkError",
    "AuthenticationError",
    "ValidationError",
    "ScanNotFoundError",
    "ScanExistsError",
    "ProjectNotFoundError",
    "ProjectExistsError",
    "ProcessError",
    "ProcessTimeoutError",
    "FileSystemError",
]
