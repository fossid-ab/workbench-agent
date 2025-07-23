"""
Custom exceptions for Workbench Agent API operations.
"""


class WorkbenchAgentError(Exception):
    """Base exception for all Workbench Agent errors."""

    def __init__(self, message: str, code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class ApiError(WorkbenchAgentError):
    """Exception raised for API-level errors."""

    pass


class NetworkError(WorkbenchAgentError):
    """Exception raised for network-related errors."""

    pass


class AuthenticationError(WorkbenchAgentError):
    """Exception raised for authentication failures."""

    pass


class ValidationError(WorkbenchAgentError):
    """Exception raised for validation errors."""

    pass


class ScanNotFoundError(WorkbenchAgentError):
    """Exception raised when a scan is not found."""

    pass


class ScanExistsError(WorkbenchAgentError):
    """Exception raised when a scan already exists."""

    pass


class ProjectNotFoundError(WorkbenchAgentError):
    """Exception raised when a project is not found."""

    pass


class ProjectExistsError(WorkbenchAgentError):
    """Exception raised when a project already exists."""

    pass


class ProcessError(WorkbenchAgentError):
    """Exception raised for process-related errors."""

    pass


class ProcessTimeoutError(ProcessError):
    """Exception raised when a process times out."""

    pass


class FileSystemError(WorkbenchAgentError):
    """Exception raised for file system errors."""

    pass
