"""Custom exception classes for the Workbench Agent."""

class WorkbenchAgentError(Exception):
    """Base class for agent-specific errors."""
    pass

class ApiError(WorkbenchAgentError):
    """Represents an error returned by the Workbench API or during API interaction."""
    pass

class NetworkError(WorkbenchAgentError):
    """Represents a network-level error during API communication (e.g., connection, timeout)."""
    pass

class NotFoundError(ApiError):
    """Base for errors when an entity is not found via the API."""
    pass

class ProjectNotFoundError(NotFoundError):
    """Raised when a project is not found."""
    pass

class ScanNotFoundError(NotFoundError):
    """Raised when a scan is not found."""
    pass

class ResourceExistsError(ApiError):
    """Base for errors when trying to create an entity that already exists."""
    pass

class ProjectExistsError(ResourceExistsError):
    """Raised when trying to create a project that already exists."""
    pass

class ScanExistsError(ResourceExistsError):
    """Raised when trying to create a scan that already exists."""
    pass

class ProcessError(WorkbenchAgentError):
    """Raised for failures during background Workbench processes (scan, report, etc.)."""
    pass

class ProcessTimeoutError(ProcessError):
    """Raised specifically when waiting for a process times out."""
    pass

class ConfigurationError(WorkbenchAgentError):
     """Raised for invalid configuration or command-line arguments."""
     pass

class FileSystemError(WorkbenchAgentError):
    """Raised for errors related to local file/directory operations."""
    pass

class CompatibilityError(WorkbenchAgentError):
    """Raised when an existing scan is incompatible with the requested operation."""
    pass