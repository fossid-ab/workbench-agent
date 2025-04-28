"""Custom exception classes for the Workbench Agent.

This module defines the exception hierarchy for the Workbench Agent. All exceptions
should inherit from WorkbenchAgentError to allow for easy catching of agent-specific
errors.

Example:
    try:
        # Some agent operation
        result = agent.upload_code(path)
    except WorkbenchAgentError as e:
        # Handle any agent-specific error
        logger.error(f"Agent error: {e}")
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Unexpected error: {e}")
"""

from typing import Optional

class WorkbenchAgentError(Exception):
    """Base class for all Workbench Agent errors.
    
    All custom exceptions in this module should inherit from this class.
    This allows for easy catching of any agent-specific error.
    
    Attributes:
        message: A human-readable error message
        code: An optional error code for programmatic handling
        details: Optional additional error details
    """
    def __init__(self, message: str, code: Optional[str] = None, details: Optional[dict] = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

class ApiError(WorkbenchAgentError):
    """Represents an error returned by the Workbench API or during API interaction.
    
    This is raised when the API returns an error response or when there's an
    issue with the API interaction that isn't network-related.
    
    Example:
        try:
            response = api.get_scan(scan_id)
        except ApiError as e:
            logger.error(f"API error: {e.message} (code: {e.code})")
    """
    pass

class NetworkError(WorkbenchAgentError):
    """Represents a network-level error during API communication.
    
    This includes connection errors, timeouts, and other network-related issues.
    
    Example:
        try:
            response = api.upload_file(file_path)
        except NetworkError as e:
            logger.error(f"Network error: {e.message}")
    """
    pass

class NotFoundError(ApiError):
    """Base class for errors when an entity is not found via the API.
    
    This is raised when attempting to access a resource that doesn't exist.
    """
    pass

class ProjectNotFoundError(NotFoundError):
    """Raised when a project is not found.
    
    Example:
        try:
            project = api.get_project("non_existent")
        except ProjectNotFoundError as e:
            logger.error(f"Project not found: {e.message}")
    """
    pass

class ScanNotFoundError(NotFoundError):
    """Raised when a scan is not found.
    
    Example:
        try:
            scan = api.get_scan("non_existent")
        except ScanNotFoundError as e:
            logger.error(f"Scan not found: {e.message}")
    """
    pass

class ResourceExistsError(ApiError):
    """Base class for errors when trying to create an entity that already exists.
    
    This is raised when attempting to create a resource with a name that's
    already in use.
    """
    pass

class ProjectExistsError(ResourceExistsError):
    """Raised when trying to create a project that already exists.
    
    Example:
        try:
            api.create_project("existing_project")
        except ProjectExistsError as e:
            logger.error(f"Project already exists: {e.message}")
    """
    pass

class ScanExistsError(ResourceExistsError):
    """Raised when trying to create a scan that already exists.
    
    Example:
        try:
            api.create_scan("existing_scan")
        except ScanExistsError as e:
            logger.error(f"Scan already exists: {e.message}")
    """
    pass

class ProcessError(WorkbenchAgentError):
    """Raised for failures during background Workbench processes.
    
    This includes errors during scanning, report generation, and other
    long-running operations.
    
    Example:
        try:
            api.wait_for_scan_completion(scan_id)
        except ProcessError as e:
            logger.error(f"Process failed: {e.message}")
    """
    pass

class ProcessTimeoutError(ProcessError):
    """Raised when waiting for a process times out.
    
    Example:
        try:
            api.wait_for_scan_completion(scan_id, timeout=300)
        except ProcessTimeoutError as e:
            logger.error(f"Scan timed out: {e.message}")
    """
    pass

class ConfigurationError(WorkbenchAgentError):
    """Raised for invalid configuration or command-line arguments.
    
    This includes missing required parameters, invalid parameter values,
    and configuration file errors.
    
    Example:
        try:
            validate_config(config)
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e.message}")
    """
    pass

class FileSystemError(WorkbenchAgentError):
    """Raised for errors related to local file/directory operations.
    
    This includes file not found, permission denied, and other filesystem-related
    errors.
    
    Example:
        try:
            process_directory(path)
        except FileSystemError as e:
            logger.error(f"File system error: {e.message}")
    """
    pass

class CompatibilityError(WorkbenchAgentError):
    """Raised when an existing scan is incompatible with the requested operation.
    
    This includes trying to run operations that aren't supported by the
    scan's current state or configuration.
    
    Example:
        try:
            api.run_dependency_analysis(scan_id)
        except CompatibilityError as e:
            logger.error(f"Operation not compatible: {e.message}")
    """
    pass

class ValidationError(WorkbenchAgentError):
    """Raised when input validation fails.
    
    This includes invalid file formats, unsupported options, and other
    validation-related errors.
    
    Example:
        try:
            validate_input_file(file_path)
        except ValidationError as e:
            logger.error(f"Validation error: {e.message}")
    """
    pass

class AuthenticationError(ApiError):
    """Raised when authentication with the Workbench API fails.
    
    This includes invalid credentials, expired tokens, and other
    authentication-related errors.
    
    Example:
        try:
            api.authenticate()
        except AuthenticationError as e:
            logger.error(f"Authentication failed: {e.message}")
    """
    pass

class RateLimitError(ApiError):
    """Raised when the API rate limit is exceeded.
    
    Example:
        try:
            api.make_request()
        except RateLimitError as e:
            logger.error(f"Rate limit exceeded: {e.message}")
    """
    pass

class DependencyError(WorkbenchAgentError):
    """Raised when there's an error with external dependencies.
    
    This includes missing system dependencies, incompatible versions,
    and other dependency-related issues.
    
    Example:
        try:
            check_dependencies()
        except DependencyError as e:
            logger.error(f"Dependency error: {e.message}")
    """
    pass