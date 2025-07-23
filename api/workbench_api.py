import logging
from .projects_api import ProjectsAPI
from .scans_api import ScansAPI
from .upload_api import UploadAPI

logger = logging.getLogger("workbench-agent")


class WorkbenchAPI(ProjectsAPI, ScansAPI, UploadAPI):
    """
    A comprehensive client for interacting with the FossID Workbench API.

    This class composes all individual API components into a single unified client,
    providing access to all Workbench functionality including:
    - Project and Scan management
    - Scan operations
    - File uploads

    The client follows modern Python practices with:
    - Comprehensive error handling with specific exception types
    - Structured logging throughout all operations
    - Type hints for better code clarity
    - Robust network error handling and retry logic

    Attributes:
        api_url: The base URL of the Workbench API
        api_user: The username used for API authentication
        api_token: The API token for authentication
    """

    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initializes the Workbench API client with authentication credentials.

        Args:
            api_url: The base URL of the Workbench API (will be adjusted to end with api.php if needed)
            api_user: The username used for API authentication
            api_token: The API token for authentication

        Note:
            The API URL will be automatically adjusted to end with '/api.php' if it doesn't already.
            A warning will be logged if this adjustment is made.
        """
        super().__init__(api_url, api_user, api_token)
        logger.info(f"Initialized Workbench API client for {self.api_url}")
        logger.debug(f"API user: {api_user}")
