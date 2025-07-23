import logging
import argparse
from typing import Tuple, Optional
from .projects_api import ProjectsAPI
from .scans_api import ScansAPI
from .upload_api import UploadAPI
from .helpers.project_scan_resolvers import ResolveWorkbenchProjectScan

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
        
        # Initialize resolver for name-based resolution
        self._resolver = ResolveWorkbenchProjectScan(api_url, api_user, api_token)

    def resolve_project(self, project_name: str, create_if_missing: bool = False) -> str:
        """
        Resolve a project name to a project code, optionally creating it if not found.
        
        Args:
            project_name: The project name to resolve
            create_if_missing: Whether to create the project if it doesn't exist
            
        Returns:
            str: The project code
        """
        return self._resolver.resolve_project(project_name, create_if_missing)
    
    def resolve_scan(self, scan_name: str, project_name: Optional[str], create_if_missing: bool, params: argparse.Namespace, import_from_report: bool = False) -> Tuple[str, int]:
        """
        Resolve a scan name to a scan code and ID, optionally creating it if not found.
        
        Args:
            scan_name: The scan name to resolve
            project_name: The project name (optional for global search)
            create_if_missing: Whether to create the scan if it doesn't exist
            params: Command line parameters
            import_from_report: Whether this is for importing from a report
            
        Returns:
            Tuple[str, int]: The scan code and scan ID
        """
        return self._resolver.resolve_scan(scan_name, project_name, create_if_missing, params, import_from_report)
    
    def prepare_project_and_scan(self, project_identifier: str, scan_identifier: str, params: argparse.Namespace = None) -> Tuple[str, int]:
        """
        Ensures project exists and creates scan if needed.
        Supports both legacy code-based approach and new name-based approach with automatic resolution.
        
        Args:
            project_identifier: Project code/name to use
            scan_identifier: Scan code/name to use  
            params: Optional command line parameters for name resolution
            
        Returns:
            Tuple[str, int]: The project code and scan ID
        """
        return self._resolver.prepare_project_and_scan(project_identifier, scan_identifier, params)
