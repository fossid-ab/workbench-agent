import logging
from typing import Dict, Any, List, Optional
from .helpers.api_base import APIBase
from ..exceptions import ApiError, ProjectNotFoundError, ProjectExistsError, ValidationError

logger = logging.getLogger("workbench-agent")


class ProjectsAPI(APIBase):
    """
    Workbench API Project Operations.
    """
    
    # --- Enhanced Validation Methods ---
    
    def _validate_project_parameters(self, project_code: str) -> None:
        """
        Validates project parameters before API operations.
        
        Args:
            project_code: The project code to validate
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not project_code or not project_code.strip():
            raise ValidationError("Project code cannot be empty")

    # --- Project Information Methods ---
    
    def get_project_information(self, project_code: str) -> Dict[str, Any]:
        """
        Retrieves detailed information about a project.
        
        Args:
            project_code: Code of the project to get information for
            
        Returns:
            Dict containing project information
            
        Raises:
            ProjectNotFoundError: If the project doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting project information for '{project_code}'")

        payload = {
            "group": "projects",
            "action": "get_information",
            "data": {
                "project_code": project_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            raise ApiError(
                f"Failed to get project information for '{project_code}': {error_msg}",
                details=response,
            )

    def check_if_project_exists(self, project_code: str) -> bool:
        """
        Check if project exists (backwards compatibility with original agent).
        
        Args:
            project_code: The unique identifier for the project
            
        Returns:
            bool: True if project exists, False otherwise
        """
        try:
            self.get_project_information(project_code)
            return True
        except ProjectNotFoundError:
            return False
        except (ApiError, Exception):
            # On other errors, assume project doesn't exist for safety
            return False

    # --- Existing Methods with Enhanced Organization ---
    
    def list_projects(self) -> List[Dict[str, Any]]:
        """
        List all projects accessible to the current user.

        Returns:
            List[Dict]: List of project dictionaries with keys like project_code, project_name, etc.

        Raises:
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug("Listing all projects")

        payload = {
            "group": "projects",
            "action": "get_all_projects",
            "data": {}
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            projects = response["data"]
            if isinstance(projects, list):
                logger.debug(f"Found {len(projects)} projects")
                return projects
            elif isinstance(projects, dict):
                # Sometimes API returns dict instead of list
                logger.debug(f"Found {len(projects)} projects (as dict)")
                return list(projects.values()) if projects else []
            else:
                logger.warning(f"Expected list or dict for projects, got {type(projects)}")
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list projects: {error_msg}", details=response)

    def get_project_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """
        Get all scans for a specific project.

        Args:
            project_code: The project code to get scans for

        Returns:
            List[Dict]: List of scan dictionaries for the specified project

        Raises:
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting scans for project '{project_code}'")

        payload = {
            "group": "projects",
            "action": "get_all_scans",
            "data": {
                "project_code": project_code
            }
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            scans = response["data"]
            if isinstance(scans, list):
                logger.debug(f"Found {len(scans)} scans for project '{project_code}'")
                return scans
            elif isinstance(scans, dict):
                # Sometimes API returns dict instead of list
                logger.debug(f"Found {len(scans)} scans for project '{project_code}' (as dict)")
                return list(scans.values()) if scans else []
            else:
                logger.warning(f"Expected list or dict for project scans, got {type(scans)}")
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            # Don't raise error for project not found - just return empty list
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                logger.debug(f"Project '{project_code}' not found, returning empty scan list")
                return []
            raise ApiError(f"Failed to get scans for project '{project_code}': {error_msg}", details=response)

    def create_project(self, project_code: str):
        """
        Create new project.
        Enhanced with better validation and error handling.

        Args:
            project_code: The unique identifier for the project

        Raises:
            ProjectExistsError: If a project with this code already exists
            ValidationError: If parameters are invalid
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        # Enhanced validation
        self._validate_project_parameters(project_code)
        
        logger.debug(f"Creating project '{project_code}'")

        payload = {
            "group": "projects",
            "action": "create",
            "data": {
                "project_code": project_code,
                "project_name": project_code,
                "description": "Automatically created by Workbench Agent script",
            },
        }

        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                logger.info(f"Successfully created project '{project_code}'")
                print(f"Created project {project_code}")  # Match original behavior for tests
            else:
                error_msg = response.get("error", f"Unexpected response: {response}")
                raise ApiError(
                    f"Failed to create project '{project_code}': {error_msg}", details=response
                )
        except ProjectExistsError:
            raise  # Re-raise specific errors
        except Exception as e:
            if isinstance(e, (ApiError, ProjectExistsError)):
                raise
            raise ApiError(
                f"Failed to create project '{project_code}': {e}", details={"error": str(e)}
            )

    def projects_get_policy_warnings_info(self, project_code: str) -> Dict[str, Any]:
        """
        Retrieve policy warnings information at project level.

        Args:
            project_code: The unique identifier for the project

        Returns:
            dict: The policy warnings data

        Raises:
            ProjectNotFoundError: If the project doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting policy warnings info for project '{project_code}'")

        payload = {
            "group": "projects",
            "action": "get_policy_warnings_info",
            "data": {
                "project_code": project_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            raise ApiError(
                f"Failed to get policy warnings info for project '{project_code}': {error_msg}",
                details=response,
            )
