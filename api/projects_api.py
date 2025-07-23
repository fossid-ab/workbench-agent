import logging
from typing import Dict, Any
from .helpers.api_base import APIBase
from .helpers.exceptions import ApiError, ProjectNotFoundError, ProjectExistsError
from .helpers.project_scan_checks import check_if_project_exists

logger = logging.getLogger("workbench-agent")


class ProjectsAPI(APIBase):
    """
    Workbench API Project Operations.
    """

    def check_if_project_exists(self, project_code: str) -> bool:
        """
        Check if project exists.

        Args:
            project_code: The unique identifier for the project

        Returns:
            bool: True if project exists, False otherwise
        """
        return check_if_project_exists(self._send_request, project_code)

    def create_project(self, project_code: str):
        """
        Create new project

        Args:
            project_code: The unique identifier for the project

        Raises:
            ProjectExistsError: If a project with this code already exists
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
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
