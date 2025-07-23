import builtins
from typing import Dict, Any
from .helpers.api_base import APIBase


class ProjectsAPI(APIBase):
    """
    Workbench API Project Operations.
    """

    def check_if_project_exists(self, project_code: str) -> bool:
        """
        Check if project exists.

        Args:
            project_code (str): The unique identifier for the project.

        Returns:
            bool: Yes or no.
        """
        payload = {
            "group": "projects",
            "action": "get_information",
            "data": {
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "0":
            return False
        return True

    def create_project(self, project_code: str):
        """
        Create new project

        Args:
            project_code (str): The unique identifier for the project.
        """
        payload = {
            "group": "projects",
            "action": "create",
            "data": {
                "project_code": project_code,
                "project_name": project_code,
                "description": "Automatically created by Workbench Agent script",
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception("Failed to create project: {}".format(response))
        print("Created project {}".format(project_code))

    def projects_get_policy_warnings_info(self, project_code: str):
        """
        Retrieve policy warnings information at project level.

        Args:
            project_code (str): The unique identifier for the project.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "projects",
            "action": "get_policy_warnings_info",
            "data": {
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting project policy warnings information \
            result: {}".format(
                response
            )
        ) 