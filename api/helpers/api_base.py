import json
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger("log")


class APIBase:
    """
    Base class with helper methods for Workbench API interactions.
    Contains methods that handle the "how" of API operations.
    """

    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initialize the base Workbench API client with authentication details.

        Args:
            api_url: URL to the API endpoint
            api_user: API username
            api_token: API token/key
        """
        self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token

    def _send_request(self, payload: dict) -> dict:
        """
        Sends a request to the Workbench API.

        Args:
            payload (dict): The payload of the request.

        Returns:
            dict: The JSON response from the API.
        """
        url = self.api_url
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json; charset=utf-8",
        }

        # Add authentication to payload
        payload.setdefault("data", {})
        payload["data"]["username"] = self.api_user
        payload["data"]["key"] = self.api_token

        req_body = json.dumps(payload)
        logger.debug("url %s", url)
        logger.debug("headers %s", headers)
        logger.debug(req_body)

        response = requests.request("POST", url, headers=headers, data=req_body, timeout=1800)
        logger.debug(response.text)

        try:
            # Attempt to parse the JSON
            parsed_json = json.loads(response.text)
            return parsed_json
        except json.JSONDecodeError as e:
            # If an error occurs, catch it and display the message along with the problematic JSON
            print("Failed to decode JSON")
            print(f"Error message: {e.msg}")
            print(f"At position: {e.pos}")
            print("Problematic JSON:")
            print(response.text)
            raise
