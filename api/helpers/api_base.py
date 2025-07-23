import json
import logging
import requests
from typing import Dict, Any
from .exceptions import (
    ApiError,
    NetworkError,
    AuthenticationError,
    ScanNotFoundError,
    ProjectNotFoundError,
    ScanExistsError,
    ProjectExistsError
)
from .process_waiters import ProcessWaiters
from .status_checkers import StatusCheckers

logger = logging.getLogger("workbench-agent")


class APIBase(ProcessWaiters, StatusCheckers):
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
        # Ensure the API URL ends with api.php
        if not api_url.endswith('/api.php'):
            self.api_url = api_url.rstrip('/') + '/api.php'
            logger.warning(f"API URL adjusted to: {self.api_url}")
        else:
            self.api_url = api_url
            
        self.api_user = api_user
        self.api_token = api_token
        self.session = requests.Session()  # Use a session for potential connection reuse
        self.session.trust_env = False  # Do not trust .netrc file

    def _send_request(self, payload: dict, timeout: int = 1800) -> dict:
        """
        Sends a POST request to the Workbench API with robust error handling.
        
        Args:
            payload: The request payload
            timeout: Request timeout in seconds
        
        Returns:
            Dict with response data
            
        Raises:
            NetworkError: For connection issues, timeouts, etc.
            AuthenticationError: For authentication failures
            ApiError: For API-level errors
            ScanNotFoundError: When scan is not found
            ProjectNotFoundError: When project is not found
            ScanExistsError: When scan already exists
            ProjectExistsError: When project already exists
        """
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json; charset=utf-8",
        }
        
        # Add authentication to payload
        payload.setdefault("data", {})
        payload["data"]["username"] = self.api_user
        payload["data"]["key"] = self.api_token

        req_body = json.dumps(payload)
        logger.debug("API URL: %s", self.api_url)
        logger.debug("Request Headers: %s", headers)
        logger.debug("Request Body: %s", req_body)

        try:
            response = self.session.post(
                self.api_url, headers=headers, data=req_body, timeout=timeout
            )
            logger.debug("Response Status Code: %s", response.status_code)
            logger.debug("Response Text (first 500 chars): %s", response.text[:500])
            
            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("Invalid credentials or expired token")
            
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            try:
                parsed_json = response.json()
                
                # Check for API-level errors indicated by status='0'
                if isinstance(parsed_json, dict) and parsed_json.get("status") == "0":
                    error_msg = parsed_json.get("error", "Unknown API error")
                    logger.debug(f"API returned status 0: {error_msg} | Payload: {payload}")

                    # Handle specific known errors
                    self._handle_api_errors(parsed_json, payload, error_msg)
                    
                    # If no specific error was handled, raise generic API error
                    raise ApiError(error_msg, code=parsed_json.get("code"), details=parsed_json)

                return parsed_json  # Return successfully parsed JSON

            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON response: {response.text[:500]}", exc_info=True)
                raise ApiError(f"Invalid JSON received from API: {e.msg}", details={"response_text": response.text[:500]})

        except requests.exceptions.ConnectionError as e:
            logger.error("API connection failed: %s", e, exc_info=True)
            raise NetworkError("Failed to connect to the API server", details={"error": str(e)})
        except requests.exceptions.Timeout as e:
            logger.error("API request timed out: %s", e, exc_info=True)
            raise NetworkError("Request to API server timed out", details={"error": str(e)})
        except requests.exceptions.RequestException as e:
            logger.error("API request failed: %s", e, exc_info=True)
            raise NetworkError(f"API request failed: {str(e)}", details={"error": str(e)})

    def _handle_api_errors(self, parsed_json: dict, payload: dict, error_msg: str):
        """
        Handle specific API errors and raise appropriate exceptions.
        
        Args:
            parsed_json: The parsed JSON response
            payload: The original request payload
            error_msg: The error message from the API
        """
        action = payload.get("action")
        group = payload.get("group")
        
        # Handle existence check errors (non-fatal for existence checks)
        is_existence_check = action == "get_information"
        is_create_action = action == "create"
        
        # Project-specific errors
        if group == "projects":
            if is_existence_check and error_msg == "Project does not exist":
                raise ProjectNotFoundError(f"Project not found")
            elif is_create_action and "Project code already exists" in error_msg:
                raise ProjectExistsError(f"Project already exists")
        
        # Scan-specific errors  
        elif group == "scans":
            if is_existence_check and ("row_not_found" in error_msg or "Scan not found" in error_msg):
                raise ScanNotFoundError(f"Scan not found")
            elif is_create_action and ("Scan code already exists" in error_msg or "Legacy.controller.scans.code_already_exists" in error_msg):
                raise ScanExistsError(f"Scan already exists")


