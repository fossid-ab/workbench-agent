import os
import re
import json
import time
import logging
import requests
import zipfile
import tempfile
import shutil
import io
import base64
from typing import Dict, List, Optional, Union, Any, Callable, Generator, Tuple
from .exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# Assume logger is configured in main.py
logger = logging.getLogger("log")

class Workbench:
    """
    A class to interact with the FossID Workbench API.
    """
    # --- Report Types ---
    ASYNC_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx", "basic"}
    PROJECT_REPORT_TYPES = {"xlsx", "spdx", "spdx_lite", "cyclone_dx"}
    SCAN_REPORT_TYPES = {"html", "dynamic_top_matched_components", "xlsx", "spdx", "spdx_lite", "cyclone_dx", "string_match"}

    def __init__(self, api_url: str, api_user: str, api_token: str):
        # Ensure the API URL ends with api.php
        if not api_url.endswith('/api.php'):
            self.api_url = api_url.rstrip('/') + '/api.php'
            print(f"Warning: API URL adjusted to: {self.api_url}")
        else:
            self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token
        self.session = requests.Session() # Use a session for potential connection reuse

    def _send_request(self, payload: dict, timeout: int = 1800) -> dict:
        """
        Sends a POST request to the Workbench API.
        Handles expected non-JSON responses for synchronous operations.
        
        Raises:
            NetworkError: For connection issues, timeouts, etc.
            AuthenticationError: For authentication failures
            ApiError: For API-level errors
        """
        headers = {
            "Accept": "*/*", # Keep broad accept for now
            "Content-Type": "application/json; charset=utf-8",
        }
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
            logger.debug("Response Headers: %s", response.headers)
            # Log first part of text regardless of JSON success/failure
            logger.debug(f"Response Text (first 500 chars): {response.text[:500] if hasattr(response, 'text') else '(No text)'}")
            
            # Handle authentication errors
            if response.status_code == 401:
                raise AuthenticationError("Invalid credentials or expired token")
            
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            content_type = response.headers.get('content-type', '').lower()
            if 'application/json' in content_type:
                try:
                    parsed_json = response.json()
                    # Check for API-level errors indicated by status='0'
                    if isinstance(parsed_json, dict) and parsed_json.get("status") == "0":
                        error_msg = parsed_json.get("error", "Unknown API error")
                        logger.debug(f"API returned status 0 JSON: {error_msg} | Payload: {payload}")

                        is_invalid_type_probe = False
                        if (payload.get("action") == "check_status" and
                            error_msg == "RequestData.Base.issues_while_parsing_request" and
                            isinstance(parsed_json.get("data"), list) and
                            len(parsed_json["data"]) > 0 and
                            isinstance(parsed_json["data"][0], dict) and
                            parsed_json["data"][0].get("code") == "RequestData.Base.field_not_valid_option" and
                            parsed_json["data"][0].get("message_parameters", {}).get("fieldname") == "type"):
                            is_invalid_type_probe = True
                            logger.debug("Detected 'invalid type option' error during check_status probe.")

                        # Determine if this error is expected and non-fatal
                        is_existence_check = payload.get("action") == "get_information"
                        is_create_action = payload.get("action") == "create"
                        project_not_found = (is_existence_check and payload.get("group") == "projects" and error_msg == "Project does not exist")
                        scan_not_found = (is_existence_check and payload.get("group") == "scans" and error_msg == "Classes.TableRepository.row_not_found")
                        project_already_exists = (is_create_action and payload.get("group") == "projects" and "Project code already exists" in error_msg)
                        scan_already_exists = (is_create_action and payload.get("group") == "scans" and ("Scan code already exists" in error_msg or "Legacy.controller.scans.code_already_exists" in error_msg))

                        # --- Include is_invalid_type_probe in non-fatal check ---
                        if not (project_not_found or scan_not_found or project_already_exists or scan_already_exists or is_invalid_type_probe):
                            logger.error(f"Unhandled API Error (status 0 JSON): {error_msg} | Payload: {payload}")
                            raise ApiError(error_msg, code=parsed_json.get("code"))
                        # Return the status 0 JSON for expected non-fatal errors

                    return parsed_json # Return successfully parsed JSON (status 1 or expected status 0)

                except json.JSONDecodeError as e:
                    # Content-Type was JSON but decoding failed - this is an error
                    logger.error(f"Failed to decode JSON response despite Content-Type being JSON: {response.text[:500]}", exc_info=True)
                    raise ApiError(f"Invalid JSON received from API: {e.msg}", details={"response_text": response.text[:500]})
            else:
                # Content-Type is NOT JSON. Assume it might be a direct synchronous response (like HTML report).
                # Return the raw response object for the caller (generate_report) to handle.
                logger.info(f"Received non-JSON Content-Type '{content_type}'. Returning raw response object.")
                # Use a special key to indicate this isn't a normal parsed response
                return {"_raw_response": response}

        except requests.exceptions.ConnectionError as e:
            logger.error("API connection failed: %s", e, exc_info=True)
            raise NetworkError("Failed to connect to the API server", details={"error": str(e)})
        except requests.exceptions.Timeout as e:
            logger.error("API request timed out: %s", e, exc_info=True)
            raise NetworkError("Request to API server timed out", details={"error": str(e)})
        except requests.exceptions.RequestException as e:
            logger.error("API request failed: %s", e, exc_info=True)
            raise NetworkError(f"API request failed: {str(e)}", details={"error": str(e)})

    def _is_status_check_supported(self, scan_code: str, process_type: str) -> bool:
        """
        Checks if the Workbench instance likely supports check_status for a given process type
        by probing the API and analyzing the response, including specific error codes.

        Args:
            scan_code: The code of the scan to check against.
            process_type: The process type string (e.g., "EXTRACT_ARCHIVES").

        Returns:
            True if the check_status call for the type seems supported, False otherwise.

        Raises:
            ApiError: If the check_status call fails for reasons other than a recognized unsupported type error.
            NetworkError: If there are network connectivity issues.
        """
        logger.debug(f"Probing check_status support for type '{process_type}' on scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": process_type.upper(),
            },
        }
        try:
            # Short timeout is sufficient for the probe.
            response = self._send_request(payload, timeout=30)

            # If status is "1", the API understood the request type.
            if response.get("status") == "1":
                logger.debug(f"check_status for type '{process_type}' appears to be supported (API status 1).")
                return True

            # --- Check for specific 'invalid type' error structure ---
            elif response.get("status") == "0":
                error_code = response.get("error")
                data_list = response.get("data")

                # Check for the specific error structure indicating an invalid 'type' option
                if (error_code == "RequestData.Base.issues_while_parsing_request" and
                    isinstance(data_list, list) and len(data_list) > 0 and
                    isinstance(data_list[0], dict) and
                    data_list[0].get("code") == "RequestData.Base.field_not_valid_option" and
                    data_list[0].get("message_parameters", {}).get("fieldname") == "type"):

                    logger.warning(
                        f"This version of Workbench does not support check_status for '{process_type}'. "
                        f"Skipping status check for this operation. (API indicated invalid type option)"
                    )
                    # Optionally log the valid types listed by the API
                    valid_options = data_list[0].get("message_parameters", {}).get("options")
                    if valid_options:
                        logger.debug(f"API reported valid types are: [{valid_options}]")
                    return False
                else:
                    # It's a different status 0 error (e.g., scan not found), raise it.
                    logger.error(f"API error during {process_type} support check (but not an invalid type error): {error_code} - {response.get('message')}")
                    raise ApiError(f"API error during {process_type} support check: {error_code} - {response.get('message', 'No details')}", details=response)

            else:
                # Unexpected response format (neither status 1 nor 0)
                logger.warning(f"Unexpected response format during {process_type} support check: {response}")
                # Assume not supported to be safe
                return False

        except requests.exceptions.RequestException as e:
            # This block now primarily catches network errors or unexpected exceptions from _send_request.
            # We add a fallback check on the exception message just in case _send_request's logic changes.
            error_msg_lower = str(e).lower()
            if "requestdata.base.field_not_valid_option" in error_msg_lower and "type" in error_msg_lower:
                logger.warning(
                    f"Workbench likely does not support check_status for type '{process_type}'. "
                    f"Skipping status check. (Detected via exception: {e})"
                )
                return False
            else:
                # Different error (network, scan not found, etc.), re-raise it.
                logger.error(f"Unexpected exception during {process_type} support check: {e}", exc_info=False)
                if isinstance(e, NetworkError):
                    raise
                raise ApiError(f"Unexpected error during {process_type} support check", details={"error": str(e)}) from e

    def _wait_for_process(
        self,
        process_description: str,
        check_function: callable,
        check_args: Dict[str, Any],
        status_accessor: callable,
        success_values: set,
        failure_values: set,
        max_tries: int,
        wait_interval: int,
        progress_indicator: bool = True
        # NO on_status_update parameter here
    ):
        # ... (simplified implementation from previous step) ...
        print(f"Waiting for {process_description}...")
        last_status = "UNKNOWN"

        for i in range(max_tries):
            status_data = None
            current_status = "UNKNOWN"

            try:
                status_data = check_function(**check_args)
                try:
                    current_status_raw = status_accessor(status_data)
                    current_status = str(current_status_raw).upper()
                except Exception as access_err:
                    logger.warning(f"Error executing status_accessor during {process_description} check: {access_err}. Response data: {status_data}", exc_info=True)
                    current_status = "ACCESS_ERROR" # Treat as failure

            except Exception as e:
                print()
                print(f"Attempt {i+1}/{max_tries}: Error checking status for {process_description}: {e}")
                print(f"Retrying in {wait_interval} seconds...")
                logger.warning(f"Error calling check_function for {process_description}", exc_info=False)
                time.sleep(wait_interval)
                continue

            # Check for Success
            if current_status in success_values:
                print()
                print(f"{process_description} completed successfully (Status: {current_status}).")
                return True

            # Check for Failure (includes ACCESS_ERROR)
            if current_status in failure_values or current_status == "ACCESS_ERROR":
                print() # Newline after dots/status
                base_error_msg = f"The {process_description} {current_status}"
                error_detail = ""
                if isinstance(status_data, dict):
                    error_detail = status_data.get("error", status_data.get("message", status_data.get("info", "")))
                if error_detail:
                    base_error_msg += f". Detail: {error_detail}"
                raise ProcessError(base_error_msg, details=status_data)

            # Basic Status Printing
            if current_status != last_status or i < 2 or i % 10 == 0:
                print()
                print(f"{process_description} status: {current_status}. Attempt {i+1}/{max_tries}.", end="", flush=True)
                last_status = current_status
            elif progress_indicator:
                print(".", end="", flush=True)

            time.sleep(wait_interval)

        print()
        raise ProcessTimeoutError(
            f"Timeout waiting for {process_description} to complete after {max_tries * wait_interval} seconds (Last Status: {last_status}).",
            details={"last_status": last_status, "max_tries": max_tries, "wait_interval": wait_interval, "last_data": status_data}
        )
    
    def _read_in_chunks(self, file_object: io.BufferedReader, chunk_size: int = 8 * 1024 * 1024) -> Generator[bytes, None, None]:
        """Reads a file in chunks."""
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

# Project and Scan Essentials
    def list_projects(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all projects.

        Returns:
            List[Dict[str, Any]]: List of project data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all projects...")
        payload = {
            "group": "projects",
            "action": "list_projects",
            "data": {}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.info(f"Successfully listed {len(data)} projects.")
                return data
            else:
                logger.warning(f"API returned success for list_projects but 'data' was not a list: {type(data)}")
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list projects: {error_msg}", details=response)

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans.

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug("Listing all scans...")
        payload = {
            "group": "scans",
            "action": "list_scans",
            "data": {}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            # API returns a dict {id: {details}}, convert to list of dicts including the code
            if isinstance(data, dict):
                scan_list = []
                for scan_id, scan_details in data.items():
                    if isinstance(scan_details, dict):
                        # Add the 'id' from the key and potentially 'code' if present
                        try: # Handle potential non-integer scan_id keys if API is weird
                            scan_details['id'] = int(scan_id)
                        except ValueError:
                            logger.warning(f"Non-integer scan ID key found in list_scans response: {scan_id}")
                            scan_details['id'] = scan_id # Keep original key if not int

                        # 'code' should be in scan_details based on previous API info
                        if 'code' not in scan_details:
                            logger.warning(f"Scan details for ID {scan_id} missing 'code' field: {scan_details}")
                        scan_list.append(scan_details)
                    else:
                        logger.warning(f"Unexpected format for scan details with ID {scan_id}: {type(scan_details)}")
                logger.info(f"Successfully listed {len(scan_list)} scans.")
                return scan_list
            elif isinstance(data, list) and not data: # Handle API returning empty list for no scans
                logger.info("Successfully listed 0 scans (API returned empty list).")
                return []
            else:
                logger.warning(f"API returned success for list_scans but 'data' was not a dict or empty list: {type(data)}")
                return [] # Return empty list on unexpected format
        elif response.get("status") == "1": # Status 1 but no data key
            logger.warning(f"API returned success for list_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list scans: {error_msg}", details=response)

    def get_project_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all scans within a specific project.

        Args:
            project_code: Code of the project to get scans for

        Returns:
            List[Dict[str, Any]]: List of scan data

        Raises:
            ApiError: If there are API issues
            ProjectNotFoundError: If the project doesn't exist
            NetworkError: If there are network issues
        """
        logger.debug(f"Listing scans for the '{project_code}' project...")
        payload = {
            "group": "projects",
            "action": "get_all_scans",
            "data": {
                "project_code": project_code
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.info(f"Successfully listed {len(data)} scans for project '{project_code}'.")
                return data
            else:
                logger.warning(f"API returned success for get_all_scans but 'data' was not a list: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning(f"API returned success for get_all_scans but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            # Treat project not found as empty list of scans
            if "Project code does not exist" in error_msg or "row_not_found" in error_msg:
                logger.warning(f"Project '{project_code}' not found when trying to list its scans.")
                return []
            else:
                raise ApiError(f"Failed to list scans for project '{project_code}': {error_msg}", details=response)

    def create_project(self, project_name: str) -> str:
        """
        Create a new project in Workbench.
        
        Args:
            project_name: Name of the project to create
            
        Returns:
            The project code of the created project
            
        Raises:
            ProjectExistsError: If a project with this name already exists
            ApiError: If project creation fails
            NetworkError: If there are network issues
        """
        try:
            # First check if project exists
            projects = self.list_projects()
            for project in projects:
                if project.get("name") == project_name:
                    raise ProjectExistsError(f"Project '{project_name}' already exists")

            # Create the project
            payload = {
                "group": "projects",
                "action": "create",
                "data": {
                    "project_name": project_name,
                }
            }
            response = self._send_request(payload)
            
            if response.get("status") == "1":
                project_code = response.get("data", {}).get("project_code")
                if not project_code:
                    raise ApiError("Project created but no code returned", details=response)
                return project_code
            else:
                error_msg = response.get("error", "Unknown error")
                raise ApiError(f"Failed to create project '{project_name}': {error_msg}", details=response)
                
        except ProjectExistsError:
            raise
        except Exception as e:
            if isinstance(e, ApiError):
                raise
            raise ApiError(f"Failed to create project '{project_name}'", details={"error": str(e)})

    def create_webapp_scan(
            self,
            scan_name: str,
            project_code: str,
            git_url: Optional[str] = None,
            git_branch: Optional[str] = None,
            git_tag: Optional[str] = None,
            git_depth: Optional[int] = None
        ) -> bool:
        """
        Creates a new webapp scan inside a project, handling Git parameters as needed.
        Returns True if successful trigger, False if scan already existed.
        """
        logger.info(f"Attempting to create or find the '{scan_name}' scan inside the '{project_code}' project...")

        # Prepare the base payload data
        payload_data = {
            "scan_name": scan_name, # Use 'name' as corrected previously
            "project_code": project_code,
            "description": f"Scan created by Workbench Agent.", # Add description
        }

        # --- Correct Git Parameter Handling ---
        git_ref_value = None
        git_ref_type = None

        if git_tag:
            git_ref_value = git_tag
            git_ref_type = "tag"
            logger.info(f"  Including Git Tag: {git_tag}")
        elif git_branch:
            git_ref_value = git_branch
            git_ref_type = "branch"
            logger.info(f"  Including Git Branch: {git_branch}")
        # If neither branch nor tag is provided but git_url is, API might default,
        # but our argparse setup requires one or the other for scan-git.

        if git_url:
            # Use the key from the monolith script
            payload_data["git_repo_url"] = git_url
            logger.info(f"  Including Git URL: {git_url}")
        if git_ref_value:
            # API uses 'git_branch' field for BOTH branch and tag values
            payload_data["git_branch"] = git_ref_value
        if git_ref_type:
            # Send the explicit type
            payload_data["git_ref_type"] = git_ref_type
            logger.info(f"  Setting Git Ref Type to: {git_ref_type}")
        if git_depth is not None:
            # Send depth as string
            payload_data["git_depth"] = str(git_depth)
            logger.info(f"  Setting Git Clone Depth to: {git_depth}")
            # Ensure ref type is set if depth is used (API requirement?)
            if not git_ref_type:
                 logger.warning("Git depth specified, but no branch or tag provided. Setting ref type to 'branch' as a default.")
                 payload_data["git_ref_type"] = "branch"

        payload = {
            "group": "scans",
            "action": "create",
            "data": payload_data,
        }

        try:
            response = self._send_request(payload)
            # API returns scan_id on success
            if response.get("status") == "1" and "data" in response and "scan_id" in response["data"]:
                 scan_id = response["data"]["scan_id"]
                 print(f"Successfully created the '{scan_name}' scan (ID: {scan_id}).")
                 return True # Signal success
            # Handle "already exists" - return False to signal it existed
            elif response.get("status") == "0" and \
               ("Scan code already exists" in response.get("error", "") or "Legacy.controller.scans.code_already_exists" in response.get("error", "")):
                 logger.warning(f"Scan creation skipped: Scan with name/code '{scan_name}' likely already exists in project '{project_code}'.")
                 # We need to signal to _resolve_scan that it existed, raising ScanExistsError is one way
                 raise ScanExistsError(f"Scan '{scan_name}' already exists in project '{project_code}' (detected during creation attempt)")
            else:
                # Handle other API errors during creation
                error_msg = response.get("error", f"Unexpected response: {response}")
                if "Project does not exist" in error_msg:
                    raise ProjectNotFoundError(f"Project '{project_code}' not found during scan creation")
                raise ApiError(f"Failed to trigger creation for scan '{scan_name}': {error_msg}", details=response)
        except ScanExistsError:
             raise # Re-raise ScanExistsError to be caught by _resolve_scan
        except ProjectNotFoundError:
             raise # Re-raise ProjectNotFoundError
        except Exception as e:
             # Catch other errors from _send_request or logic
             logger.error(f"Unexpected error during scan creation trigger for '{scan_name}': {e}", exc_info=True)
             # Re-raise as ApiError for consistency in _resolve_scan
             raise ApiError(f"Failed to trigger creation for scan '{scan_name}': {e}") from e

# Scan Target Upload and Extraction
    def upload_files(self, scan_code: str, path: str, is_da_import: bool = False):
        """
        Uploads a file or directory (as zip) to a scan using the direct data
        posting method with custom headers, mimicking the original script's logic.
        """
        if not os.path.exists(path):
            raise FileSystemError(f"Path does not exist: {path}")

        archive_path = None
        upload_path = path
        original_basename = os.path.basename(path)
        file_handle = None # Define outside try for finally block

        try:
            # --- Archive Directory if Necessary ---
            if os.path.isdir(path):
                logger.info(f"Compressing target directory '{path}'...")
                # Use a temporary directory for the archive to ensure cleanup
                with tempfile.TemporaryDirectory() as temp_dir:
                    base_name = os.path.join(temp_dir, f"{original_basename}_temp_archive")
                    try:
                        # Ensure root_dir and base_dir are correctly set for shutil.make_archive
                        # root_dir should be the parent of the directory being archived
                        # base_dir should be the name of the directory itself
                        parent_dir = os.path.dirname(path) or '.' # Parent directory
                        dir_to_archive = os.path.basename(path) # Directory name itself
                        if not dir_to_archive: # Handle case like path = "/some/dir/"
                             raise FileSystemError(f"Cannot determine directory name from path: {path}")

                        archive_path = shutil.make_archive(base_name, 'zip', root_dir=parent_dir, base_dir=dir_to_archive)
                        upload_path = archive_path # Upload the created archive
                        logger.info(f"Archive created: {upload_path}")

                        # --- Perform Upload Logic for Archive ---
                        # This block is now inside the temp dir context if archiving
                        file_size = os.path.getsize(upload_path)
                        size_limit = 16 * 1024 * 1024 # Chunking threshold
                        upload_basename = os.path.basename(upload_path) # e.g., archive_temp.zip

                        # Encode headers (as per old script)
                        name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
                        scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")

                        headers = {
                            "FOSSID-SCAN-CODE": scan_code_b64,
                            "FOSSID-FILE-NAME": name_b64,
                            "Accept": "*/*" # Keep Accept broad
                        }
                        if is_da_import:
                            headers["FOSSID-UPLOAD-TYPE"] = "dependency_analysis"
                            logger.info(f"Uploading DA results file '{upload_basename}' ({file_size} bytes)...")
                        else:
                            logger.info(f"Uploading archive '{upload_basename}' ({file_size} bytes)...")

                        logger.debug(f"Upload Request Headers: {headers}")

                        file_handle = open(upload_path, "rb")

                        if file_size > size_limit:
                            logger.info(f"File size exceeds limit ({size_limit} bytes). Using chunked upload...")
                            headers['Transfer-Encoding'] = 'chunked'
                            headers['Content-Type'] = 'application/octet-stream' # Required for chunked

                            for i, chunk in enumerate(self._read_in_chunks(file_handle)):
                                logger.debug(f"Uploading chunk {i+1}...")
                                # Send chunk directly using session.post with auth and data
                                resp_chunk = self.session.post(
                                    self.api_url,
                                    headers=headers,
                                    data=chunk,
                                    auth=(self.api_user, self.api_token), # Use Basic Auth
                                    timeout=1800,
                                )
                                logger.debug(f"Chunk {i+1} upload response status: {resp_chunk.status_code}")
                                resp_chunk.raise_for_status() # Check for HTTP errors per chunk
                            logger.info("Chunked upload completed successfully.")
                        else:
                            # Standard upload for smaller files (send all data at once)
                            resp = self.session.post(
                                self.api_url,
                                headers=headers,
                                data=file_handle, # Send file handle directly in data
                                auth=(self.api_user, self.api_token), # Use Basic Auth
                                timeout=1800,
                            )
                            logger.debug(f"Upload Response Status: {resp.status_code}")
                            logger.debug(f"Upload Response Text (first 500): {resp.text[:500]}")
                            resp.raise_for_status() # Check for HTTP errors

                            logger.info(f"Upload for '{upload_basename}' completed.")

                        # Close handle after upload completes inside the context
                        if file_handle and not file_handle.closed:
                            file_handle.close()
                            file_handle = None # Reset handle

                    except Exception as archive_err: 
                        raise FileSystemError(f"Failed to create zip archive from directory '{path}'", details={"error": str(archive_err)}) # Level 4

            # --- Handle Single File Upload (outside temp dir context) ---
            elif os.path.isfile(path):
                upload_path = path # Use original path
                file_size = os.path.getsize(upload_path)
                size_limit = 16 * 1024 * 1024
                upload_basename = os.path.basename(upload_path)

                name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
                scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")

                headers = {
                    "FOSSID-SCAN-CODE": scan_code_b64,
                    "FOSSID-FILE-NAME": name_b64,
                    "Accept": "*/*"
                }
                if is_da_import:
                    headers["FOSSID-UPLOAD-TYPE"] = "dependency_analysis"
                    logger.info(f"Uploading DA results file '{upload_basename}' ({file_size} bytes)...")
                else:
                    logger.info(f"Uploading file '{upload_basename}' ({file_size} bytes)...")

                logger.debug(f"Upload Request Headers: {headers}")

                file_handle = open(upload_path, "rb")

                if file_size > size_limit:
                    logger.info(f"File size exceeds limit ({size_limit} bytes). Using chunked upload...")
                    headers['Transfer-Encoding'] = 'chunked'
                    headers['Content-Type'] = 'application/octet-stream'

                    for i, chunk in enumerate(self._read_in_chunks(file_handle)):
                        logger.debug(f"Uploading chunk {i+1}...")
                        resp_chunk = self.session.post(
                            self.api_url,
                            headers=headers,
                            data=chunk,
                            auth=(self.api_user, self.api_token),
                            timeout=1800,
                        )
                        logger.debug(f"Chunk {i+1} upload response status: {resp_chunk.status_code}")
                        resp_chunk.raise_for_status()
                    logger.info("Chunked upload completed successfully.")
                else:
                    resp = self.session.post(
                        self.api_url,
                        headers=headers,
                        data=file_handle,
                        auth=(self.api_user, self.api_token),
                        timeout=1800,
                    )
                    logger.debug(f"Upload Response Status: {resp.status_code}")
                    logger.debug(f"Upload Response Text (first 500): {resp.text[:500]}")
                    resp.raise_for_status()
                    logger.info(f"Upload for '{upload_basename}' completed.")

        except FileSystemError as e:
             logger.error(f"File system error during upload preparation for {path}: {e}", exc_info=True)
             raise # Re-raise specific error
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during upload for {upload_path}: {e}", exc_info=True)
            raise NetworkError(f"Network error during file upload: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error during file upload for {path}: {e}", exc_info=True)
            # Wrap in a more specific error if possible, otherwise generic
            raise WorkbenchAgentError(f"Unexpected error during file upload process for '{path}'", details={"error": str(e)}) from e
        finally:
            # Ensure file handle is closed if it was opened
            if file_handle and not file_handle.closed:
                file_handle.close()
                logger.debug(f"Closed file handle for {upload_path}")

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ):
        """
        Triggers archive extraction for a scan.

        Args:
            scan_code: Code of the scan to extract archives for
            recursively_extract_archives: Whether to recursively extract archives
            jar_file_extraction: Whether to extract JAR files

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        print(f"Extracting Uploaded Archives for Scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": {
                "scan_code": scan_code,
                # API expects boolean as string "true"/"false" or integer 1/0
                "recursively_extract_archives": str(recursively_extract_archives).lower(),
                "jar_file_extraction": str(jar_file_extraction).lower(),
            },
        }
        response = self._send_request(payload)
        if response.get("status") == "1":
            print(f"Archive Extraction operation successfully queued/completed for scan '{scan_code}'.")
            return True
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Archive extraction failed for scan '{scan_code}': {error_msg}",
                details=response
            )

    def wait_for_archive_extraction(
        self,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ):
        """
        Wait for archive extraction to complete.
        
        Args:
            scan_code: The code of the scan to check
            scan_number_of_tries: Maximum number of attempts
            scan_wait_time: Time to wait between attempts
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        def status_accessor(data):
            try:
                # Check if 'is_finished' flag indicates completion
                is_finished_flag = data.get("is_finished")
                is_finished = str(is_finished_flag) == "1" or is_finished_flag is True

                # If finished, return "FINISHED" (using the hardcoded success value)
                if is_finished:
                    return "FINISHED"

                # Otherwise, return the value of the 'status' key (or UNKNOWN)
                return data.get("status", "UNKNOWN")

            except (ValueError, TypeError, AttributeError):
                # Handle errors accessing keys or converting types
                logger.warning(f"Error accessing status keys in data: {data}", exc_info=True)
                return "ACCESS_ERROR" # Use the ACCESS_ERROR state

        try:
            return self._wait_for_process(
                "Archive extraction",
                self.get_scan_status,
                {"scan_type": "EXTRACT_ARCHIVES", "scan_code": scan_code},
                status_accessor,
                {"FINISHED"},
                {"FAILED", "CANCELLED", "ACCESS_ERROR"},
                scan_number_of_tries,
                scan_wait_time,
                progress_indicator=True
            )
        except ProcessTimeoutError as e:
            raise ProcessTimeoutError(f"Timeout waiting for archive extraction on scan {scan_code}", details=e.details)
        except ProcessError as e:
            raise ProcessError(f"Archive extraction failed for scan {scan_code}", details=e.details)
        except Exception as e:
            raise ApiError(f"Error during archive extraction: {str(e)}", details={"scan_code": scan_code})

# Scan Ops
    def assert_process_can_start(self, process_type: str, scan_code: str):
        """
        Checks if a SCAN or DEPENDENCY_ANALYSIS can be started.

        Args:
            process_type: Type of process to check (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check

        Raises:
            CompatibilityError: If the process cannot be started due to incompatible state
            ProcessError: If there are process-related issues
            ApiError: If there are API issues
            NetworkError: If there are network issues
            ScanNotFoundError: If the scan doesn't exist
        """
        process_type_upper = process_type.upper()
        if process_type_upper not in ["SCAN", "DEPENDENCY_ANALYSIS"]:
             raise ValueError(f"Invalid process_type '{process_type}' provided to assert_process_can_start.")

        try:
            scan_status = self.get_scan_status(process_type, scan_code)
            current_status = scan_status.get("status", "UNKNOWN").upper()
            # Allow starting if NEW, FINISHED, FAILED, or CANCELLED
            allowed_statuses = ["NEW", "FINISHED", "FAILED", "CANCELLED"]
            if current_status not in allowed_statuses:
                raise CompatibilityError(
                    f"Cannot start {process_type.lower()} for '{scan_code}'. Current status is {current_status} (Must be one of {allowed_statuses})."
                )
            print(f"The {process_type.capitalize()} for '{scan_code}' can start (Current status: {current_status}).")
        except (ApiError, NetworkError, ScanNotFoundError):
            raise
        except Exception as e:
            raise ProcessError(f"Could not verify if {process_type.lower()} can start for '{scan_code}'", details={"error": str(e)})

    def run_scan(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        autoid_file_licenses: bool,
        autoid_file_copyrights: bool,
        autoid_pending_ids: bool,
        delta_scan: bool,
        id_reuse: bool,
        id_reuse_type: Optional[str] = None,
        id_reuse_source: Optional[str] = None,
    ):
        """
        Run a scan with the specified parameters.
        """

        payload = {
            "group": "scans",
            "action": "run",
            "data": {
                "scan_code": scan_code,
                "limit": limit,
                "sensitivity": sensitivity,
                "auto_identification_detect_declaration": int(autoid_file_licenses),
                "auto_identification_detect_copyright": int(autoid_file_copyrights),
                "auto_identification_resolve_pending_ids": int(autoid_pending_ids),
                "delta_only": int(delta_scan),
            }
        }

        if id_reuse:
            data = payload["data"]
            data["reuse_identification"] = "1" # Always send this if reuse is enabled

            # Determine the value to send to the API based on the user input
            api_reuse_type_value = id_reuse_type

            if id_reuse_type == "project":
                api_reuse_type_value = "specific_project"
            elif id_reuse_type == "scan":
                api_reuse_type_value = "specific_scan"

            data["identification_reuse_type"] = api_reuse_type_value

            if api_reuse_type_value in ['specific_project', 'specific_scan']:
                if not id_reuse_source:
                    raise ValueError(f"--id-reuse-source is required when --id-reuse-type is '{id_reuse_type}' (translated to '{api_reuse_type_value}').")
                data["specific_code"] = id_reuse_source

        # --- Send Request ---
        try:
            response = self._send_request(payload)
            if response.get("status") == "1":
                print(f"KB Scan initiated for scan '{scan_code}'.")
                return # Return None or True on success
            else:
                error_msg = response.get("error", "Unknown error")
                if "Scan not found" in error_msg:
                    raise ScanNotFoundError(f"Scan '{scan_code}' not found")
                raise ApiError(f"Failed to run scan '{scan_code}': {error_msg}", details=response)
        except (ScanNotFoundError, ApiError):
             raise # Re-raise specific errors
        except Exception as e:
             # Catch other errors like network issues from _send_request
             logger.error(f"Unexpected error trying to run scan '{scan_code}': {e}", exc_info=True)
             raise ApiError(f"Failed to run scan '{scan_code}': {e}") from e

    def start_dependency_analysis(self, scan_code: str, import_only: bool = False):
        """
        Starts or imports dependency analysis for a scan.

        Args:
            scan_code: Code of the scan to start dependency analysis for
            import_only: Whether to only import results without running analysis

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": {
                "scan_code": scan_code,
            },
        }
        if import_only:
            payload["data"]["import_only"] = "1"
            print("DA Result Import Mode.")
            print(f"Importing DA results into Scan '{scan_code}'.")
        else:
            print(f"Starting Dependency Analysis for scan '{scan_code}'.")

        response = self._send_request(payload)
        if response.get("status") == "1":
            print(f"Dependency Analysis started for scan '{scan_code}'.")
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Dependency Analysis for scan '{scan_code}' failed to start: {error_msg}",
                details=response
            )

    def get_scan_status(self, scan_type: str, scan_code: str) -> dict:
        """
        Retrieves the status of a scan operation (SCAN or DEPENDENCY_ANALYSIS).

        Args:
            scan_type: Type of scan operation (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check

        Returns:
            dict: The scan status data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": scan_type.upper(),
            },
        }
        response = self._send_request(payload)
        # _send_request handles basic API errors, check for expected data
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response format: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to retrieve {scan_type} status for scan '{scan_code}': {error_msg}",
                details=response
            )

    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ):
        """
        Wait for a scan to complete.
        
        Args:
            scan_type: Type of scan ("SCAN" or "DEPENDENCY_ANALYSIS")
            scan_code: Code of the scan to check
            scan_number_of_tries: Maximum number of attempts
            scan_wait_time: Time to wait between attempts
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        def status_accessor(data):
            try:
                # Check if 'is_finished' flag indicates completion
                is_finished_flag = data.get("is_finished")
                is_finished = str(is_finished_flag) == "1" or is_finished_flag is True

                # If finished, return "FINISHED" (using the hardcoded success value)
                if is_finished:
                    return "FINISHED"

                # Otherwise, return the value of the 'status' key (or UNKNOWN)
                return data.get("status", "UNKNOWN")

            except (ValueError, TypeError, AttributeError):
                # Handle errors accessing keys or converting types
                logger.warning(f"Error accessing status keys in data: {data}", exc_info=True)
                return "ACCESS_ERROR" # Use the ACCESS_ERROR state

        try:
            return self._wait_for_process(
                f"{scan_type} scan",
                self.get_scan_status,
                {"scan_type": scan_type, "scan_code": scan_code},
                status_accessor,
                {"FINISHED"},
                {"FAILED", "CANCELLED", "ACCESS_ERROR"},
                scan_number_of_tries,
                scan_wait_time,
                progress_indicator=True # Keep True as fallback
            )
        except ProcessTimeoutError as e:
            raise ProcessTimeoutError(f"Timeout waiting for {scan_type} scan {scan_code}", details=e.details)
        except ProcessError as e:
            raise ProcessError(f"{scan_type} scan failed for {scan_code}", details=e.details)
        except Exception as e:
            # Catch any other unexpected errors from _wait_for_process or status_accessor
            raise ApiError(f"Error during {scan_type} scan: {str(e)}", details={"scan_code": scan_code})

# Fetching Results
    def get_scan_folder_metrics(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves scan folder metrics (total files, pending, identified, no match).

        Args:
            scan_code: Code of the scan to get metrics for

        Returns:
            Dict[str, Any]: Dictionary containing the metrics counts.

        Raises:
            ScanNotFoundError: If the scan doesn't exist.
            ApiError: If the API call fails for other reasons.
            NetworkError: If there are network issues.
        """
        logger.debug(f"Fetching folder metrics for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_folder_metrics",
            "data": {"scan_code": scan_code}
        }
        response = self._send_request(payload)

        if response.get("status") == "1" and "data" in response and isinstance(response["data"], dict):
            logger.info(f"Successfully fetched folder metrics for scan '{scan_code}'.")
            return response["data"]
        elif response.get("status") == "1": # Status 1 but no data or wrong format
             logger.warning(f"Folder metrics API returned success but unexpected data format for scan '{scan_code}': {response.get('data')}")
             raise ApiError(f"Unexpected data format received for scan folder metrics: {response.get('data')}", details=response)
        else:
            # Handle API errors (status 0)
            error_msg = response.get("error", "Unknown API error")
            if "row_not_found" in error_msg:
                logger.warning(f"Scan '{scan_code}' not found when fetching folder metrics.")
                raise ScanNotFoundError(f"Scan '{scan_code}' not found.")
            else:
                logger.error(f"API error fetching folder metrics for scan '{scan_code}': {error_msg}")
                raise ApiError(f"Failed to get scan folder metrics: {error_msg}", details=response)
    
    def get_scan_identified_components(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets identified components from KB scanning.

        Args:
            scan_code: Code of the scan to get components from

        Returns:
            List[Dict[str, Any]]: List of identified components

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            # API returns a dict { comp_id: {details} }, convert to list
            data = response["data"]
            return list(data.values()) if isinstance(data, dict) else []
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error retrieving identified components from scan '{scan_code}': {error_msg}",
                details=response
            )

    def get_scan_identified_licenses(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Get the list of identified licenses for a scan.

        Args:
            scan_code: Code of the scan to get licenses from

        Returns:
            List[Dict[str, Any]]: List of identified licenses

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "scan_code": scan_code,
                "unique": "1"
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, list):
                logger.debug(f"Successfully fetched {len(data)} unique licenses.")
                return data
            else:
                logger.warning(f"API returned success for get_scan_identified_licenses but 'data' was not a list: {type(data)}")
                return []
        elif response.get("status") == "1":
            logger.warning("API returned success for get_scan_identified_licenses but no 'data' key found.")
            return []
        else:
            error_msg = response.get("error", f"Unexpected response format or status: {response}")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting identified licenses for scan '{scan_code}': {error_msg}",
                details=response
            )

    def get_dependency_analysis_results(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Gets dependency analysis results.

        Args:
            scan_code: Code of the scan to get results from

        Returns:
            List[Dict[str, Any]]: List of dependency analysis results

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            return data if isinstance(data, list) else []
        elif response.get("status") == "1": # Success but no data key
            logger.info(f"Dependency Analysis results requested for '{scan_code}', but no 'data' key in response. Assuming empty.")
            return []
        else:
            # Check for specific "not run yet" error
            error_msg = response.get("error", "")
            if "Dependency analysis has not been run" in error_msg:
                logger.info(f"Dependency analysis results requested for '{scan_code}', but analysis has not been run.")
                return [] # Return empty list, not an error
            elif "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            else:
                raise ApiError(
                    f"Error getting dependency analysis results for scan '{scan_code}': {error_msg}",
                    details=response
                )

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """Retrieves pending files for a scan."""
        logger.debug(f"Fetching files with Pending IDs for scan '{scan_code}'...")
        payload = {
            "group": "scans", 
            "action": "get_pending_files", 
            "data": {"scan_code": scan_code}
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.info(f"The scan {scan_code} has {len(data)} files pending ID'.")
                return data
            elif isinstance(data, list) and not data: # Handle API sometimes returning empty list?
                 logger.info(f"Pending files API returned empty list for scan '{scan_code}'.")
                 return {} # Return empty dict
            else:
                # Log unexpected format but return empty dict
                logger.warning(f"Pending files API returned unexpected data type: {type(data)}")
                return {}
        elif response.get("status") == "1": # Status 1 but no data key
             logger.info(f"Pending files API returned success but no 'data' key for scan '{scan_code}'.")
             return {}
        else:
            # On API error (status 0), log but return empty dict - let handler decide gate status
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get pending files for scan '{scan_code}': {error_msg}")
            return {} # Return empty dict on error

    def scans_get_policy_warnings_counter(self, scan_code: str) -> Dict[str, Any]:
        """
        Gets the count of policy warnings for a specific scan.

        Args:
            scan_code: Code of the scan to get policy warnings for

        Returns:
            Dict[str, Any]: The policy warnings counter data

        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Error getting scan policy warnings counter for '{scan_code}': {error_msg}",
                details=response
            )

    def get_policy_violations(self, scan_code: str) -> List[Dict[str, Any]]:
        """ Retrieves policy violations for a scan. """
        print(f"Checking the '{scan_code}' scan for policy violations...")
        # Option 1: Use the counter (simple, just counts)
        try:
            warnings_data = self.scans_get_policy_warnings_counter(scan_code)
            violations = []
            total_violations = 0
            for level, count_str in warnings_data.items():
                try:
                    count = int(count_str)
                    if count > 0:
                        violations.append({"level": level, "count": count, "description": f"{count} {level.capitalize()} policy violations found."})
                        total_violations += count
                except ValueError:
                    logger.warning(f"Could not parse policy warning count for level '{level}': {count_str}")

            if total_violations > 0:
                 print(f"Found {total_violations} policy violations (based on counter).")
            else:
                 print("No policy violations found (based on counter).")
            return violations # Return a list summarizing counts

        except Exception as e:
             print(f"Warning: Could not retrieve policy violation counts: {e}")
             # Fallback or re-raise depending on desired behavior
             return []

# Reporting
    def generate_report(
        self,
        scope: str,
        project_code: str,
        scan_code: Optional[str],
        report_type: str,
        selection_type: Optional[str] = None,
        selection_view: Optional[str] = None,
        disclaimer: Optional[str] = None,
        include_vex: bool = True,
    ) -> Union[int, requests.Response]:
        """
        Triggers report generation for a scan or project.
        Project reports are always async. Scan reports can be sync or async.
        Returns process queue ID for async, or raw response for sync scan reports.

        Args:
            scope: Either 'scan' or 'project'
            project_code: Code of the project
            scan_code: Code of the scan (required for scan scope)
            report_type: Type of report to generate
            selection_type: Optional selection type
            selection_view: Optional selection view
            disclaimer: Optional disclaimer text
            include_vex: Whether to include VEX data

        Returns:
            Union[int, requests.Response]: Process queue ID for async reports, or raw response for sync reports

        Raises:
            ValidationError: If scope is invalid or required parameters are missing
            ApiError: If there are API issues
            ProjectNotFoundError: If the project doesn't exist
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValidationError("Invalid scope provided to generate_report. Must be 'scan' or 'project'.")

        is_project_scope = (scope == "project")

        # --- Force Async for Project Scope ---
        if is_project_scope:
            use_async = True
            # Validate report type against allowed project types
            if report_type not in self.PROJECT_REPORT_TYPES:
                raise ValidationError(f"Report type '{report_type}' is not supported for project scope reports.")
        else: # scan scope
            use_async = report_type in self.ASYNC_REPORT_TYPES
            # No need to validate scan report types here, API will handle it

        async_value = "1" if use_async else "0" # Will always be "1" for project scope

        # Determine group, action, and primary code based on scope
        if is_project_scope:
            group = "projects"
            action = "generate_report"
            code_key = "project_code"
            code_value = project_code
            entity_name = f"project '{project_code}'"
            if not project_code:
                raise ValidationError("project_code is required for project scope reports.")
        else: # scan scope
            group = "scans"
            action = "generate_report"
            code_key = "scan_code"
            code_value = scan_code
            entity_name = f"scan '{scan_code}'"
            if not scan_code:
                raise ValidationError("scan_code is required for scan scope reports.")

        logger.info(f"Requesting generation of '{report_type}' report for {entity_name} (Async: {use_async})...")

        payload_data = {
            code_key: code_value,
            "report_type": report_type,
            "async": async_value,
            "include_vex": include_vex,
        }
        # Add optional parameters if provided
        if selection_type:
            payload_data["selection_type"] = selection_type
        if selection_view:
            payload_data["selection_view"] = selection_view
        if disclaimer:
            payload_data["disclaimer"] = disclaimer

        payload = {
            "group": group,
            "action": action,
            "data": payload_data
        }

        response_data = self._send_request(payload)

        # --- Response Handling ---
        if "_raw_response" in response_data:
            # This block should ONLY be reached for SYNCHRONOUS SCAN reports
            if is_project_scope:
                # This is unexpected based on the requirement that project reports are always async
                logger.error(f"API returned a synchronous response for a project report ({report_type}), which was not expected. Cannot proceed.")
                raise ApiError(f"Unexpected synchronous response received for project report '{report_type}'.")
            else:
                # Handle synchronous scan report
                raw_response = response_data["_raw_response"]
                logger.info(f"Synchronous report generation likely completed for {entity_name}. Returning raw response object.")
                return raw_response

        elif response_data.get("status") == "1" and "data" in response_data and "process_queue_id" in response_data["data"]:
            # This block handles ASYNC scan reports AND ALL project reports
            process_id = response_data["data"]["process_queue_id"]
            logger.debug(f"Report generation requested successfully (async) for {entity_name}. Process ID: {process_id}")
            return int(process_id)
        else:
            # Handle API errors (status 0 or unexpected format)
            error_msg = response_data.get("error", f"Unexpected response: {response_data}")
            if "Project does not exist" in error_msg or "row_not_found" in error_msg:
                raise ProjectNotFoundError(f"Project '{project_code}' not found")
            elif "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(f"Failed to request report generation for {entity_name}: {error_msg}", details=response_data)

    def check_report_generation_status(
        self,
        scope: str, 
        process_id: int,
        scan_code: Optional[str] = None,
        project_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Checks the status of an asynchronous report generation process.

        Args:
            scope: Either 'scan' or 'project'
            process_id: ID of the process to check
            scan_code: Optional scan code for context
            project_code: Optional project code for context

        Returns:
            Dict[str, Any]: The process status data

        Raises:
            ValidationError: If scope is invalid
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValidationError("Invalid scope provided to check_report_generation_status.")

        group = "projects" if scope == "project" else "scans"
        entity_name = f"project '{project_code}'" if scope == "project" else f"scan '{scan_code}'"
        logger.debug(f"Checking report generation status for process {process_id} ({scope} scope)...")

        payload = {
            "group": group,
            "action": "check_status",
            "data": {
                "process_id": str(process_id),
                "type": "REPORT_GENERATION",
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to check report status for process {process_id} ({entity_name}): {error_msg}", details=response)

    def download_report(self, scope: str, process_id: int):
        """
        Downloads a generated report using its process ID.
        Returns the requests.Response object containing the report content.

        Args:
            scope: Either 'scan' or 'project'
            process_id: ID of the process to download report from

        Returns:
            requests.Response: The response object containing the report content

        Raises:
            ValidationError: If scope is invalid
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValidationError("Invalid scope provided to download_report.")

        report_entity = "projects" if scope == "project" else "scans"
        logger.debug(f"Attempting to download report for process ID '{process_id}' (entity: {report_entity})...")

        payload = {
            "group": "download",
            "action": "download_report",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "report_entity": report_entity,
                "process_id": str(process_id)
            }
        }
        req_body = json.dumps(payload)
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "*/*",
        }

        logger.debug("Download API URL: %s", self.api_url)
        logger.debug("Download Request Headers: %s", headers)
        logger.debug("Download Request Body: %s", req_body)

        try:
            logger.debug(f"Initiating download request for process ID: {process_id}")
            # IMPORTANT: Do NOT use 'with' here if returning the response object
            r = self.session.post(
                self.api_url,
                headers=headers,
                data=req_body,
                stream=True, # Still use stream in case caller wants it
                timeout=1800
            )
            logger.debug(f"Download Response Status Code: {r.status_code}")
            logger.debug(f"Download Response Headers: {r.headers}")
            r.raise_for_status() # Check for HTTP errors (4xx, 5xx)

            content_type = r.headers.get('content-type', '').lower()
            content_disposition = r.headers.get('content-disposition')
            logger.info(f"Download Content-Type received: {content_type}")
            if content_disposition:
                logger.info(f"Download Content-Disposition received: {content_disposition}")

            is_likely_file_content = bool(content_disposition) or ('application/json' not in content_type)

            if not is_likely_file_content:
                # Treat as potential JSON API error
                logger.warning(f"Received JSON content type without Content-Disposition. Assuming API error message.")
                try:
                    error_json = r.json()
                    error_msg = error_json.get("error", "Unknown error")
                    logger.error(f"API error during download: {error_msg} | JSON: {error_json}")
                    raise ApiError(f"Failed to download report (process ID {process_id}): API returned error - {error_msg}", details=error_json)
                except json.JSONDecodeError as json_err:
                    logger.error(f"Failed to decode JSON error response during download: {r.text[:500]}", exc_info=True)
                    raise ApiError(f"Failed to download report (process ID {process_id}): Could not parse API error response.", details={"response_text": r.text[:500]})

            # If we reach here, it's likely the actual report content. Return the response object.
            logger.debug("Download request successful, returning response object.")
            return r # Return the response object

        except requests.exceptions.RequestException as req_err:
            logger.error(f"Failed to initiate report download request for process {process_id}: {req_err}", exc_info=True)
            raise NetworkError(f"Failed to download report (process ID {process_id}): {req_err}")
        except Exception as final_dl_err:
            logger.error(f"Unexpected error within download_report function for process {process_id}: {final_dl_err}", exc_info=True)
            raise ApiError(f"Unexpected error during report download (process ID {process_id})", details={"error": str(final_dl_err)})

    @staticmethod
    def format_duration(duration_seconds):
        """Formats a duration in seconds into a 'X minutes, Y seconds' string."""
        if duration_seconds is None:
            return "N/A"
        duration_seconds = round(duration_seconds) # Round to nearest second
        minutes = int(duration_seconds // 60)
        seconds = int(duration_seconds % 60)
        if minutes > 0:
            return f"{minutes} minutes, {seconds} seconds"
        else:
            return f"{seconds} seconds"