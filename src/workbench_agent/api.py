import requests
import json
import base64
import time
import re
import os
import logging
import io
import shutil
import tempfile
import builtins
from typing import Generator, Optional, Dict, Any, List, Union, Tuple

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
                             raise builtins.Exception(f"API returned error: {error_msg}")
                        # Return the status 0 JSON for expected non-fatal errors

                    return parsed_json # Return successfully parsed JSON (status 1 or expected status 0)

                except json.JSONDecodeError as e:
                    # Content-Type was JSON but decoding failed - this is an error
                    logger.error(f"Failed to decode JSON response despite Content-Type being JSON: {response.text[:500]}", exc_info=True)
                    raise builtins.Exception(f"Invalid JSON received from API: {e.msg}. Response text: {response.text[:500]}...")
            else:
                # Content-Type is NOT JSON. Assume it might be a direct synchronous response (like HTML report).
                # Return the raw response object for the caller (generate_report) to handle.
                logger.info(f"Received non-JSON Content-Type '{content_type}'. Returning raw response object.")
                # Use a special key to indicate this isn't a normal parsed response
                return {"_raw_response": response}

        except requests.exceptions.RequestException as e:
            logger.error("API request failed: %s", e, exc_info=True)
            raise builtins.Exception(f"API request failed: {e}")

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
            Exception: If the check_status call fails for reasons other than a recognized unsupported type error.
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
            # _send_request is now modified to return the JSON for the specific invalid type error.
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
                        f"Workbench does not support check_status for type '{process_type}'. "
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
                    raise builtins.Exception(f"API error during {process_type} support check: {error_code} - {response.get('message', 'No details')}")

            else:
                # Unexpected response format (neither status 1 nor 0)
                logger.warning(f"Unexpected response format during {process_type} support check: {response}")
                # Assume not supported to be safe
                return False

        except builtins.Exception as e:
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
                raise # Re-raise the original exception

    def _wait_for_process(
        self,
        process_description: str,
        check_function: callable, # The function to call for status (e.g., self.get_scan_status)
        check_args: Dict[str, Any], # Arguments for the check_function
        status_accessor: callable, # Function to extract status string from check_function result (e.g., lambda r: r.get("status"))
        success_values: set, # Set of uppercase strings indicating success (e.g., {"FINISHED"})
        failure_values: set, # Set of uppercase strings indicating failure (e.g., {"FAILED", "CANCELLED"})
        max_tries: int,
        wait_interval: int,
        progress_indicator: bool = True # Option to show dots
    ):
        """
        Generic method to wait for a background process to complete by polling its status.
        Provides enhanced error reporting on failure.
        """
        print(f"Waiting for {process_description}...")
        last_status = "UNKNOWN" # Keep track of the last status printed

        for i in range(max_tries):
            status_data = None # Initialize status_data for the current iteration
            try:
                # Call the provided check function with its arguments
                status_data = check_function(**check_args)
                # Use the accessor to get the status string, handle potential errors during access
                try:
                    current_status_raw = status_accessor(status_data)
                    current_status = str(current_status_raw).upper() # Ensure string and uppercase
                except Exception as access_err:
                    logger.warning(f"Error accessing status via accessor during {process_description} check: {access_err}. Response data: {status_data}")
                    current_status = "ACCESS_ERROR" # Treat as a distinct state

            except Exception as e:
                 # Error during the API call itself
                 print() # Newline after potential dots
                 print(f"Attempt {i+1}/{max_tries}: Error checking status for {process_description}: {e}")
                 print(f"Retrying in {wait_interval} seconds...")
                 logger.warning(f"Error checking status for {process_description}", exc_info=False)
                 time.sleep(wait_interval)
                 continue

            # Check for Success
            if current_status in success_values:
                print() # Newline after potential dots
                print(f"{process_description} completed successfully (Status: {current_status}).")
                return True # Indicate success

            # Check for Failure
            if current_status in failure_values:
                print() # Newline after potential dots
                base_error_msg = f"The {process_description} {current_status}" # Start building the message

                # Try to get more specific details if status_data is a dict (like the example)
                if isinstance(status_data, dict):
                    percentage = status_data.get("percentage_done", "N/A")
                    current_f = status_data.get("current_file", "N/A")
                    total_f = status_data.get("total_files", "N/A")
                    # Try 'info', then 'comment', as fallbacks for the Workbench message
                    wb_info = status_data.get("info", status_data.get("comment", None))
                    current_filename = status_data.get("current_filename") # Get filename if available

                    # Append details to the message
                    if percentage != "N/A":
                        base_error_msg += f" at {percentage}"
                    if current_f != "N/A" and total_f != "N/A":
                        # Try to format as numbers, fallback to raw strings
                        try:
                             base_error_msg += f". {int(current_f)} files were scanned out of the total {int(total_f)}"
                        except (ValueError, TypeError):
                             base_error_msg += f". {current_f}/{total_f} files processed"
                    if wb_info:
                        base_error_msg += f". The error returned by Workbench was: {wb_info}"
                    else:
                        # If no specific 'info'/'comment', try the generic error fields as a last resort
                        generic_error = status_data.get("error_message", status_data.get("error", None))
                        if generic_error:
                             base_error_msg += f". Detail: {generic_error}"

                    # Log the filename where it might have failed
                    if current_filename:
                         logger.warning(f"Failure occurred potentially around file: {current_filename}")
                         print(f"Failure occurred potentially around file: {current_filename}") # Also print for visibility

                # Raise the exception with the constructed, more informative message
                raise builtins.Exception(base_error_msg)

            # Still running or in an intermediate state
            # Only print if status changed or it's the first/last few attempts for less noise
            if current_status != last_status or i < 2 or i % 10 == 0: # Print if status changes, first 2 tries, or every 10th try
                 print() # Newline after potential dots
                 print(f"{process_description} status: {current_status}. Attempt {i+1}/{max_tries}.", end="", flush=True)
                 last_status = current_status
            elif progress_indicator:
                 print(".", end="", flush=True) # Print progress dot

            time.sleep(wait_interval)

        # If loop finishes, it's a timeout
        print() # Newline after potential dots
        # Include last known status in timeout message
        raise builtins.Exception(
            f"Timeout waiting for {process_description} to complete after {max_tries * wait_interval} seconds (Last Status: {last_status})."
        )

    def _read_in_chunks(self, file_object: io.BufferedReader, chunk_size: int = 8 * 1024 * 1024) -> Generator[bytes, None, None]:
        """Reads a file in chunks."""
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _chunked_upload_request(self, scan_code: str, headers: dict, chunk: bytes) -> None:
        """Sends a single chunk for upload."""
        try:
            # Use session for potential keep-alive
            response = self.session.post(
                self.api_url,
                headers=headers,
                data=chunk,
                auth=(self.api_user, self.api_token), # Auth needed for direct upload endpoint
                timeout=1800,
            )
            logger.debug(f"Chunk upload response status: {response.status_code}")
            logger.debug(f"Chunk upload response headers: {response.headers}")
            response.raise_for_status() # Check for HTTP errors

        except requests.exceptions.RequestException as e:
            error_msg = f"Network error during chunk upload: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise Exception(error_msg)

    def upload_files(self, scan_code: str, path: str, is_da_import: bool = False):
        """Uploads a file or directory (as zip) to a scan."""
        if not os.path.exists(path):
             # Raise exception instead of sys.exit
             raise FileNotFoundError(f"Path does not exist: {path}")

        archive_path = None
        upload_path = path
        original_basename = os.path.basename(path)

        try:
            if os.path.isdir(path):
                print(f"Compressing target directory '{path}'...")
                # Create the archive, append temp to the name.
                base_name = os.path.join(tempfile.gettempdir(), f"{original_basename}_temp")
                root_dir = os.path.dirname(path) or '.'
                base_dir = original_basename
                if not base_dir:
                    raise ValueError(f"Cannot archive directory '{path}'")
                archive_path = shutil.make_archive(base_name, 'zip', root_dir=root_dir, base_dir=base_dir)
                upload_path = archive_path
                print(f"Archive creation complete! Saved to {os.path.basename(archive_path)}")

            file_size = os.path.getsize(upload_path)
            size_limit = 16 * 1024 * 1024 # Increased limit slightly, adjust as needed
            upload_basename = os.path.basename(upload_path)

            name_b64 = base64.b64encode(upload_basename.encode()).decode("utf-8")
            scan_code_b64 = base64.b64encode(scan_code.encode()).decode("utf-8")

            headers = {
                "FOSSID-SCAN-CODE": scan_code_b64,
                "FOSSID-FILE-NAME": name_b64
            }

            if is_da_import:
                headers["FOSSID-UPLOAD-TYPE"] = "dependency_analysis"
                print(f"Uploading DA results file '{upload_basename}' ({file_size} bytes)...")
            else:
                 print(f"Uploading '{upload_basename}' ({file_size} bytes)...")

            logger.debug(f"Upload Request Headers: {headers}")

            with open(upload_path, "rb") as file:
                if file_size > size_limit:
                    print(f"File size exceeds limit ({size_limit} bytes). Using chunked upload...")
                    headers['Transfer-Encoding'] = 'chunked'
                    headers['Content-Type'] = 'application/octet-stream' # Required for chunked

                    for i, chunk in enumerate(self._read_in_chunks(file)):
                        logger.debug(f"Uploading chunk {i+1}...")
                        self._chunked_upload_request(scan_code, headers, chunk)
                    print("Chunked upload completed successfully.")
                else:
                    # Standard upload for smaller files
                    resp = self.session.post(
                        self.api_url,
                        headers=headers,
                        data=file,
                        auth=(self.api_user, self.api_token), # Auth needed for direct upload
                        timeout=1800,
                    )
                    logger.debug(f"Upload Response Status: {resp.status_code}")
                    logger.debug(f"Upload Response Text: {resp.text}")
                    resp.raise_for_status() # Check for HTTP errors
                    print(f"Upload for '{upload_basename}' completed.")

        except IOError as e:
            # Raise exception instead of sys.exit
            raise builtins.Exception(f"Error accessing file/directory for upload: {path}. Error: {e}") from e
        except requests.exceptions.RequestException as e:
            # Raise exception instead of sys.exit
            raise builtins.Exception(f"Failed to upload {upload_path} to scan {scan_code}. Error: {e}") from e
        except Exception as e:
            # Raise exception instead of sys.exit
            raise builtins.Exception(f"Unexpected error during file upload: {e}") from e
        finally:
            # Clean up temporary archive
            if archive_path and os.path.exists(archive_path):
                try:
                    os.remove(archive_path)
                    logger.info(f"Removed temporary archive: {archive_path}")
                except OSError as e:
                    logger.warning(f"Could not remove temporary archive {archive_path}: {e}")

    def get_scan_status(self, scan_type: str, scan_code: str) -> dict:
        """Retrieves the status of a scan operation (SCAN or DEPENDENCY_ANALYSIS)."""
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": scan_type.upper(), # Ensure type is uppercase
            },
        }
        response = self._send_request(payload)
        # _send_request handles basic API errors, check for expected data
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response format: {response}")
            raise builtins.Exception(
                f"Failed to retrieve {scan_type} status for scan '{scan_code}': {error_msg}"
            )

    def start_dependency_analysis(self, scan_code: str, import_only: bool = False):
        """Starts or imports dependency analysis for a scan."""
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
            # Error handled by _send_request, but add context
            raise builtins.Exception(
                f"Dependency Analysis for scan '{scan_code}' failed to start (see logs for details)."
            )

    def wait_for_archive_extraction(
        self,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int, # Note: scan_wait_time is passed but 5s is hardcoded below
    ):
        """Waits for the EXTRACT_ARCHIVES operation to complete."""
        process_description = f"Archive Extraction for scan '{scan_code}'"
        logger.info(f"Waiting for {process_description} to complete...")

        # Use _send_request directly as the check function
        # The status accessor needs to handle the full response structure
        self._wait_for_process(
            process_description=process_description,
            check_function=self._send_request,
            check_args={
                "payload": {
                    "group": "scans",
                    "action": "check_status",
                    "data": {
                        "scan_code": scan_code,
                        "type": "EXTRACT_ARCHIVES" # Use the specific type
                    }
                }
            },
            # Access status within the 'data' part of the response
            status_accessor=lambda response: response.get("data", {}).get("status", "UNKNOWN"),
            success_values={"FINISHED"},
            failure_values={"FAILED", "CANCELLED"}, # Add CANCELLED just in case
            max_tries=scan_number_of_tries,
            wait_interval=5, # Use a potentially shorter interval for extraction? 5s?
            progress_indicator=True
        )


    def wait_for_scan_to_finish(
        self,
        scan_type: str, # "SCAN" or "DEPENDENCY_ANALYSIS"
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ):
        """Waits for a SCAN or DEPENDENCY_ANALYSIS operation to complete using the generic waiter."""
        scan_type_upper = scan_type.upper()
        process_description = f"{scan_type_upper} operation for scan '{scan_code}'"

        # Define how to get status for SCAN/DA
        def status_accessor(data):
            status_val = data.get("status", "UNKNOWN") # Use hardcoded default
            is_finished_flag = data.get("is_finished")
            # Handle both boolean True and string "1" for is_finished
            is_finished = str(is_finished_flag).lower() == "true" or str(is_finished_flag) == "1"
            # Use hardcoded strings for comparison
            if is_finished and status_val not in ["FAILED", "CANCELLED"]:
                return "FINISHED" # Use hardcoded string
            return status_val

        self._wait_for_process(
            process_description=process_description,
            check_function=self.get_scan_status,
            check_args={"scan_type": scan_type_upper, "scan_code": scan_code},
            status_accessor=status_accessor,
            success_values={"FINISHED"}, # Use hardcoded string
            failure_values={"FAILED", "CANCELLED"}, # Use hardcoded strings
            max_tries=scan_number_of_tries,
            wait_interval=scan_wait_time,
            progress_indicator=True
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
        """Gets the count of policy warnings for a specific scan."""
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": { "scan_code": scan_code },
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            raise builtins.Exception(f"Error getting scan policy warnings counter for '{scan_code}' (see logs).")


    def get_policy_warnings_info(self, scan_code: str) -> Dict[str, Any]:
        """Retrieves detailed policy warnings information for a scan."""
        logger.debug(f"Fetching policy warnings info for scan '{scan_code}'...")
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_info",
            "data": {"scan_code": scan_code}
        }
        response = self._send_request(payload)

        if response.get("status") == "1" and "data" in response:
            # Ensure the expected key exists, return empty if not present but API succeeded
            # The API returns the list directly under the 'data' key based on post_scan_gates.py
            # Let's adjust to return the structure expected by the handler { "policy_warnings_list": [...] }
            data_content = response["data"]
            if isinstance(data_content, dict) and "policy_warnings_list" in data_content:
                 return data_content # Return the dict containing the list
            elif isinstance(data_content, list): # If API returns list directly under 'data'
                 logger.debug("API returned list directly under 'data' for policy warnings. Wrapping.")
                 return {"policy_warnings_list": data_content}
            else:
                 logger.warning(f"Policy warnings info API returned success but 'data' key has unexpected type: {type(data_content)}. Assuming no warnings.")
                 return {"policy_warnings_list": []}

        elif response.get("status") == "1": # Status 1 but no data key
             logger.warning(f"Policy warnings info API returned success but no 'data' key for scan '{scan_code}'. Assuming no warnings.")
             return {"policy_warnings_list": []} # Return structure expected by handler
        else:
            # Raise exception on API failure (status 0 or other errors)
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get policy warnings info for scan '{scan_code}': {error_msg}")
            raise builtins.Exception(f"API Error: Failed to get policy warnings info for scan '{scan_code}': {error_msg}")

    # --- Methods for fetching results ---
    def get_scan_identified_components(self, scan_code: str) -> List[Dict[str, Any]]:
        """Gets identified components from KB scanning."""
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
            raise builtins.Exception(f"Error retrieving identified components from scan '{scan_code}' (see logs).")

    def get_scan_identified_licenses(self, scan_code: str) -> List[Dict[str, Any]]:
        """Get the list of identified licenses for a scan."""
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
                return data # Return the list of licenses
            else:
                # Log unexpected data format but return empty list to avoid breaking caller
                logger.warning(f"API returned success for get_scan_identified_licenses but 'data' was not a list: {type(data)}")
                return []
        elif response.get("status") == "1": # Status 1 but no data key
             logger.warning("API returned success for get_scan_identified_licenses but no 'data' key found.")
             return []
        else:
            # If _send_request didn't raise an error but status is not 1, raise one now
            # This handles cases where the API might return status 0 for reasons other than non-fatal ones
            error_msg = response.get("error", f"Unexpected response format or status: {response}")
            logger.error(f"Failed to get identified licenses for scan '{scan_code}'. Response: {response}")
            raise builtins.Exception(f"Error getting identified licenses for scan '{scan_code}': {error_msg}")

    def get_dependency_analysis_results(self, scan_code: str) -> List[Dict[str, Any]]:
        """Gets dependency analysis results."""
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
            else:
                 raise builtins.Exception(f"Error getting dependency analysis results for scan '{scan_code}' (see logs).")


    def _assert_process_can_start(self, process_type: str, scan_code: str):
        """Checks if a SCAN or DEPENDENCY_ANALYSIS can be started."""
        try:
            scan_status = self.get_scan_status(process_type, scan_code)
            current_status = scan_status.get("status", "UNKNOWN").upper()
            # Allow starting if NEW, FINISHED, FAILED, or CANCELLED
            allowed_statuses = ["NEW", "FINISHED", "FAILED", "CANCELLED"]
            if current_status not in allowed_statuses:
                raise builtins.Exception(
                    f"Cannot start {process_type.lower()} for '{scan_code}'. Current status is {current_status} (Must be one of {allowed_statuses})."
                )
            print(f"The {process_type.capitalize()} for '{scan_code}' can start (Current status: {current_status}).")
        except Exception as e:
            # Re-raise with context
            raise builtins.Exception(f"Could not verify if {process_type.lower()} can start for '{scan_code}': {e}")

    def assert_scan_can_start(self, scan_code: str):
        """Checks if a KB scan can start."""
        self._assert_process_can_start("SCAN", scan_code)

    def assert_dependency_analysis_can_start(self, scan_code: str):
        """Checks if dependency analysis can start."""
        self._assert_process_can_start("DEPENDENCY_ANALYSIS", scan_code)

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ):
        """Triggers archive extraction for a scan."""
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
            raise builtins.Exception(f"Archive extraction failed for scan '{scan_code}' (see logs).")


    def list_projects(self) -> List[Dict[str, Any]]:
        """Retrieves a list of all projects."""
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
            raise builtins.Exception(f"Failed to list projects: {error_msg}")

    def list_scans(self) -> List[Dict[str, Any]]:
        """Retrieves a list of all scans."""
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
            raise builtins.Exception(f"Failed to list scans: {error_msg}")

    def get_project_scans(self, project_code: str) -> List[Dict[str, Any]]:
        """Retrieves a list of all scans within a specific project."""
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
                 raise builtins.Exception(f"Failed to list scans for project '{project_code}': {error_msg}")

    def create_project(self, project_name: str) -> str:
        """Creates a new project using project_name. Returns the assigned project_code."""
        logger.info(f"Attempting to create the '{project_name}' project...")
        payload = {
            "group": "projects",
            "action": "create",
            "data": {
                "project_name": project_name,
                "description": f"Project created by Workbench Agent.",
            },
        }
        try:
            response = self._send_request(payload)
            # API returns assigned code on success
            if response.get("status") == "1" and "data" in response and "project_code" in response["data"]:
                 assigned_code = response["data"]["project_code"]
                 print(f"Successfully created the '{project_name}' project with code '{assigned_code}'")
                 return assigned_code
            # Handle "already exists" - find the existing code by name
            elif response.get("status") == "0" and "Project code already exists" in response.get("error", ""):
                 logger.warning(f"Project creation failed (name/code clash for '{project_name}'). Finding existing.")
                 all_projects = self.list_projects()
                 found_project = next((p for p in all_projects if p.get('project_name') == project_name), None)
                 if found_project and 'project_code' in found_project:
                      print(f"Project '{project_name}' already exists with code '{found_project['project_code']}'.")
                      return found_project['project_code']
                 else:
                      raise builtins.Exception(f"Failed to create project '{project_name}' and could not find existing project by name after clash.")
            else:
                 error_msg = response.get("error", f"Unexpected response: {response}")
                 raise builtins.Exception(f"Failed to create project '{project_name}': {error_msg}")
        except Exception as e:
             # Catch errors from _send_request or logic above, retry finding on "exists" error
             if "Project code already exists" in str(e):
                 logger.warning(f"Project creation failed (name/code clash for '{project_name}'). Finding existing.")
                 all_projects = self.list_projects()
                 found_project = next((p for p in all_projects if p.get('project_name') == project_name), None)
                 if found_project and 'project_code' in found_project:
                      print(f"Project '{project_name}' already exists with code '{found_project['project_code']}'.")
                      return found_project['project_code']
                 else:
                      raise builtins.Exception(f"Failed to create project '{project_name}' and could not find existing project by name after error: {e}")
             else:
                 # Ensure other exceptions are re-raised clearly
                 raise builtins.Exception(f"Failed to create project '{project_name}': {e}") from e

    def create_webapp_scan(
            self,
            scan_name: str,
            project_code: str,
            git_url: Optional[str] = None,
            git_branch: Optional[str] = None,
            git_tag: Optional[str] = None,
            git_depth: Optional[int] = None
        ) -> bool: # Returns True on success trigger
        """Creates a new scan inside a project. Returns True if successful."""
        logger.info(f"Attempting to create the '{scan_name}' scan inside the '{project_code}' project...")
        payload_data = {
            "scan_name": scan_name,
            "project_code": project_code,
            "description": f"Scan created by Workbench Agent.",
        }

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

        if git_url:
            payload_data["git_repo_url"] = git_url
            logger.info(f"Including Git URL: {git_url}")
        if git_ref_value:
            # API uses 'git_branch' field for both branch and tag names
            payload_data["git_branch"] = git_ref_value
        if git_ref_type:
            payload_data["git_ref_type"] = git_ref_type
            logger.info(f"Setting Git Ref Type to: {git_ref_type}")
        if git_depth is not None:
            payload_data["git_depth"] = str(git_depth) # API expects string according to schema example
            logger.info(f"Setting Git Clone Depth to: {git_depth}")
            # Ensure ref type is set if depth is used (API requirement)
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
            # API returns scan_id, not scan_code
            if response.get("status") == "1" and "data" in response and "scan_id" in response["data"]:
                 scan_id = response["data"]["scan_id"]
                 print(f"Successfully created the '{scan_name}' scan (ID: {scan_id}).")
                 return True
            # Handle "already exists" - return False to signal it existed
            elif response.get("status") == "0" and \
               ("Scan code already exists" in response.get("error", "") or "Legacy.controller.scans.code_already_exists" in response.get("error", "")):
                 logger.warning(f"Scan creation skipped: Scan with name/code '{scan_name}' likely already exists in project '{project_code}'.")
                 return False # Signal that it already existed (or clashed)
            else:
                error_msg = response.get("error", f"Unexpected response: {response}")
                raise builtins.Exception(f"Failed to trigger creation for scan '{scan_name}': {error_msg}")
        except Exception as e:
             if "Scan code already exists" in str(e) or "Legacy.controller.scans.code_already_exists" in str(e):
                 logger.warning(f"Scan creation skipped: Scan with name/code '{scan_name}' likely already exists in project '{project_code}'.")
                 return False
             else:
                 logger.error(f"Unexpected error during scan creation trigger for '{scan_name}': {e}", exc_info=True)
                 raise builtins.Exception(f"Failed to trigger creation for scan '{scan_name}': {e}") from e

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
        id_reuse_type: Optional[str] = None, # This will receive the *translated* API value
        id_reuse_source: Optional[str] = None,
    ):
        """Starts a Signature / License Extractor scan with specified parameters."""
        self.assert_scan_can_start(scan_code)
        print(f"Starting KB scan for '{scan_code}' with specified parameters...")
        payload = {
            "group": "scans",
            "action": "run",
            "data": {
                "scan_code": scan_code,
                "limit": limit,
                "sensitivity": sensitivity,
                # API expects integer 0 or 1 for boolean flags
                "auto_identification_detect_declaration": int(autoid_file_licenses),
                "auto_identification_detect_copyright": int(autoid_file_copyrights),
                "auto_identification_resolve_pending_ids": int(autoid_pending_ids),
                "delta_only": int(delta_scan),
            },
        }
        if id_reuse:
            data = payload["data"]
            data["reuse_identification"] = "1" # API expects string "1"
            if id_reuse_type: # Use the translated value passed in
                 data["identification_reuse_type"] = id_reuse_type
                 # Check API-specific values here
                 if id_reuse_type in {"specific_project", "specific_scan"}:
                     if not id_reuse_source:
                          # This should be caught by argparse/caller, but double-check
                          raise ValueError(f"--id-reuse-source is required when --id-reuse-type is '{id_reuse_type}' (API value)")
                     data["specific_code"] = id_reuse_source
            else:
                 # Default reuse type is usually 'any' if not specified, but log a warning
                 print("Warning: --id-reuse is set, but --id-reuse-type is not specified. Workbench will reuse ANY identification.")

        response = self._send_request(payload)
        if response.get("status") == "1":
            print(f"KB Scan initiated for scan '{scan_code}'.")
            return response # Return the response which might contain job ID etc.
        else:
            raise builtins.Exception(f"Failed to start KB scan '{scan_code}' (see logs).")

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
    ) -> Union[int, requests.Response]: # Return type remains Union for scan scope
        """
        Triggers report generation for a scan or project.
        Project reports are always async. Scan reports can be sync or async.
        Returns process queue ID for async, or raw response for sync scan reports.
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValueError("Invalid scope provided to generate_report. Must be 'scan' or 'project'.")

        is_project_scope = (scope == "project")

        # --- Force Async for Project Scope ---
        if is_project_scope:
            use_async = True
            # Validate report type against allowed project types
            if report_type not in self.PROJECT_REPORT_TYPES:
                 # Raise error immediately if type not supported for project
                 raise ValueError(f"Report type '{report_type}' is not supported for project scope reports.")
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
            if not project_code: raise ValueError("project_code is required for project scope reports.")
        else: # scan scope
            group = "scans"
            action = "generate_report"
            code_key = "scan_code"
            code_value = scan_code
            entity_name = f"scan '{scan_code}'"
            if not scan_code: raise ValueError("scan_code is required for scan scope reports.")

        logger.info(f"Requesting generation of '{report_type}' report for {entity_name} (Async: {use_async})...")

        payload_data = {
            code_key: code_value,
            "report_type": report_type,
            "async": async_value,
            "include_vex": include_vex,
        }
        # Add optional parameters if provided
        if selection_type: payload_data["selection_type"] = selection_type
        if selection_view: payload_data["selection_view"] = selection_view
        if disclaimer: payload_data["disclaimer"] = disclaimer
        # Add project-specific options if needed (e.g., report_content_type for xlsx)
        # if is_project_scope and report_type == 'xlsx' and report_content_type:
        #     payload_data["report_content_type"] = report_content_type

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
                 raise builtins.Exception(f"Unexpected synchronous response received for project report '{report_type}'.")
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
            raise builtins.Exception(f"Failed to request report generation for {entity_name}: {error_msg}")

    def check_report_generation_status(
        self,
        scope: str, 
        process_id: int,
        scan_code: Optional[str] = None, # Keep for scan scope context if needed by API later
        project_code: Optional[str] = None # Keep for project scope context if needed by API later
    ) -> Dict[str, Any]:
        """Checks the status of an asynchronous report generation process."""
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValueError("Invalid scope provided to check_report_generation_status.")

        group = "projects" if scope == "project" else "scans"
        entity_name = f"project '{project_code}'" if scope == "project" else f"scan '{scan_code}'"
        logger.debug(f"Checking report generation status for process {process_id} ({scope} scope)...")

        payload = {
            "group": group,
            "action": "check_status",
            "data": {
                # API schema only shows process_id and type needed
                "process_id": str(process_id),
                "type": "REPORT_GENERATION",
                # Add scan_code/project_code if API requires them for context, e.g.:
                # **({ "scan_code": scan_code } if scope == "scan" else {}),
                # **({ "project_code": project_code } if scope == "project" else {}),
            }
        }
        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise builtins.Exception(f"Failed to check report status for process {process_id} ({entity_name}): {error_msg}")


    def download_report(self, scope: str, process_id: int): # Corrected signature
        """
        Downloads a generated report using its process ID.
        Returns the requests.Response object containing the report content.
        """
        scope = scope.lower()
        if scope not in ["scan", "project"]:
            raise ValueError("Invalid scope provided to download_report.")

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
                    raise builtins.Exception(f"Failed to download report (process ID {process_id}): API returned error - {error_msg}")
                except json.JSONDecodeError as json_err:
                    logger.error(f"Failed to decode JSON error response during download: {r.text[:500]}", exc_info=True)
                    raise builtins.Exception(f"Failed to download report (process ID {process_id}): Could not parse API error response.")

            # If we reach here, it's likely the actual report content. Return the response object.
            logger.debug("Download request successful, returning response object.")
            return r # Return the response object

        except requests.exceptions.RequestException as req_err:
            logger.error(f"Failed to initiate report download request for process {process_id}: {req_err}", exc_info=True)
            raise builtins.Exception(f"Failed to download report (process ID {process_id}): {req_err}")
        except Exception as final_dl_err:
             logger.error(f"Unexpected error within download_report function for process {process_id}: {final_dl_err}", exc_info=True)
             raise

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

    def generate_links(self, base_url: str, scan_id: int) -> Dict[str, str]:
        """Generate links for scan results."""
        # Ensure base_url doesn't end with /api.php or trailing slash for link building
        base_url_cleaned = re.sub(r'/api\.php$', '', base_url).rstrip('/')
        return {
            "pending_link": (
                f"{base_url_cleaned}/index.html?form=main_interface&action=scanview&sid={scan_id}"
                f"&current_view=pending_items"
            ),
            "policy_link": (
                f"{base_url_cleaned}/index.html?form=main_interface&action=scanview&sid={scan_id}"
                f"&current_view=mark_as_identified"
            ),
            "main_scan_link": (
                f"{base_url_cleaned}/index.html?form=main_interface&action=scanview&sid={scan_id}"
            ),
    }

    def set_env_variable(self, name: str, value: str):
        """Sets an environment variable."""
        try:
            os.environ[name] = value
            logger.info(f"Setting the environment variable '{name}'.")
            print(f"Setting environment variable: {name}={value}") # Also print for visibility
        except Exception as e:
            logger.error(f"Failed to set environment variable '{name}': {e}")
            print(f"Warning: Failed to set environment variable '{name}': {e}")

