import logging
from typing import Dict, Any, List, TYPE_CHECKING

from ...exceptions import (
    ApiError,
    NetworkError,
    CompatibilityError,
    ProcessError,
    ProcessTimeoutError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")

class StatusCheckers:
    """
    Mixin class for checking process statuses.
    This class should be mixed into APIBase to provide status checking capabilities.
    """
    
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

                    logger.warning(f"This version of Workbench does not support check_status for '{process_type}'. ")

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

        except Exception as e:
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

    def _standard_scan_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Standard status accessor for extracting status from API responses.
        Works with responses from SCAN, DEPENDENCY_ANALYSIS, EXTRACT_ARCHIVES and other operations.
        
        This method handles various status formats and normalizes them:
        1. Checks if 'is_finished' flag indicates completion (returns "FINISHED")
        2. Falls back to the 'status' field if present
        3. Returns "UNKNOWN" if neither is available
        4. Handles errors gracefully by returning "ACCESS_ERROR"
        
        Args:
            data: Response data dictionary from an API call
            
        Returns:
            str: Normalized uppercase status string ("FINISHED", "RUNNING", "QUEUED", "FAILED", etc.)
        """
        try:
            # Some API endpoints use is_finished=1/true to indicate completion
            is_finished_flag = data.get("is_finished")
            is_finished = str(is_finished_flag) == "1" or is_finished_flag is True

            # If finished, return "FINISHED" (using the hardcoded success value)
            if is_finished:
                return "FINISHED"

            # Otherwise, return the value of the 'status' key (or UNKNOWN)
            # Make sure it's uppercase for consistent comparison
            status = data.get("status", "UNKNOWN")
            if status:
                return status.upper()
            return "UNKNOWN"
        except (ValueError, TypeError, AttributeError) as e:
            logger.warning(f"Error accessing status keys in data: {data}", exc_info=True)
            return "ACCESS_ERROR" # Use the ACCESS_ERROR state

    def check_status(self, scan_type: str, scan_code: str) -> Dict[str, Any]:
        """
        Calls API scans -> check_status to determine if the process is finished.

        Args:
            scan_type: One of these: SCAN, DEPENDENCY_ANALYSIS
            scan_code: The unique identifier for the scan

        Returns:
            dict: The data section from the JSON response returned from API

        Raises:
            ApiError: If the API call fails
            ScanNotFoundError: If the scan doesn't exist
        """
        logger.debug(f"Checking status for {scan_type} on scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": scan_type,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to check status for {scan_type} on scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_status(self, scan_type: str, scan_code: str) -> dict:
        """
        Retrieve scan status.
        
        Args:
            scan_type: Type of scan operation (SCAN, DEPENDENCY_ANALYSIS, or EXTRACT_ARCHIVES)
            scan_code: Code of the scan to check
            
        Returns:
            dict: The scan status data
            
        Raises:
            ApiError: If there are API issues
            ScanNotFoundError: If the scan doesn't exist
            NetworkError: If there are network issues
        """
        return self.check_status(scan_type, scan_code)
    
    def ensure_scan_is_idle(
        self,
        scan_code: str,
        process_types_to_check: List[str],
        scan_number_of_tries: int = 10,
        scan_wait_time: int = 30
    ):
        """
        Ensures specified background processes for a scan are idle (not RUNNING or QUEUED).
        If a process is running/queued, waits for it to finish before proceeding.
        
        This method can handle multiple process types at once and supports various process types 
        including SCAN, DEPENDENCY_ANALYSIS, GIT_CLONE, EXTRACT_ARCHIVES, and REPORT_IMPORT.
        
        Args:
            scan_code: Code of the scan to check
            process_types_to_check: List of process types to check (e.g., ["SCAN", "DEPENDENCY_ANALYSIS"])
            scan_number_of_tries: Maximum number of attempts for waiting
            scan_wait_time: Time to wait between attempts
        
        Raises:
            ProcessError: If there are process-related issues
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Asserting idle status for processes {process_types_to_check} on scan '{scan_code}'...")
        while True:
            all_processes_idle_this_pass = True
            logger.debug("Starting a new pass to check idle status...")
            for process_type in process_types_to_check:
                process_type_upper = process_type.upper()
                logger.debug(f"Checking status for process type: {process_type_upper}")
                current_status = "UNKNOWN"
                try:
                    if process_type_upper in ["SCAN", "DEPENDENCY_ANALYSIS", "REPORT_IMPORT"]:
                        status_data = self.get_scan_status(process_type_upper, scan_code)
                        current_status = status_data.get("status", "UNKNOWN").upper()
                    elif process_type_upper == "EXTRACT_ARCHIVES":
                        # EXTRACT_ARCHIVES status checking is handled differently
                        # Check if status checking is supported for this process type
                        if self._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
                            # Use the specialized method for checking archive extraction status
                            try:
                                status_data = self.get_scan_status("EXTRACT_ARCHIVES", scan_code)
                                current_status = self._standard_scan_status_accessor(status_data)
                            except (ApiError, ScanNotFoundError) as e:
                                logger.debug(f"Could not check EXTRACT_ARCHIVES status, assuming finished: {e}")
                                current_status = "FINISHED"
                        else:
                            logger.debug(f"EXTRACT_ARCHIVES status checking not supported. Assuming idle.")
                            current_status = "FINISHED"
                    else:
                        logger.warning(f"Unknown process type '{process_type_upper}' requested for idle check. Skipping.")
                        continue
                    logger.debug(f"Current status for {process_type_upper}: {current_status}")
                except ScanNotFoundError:
                    logger.debug(f"Scan '{scan_code}' not found during idle check for {process_type_upper}. Assuming idle.")
                    print(f"  - {process_type_upper}: Not found (considered idle).")
                    continue
                except (ApiError, NetworkError) as e:
                    raise ProcessError(f"Cannot proceed: Failed to check status for {process_type_upper} due to API/Network error: {e}") from e
                except Exception as e:
                    raise ProcessError(f"Cannot proceed: Unexpected error checking status for {process_type_upper}: {e}") from e

                if current_status in ["RUNNING", "QUEUED", "NOT FINISHED"]:
                    all_processes_idle_this_pass = False
                    print(f"  - {process_type_upper}: Status is {current_status}. Waiting for completion...")
                    try:
                        # Use the mixin methods directly since we're now a mixin
                        if process_type_upper == "EXTRACT_ARCHIVES":
                            # Use the specialized wait method with 3-second intervals for archive extraction
                            _, _ = self.wait_for_archive_extraction(scan_code, scan_number_of_tries, scan_wait_time)
                        else:
                            _, _ = self.wait_for_scan_to_finish(process_type_upper, scan_code, scan_number_of_tries, scan_wait_time)
                        print(f"  - {process_type_upper}: Previous run finished.")
                        logger.debug(f"Breaking inner loop after waiting for {process_type_upper} to re-check all statuses.")
                        break
                    except (ProcessTimeoutError, ProcessError) as wait_err:
                        raise ProcessError(f"Cannot proceed: Waiting for existing {process_type_upper} failed: {wait_err}") from wait_err
                    except Exception as wait_exc:
                        raise ProcessError(f"Cannot proceed: Unexpected error waiting for {process_type_upper}: {wait_exc}") from wait_exc
                else:
                    print(f"  - {process_type_upper}: Status is {current_status} (considered idle).")
            
            if all_processes_idle_this_pass:
                logger.debug("All processes confirmed idle in this pass. Exiting check loop.")
                break
        print("All Scan processes confirmed idle! Proceeding...")
