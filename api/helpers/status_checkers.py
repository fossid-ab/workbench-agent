import logging
import requests
from typing import Callable, Dict, Any, List
from .exceptions import ApiError, ProcessError, NetworkError, ValidationError, ProcessTimeoutError

logger = logging.getLogger("workbench-agent")


class StatusCheckers:
    """
    Mixin class that provides status checking functionality for various operations.
    This class should be mixed into APIBase to provide status checking capabilities.
    """

    def _is_status_check_supported(self, scan_code: str, process_type: str) -> bool:
        """
        Checks if the Workbench instance supports check_status for a given process type
        by probing the API and analyzing the response, including specific error codes.

        Args:
            scan_code: The code of the scan to check against
            process_type: The process type string (e.g., "EXTRACT_ARCHIVES")

        Returns:
            True if the check_status call for the type seems supported, False otherwise

        Raises:
            ApiError: If the check_status call fails for reasons other than a recognized unsupported type error
            NetworkError: If there are network connectivity issues
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
            # Short timeout is sufficient for the probe
            response = self._send_request(payload, timeout=30)

            # If status is "1", the API understood the request type
            if response.get("status") == "1":
                logger.debug(f"check_status for type '{process_type}' appears to be supported (API status 1).")
                return True

            # Check for specific 'invalid type' error structure
            elif response.get("status") == "0":
                error_code = response.get("error")
                data_list = response.get("data")

                # Check for the specific error structure indicating an invalid 'type' option
                if (error_code == "RequestData.Base.issues_while_parsing_request" and
                    isinstance(data_list, list) and len(data_list) > 0 and
                    isinstance(data_list[0], dict) and
                    data_list[0].get("code") == "RequestData.Base.field_not_valid_option" and
                    data_list[0].get("message_parameters", {}).get("fieldname") == "type"):

                    logger.warning(f"This version of Workbench does not support check_status for '{process_type}'.")

                    # Optionally log the valid types listed by the API
                    valid_options = data_list[0].get("message_parameters", {}).get("options")
                    if valid_options:
                        logger.debug(f"API reported valid types are: [{valid_options}]")
                    return False
                else:
                    # It's a different status 0 error (e.g., scan not found), raise it
                    logger.error(f"API error during {process_type} support check (but not an invalid type error): {error_code} - {response.get('message')}")
                    raise ApiError(f"API error during {process_type} support check: {error_code} - {response.get('message', 'No details')}", details=response)

            else:
                # Unexpected response format (neither status 1 nor 0)
                logger.warning(f"Unexpected response format during {process_type} support check: {response}")
                # Assume not supported to be safe
                return False

        except requests.exceptions.RequestException as e:
            # Check for type validation errors in the exception message
            error_msg_lower = str(e).lower()
            if "requestdata.base.field_not_valid_option" in error_msg_lower and "type" in error_msg_lower:
                logger.warning(
                    f"Workbench likely does not support check_status for type '{process_type}'. "
                    f"Skipping status check. (Detected via exception: {e})"
                )
                return False
            else:
                # Different error (network, scan not found, etc.), re-raise it
                logger.error(f"Unexpected exception during {process_type} support check: {e}", exc_info=False)
                if isinstance(e, NetworkError):
                    raise
                raise ApiError(f"Unexpected error during {process_type} support check", details={"error": str(e)}) from e

    def assert_scan_can_start(self, scan_code: str):
        """
        Verify if a new scan can be initiated.

        Args:
            scan_code: The unique identifier for the scan

        Raises:
            ProcessError: If a scan cannot be started due to existing operations
            ApiError: If there are API issues during status checking
        """
        logger.debug(f"Checking if scan '{scan_code}' can start...")
        
        try:
            status_data = self.check_status("SCAN", scan_code)
            status = status_data.get("status", "UNKNOWN").upper()
            
            # List of possible scan statuses taken from Workbench code:
            # NEW, QUEUED, STARTING, RUNNING, FINISHED, FAILED
            if status not in ["NEW", "FINISHED", "FAILED"]:
                raise ProcessError(
                    f"Cannot start scan '{scan_code}': scan is currently {status}. "
                    f"Please wait for the current scan to complete or cancel it."
                )
            
            logger.debug(f"Scan '{scan_code}' can start (status: {status})")
                
        except ProcessError:
            raise
        except Exception as e:
            # If we can't get scan status, assume it's safe to start
            logger.debug(f"Could not check scan status for '{scan_code}': {e}. Assuming scan can start.")

    def assert_dependency_analysis_can_start(self, scan_code: str):
        """
        Verify if a new dependency analysis scan can be initiated.

        Args:
            scan_code: The unique identifier for the scan

        Raises:
            ProcessError: If dependency analysis cannot be started due to existing operations
            ApiError: If there are API issues during status checking
        """
        logger.debug(f"Checking if dependency analysis for scan '{scan_code}' can start...")
        
        try:
            status_data = self.check_status("DEPENDENCY_ANALYSIS", scan_code)
            status = status_data.get("status", "UNKNOWN").upper()
            
            # List of possible scan statuses taken from Workbench code:
            # NEW, QUEUED, STARTING, RUNNING, FINISHED, FAILED
            if status not in ["NEW", "FINISHED", "FAILED"]:
                raise ProcessError(
                    f"Cannot start dependency analysis for scan '{scan_code}': "
                    f"dependency analysis is currently {status}. "
                    f"Please wait for the current analysis to complete or cancel it."
                )
            
            logger.debug(f"Dependency analysis for scan '{scan_code}' can start (status: {status})")
                
        except ProcessError:
            raise
        except Exception as e:
            # If we can't get dependency analysis status, assume it's safe to start
            logger.debug(f"Could not check dependency analysis status for '{scan_code}': {e}. Assuming analysis can start.")

    def get_scan_status(self, scan_type: str, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves the status of a scan operation (SCAN or DEPENDENCY_ANALYSIS).
        
        This is a public helper method that provides access to status checking with proper error handling.

        Args:
            scan_type: Type of scan operation (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check

        Returns:
            dict: The scan status data

        Raises:
            ApiError: If there are API issues
            ValidationError: If scan_type is not supported
        """
        valid_scan_types = ["SCAN", "DEPENDENCY_ANALYSIS"]
        if scan_type.upper() not in valid_scan_types:
            raise ValidationError(f"Invalid scan type '{scan_type}'. Must be one of: {valid_scan_types}")
            
        return self.check_status(scan_type.upper(), scan_code)

    def _standard_status_accessor(self, data: Dict[str, Any]) -> str:
        """
        Standard status accessor for extracting status from API responses.
        Works with responses from SCAN, DEPENDENCY_ANALYSIS and other operations.
        
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
            return "ACCESS_ERROR"  # Use the ACCESS_ERROR state
    
    def ensure_scan_is_idle(
        self, 
        scan_code: str, 
        params, 
        operation_types: List[str],
        check_interval: int = 5
    ):
        """
        Ensure a scan is in an idle state before starting a new operation.
        If any operation is running, waits for it to complete.
        
        This is a status verification method that checks multiple operation types
        and ensures they are all idle before proceeding.
        
        Args:
            scan_code: The scan code to check
            params: Parameters object with scan_number_of_tries and scan_wait_time
            operation_types: List of operation types to check (e.g., ["SCAN", "DEPENDENCY_ANALYSIS"])
            check_interval: Time to wait between checks in seconds
        
        Raises:
            ProcessTimeoutError: If scan doesn't become idle within the specified time
            ProcessError: If there are process-related issues
            ApiError: If there are API issues during status checking
        """
        logger.debug(f"Ensuring scan '{scan_code}' is idle for operations: {operation_types}")
        
        while True:
            all_processes_idle_this_pass = True
            logger.debug("Starting a new pass to check idle status...")
            
            for operation_type in operation_types:
                operation_type_upper = operation_type.upper()
                logger.debug(f"Checking status for process type: {operation_type_upper}")
                current_status = "UNKNOWN"
                
                try:
                    if operation_type_upper in ["SCAN", "DEPENDENCY_ANALYSIS"]:
                        status_data = self.check_status(operation_type_upper, scan_code)
                        current_status = self._standard_status_accessor(status_data)
                    else:
                        logger.warning(f"Unknown process type '{operation_type_upper}' requested for idle check. Skipping.")
                        continue
                        
                    logger.debug(f"Current status for {operation_type_upper}: {current_status}")
                    
                except Exception as e:
                    logger.debug(f"Could not check {operation_type_upper} status for scan '{scan_code}': {e}. Assuming idle.")
                    print(f"  - {operation_type_upper}: Not found (considered idle).")
                    continue

                if current_status in ["RUNNING", "QUEUED", "PENDING"]:
                    all_processes_idle_this_pass = False
                    print(f"  - {operation_type_upper}: Status is {current_status}. Waiting for completion...")
                    try:
                        self.wait_for_scan_to_finish(operation_type_upper, scan_code, params.scan_number_of_tries, params.scan_wait_time)
                        print(f"  - {operation_type_upper}: Previous run finished.")
                        logger.debug(f"Breaking inner loop after waiting for {operation_type_upper} to re-check all statuses.")
                        break
                    except (ProcessTimeoutError, ProcessError) as wait_err:
                        raise ProcessError(f"Cannot proceed: Waiting for existing {operation_type_upper} failed: {wait_err}") from wait_err
                    except Exception as wait_exc:
                        raise ProcessError(f"Cannot proceed: Unexpected error waiting for {operation_type_upper}: {wait_exc}") from wait_exc
                else:
                    print(f"  - {operation_type_upper}: Status is {current_status} (considered idle).")
            
            if all_processes_idle_this_pass:
                logger.debug("All processes confirmed idle in this pass. Exiting check loop.")
                break
                
        print("All Scan processes confirmed idle! Proceeding...") 