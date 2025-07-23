import logging
import requests
from typing import Callable, Dict, Any, List
from .exceptions import ApiError, ProcessError, NetworkError, ValidationError

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
            status_data = self._get_scan_status("SCAN", scan_code)
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
            status_data = self._get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
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
        
        This is a public method that provides access to status checking with proper error handling.

        Args:
            scan_type: Type of scan operation (SCAN or DEPENDENCY_ANALYSIS)
            scan_code: Code of the scan to check

        Returns:
            dict: The scan status data

        Raises:
            ApiError: If there are API issues
            ValidationError: If scan_type is not supported
        """
        valid_scan_types = ["SCAN", "DEPENDENCY_ANALYSIS", "REPORT_GENERATION", "DELETE_SCAN", "REPORT_IMPORT"]
        if scan_type.upper() not in valid_scan_types:
            raise ValidationError(f"Invalid scan type '{scan_type}'. Must be one of: {valid_scan_types}")
            
        return self._get_scan_status(scan_type.upper(), scan_code) 