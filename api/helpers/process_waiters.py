import time
import logging
from typing import Callable, List, Dict, Any, Tuple
from .exceptions import ProcessTimeoutError, ApiError, ProcessError

logger = logging.getLogger("workbench-agent")


class ProcessWaiters:
    """
    Mixin class that provides waiting functionality for various processes.
    This class should be mixed into APIBase to provide waiting capabilities.
    """

    def _wait_for_process(
        self,
        process_description: str,
        check_function: Callable,
        check_args: Dict[str, Any],
        status_accessor: Callable,
        success_values: set,
        failure_values: set,
        max_tries: int,
        wait_interval: int,
        progress_indicator: bool = True
    ) -> Tuple[Dict[str, Any], float]:
        """
        Generic process status checking and waiting function.
        Repeatedly calls check_function until success, failure, or timeout.
        
        Args:
            process_description: Human-readable description of the process being waited for
            check_function: Function to call to check status
            check_args: Arguments to pass to check_function
            status_accessor: Function to extract status from check_function's result
            success_values: Set of status values indicating success
            failure_values: Set of status values indicating failure
            max_tries: Maximum number of status checks before timeout
            wait_interval: Seconds to wait between status checks
            progress_indicator: Whether to print progress indicators (dots)
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing final status data and duration in seconds
            
        Raises:
            ProcessTimeoutError: If max_tries is reached before success/failure
            ProcessError: If status is in failure_values
        """
        logger.debug(f"Waiting for {process_description}...")
        last_status = "UNKNOWN"
        start_time = time.time()
        status_data = None

        for i in range(max_tries):
            current_status = "UNKNOWN"

            try:
                status_data = check_function(**check_args)
                try:
                    current_status_raw = status_accessor(status_data)
                    current_status = str(current_status_raw).upper()
                except Exception as access_err:
                    logger.warning(f"Error executing status_accessor during {process_description} check: {access_err}. Response data: {status_data}", exc_info=True)
                    current_status = "ACCESS_ERROR"  # Treat as failure

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
                duration = time.time() - start_time
                logger.debug(f"{process_description} completed successfully (Status: {current_status}).")
                if status_data:
                    status_data["_duration_seconds"] = duration
                return status_data or {}, duration

            # Check for Failure (includes ACCESS_ERROR)
            if current_status in failure_values or current_status == "ACCESS_ERROR":
                print()  # Newline after dots/status
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
        duration = time.time() - start_time
        raise ProcessTimeoutError(
            f"Timeout waiting for {process_description} to complete after {max_tries * wait_interval} seconds (Last Status: {last_status}).",
            details={"last_status": last_status, "max_tries": max_tries, "wait_interval": wait_interval, "last_data": status_data, "duration": duration}
        )

    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Wait for a scan to complete using the consolidated implementation.
        
        Args:
            scan_type: Types: SCAN, DEPENDENCY_ANALYSIS
            scan_code: Unique scan identifier
            scan_number_of_tries: Number of calls to "check_status" till declaring the scan failed
            scan_wait_time: Time interval between calling "check_status", expressed in seconds

        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing final status data and duration in seconds

        Raises:
            ProcessTimeoutError: If scan doesn't finish within the specified time
            ProcessError: If the scan fails
            ApiError: If there are API issues during status checking
        """
        if scan_type == "SCAN":
            operation_name = "KB Scan"
        elif scan_type == "DEPENDENCY_ANALYSIS":
            operation_name = "Dependency Analysis"
        else:
            operation_name = scan_type

        return self._wait_for_process(
            process_description=operation_name,
            check_function=self.check_status,
            check_args={"scan_type": scan_type, "scan_code": scan_code},
            status_accessor=self._standard_status_accessor,
            success_values={"FINISHED"},
            failure_values={"FAILED", "CANCELLED", "ERROR"},
            max_tries=scan_number_of_tries,
            wait_interval=scan_wait_time,
            progress_indicator=True
        )

 