import time
import logging
from typing import Callable, List, Dict, Any, Tuple
from ...exceptions import ProcessTimeoutError, ApiError, ProcessError

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
        progress_indicator: bool = True,
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
        last_state = ""
        last_step = ""
        start_time = time.time()
        client_start_time = time.time()
        status_data = None
        api_start_time = None

        for i in range(max_tries):
            current_status = "UNKNOWN"

            try:
                status_data = check_function(**check_args)
                try:
                    current_status_raw = status_accessor(status_data)
                    current_status = str(current_status_raw).upper()
                except Exception as access_err:
                    logger.warning(
                        f"Error executing status_accessor during {process_description} check: {access_err}. Response data: {status_data}",
                        exc_info=True,
                    )
                    current_status = "ACCESS_ERROR"  # Treat as failure

            except Exception as e:
                print()
                print(
                    f"Attempt {i+1}/{max_tries}: Error checking status for {process_description}: {e}"
                )
                print(f"Retrying in {wait_interval} seconds...")
                logger.warning(
                    f"Error calling check_function for {process_description}", exc_info=False
                )
                time.sleep(wait_interval)
                continue

            # Check for Success
            if current_status in success_values:
                print()
                
                # Calculate duration using API timestamps if available
                duration_str = ""
                api_finish_time = status_data.get("finished") if isinstance(status_data, dict) else None
                api_duration_sec = None
                
                if api_start_time and api_finish_time:
                    try:
                        # Parse timestamps and calculate duration
                        from datetime import datetime
                        start_dt = datetime.strptime(api_start_time, "%Y-%m-%d %H:%M:%S")
                        finish_dt = datetime.strptime(api_finish_time, "%Y-%m-%d %H:%M:%S")
                        api_duration_sec = (finish_dt - start_dt).total_seconds()
                        
                        # Format duration as a string
                        minutes, seconds = divmod(api_duration_sec, 60)
                        hours, minutes = divmod(minutes, 60)
                        if hours > 0:
                            duration_str = f" (Completed in {int(hours)}h {int(minutes)}m {int(seconds)}s)"
                        elif minutes > 0:
                            duration_str = f" (Completed in {int(minutes)}m {int(seconds)}s)"
                        else:
                            duration_str = f" (Completed in {int(seconds)}s)"
                    except Exception as e:
                        logger.debug(f"Error calculating duration: {e}")
                
                # Calculate client-side duration as fallback
                client_duration = time.time() - client_start_time
                
                # Prefer API-reported duration if available, otherwise use client-side duration
                final_duration = api_duration_sec if api_duration_sec is not None else client_duration
                
                logger.debug(
                    f"{process_description} completed successfully (Status: {current_status})."
                )
                print(f"{process_description} completed successfully{duration_str}.")
                
                if status_data:
                    status_data["_duration_seconds"] = final_duration
                return status_data or {}, final_duration

            # Check for Failure (includes ACCESS_ERROR)
            if current_status in failure_values or current_status == "ACCESS_ERROR":
                print()  # Newline after dots/status
                base_error_msg = f"The {process_description} {current_status}"
                error_detail = ""
                if isinstance(status_data, dict):
                    error_detail = status_data.get(
                        "error", status_data.get("message", status_data.get("info", ""))
                    )
                if error_detail:
                    base_error_msg += f". Detail: {error_detail}"
                raise ProcessError(base_error_msg, details=status_data)

            # Extract additional status information for enhanced progress reporting
            current_state = ""
            current_step = ""
            progress_info = ""
            
            if isinstance(status_data, dict):
                current_state = status_data.get("state", "")
                current_step = status_data.get("current_step", "")
                
                # Get operation start time from API if available and not already set
                if not api_start_time:
                    api_start_time = status_data.get("started")
                
                # Extract file processing information if available
                total_files = status_data.get("total_files", 0)
                current_file_idx = status_data.get("current_file", 0)
                percentage = status_data.get("percentage_done", "")
                current_filename = status_data.get("current_filename", "")
                
                # Create progress info if available
                if total_files and int(total_files) > 0:
                    progress_info = f" - File {current_file_idx}/{total_files}"
                    if percentage:
                        progress_info += f" ({percentage})"
                elif percentage:
                    progress_info = f" - {percentage}"
                
                # Add current filename if available and not too long
                if current_filename and len(current_filename) < 50:
                    progress_info += f" - {current_filename}"

            # Enhanced Status Printing with more context
            details_changed = (
                current_status != last_status or 
                current_state != last_state or 
                current_step != last_step
            )
            
            # Print a new line on first status check
            if i == 0:
                details_changed = True
                
            # Print a new line every 10 status checks to update the user
            show_periodic_update = i > 0 and i % 10 == 0 and current_status == "RUNNING"
            
            if details_changed or show_periodic_update:
                print()
                
                # Construct a detailed status message
                status_msg = f"{process_description} status: {current_status}"
                if current_state:
                    status_msg += f" ({current_state})"
                
                # Include progress information
                if progress_info:
                    status_msg += progress_info
                
                # Show current step
                if current_step:
                    status_msg += f" - Step: {current_step}"
                    
                print(f"{status_msg}. Attempt {i+1}/{max_tries}", end="", flush=True)
                
                # Update last values
                last_status = current_status
                last_state = current_state
                last_step = current_step
            elif progress_indicator:
                print(".", end="", flush=True)

            time.sleep(wait_interval)

        print()
        duration = time.time() - start_time
        raise ProcessTimeoutError(
            f"Timeout waiting for {process_description} to complete after {max_tries * wait_interval} seconds (Last Status: {last_status}).",
            details={
                "last_status": last_status,
                "max_tries": max_tries,
                "wait_interval": wait_interval,
                "last_data": status_data,
                "duration": duration,
            },
        )

    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Wait for a scan to complete using the enhanced implementation with detailed progress reporting.

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

        logger.debug(f"Waiting for {scan_type} operation to complete for scan '{scan_code}'...")

        return self._wait_for_process(
            process_description=operation_name,
            check_function=self.check_status,
            check_args={"scan_type": scan_type, "scan_code": scan_code},
            status_accessor=self._standard_status_accessor,
            success_values={"FINISHED"},
            failure_values={"FAILED", "CANCELLED", "ERROR"},
            max_tries=scan_number_of_tries,
            wait_interval=scan_wait_time,
            progress_indicator=True,
        )
