import logging
import time
from typing import Dict, Any, Tuple, Callable, TYPE_CHECKING

from ...exceptions import (
    ProcessTimeoutError,
    ProcessError,
    ApiError,
    NetworkError,
    ScanNotFoundError,
)

logger = logging.getLogger("workbench-agent")

class ProcessWaiters:
    """
    Mixin class for waiting on long-running processes.
    This class should be mixed into APIBase to provide waiting capabilities.
    """
    
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
    ):
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
            True if the process succeeded (status in success_values)
            
        Raises:
            ProcessTimeoutError: If max_tries is reached before success/failure
            ProcessError: If status is in failure_values
        """
        logger.debug(f"Waiting for {process_description}...")
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
                logger.debug(f"{process_description} completed successfully (Status: {current_status}).")
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
        
    def wait_for_archive_extraction(
        self,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Wait for archive extraction to complete.
        
        Args:
            scan_code: The code of the scan to check
            scan_number_of_tries: Maximum number of attempts
            scan_wait_time: Time to wait between attempts (ignored, fixed at 3 seconds)
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Waiting for archive extraction to complete for scan '{scan_code}'...")
        
        # Use fixed 3-second wait interval for archive extraction
        archive_wait_interval = 3
        
        last_status = "UNKNOWN"
        last_state = ""
        last_step = ""
        client_start_time = time.time()  # Start tracking client-side duration
        status_data = {}
        
        for i in range(scan_number_of_tries):
            try:
                # Get current status from API using the mixin method
                status_data = self.get_scan_status("EXTRACT_ARCHIVES", scan_code)
                
                # Extract key information
                is_finished = str(status_data.get("is_finished", "0")) == "1" or status_data.get("is_finished") is True
                current_status = status_data.get("status", "UNKNOWN").upper()
                current_state = status_data.get("state", "")
                percentage = status_data.get("percentage_done", "")
                current_step = status_data.get("current_step", "")
                current_file = status_data.get("current_filename", "")
                info = status_data.get("info", "")
                
                # If finished flag is set, use FINISHED status
                if is_finished:
                    current_status = "FINISHED"
                
                # Only print a new line when status, state, or step changes
                details_changed = (
                    current_status != last_status or 
                    current_state != last_state or 
                    current_step != last_step
                )
                
                # Print a new line on first status check
                if i == 0:
                    details_changed = True
                
                # Check for success (finished)
                if current_status == "FINISHED":
                    print("\nArchive Extraction completed successfully.")
                    logger.debug(f"Archive extraction for scan '{scan_code}' completed successfully")
                    # Calculate duration
                    duration = time.time() - client_start_time
                    # Add duration to status_data for reference
                    status_data["_duration_seconds"] = duration
                    return status_data, duration
                
                # Check for failure
                if current_status in ["FAILED", "CANCELLED"]:
                    error_msg = f"Archive Extraction {current_status}"
                    if info:
                        error_msg += f" - Detail: {info}"
                    print(f"\n{error_msg}")
                    logger.error(f"Archive extraction for scan '{scan_code}' failed: {error_msg}")
                    raise ProcessError(error_msg, details=status_data)
                
                # Progress reporting
                if details_changed:
                    print()
                    
                    # Construct a detailed status message
                    status_msg = f"Archive Extraction status: {current_status}"
                    if current_state:
                        status_msg += f" ({current_state})"
                    if percentage:
                        status_msg += f" - {percentage}"
                    if current_step:
                        status_msg += f" - Step: {current_step}"
                    if current_file:
                        status_msg += f" - File: {current_file}"
                        
                    print(f"{status_msg}. Attempt {i+1}/{scan_number_of_tries}", end="", flush=True)
                    
                    # Update last values
                    last_status = current_status
                    last_state = current_state
                    last_step = current_step
                else:
                    # Just show a dot for minor updates
                    print(".", end="", flush=True)
                
                time.sleep(archive_wait_interval)
                
            except (ApiError, NetworkError, ScanNotFoundError) as e:
                logger.error(f"Error checking archive extraction status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nError checking Archive Extraction status: {e}")
                raise
            except ProcessError:
                # Re-raise ProcessError directly
                raise
            except Exception as e:
                logger.error(f"Unexpected error checking archive extraction status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nUnexpected error during Archive Extraction status check: {e}")
                raise ProcessError(f"Error during archive extraction for scan '{scan_code}'", details={"error": str(e)})
                
        # If we exhaust all tries
        logger.error(f"Timed out waiting for archive extraction to complete for scan '{scan_code}' after {scan_number_of_tries*archive_wait_interval} seconds")
        print(f"\nTimed out waiting for Archive Extraction to complete")
        raise ProcessTimeoutError(
            f"Archive extraction timed out for scan '{scan_code}' after {scan_number_of_tries*archive_wait_interval} seconds",
            details={"last_status": last_status, "max_tries": scan_number_of_tries, "wait_interval": archive_wait_interval}
        )
        
    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ) -> Tuple[Dict[str, Any], float]:
        """
        Wait for a scan to complete. Delegates to the consolidated implementation with appropriate parameters.
        
        Args:
            scan_type: Type of scan ("SCAN" or "DEPENDENCY_ANALYSIS")
            scan_code: Code of the scan to check
            scan_number_of_tries: Maximum number of attempts
            scan_wait_time: Time to wait between attempts
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        if scan_type == "SCAN":
            operation_name = "KB Scan"
            should_track_files = True
        elif scan_type == "DEPENDENCY_ANALYSIS":
            operation_name = "Dependency Analysis"
            should_track_files = False
        elif scan_type == "REPORT_IMPORT":
            operation_name = "SBOM Import"
            should_track_files = False
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")
            
        return self._wait_for_operation_with_status(
            operation_name=operation_name,
            scan_type=scan_type,
            scan_code=scan_code,
            max_tries=scan_number_of_tries,
            wait_interval=scan_wait_time,
            should_track_files=should_track_files
        )
            
    def _wait_for_operation_with_status(
        self,
        operation_name: str,
        scan_type: str,
        scan_code: str,
        max_tries: int,
        wait_interval: int,
        should_track_files: bool = False
    ) -> Tuple[Dict[str, Any], float]:
        """
        Consolidated implementation for waiting on scan operations with customized progress display.
        
        Args:
            operation_name: Human-readable name of the operation (e.g., "KB Scan")
            scan_type: API type of the scan ("SCAN" or "DEPENDENCY_ANALYSIS")
            scan_code: Code of the scan to check
            max_tries: Maximum number of attempts
            wait_interval: Time to wait between attempts
            should_track_files: Whether to track file counting information
            
        Returns:
            Tuple[Dict[str, Any], float]: Tuple containing the final status data and the duration in seconds
            
        Raises:
            ProcessTimeoutError: If the process times out
            ProcessError: If the process fails
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Waiting for {scan_type} operation to complete for scan '{scan_code}'...")
        
        # Initialize tracking variables
        last_status = "UNKNOWN"
        last_state = ""
        last_step = ""
        start_time = None
        client_start_time = time.time()  # Start tracking client-side duration
        status_data = None
        
        for i in range(max_tries):
            try:
                # Get current status from API using the mixin method
                status_data = self.get_scan_status(scan_type, scan_code)
                
                # Extract key information
                current_status = status_data.get("status", "UNKNOWN").upper()
                current_state = status_data.get("state", "")
                current_step = status_data.get("current_step", "")
                
                # Extract additional information specific to the scan type
                file_count_info = ""
                total_files = 0
                current_file_idx = 0
                percentage = ""
                
                if should_track_files:
                    # Extract file processing information (KB scan only)
                    total_files = status_data.get("total_files", 0)
                    current_file_idx = status_data.get("current_file", 0)
                    percentage = status_data.get("percentage_done", "")
                    
                    # Create file progress info if available
                    if total_files and int(total_files) > 0:
                        # Display progress as a fraction with percentage
                        file_count_info = f" - File {current_file_idx}/{total_files}"
                        if percentage:
                            file_count_info += f" ({percentage})"
                
                # Get operation start time from API if available
                api_start_time = status_data.get("started")
                if api_start_time and not start_time:
                    start_time = api_start_time
                
                # Only print a new line when status, state, or step changes
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
                
                # Check for success (finished)
                if current_status == "FINISHED" or status_data.get("is_finished") in [True, "1", 1]:
                    # Calculate duration using API timestamps if available
                    duration_str = ""
                    api_finish_time = status_data.get("finished")
                    api_duration_sec = None
                    
                    if start_time and api_finish_time:
                        try:
                            # Parse timestamps and calculate duration
                            from datetime import datetime
                            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
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
                    
                    print(f"\n{operation_name} completed successfully{duration_str}.")
                    logger.debug(f"{scan_type} for scan '{scan_code}' completed successfully")
                    
                    # Calculate client-side duration as fallback
                    client_duration = time.time() - client_start_time
                    
                    # Prefer API-reported duration if available, otherwise use client-side duration
                    final_duration = api_duration_sec if api_duration_sec is not None else client_duration
                    
                    # Add duration to status_data for reference
                    status_data["_duration_seconds"] = final_duration
                    
                    return status_data, final_duration
                
                # Check for failure
                if current_status in ["FAILED", "CANCELLED"]:
                    error_msg = f"{operation_name} {current_status}"
                    info = status_data.get("info", "")
                    if info:
                        error_msg += f" - Detail: {info}"
                    print(f"\n{error_msg}")
                    logger.error(f"{scan_type} for scan '{scan_code}' failed: {error_msg}")
                    raise ProcessError(error_msg, details=status_data)
                
                # Progress reporting
                if details_changed or show_periodic_update:
                    print()
                    
                    # Construct a detailed status message
                    status_msg = f"{operation_name} status: {current_status}"
                    if current_state:
                        status_msg += f" ({current_state})"
                    
                    # Include file progress information for KB scan
                    if file_count_info:
                        status_msg += file_count_info
                    elif percentage:
                        status_msg += f" - {percentage}"
                    
                    # Show current step
                    if current_step:
                        status_msg += f" - Step: {current_step}"
                        
                    print(f"{status_msg}. Attempt {i+1}/{max_tries}", end="", flush=True)
                    
                    # Update last values
                    last_status = current_status
                    last_state = current_state
                    last_step = current_step
                else:
                    # Just show a dot for minor updates
                    print(".", end="", flush=True)
                
                time.sleep(wait_interval)
                
            except (ApiError, NetworkError, ScanNotFoundError) as e:
                logger.error(f"Error checking {scan_type} status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nError checking {operation_name} status: {e}")
                raise
            except ProcessError:
                # Re-raise ProcessError directly
                raise
            except Exception as e:
                logger.error(f"Unexpected error checking {scan_type} status for scan '{scan_code}': {e}", exc_info=True)
                print(f"\nUnexpected error during {operation_name} status check: {e}")
                raise ProcessError(f"Error during {scan_type} operation for scan '{scan_code}'", details={"error": str(e)})
                
        # If we exhaust all tries
        logger.error(f"Timed out waiting for {scan_type} to complete for scan '{scan_code}' after {max_tries} attempts")
        print(f"\nTimed out waiting for {operation_name} to complete")
        raise ProcessTimeoutError(
            f"{scan_type} timed out for scan '{scan_code}' after {max_tries} attempts",
            details={"last_status": last_status, "max_tries": max_tries, "wait_interval": wait_interval}
        )
