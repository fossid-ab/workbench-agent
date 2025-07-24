import logging
import time
import os
import tempfile
from typing import Dict, Any, Tuple, Optional, Union

from ..api.workbench_api import WorkbenchAPI
from .cli_wrapper import CliWrapper
from .result_handler import save_results
from ..exceptions import (
    WorkbenchAgentError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError
)

logger = logging.getLogger("workbench-agent")



def determine_scans_to_run(params) -> Dict[str, bool]:
    """
    Determines which scan processes to run based on the provided parameters.
    
    Args:
        params: Command line parameters
        
    Returns:
        Dict with 'run_kb_scan' and 'run_dependency_analysis' keys
    """
    run_dependency_analysis = getattr(params, 'run_dependency_analysis', False)
    dependency_analysis_only = getattr(params, 'run_only_dependency_analysis', False)
    
    scan_operations = {"run_kb_scan": True, "run_dependency_analysis": False}
    
    if run_dependency_analysis and dependency_analysis_only:
        logger.warning("Both --run-only-dependency-analysis and --run-dependency-analysis were specified. Using dependency-analysis-only mode (skipping KB scan).")
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif dependency_analysis_only:
        scan_operations["run_kb_scan"] = False
        scan_operations["run_dependency_analysis"] = True
    elif run_dependency_analysis:
        scan_operations["run_kb_scan"] = True
        scan_operations["run_dependency_analysis"] = True
    
    logger.debug(f"Determined scan operations: {scan_operations}")
    return scan_operations


def get_workbench_links(api_url: str, scan_id: int) -> Dict[str, Dict[str, str]]:
    """
    Get all Workbench UI links and messages for a scan.
    
    Args:
        api_url: The Workbench API URL (includes /api.php)
        scan_id: The scan ID
        
    Returns:
        Dict with link types as keys, each containing 'url' and 'message'
    """
    # Link type configuration
    link_config = {
        "main": {
            "view_param": None,
            "message": "View scan results in Workbench"
        },
        "pending": {
            "view_param": "pending_items", 
            "message": "Review Pending IDs in Workbench"
        },
        "policy": {
            "view_param": "mark_as_identified",
            "message": "Review policy warnings in Workbench"
        },
    }
    
    # Build base URL once
    base_url = api_url.replace("/api.php", "").rstrip("/")
    
    # Build all links
    links = {}
    for link_type, config in link_config.items():
        url = f"{base_url}/index.html?form=main_interface&action=scanview&sid={scan_id}"
        if config["view_param"]:
            url += f"&current_view={config['view_param']}"
        
        links[link_type] = {
            "url": url,
            "message": config["message"]
        }
    
    return links


def print_workbench_links(api_url: str, scan_id: int) -> None:
    """
    Print convenient links to Workbench UI.
    
    Args:
        api_url: The Workbench API URL
        scan_id: The scan ID
    """
    if scan_id:
        print("\n--- Workbench UI Links ---")
        links = get_workbench_links(api_url, scan_id)
        for link_type, link_info in links.items():
            print(f"{link_info['message']}: {link_info['url']}")
        print("------------------------------------")


def perform_blind_scan(cli_wrapper: CliWrapper, path: str, run_dependency_analysis: bool = False) -> str:
    """
    Performs blind scan using CLI to generate file hashes.
    
    Args:
        cli_wrapper: CliWrapper instance
        path: Path to scan
        run_dependency_analysis: Whether to include dependency analysis in hash generation
        
    Returns:
        Path to temporary file containing generated hashes
        
    Raises:
        ProcessError: If CLI execution fails
        FileSystemError: If path doesn't exist or temp file can't be created
    """
    if not os.path.exists(path):
        raise FileSystemError(f"Path does not exist: {path}")
    
    logger.info("Performing blind scan to generate file hashes...")
    
    # Display CLI version for validation
    try:
        version = cli_wrapper.get_version()
        logger.info(f"Using FossID CLI: {version}")
    except Exception as e:
        logger.warning(f"Could not get CLI version: {e}")
    
    # Generate hashes
    try:
        hash_file_path = cli_wrapper.blind_scan(path, run_dependency_analysis)
        logger.info(f"Hash file generated at: {hash_file_path}")
        return hash_file_path
    except Exception as e:
        raise ProcessError(f"Failed to generate hash file: {e}")


def upload_scan_content(workbench: WorkbenchAPI, scan_code: str, path: str, chunked_upload: bool = False) -> None:
    """
    Uploads files or directories to the scan.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to upload to
        path: Path to file or directory to upload
        chunked_upload: Whether to use chunked upload for large files
        
    Raises:
        FileSystemError: If path doesn't exist
    """
    if not os.path.exists(path):
        raise FileSystemError(f"Path does not exist: {path}")
    
    logger.info(f"Uploading content from: {path}")
    
    if os.path.isfile(path):
        # Single file upload
        logger.info(f"Uploading single file: {path}")
        workbench.upload_files(
            scan_code=scan_code,
            path=path,
            chunked_upload=chunked_upload
        )
    else:
        # Directory upload - upload all files
        logger.info(f"Uploading directory contents: {path}")
        file_count = 0
        for root, directories, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                if os.path.isfile(file_path):  # Skip directories
                    workbench.upload_files(
                        scan_code=scan_code,
                        path=file_path,
                        chunked_upload=chunked_upload
                    )
                    file_count += 1
        logger.info(f"Uploaded {file_count} files total")
    
    logger.info("Upload completed successfully.")


def extract_archives(workbench: WorkbenchAPI, scan_code: str, recursive: bool = False, jar_extraction: bool = False) -> None:
    """
    Extracts archives in the scan.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to extract archives for
        recursive: Whether to extract recursively
        jar_extraction: Whether to extract JAR files
    """
    logger.info("Extracting uploaded archives...")
    try:
        workbench.extract_archives(scan_code, recursive, jar_extraction)
        logger.info("Archive extraction completed.")
    except Exception as e:
        logger.warning(f"Archive extraction failed: {e}")
        logger.info("Continuing with scan process...")


def run_kb_scan(workbench: WorkbenchAPI, scan_code: str, scan_options: Dict[str, Any]) -> None:
    """
    Runs the knowledge base scan with the provided options.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to run
        scan_options: Dictionary of scan configuration options
    """
    logger.info("Starting KB scan...")
    
    try:
        workbench.run_scan(
            scan_code=scan_code,
            limit=scan_options.get("limit", 10),
            sensitivity=scan_options.get("sensitivity", 10),
            auto_identification_detect_declaration=scan_options.get("auto_identification_detect_declaration", False),
            auto_identification_detect_copyright=scan_options.get("auto_identification_detect_copyright", False),
            auto_identification_resolve_pending_ids=scan_options.get("auto_identification_resolve_pending_ids", False),
            delta_only=scan_options.get("delta_only", False),
            reuse_identification=scan_options.get("reuse_identifications", False),
            identification_reuse_type=scan_options.get("identification_reuse_type", "any"),
            specific_code=scan_options.get("specific_code"),
            advanced_match_scoring=scan_options.get("advanced_match_scoring", True),
            match_filtering_threshold=scan_options.get("match_filtering_threshold", -1)
        )
        logger.info("KB scan started successfully.")
    except Exception as e:
        raise ProcessError(f"Failed to start KB scan: {e}")


def run_dependency_analysis(workbench: WorkbenchAPI, scan_code: str) -> None:
    """
    Runs dependency analysis on the scan.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to run dependency analysis on
    """
    logger.info("Starting dependency analysis...")
    
    try:
        workbench.start_dependency_analysis(scan_code)
        logger.info("Dependency analysis started successfully.")
    except Exception as e:
        raise ProcessError(f"Failed to start dependency analysis: {e}")


def wait_for_scan_completion(workbench: WorkbenchAPI, scan_code: str, timeout_minutes: int) -> None:
    """
    Waits for KB scan to complete.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to wait for
        timeout_minutes: Maximum time to wait in minutes
    """
    logger.info("Waiting for KB scan to complete...")
    
    try:
        # Convert timeout to tries and wait time (using 30 second intervals)
        wait_time_seconds = 30
        number_of_tries = (timeout_minutes * 60) // wait_time_seconds
        
        # Use the new process waiters which return (status_data, duration)
        status_data, duration = workbench.wait_for_scan_to_finish(
            scan_type="SCAN",
            scan_code=scan_code,
            scan_number_of_tries=number_of_tries,
            scan_wait_time=wait_time_seconds
        )
        logger.info("KB scan completed successfully.")
    except ProcessTimeoutError:
        raise ProcessTimeoutError(f"KB scan timed out after {timeout_minutes} minutes")
    except Exception as e:
        raise ProcessError(f"KB scan failed: {e}")


def wait_for_scan_completion_with_duration(workbench: WorkbenchAPI, scan_code: str, timeout_minutes: int) -> Tuple[bool, float]:
    """
    Enhanced version that waits for KB scan to complete and returns duration.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to wait for
        timeout_minutes: Maximum time to wait in minutes
        
    Returns:
        Tuple of (success, duration_in_seconds)
    """
    start_time = time.time()
    
    try:
        # Convert timeout to tries and wait time (using 30 second intervals)
        wait_time_seconds = 30
        number_of_tries = (timeout_minutes * 60) // wait_time_seconds
        
        # Use the new process waiters which return (status_data, duration)
        status_data, duration = workbench.wait_for_scan_to_finish(
            scan_type="SCAN",
            scan_code=scan_code,
            scan_number_of_tries=number_of_tries,
            scan_wait_time=wait_time_seconds
        )
        logger.info("KB scan completed successfully.")
        return True, duration
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"KB scan failed after {format_duration(duration)}: {e}")
        raise e


def wait_for_dependency_analysis_completion(workbench: WorkbenchAPI, scan_code: str, timeout_minutes: int) -> None:
    """
    Waits for dependency analysis to complete.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to wait for
        timeout_minutes: Maximum time to wait in minutes
    """
    logger.info("Waiting for dependency analysis to complete...")
    
    try:
        # Convert timeout to tries and wait time (using 30 second intervals)
        wait_time_seconds = 30
        number_of_tries = (timeout_minutes * 60) // wait_time_seconds
        
        # Use the new process waiters which return (status_data, duration)
        status_data, duration = workbench.wait_for_scan_to_finish(
            scan_type="DEPENDENCY_ANALYSIS",
            scan_code=scan_code,
            scan_number_of_tries=number_of_tries,
            scan_wait_time=wait_time_seconds
        )
        logger.info("Dependency analysis completed successfully.")
    except ProcessTimeoutError:
        raise ProcessTimeoutError(f"Dependency analysis timed out after {timeout_minutes} minutes")
    except Exception as e:
        raise ProcessError(f"Dependency analysis failed: {e}")


def wait_for_dependency_analysis_completion_with_duration(workbench: WorkbenchAPI, scan_code: str, timeout_minutes: int) -> Tuple[bool, float]:
    """
    Enhanced version that waits for dependency analysis to complete and returns duration.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to wait for
        timeout_minutes: Maximum time to wait in minutes
        
    Returns:
        Tuple of (success, duration_in_seconds)
    """
    start_time = time.time()
    
    try:
        # Convert timeout to tries and wait time (using 30 second intervals)
        wait_time_seconds = 30
        number_of_tries = (timeout_minutes * 60) // wait_time_seconds
        
        # Use the new process waiters which return (status_data, duration)
        status_data, duration = workbench.wait_for_scan_to_finish(
            scan_type="DEPENDENCY_ANALYSIS",
            scan_code=scan_code,
            scan_number_of_tries=number_of_tries,
            scan_wait_time=wait_time_seconds
        )
        logger.info("Dependency analysis completed successfully.")
        return True, duration
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Dependency analysis failed after {format_duration(duration)}: {e}")
        raise e


def wait_for_archive_extraction(workbench: WorkbenchAPI, scan_code: str, timeout_minutes: int) -> None:
    """
    Waits for archive extraction to complete using a 3-second interval.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to wait for
        timeout_minutes: Maximum time to wait in minutes
    """
    logger.info("Waiting for archive extraction to complete...")
    
    try:
        # Convert timeout to tries using 3-second intervals
        wait_time_seconds = 3  # Fixed 3-second interval for archive extraction
        number_of_tries = (timeout_minutes * 60) // wait_time_seconds
        
        # Use the specialized archive extraction waiter
        status_data, duration = workbench.wait_for_archive_extraction(
            scan_code=scan_code,
            scan_number_of_tries=number_of_tries,
            scan_wait_time=wait_time_seconds
        )
        logger.info("Archive extraction completed successfully.")
    except ProcessTimeoutError:
        raise ProcessTimeoutError(f"Archive extraction timed out after {timeout_minutes} minutes")
    except Exception as e:
        raise ProcessError(f"Archive extraction failed: {e}")


def wait_for_archive_extraction_with_duration(workbench: WorkbenchAPI, scan_code: str, timeout_minutes: int) -> Tuple[bool, float]:
    """
    Enhanced version that waits for archive extraction to complete and returns duration using a 3-second interval.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to wait for
        timeout_minutes: Maximum time to wait in minutes
        
    Returns:
        Tuple of (success, duration_in_seconds)
    """
    start_time = time.time()
    
    try:
        # Convert timeout to tries using 3-second intervals
        wait_time_seconds = 3  # Fixed 3-second interval for archive extraction
        number_of_tries = (timeout_minutes * 60) // wait_time_seconds
        
        # Use the specialized archive extraction waiter
        status_data, duration = workbench.wait_for_archive_extraction(
            scan_code=scan_code,
            scan_number_of_tries=number_of_tries,
            scan_wait_time=wait_time_seconds
        )
        logger.info("Archive extraction completed successfully.")
        return True, duration
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Archive extraction failed after {format_duration(duration)}: {e}")
        raise e


def collect_and_save_results(workbench: WorkbenchAPI, scan_code: str, args) -> Dict[str, Any]:
    """
    Collects scan results and saves them if requested.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to get results for
        args: Command line arguments
        
    Returns:
        Dictionary containing the collected results
    """
    logger.info("Retrieving final scan results...")
    
    try:
        # Get identified licenses (default result type)
        results = workbench.get_scan_identified_licenses(scan_code)
        
        # Save results if path specified
        if hasattr(args, 'path_result') and args.path_result:
            save_results(args, results)
            
        return results
        
    except Exception as e:
        logger.error(f"Failed to retrieve results: {e}")
        return {}


def collect_and_save_results_enhanced(workbench: WorkbenchAPI, scan_code: str, args) -> Dict[str, Any]:
    """
    Enhanced result collection with better structure, metadata, and support for different result types.
    
    Args:
        workbench: WorkbenchAPI instance
        scan_code: Scan code to get results for
        args: Command line arguments
        
    Returns:
        Dictionary containing the collected results with metadata
    """
    logger.info("Retrieving final scan results...")
    
    collected_results = {}
    
    try:
        # Determine what to collect based on existing flags (preserving original functionality)
        if getattr(args, 'get_scan_identified_components', False):
            results = workbench.get_scan_identified_components(scan_code)
            result_type = 'identified_components'
            print("Identified components:")
        elif getattr(args, 'scans_get_policy_warnings_counter', False):
            results = workbench.scans_get_policy_warnings_counter(scan_code)
            result_type = 'policy_warnings_counter'
            print(f"Scan: {scan_code} policy warnings info:")
        elif getattr(args, 'projects_get_policy_warnings_info', False):
            results = workbench.projects_get_policy_warnings_info(args.project_code)
            result_type = 'project_policy_warnings'
            print(f"Project {args.project_code} policy warnings info:")
        elif getattr(args, 'scans_get_results', False):
            results = workbench.get_results(scan_code)
            result_type = 'scan_results'
            print(f"Scan {scan_code} results:")
        else:
            # Default: get identified licenses (original behavior)
            results = workbench.get_scan_identified_licenses(scan_code)
            result_type = 'identified_licenses'
            print("Identified licenses:")
        
        # Structure the results with metadata
        collected_results = {
            'data': results,
            'metadata': {
                'scan_code': scan_code,
                'result_type': result_type,
                'timestamp': time.time(),
                'count': len(results) if isinstance(results, (list, dict)) else 0
            }
        }
        
        # Print the results (preserving original behavior)
        import json
        print(json.dumps(results))
        
        # Save results if path specified
        if hasattr(args, 'path_result') and args.path_result:
            save_results(args, collected_results)
            
        return collected_results
        
    except Exception as e:
        logger.error(f"Failed to retrieve results: {e}")
        return {
            'data': {},
            'metadata': {
                'scan_code': scan_code,
                'result_type': 'error',
                'timestamp': time.time(),
                'count': 0,
                'error': str(e)
            }
        }


def cleanup_temp_file(file_path: str) -> bool:
    """
    Cleanup temporary file safely.
    
    Args:
        file_path: Path to temporary file to clean up
        
    Returns:
        True if cleanup was successful, False otherwise
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.debug(f"Cleaned up temporary file: {file_path}")
            return True
        return True  # File doesn't exist, consider it cleaned up
    except Exception as e:
        logger.warning(f"Failed to clean up temporary file {file_path}: {e}")
        return False


def format_duration(duration_seconds: Optional[Union[int, float]]) -> str:
    """
    Formats a duration in seconds into a human-readable string.
    
    Args:
        duration_seconds: Duration in seconds
        
    Returns:
        Formatted duration string
    """
    if duration_seconds is None: 
        return "N/A"
    try:
        duration_seconds = round(float(duration_seconds))
    except (ValueError, TypeError):
        return "Invalid Duration"

    minutes, seconds = divmod(int(duration_seconds), 60)
    if minutes > 0 and seconds > 0: 
        return f"{minutes} minutes, {seconds} seconds"
    elif minutes > 0: 
        return f"{minutes} minutes"
    elif seconds == 1: 
        return f"1 second"
    else: 
        return f"{seconds} seconds"


def print_operation_summary(params, scan_completed: bool, da_completed: bool, 
                          project_code: str, scan_code: str, durations: Dict[str, float] = None) -> None:
    """
    Prints a standardized summary of the scan operations performed and settings used.
    
    Args:
        params: Command line parameters
        scan_completed: Whether KB scan completed successfully
        da_completed: Whether dependency analysis completed successfully
        project_code: Project code associated with the scan
        scan_code: Scan code of the operation
        durations: Dictionary containing operation durations in seconds
    """
    durations = durations or {}
    
    print(f"\n--- Operation Summary ---")
    print("Workbench Agent Operation Details:")
    
    # Determine scan method
    if getattr(params, 'blind_scan', False) or getattr(params, 'scan_type', None) == 'blind_scan':
        print(f"  - Method: Blind Scan (using CLI hash generation)")
    else:
        print(f"  - Method: Code Upload (using --path)")
    
    print(f"  - Source Path: {getattr(params, 'path', 'N/A')}")
    print(f"  - Recursive Archive Extraction: {getattr(params, 'recursively_extract_archives', 'N/A')}")
    print(f"  - JAR File Extraction: {getattr(params, 'jar_file_extraction', 'N/A')}")
    
    print("\nScan Parameters:")
    print(f"  - Auto-ID File Licenses: {'Yes' if getattr(params, 'auto_identification_detect_declaration', False) else 'No'}")
    print(f"  - Auto-ID File Copyrights: {'Yes' if getattr(params, 'auto_identification_detect_copyright', False) else 'No'}")
    print(f"  - Auto-ID Pending IDs: {'Yes' if getattr(params, 'auto_identification_resolve_pending_ids', False) else 'No'}")
    print(f"  - Delta Scan: {'Yes' if getattr(params, 'delta_only', False) else 'No'}")
    print(f"  - Identification Reuse: {'Yes' if getattr(params, 'reuse_identifications', False) else 'No'}")
    
    print("\nAnalysis Performed:")
    kb_scan_performed = not getattr(params, 'run_only_dependency_analysis', False)
    
    if kb_scan_performed and scan_completed:
        kb_duration_str = format_duration(durations.get("kb_scan", 0)) if durations.get("kb_scan") else "N/A"
        print(f"  - Signature Scan: Yes (Duration: {kb_duration_str})")
    elif kb_scan_performed:
        print(f"  - Signature Scan: Started but not completed")
    else:
        print(f"  - Signature Scan: No")
    
    if da_completed:
        da_duration_str = format_duration(durations.get("dependency_analysis", 0)) if durations.get("dependency_analysis") else "N/A"
        print(f"  - Dependency Analysis: Yes (Duration: {da_duration_str})")
    else:
        print(f"  - Dependency Analysis: No")
    
    # Show extraction duration if available
    if durations.get("extraction_duration", 0) > 0:
        extraction_duration_str = format_duration(durations.get("extraction_duration", 0))
        print(f"  - Archive Extraction: Yes (Duration: {extraction_duration_str})")
    
    print("------------------------------------") 