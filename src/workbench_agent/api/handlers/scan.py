import logging
import argparse
from typing import Dict, Any

from ..workbench_api import WorkbenchAPI
from ...utilities.scan_workflows import (
    upload_scan_content,
    extract_archives,
    run_kb_scan,
    run_dependency_analysis,
    wait_for_scan_completion,
    wait_for_dependency_analysis_completion,
    collect_and_save_results
)
from ...utilities.error_handling import handler_error_wrapper
from ...exceptions import ValidationError, FileSystemError

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_scan(workbench: WorkbenchAPI, params: argparse.Namespace) -> bool:
    """
    Handler for the 'scan' command. Uploads code files directly, runs KB scan, 
    optional dependency analysis, and collects results.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
        
    Raises:
        ValidationError: If required parameters are missing or invalid
        FileSystemError: If specified paths don't exist
    """
    logger.info("--- Starting SCAN Command ---")
    
    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the scan command.")
    
    # Resolve project and scan (find or create) - matching inspiration pattern
    if getattr(params, 'use_name_resolution', False):
        # Name-based resolution
        project_code = workbench.resolve_project(params.project_name, create_if_missing=True)
        scan_code, scan_id = workbench.resolve_scan(
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )
    else:
                 # Legacy code-based approach
         scan_code = params.scan_code  # For legacy, use the scan_code directly
         project_code, scan_id = workbench.prepare_project_and_scan(
             project_identifier=params.project_code,
             scan_identifier=params.scan_code,
             params=params
         )
    
    # Upload content if path is provided
    if params.path:
        upload_scan_content(
            workbench=workbench,
            scan_code=params.scan_code,
            path=params.path,
            chunked_upload=getattr(params, 'chunked_upload', False)
        )
        
        # Extract archives after upload
        extract_archives(
            workbench=workbench,
            scan_code=params.scan_code,
            recursive=getattr(params, 'recursively_extract_archives', False),
            jar_extraction=getattr(params, 'jar_file_extraction', False)
        )
    
    # Determine what scans to run
    run_kb = not getattr(params, 'run_only_dependency_analysis', False)
    run_da = getattr(params, 'run_dependency_analysis', False) or getattr(params, 'run_only_dependency_analysis', False)
    
    # Calculate timeout in minutes
    timeout_minutes = (getattr(params, 'scan_number_of_tries', 960) * 
                      getattr(params, 'scan_wait_time', 30)) // 60
    
    # Build scan options
    scan_options = {
        "limit": getattr(params, 'limit', 10),
        "sensitivity": getattr(params, 'sensitivity', 10),
        "auto_identification_detect_declaration": getattr(params, 'auto_identification_detect_declaration', False),
        "auto_identification_detect_copyright": getattr(params, 'auto_identification_detect_copyright', False),
        "auto_identification_resolve_pending_ids": getattr(params, 'auto_identification_resolve_pending_ids', False),
        "delta_only": getattr(params, 'delta_only', False),
        "reuse_identifications": getattr(params, 'reuse_identifications', False),
        "identification_reuse_type": getattr(params, 'identification_reuse_type', 'any'),
        "specific_code": getattr(params, 'specific_code', None),
        "advanced_match_scoring": getattr(params, 'advanced_match_scoring', True),
        "match_filtering_threshold": getattr(params, 'match_filtering_threshold', -1)
    }
    
    # Run KB scan if requested
    if run_kb:
        run_kb_scan(workbench, params.scan_code, scan_options)
        wait_for_scan_completion(workbench, params.scan_code, timeout_minutes)
    
    # Run dependency analysis if requested
    if run_da:
        run_dependency_analysis(workbench, params.scan_code)
        wait_for_dependency_analysis_completion(workbench, params.scan_code, timeout_minutes)
    
    # Collect and save results
    results = collect_and_save_results(workbench, params.scan_code, params)
    
    logger.info(f"Scan command completed successfully. Found {len(results)} license entries.")
    return True
