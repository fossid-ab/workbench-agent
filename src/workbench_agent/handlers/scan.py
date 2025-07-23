import logging
import argparse
import time
from typing import Dict, Any

from ..api.workbench_api import WorkbenchAPI
from ..utilities.scan_workflows import (
    upload_scan_content,
    extract_archives,
    run_kb_scan,
    run_dependency_analysis,
    wait_for_scan_completion,
    wait_for_dependency_analysis_completion,
    wait_for_scan_completion_with_duration,
    wait_for_dependency_analysis_completion_with_duration,
    collect_and_save_results,
    collect_and_save_results_enhanced,
    determine_scans_to_run,
    print_operation_summary,
    print_workbench_links,
    format_duration
)
from ..utilities.error_handling import handler_error_wrapper
from ..exceptions import ValidationError, FileSystemError

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
    print(f"\n--- Running SCAN Command ---")
    
    # Initialize comprehensive duration tracking
    durations = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "extraction_duration": 0.0
    }
    
    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the scan command.")
    
    # Determine scan operations upfront
    scan_operations = determine_scans_to_run(params)
    logger.info(f"Scan operations to perform: {scan_operations}")
    
    # Resolve project and scan (find or create) - matching inspiration pattern
    print("\nChecking if the Project and Scan exist or need to be created...")
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
    
    # Enhanced upload process with clear feedback
    if params.path:
        print("\nClearing existing scan content...")
        try:
            # This method exists in the API
            workbench.remove_uploaded_content("", params.scan_code)
            print("Successfully cleared existing scan content.")
        except Exception as e:
            logger.warning(f"Failed to clear existing scan content: {e}")
            print(f"Warning: Could not clear existing scan content: {e}")
            print("Continuing with upload...")
        
        print(f"\nUploading Code to Workbench...")
        upload_scan_content(
            workbench=workbench,
            scan_code=params.scan_code,
            path=params.path,
            chunked_upload=getattr(params, 'chunked_upload', False)
        )
        print(f"Successfully uploaded {params.path} to Workbench.")
        
        print("\nExtracting Uploaded Archives...")
        extract_start_time = time.time()
        extract_archives(
            workbench=workbench,
            scan_code=params.scan_code,
            recursive=getattr(params, 'recursively_extract_archives', False),
            jar_extraction=getattr(params, 'jar_file_extraction', False)
        )
        durations["extraction_duration"] = time.time() - extract_start_time
        print("Archive extraction completed.")
    
    # Track completion states
    scan_completed = False
    da_completed = False
    
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
    
    # Handle dependency analysis only mode
    if not scan_operations["run_kb_scan"] and scan_operations["run_dependency_analysis"]:
        print("\nStarting Dependency Analysis only (skipping KB scan)...")
        run_dependency_analysis(workbench, params.scan_code)
        
        da_completed, durations["dependency_analysis"] = wait_for_dependency_analysis_completion_with_duration(
            workbench, params.scan_code, timeout_minutes
        )
    
    # Run KB scan if requested
    elif scan_operations["run_kb_scan"]:
        print("\nStarting KB Scan Process...")
        run_kb_scan(workbench, params.scan_code, scan_options)
        
        scan_completed, durations["kb_scan"] = wait_for_scan_completion_with_duration(
            workbench, params.scan_code, timeout_minutes
        )
        
        # Run dependency analysis if requested
        if scan_completed and scan_operations["run_dependency_analysis"]:
            print("\nWaiting for Dependency Analysis to complete...")
            run_dependency_analysis(workbench, params.scan_code)
            da_completed, durations["dependency_analysis"] = wait_for_dependency_analysis_completion_with_duration(
                workbench, params.scan_code, timeout_minutes
            )
    
    # Collect results with enhanced structure
    results = collect_and_save_results_enhanced(workbench, params.scan_code, params)
    
    # Print comprehensive operation summary
    print_operation_summary(params, scan_completed, da_completed, project_code, params.scan_code, durations)
    
    # Print Workbench links if available
    if scan_id:
        print_workbench_links(workbench.api_url, scan_id)
    
    # Enhanced completion summary
    total_operations_time = sum(durations.values())
    result_count = results.get('metadata', {}).get('count', len(results.get('data', [])) if isinstance(results.get('data'), (list, dict)) else 0)
    
    print(f"\n✅ Scan command completed successfully!")
    print(f"📊 Total operation time: {format_duration(total_operations_time)}")
    print(f"📋 Found {result_count} result entries.")
    
    logger.info(f"Scan command completed successfully. Found {result_count} result entries.")
    
    return True
