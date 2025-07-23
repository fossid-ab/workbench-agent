import logging
import argparse
import time

from ..api.workbench_api import WorkbenchAPI
from ..utilities.scan_workflows import (
    perform_blind_scan,
    upload_scan_content,
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
    format_duration,
    cleanup_temp_file
)
from ..utilities.error_handling import handler_error_wrapper
from ..utilities.cli_wrapper import CliWrapper
from ..exceptions import ValidationError

logger = logging.getLogger("workbench-agent")


@handler_error_wrapper
def handle_blind_scan(workbench: WorkbenchAPI, params: argparse.Namespace) -> bool:
    """
    Handler for the 'blind-scan' command. Uses FossID CLI to generate file hashes,
    uploads the hash file, runs KB scan, optional dependency analysis, and collects results.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Returns:
        bool: True if the operation completed successfully
        
    Raises:
        ValidationError: If required parameters are missing or invalid
        FileSystemError: If specified paths don't exist
        ProcessError: If CLI execution fails
    """
    print(f"\n--- Running BLIND SCAN Command ---")
    
    # Initialize comprehensive duration tracking
    durations = {
        "kb_scan": 0.0,
        "dependency_analysis": 0.0,
        "hash_generation": 0.0
    }
    
    # Validate scan parameters
    if not params.path:
        raise ValidationError("A path must be provided for the blind-scan command.")
    
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
    
    # Initialize CLI wrapper
    cli_wrapper = CliWrapper(
        cli_path=getattr(params, 'cli_path', '/usr/bin/fossid-cli'),
        config_path=getattr(params, 'config_path', '/etc/fossid.conf')
    )
    
    # Track completion states
    scan_completed = False
    da_completed = False
    hash_file_path = None
    
    try:
        # Determine DA inclusion in hash generation
        include_da_in_hash = scan_operations["run_dependency_analysis"]
        
        # Calculate timeout in minutes
        timeout_minutes = (getattr(params, 'scan_number_of_tries', 960) * 
                          getattr(params, 'scan_wait_time', 30)) // 60
        
        print(f"\nGenerating file hashes using FossID CLI...")
        hash_start_time = time.time()
        hash_file_path = perform_blind_scan(
            cli_wrapper=cli_wrapper,
            path=params.path,
            run_dependency_analysis=include_da_in_hash
        )
        durations["hash_generation"] = time.time() - hash_start_time
        print(f"Hash generation completed in {format_duration(durations['hash_generation'])}.")
        
        print(f"\nUploading hash file to Workbench...")
        upload_scan_content(
            workbench=workbench,
            scan_code=params.scan_code,
            path=hash_file_path,
            chunked_upload=getattr(params, 'chunked_upload', False)
        )
        print("Hash file uploaded successfully.")
        
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
            if not include_da_in_hash:
                run_dependency_analysis(workbench, params.scan_code)
                da_completed, durations["dependency_analysis"] = wait_for_dependency_analysis_completion_with_duration(
                    workbench, params.scan_code, timeout_minutes
                )
            else:
                print("Dependency analysis was included in hash generation - no additional DA scan needed.")
                da_completed = True
        
        # Run KB scan if requested
        elif scan_operations["run_kb_scan"]:
            print("\nStarting KB Scan Process...")
            run_kb_scan(workbench, params.scan_code, scan_options)
            
            scan_completed, durations["kb_scan"] = wait_for_scan_completion_with_duration(
                workbench, params.scan_code, timeout_minutes
            )
            
            # Run dependency analysis if requested and not already included in hash generation
            if scan_completed and scan_operations["run_dependency_analysis"] and not include_da_in_hash:
                print("\nWaiting for Dependency Analysis to complete...")
                run_dependency_analysis(workbench, params.scan_code)
                da_completed, durations["dependency_analysis"] = wait_for_dependency_analysis_completion_with_duration(
                    workbench, params.scan_code, timeout_minutes
                )
            elif scan_operations["run_dependency_analysis"] and include_da_in_hash:
                print("Dependency analysis was included in hash generation.")
                da_completed = True
        
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
        
        print(f"\n✅ Blind scan command completed successfully!")
        print(f"📊 Total operation time: {format_duration(total_operations_time)}")
        print(f"📋 Found {result_count} result entries.")
        
        logger.info(f"Blind scan command completed successfully. Found {result_count} result entries.")
        
        return True
        
    finally:
        # Cleanup temporary hash file
        if hash_file_path:
            cleanup_success = cleanup_temp_file(hash_file_path)
            if cleanup_success:
                logger.debug("Temporary hash file cleaned up successfully.")
            else:
                logger.warning("Failed to clean up temporary hash file.")
