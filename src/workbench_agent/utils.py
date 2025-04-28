# workbench_agent/utils.py

import os
import sys
import json
import time
import logging
import argparse
import re
import requests
from typing import Generator, Optional, Dict, Any, List, Union, Tuple
from datetime import datetime

# Import Workbench class for type hinting and accessing constants/methods if needed
# Use relative import within the package
from .api import Workbench
from .exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError
)

# Assume logger is configured in main.py and get it
logger = logging.getLogger("log")

# --- Project and Scan Resolution ---

def _resolve_project(workbench: Workbench, project_name: str, create_if_missing: bool = False) -> str:
    """
    Resolve project name to project code.
    
    Args:
        workbench: The Workbench API client instance
        project_name: Name of the project
        create_if_missing: Whether to create the project if it doesn't exist
        
    Returns:
        str: Project code
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist and create_if_missing is False
        ProjectExistsError: If the project exists and create_if_missing is True
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
    """
    try:
        # List all projects
        projects = workbench.list_projects()
        
        # Find project by name
        project = next((p for p in projects if p.get("name") == project_name), None)
        
        if project:
            if create_if_missing:
                raise ProjectExistsError(f"Project '{project_name}' already exists")
            return project.get("code")
        else:
            if create_if_missing:
                # Create project
                response = workbench.create_project(project_name)
                if response.get("status") != "1":
                    raise ApiError(f"Failed to create project: {response.get('error', 'Unknown error')}", 
                                 details=response)
                return response.get("data", {}).get("code")
            else:
                raise ProjectNotFoundError(f"Project '{project_name}' not found")
    except ApiError as e:
        raise ApiError(f"Failed to resolve project '{project_name}': {e}", details=e.details)
    except NetworkError as e:
        raise NetworkError(f"Network error while resolving project '{project_name}': {e}", details=e.details)
    except Exception as e:
        raise WorkbenchAgentError(f"Unexpected error while resolving project '{project_name}': {e}", 
                                details={"error": str(e)})

def _ensure_scan_compatibility(params: argparse.Namespace, existing_scan_info: Dict[str, Any], scan_code: str):
    """Checks if the existing scan configuration is compatible with the current command."""
    if not existing_scan_info: return

    print(f"Verifying if the '{scan_code}' scan is compatible with the current operation...") # Use passed scan_code

    existing_git_repo = existing_scan_info.get("git_repo_url")
    existing_git_branch = existing_scan_info.get("git_branch")
    existing_git_ref_type = existing_scan_info.get("git_ref_type")

    current_command = params.command
    current_uses_path = bool(getattr(params, 'path', None)) # Still relevant for 'scan'
    current_uses_git = current_command == 'scan-git'
    current_git_branch = getattr(params, 'git_branch', None)
    current_git_tag = getattr(params, 'git_tag', None)
    current_git_ref_type = None
    current_git_ref_value = None
    if current_git_tag:
        current_git_ref_type = "tag"
        current_git_ref_value = current_git_tag
    elif current_git_branch:
        current_git_ref_type = "branch"
        current_git_ref_value = current_git_branch

    error_message = None

    # --- MODIFIED --- Validation Logic (simplified) ---
    if current_command == 'scan':
        # 'scan' command now only uses --path (upload)
        if existing_git_repo:
            error_message = f"Scan '{scan_code}' was created for Git scanning and cannot be reused for code upload via --path."

    elif current_command == 'scan-git':
        # Check if the existing scan was NOT a git scan
        if not existing_git_repo:
             error_message = f"Scan '{scan_code}' was created for code upload and cannot be reused for Git scanning."
        # Existing scan IS a git scan, check for compatibility
        elif existing_git_repo != params.git_url:
            error_message = f"Scan '{scan_code}' already exists with a different Git repository ('{existing_git_repo}'). Please create a new scan for the '{params.git_url}' repository."
        # Check ref type mismatch
        elif current_git_ref_type and (not existing_git_ref_type or existing_git_ref_type.lower() != current_git_ref_type):
             error_message = f"Scan '{scan_code}' exists with ref type '{existing_git_ref_type or 'branch/unknown'}', but current command specified ref type '{current_git_ref_type}'. Please create a new scan or use matching ref type."
        # Check ref value mismatch
        elif existing_git_branch != current_git_ref_value:
             error_message = f"Scan '{scan_code}' already exists with {existing_git_ref_type or 'branch'} '{existing_git_branch}', but current command specified {current_git_ref_type} '{current_git_ref_value}'. Please create a new scan or use matching ref."

    # --- Error Handling ---
    if error_message:
        print(f"Error: Incompatible scan usage.")
        print(error_message)
        logger.error(f"Incompatible usage for existing scan '{scan_code}': {error_message}")
        raise CompatibilityError(f"Incompatible usage for existing scan '{scan_code}': {error_message}")
    else:
        print("Compatibility check passed.")
        # Log reuse notes
        if current_uses_git and existing_git_repo:
             ref_display = f"{existing_git_ref_type or 'branch'} '{existing_git_branch}'"
             print(f"Note: Reusing existing scan '{scan_code}' with matching Git repository '{existing_git_repo}' and {ref_display}.")
        elif current_command == 'scan' and not existing_git_repo:
             print(f"Note: Reusing existing scan '{scan_code}' for code upload.")

def _resolve_scan(
    workbench: Workbench,
    scan_name: str,
    project_name: Optional[str], # If None, search globally
    create_if_missing: bool,
    params: argparse.Namespace # Needed for creation details and compatibility check
) -> Tuple[str, int]:
    """
    Finds a scan by name, optionally creating it, handling both global and project scopes.

    Args:
        workbench: The initialized Workbench object.
        scan_name: The name of the scan to find or create.
        project_name: The name of the project to search within. If None, searches globally.
        create_if_missing: If True, create the scan if it's not found (requires project_name).
                           If False, raise an Exception if it's not found.
        params: The full argparse Namespace, used for creation details (Git) and compatibility checks.

    Returns:
        A tuple: (scan_code, scan_id).

    Raises:
        ConfigurationError: If create_if_missing is True but project_name is None
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ValidationError: If there are data validation issues
        ScanNotFoundError: If the scan is not found and create_if_missing is False
        CompatibilityError: If the existing scan is not compatible with the current operation
        WorkbenchAgentError: For unexpected errors during the resolution process
    """
    project_code: Optional[str] = None
    scan_list: List[Dict[str, Any]] = []
    search_context = ""

    # 1. Determine Scope and List Scans
    if project_name:
        search_context = f"in project '{project_name}'"
        print(f"Resolving scan '{scan_name}' within project '{project_name}' (Create if missing: {create_if_missing})...")
        # Resolve project first. If creation is allowed for scan, it should be allowed for project too.
        project_code = _resolve_project(workbench, project_name, create_if_missing=create_if_missing)
        try:
            scan_list = workbench.get_project_scans(project_code)
        except Exception as e:
            raise ApiError(f"Failed to list scans {search_context} while resolving '{scan_name}': {e}") from e
    else:
        # Global search
        search_context = "globally"
        print(f"Resolving scan '{scan_name}' globally (Create if missing: {create_if_missing})...")
        if create_if_missing:
            # We cannot create a scan without a project context.
            raise ConfigurationError("Cannot create a scan (create_if_missing=True) without specifying a --project-name.")
        try:
            scan_list = workbench.list_scans() # list_scans adds 'id' and 'code'
        except Exception as e:
            raise ApiError(f"Failed to list all scans while resolving '{scan_name}' globally: {e}") from e

    # 2. Search for Scan by Name
    found_scans = [s for s in scan_list if s.get('name') == scan_name]

    # 3. Handle Search Results
    if len(found_scans) == 1:
        # Exactly one scan found
        scan_info = found_scans[0]
        scan_code = scan_info.get('code')
        scan_id_str = scan_info.get('id')
        resolved_project_code = scan_info.get('project_code', project_code)

        if not scan_code or scan_id_str is None:
            raise ValidationError(f"Found scan '{scan_name}' {search_context} but it's missing required 'code' or 'id' fields.")

        try:
            scan_id = int(scan_id_str)
            print(f"Found existing scan '{scan_name}' with code '{scan_code}' and ID {scan_id} (Project: {resolved_project_code}).")

            # Perform compatibility check ONLY if the scan existed AND creation was a possibility
            if create_if_missing:
                _ensure_scan_compatibility(params, scan_info, scan_code)

            return scan_code, scan_id
        except (ValueError, TypeError):
            raise ValidationError(f"Found scan '{scan_name}' {search_context} but its ID '{scan_id_str}' is not a valid integer.")

    elif len(found_scans) > 1:
        # Multiple scans found (only possible in global search)
        project_codes = [s.get('project_code', 'UnknownProject') for s in found_scans]
        raise ValidationError(
            f"Multiple scans found globally with the name '{scan_name}' in projects: {', '.join(project_codes)}. "
            f"Please specify the --project-name to disambiguate."
        )
    else:
        # No scan found
        if create_if_missing:
            # Creation is requested and allowed (project_name must be set, checked earlier)
            print(f"Scan '{scan_name}' not found {search_context}. Creating it...")
            if not project_code: # Should be impossible due to earlier checks, but safeguard
                 raise ConfigurationError("Internal Error: project_code not resolved before scan creation attempt.")
            try:
                # Prepare Git details if needed
                create_git_url = getattr(params, 'git_url', None) if params.command == 'scan-git' else None
                create_git_branch = getattr(params, 'git_branch', None) if params.command == 'scan-git' else None
                create_git_tag = getattr(params, 'git_tag', None) if params.command == 'scan-git' else None
                create_git_depth = getattr(params, 'git_depth', None) if params.command == 'scan-git' else None

                # Trigger creation
                creation_triggered = workbench.create_webapp_scan(
                    project_code=project_code,
                    scan_name=scan_name,
                    git_url=create_git_url,
                    git_branch=create_git_branch,
                    git_tag=create_git_tag,
                    git_depth=create_git_depth
                )
                if not creation_triggered:
                    raise ApiError(f"Failed to create scan '{scan_name}' {search_context}")
                
                # Get the newly created scan's details
                scan_list = workbench.get_project_scans(project_code)
                new_scan = next((s for s in scan_list if s.get('name') == scan_name), None)
                if not new_scan:
                    raise ApiError(f"Failed to retrieve newly created scan '{scan_name}' {search_context}")
                
                scan_code = new_scan.get('code')
                scan_id_str = new_scan.get('id')
                if not scan_code or scan_id_str is None:
                    raise ValidationError(f"Newly created scan '{scan_name}' is missing required 'code' or 'id' fields.")
                
                try:
                    scan_id = int(scan_id_str)
                    print(f"Created new scan '{scan_name}' with code '{scan_code}' and ID {scan_id} (Project: {project_code}).")
                    return scan_code, scan_id
                except (ValueError, TypeError):
                    raise ValidationError(f"Newly created scan '{scan_name}' has invalid ID '{scan_id_str}'")
            except Exception as e:
                raise ApiError(f"Failed to create scan '{scan_name}' {search_context}: {e}") from e
        else:
            raise ScanNotFoundError(f"Scan '{scan_name}' not found {search_context}")

# --- File Saving ---

def _save_report_content(content: str, output_dir: str, scope: str, name: str, report_type: str) -> None:
    """
    Saves report content to a file in the specified output directory.
    
    Args:
        content: The report content to save
        output_dir: Directory to save the report in
        scope: The scope of the report
        name: The name of the report
        report_type: The type of report
        
    Raises:
        FileSystemError: If there are file system related errors
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during report saving
    """
    try:
        # Validate inputs
        if not content:
            raise ValidationError("Report content is empty")
        if not output_dir:
            raise ValidationError("Output directory is not specified")
        if not name:
            raise ValidationError("Report name is not specified")
            
        # Create sanitized filename
        try:
            safe_name = re.sub(r'[^\w\-_.]', '_', name)
            safe_scope = re.sub(r'[^\w\-_.]', '_', scope)
            safe_type = re.sub(r'[^\w\-_.]', '_', report_type)
            
            filename = f"{safe_scope}_{safe_name}_{safe_type}.txt"
            filepath = os.path.join(output_dir, filename)
        except Exception as e:
            logger.error(f"Failed to create safe filename: {e}", exc_info=True)
            raise ValidationError(f"Failed to create safe filename: {e}") from e
            
        # Ensure output directory exists
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create output directory {output_dir}: {e}", exc_info=True)
            raise FileSystemError(f"Failed to create output directory: {e}") from e
            
        # Write report content
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Saved report to {filepath}")
        except IOError as e:
            logger.error(f"Failed to write report to {filepath}: {e}", exc_info=True)
            raise FileSystemError(f"Failed to write report: {e}") from e
            
    except (ValidationError, FileSystemError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error saving report: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to save report: {e}", details={
            "error": str(e),
            "scope": scope,
            "name": name,
            "type": report_type
        }) from e

def save_results(save_path: str, results_dict: dict, scan_code: str) -> None:
    """
    Saves scan results to a JSON file.
    
    Args:
        save_path: Directory to save the results in
        results_dict: Dictionary containing the scan results
        scan_code: The scan code identifier
        
    Raises:
        FileSystemError: If there are file system related errors
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during results saving
    """
    try:
        # Validate inputs
        if not save_path:
            raise ValidationError("Save path is not specified")
        if not results_dict:
            raise ValidationError("Results dictionary is empty")
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Create sanitized filename
        try:
            safe_scan_code = re.sub(r'[^\w\-_.]', '_', scan_code)
            filename = f"scan_results_{safe_scan_code}.json"
            filepath = os.path.join(save_path, filename)
        except Exception as e:
            logger.error(f"Failed to create safe filename: {e}", exc_info=True)
            raise ValidationError(f"Failed to create safe filename: {e}") from e
            
        # Ensure output directory exists
        try:
            os.makedirs(save_path, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create output directory {save_path}: {e}", exc_info=True)
            raise FileSystemError(f"Failed to create output directory: {e}") from e
            
        # Write results to file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results_dict, f, indent=2)
            print(f"Saved scan results to {filepath}")
        except IOError as e:
            logger.error(f"Failed to write results to {filepath}: {e}", exc_info=True)
            raise FileSystemError(f"Failed to write results: {e}") from e
        except TypeError as e:
            logger.error(f"Failed to serialize results to JSON: {e}", exc_info=True)
            raise ValidationError(f"Failed to serialize results: {e}") from e
            
    except (ValidationError, FileSystemError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error saving results: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to save results: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e

# --- Scan Flow and Result Processing ---

def _print_operation_summary(params: argparse.Namespace, da_completed: bool, project_code: str, scan_code: str):
    """Prints a standardized summary of the scan operations performed and settings used."""
    print(f"\n--- Operation Summary for Scan '{scan_code}' (Project '{project_code}') ---")

    print("Workbench Agent Operation Details:")
    if params.command == 'scan':
        print(f"  - Method: Standard Upload (using --path)")
    elif params.command == 'scan-git':
        print(f"  - Method: Git Scan")
        print(f"  - Git Repository URL: {getattr(params, 'git_url', 'N/A')}")
        if getattr(params, 'git_tag', None):
            print(f"  - Git Tag: {params.git_tag}")
        elif getattr(params, 'git_branch', None):
            print(f"  - Git Branch: {params.git_branch}")
        else:
             print(f"  - Git Branch/Tag: Not Specified")
        if getattr(params, 'git_depth', None) is not None:
             print(f"  - Git Clone Depth: {params.git_depth}")
    else:
        print(f"  - Method: Unknown ({params.command})")

    print("\nScans Performed:")
    print("  - Signature (KB) Scan: Yes")
    license_extraction = params.autoid_file_licenses
    print(f"  - License Extraction: {'Yes' if license_extraction else 'No'}")
    copyright_extraction = params.autoid_file_copyrights
    print(f"  - Copyright Extraction: {'Yes' if copyright_extraction else 'No'}")
    print(f"  - Dependency Analysis: {'Yes' if da_completed else 'No'}")

    print("\nIdentification Settings:")
    print(f"  - Identification Reuse: {'Yes' if params.id_reuse else 'No'}")
    if params.id_reuse:
        print(f"  - Identification Reuse Type: {params.id_reuse_type}")
        if params.id_reuse_type in {"project", "scan"}:
             print(f"  - Specific Code for Reuse: {params.id_reuse_source}")
    print(f"  - Auto-Resolve Pending IDs: {'Yes' if params.autoid_pending_ids else 'No'}")

    print("------------------------------------")

def _execute_standard_scan_flow(workbench: Workbench, params: argparse.Namespace, project_code: str, scan_code: str, scan_id: int):
    """
    Executes the standard workflow after initial scan setup:
    Run KB Scan -> Wait -> Optional DA -> Wait -> Summary -> Results.
    Requires scan_id for result processing.
    
    Args:
        workbench: The initialized Workbench object
        params: The full argparse Namespace with scan parameters
        project_code: Code of the project containing the scan
        scan_code: Code of the scan to execute
        scan_id: ID of the scan for result processing
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If the scan process fails
        ProcessTimeoutError: If the scan process times out
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during the scan flow
    """
    da_completed = False
    scan_completed = False

    resolved_specific_code_for_reuse = None
    api_reuse_type = None

    if params.id_reuse:
        user_provided_name_for_reuse = params.id_reuse_source
        user_reuse_type = params.id_reuse_type

        if user_reuse_type == "project":
            if not user_provided_name_for_reuse:
                 raise ValidationError("Missing project name in --id-reuse-source for ID reuse type 'project'.")
            print(f"Retrieving project code for the ID Reuse source Project named: '{user_provided_name_for_reuse}'...")
            try:
                all_projects = workbench.list_projects()
                found_project = next((p for p in all_projects if p.get('project_name') == user_provided_name_for_reuse), None)
                if found_project and 'project_code' in found_project:
                    resolved_specific_code_for_reuse = found_project['project_code']
                    print(f"Found project code for reuse: '{resolved_specific_code_for_reuse}'")
                else:
                    raise ValidationError(f"The project source for identification reuse ('{user_provided_name_for_reuse}') was not found.")
            except (ApiError, NetworkError) as e:
                raise ApiError(f"Error looking up project code for reuse: {e}") from e
            except Exception as e:
                raise WorkbenchAgentError(f"Unexpected error looking up project code for reuse: {e}", details={"error": str(e)}) from e

        elif user_reuse_type == "scan":
            if not user_provided_name_for_reuse:
                 raise ValidationError("Missing scan name in --id-reuse-source for ID reuse type 'scan'.")
            print(f"Retrieving scan code for the ID Reuse source Scan named: '{user_provided_name_for_reuse}'...")
            try:
                all_scans = workbench.list_scans()
                found_scan = next((s for s in all_scans if s.get('name') == user_provided_name_for_reuse), None)
                if found_scan and 'code' in found_scan:
                    resolved_specific_code_for_reuse = found_scan['code']
                    print(f"Successfully retrieved scan code for ID Reuse Source Scan: '{resolved_specific_code_for_reuse}'")
                else:
                    raise ValidationError(f"The scan source for identification reuse ('{user_provided_name_for_reuse}') was not found.")
            except (ApiError, NetworkError) as e:
                raise ApiError(f"Error looking up scan code for reuse: {e}") from e
            except Exception as e:
                raise WorkbenchAgentError(f"Unexpected error looking up scan code for reuse: {e}", details={"error": str(e)}) from e

        api_reuse_type = user_reuse_type
        if user_reuse_type == "project":
            api_reuse_type = "specific_project"
        elif user_reuse_type == "scan":
            api_reuse_type = "specific_scan"

    print("\nStarting KB Scan process...")
    try:
        workbench.run_scan(
            scan_code,
            params.limit,
            params.sensitivity,
            params.autoid_file_licenses,
            params.autoid_file_copyrights,
            params.autoid_pending_ids,
            params.delta_scan,
            params.id_reuse,
            api_reuse_type,
            resolved_specific_code_for_reuse
        )
    except (ApiError, NetworkError, ScanNotFoundError, ValidationError) as e:
        # Re-raise specific known errors from run_scan
        raise
    except Exception as e:
        # Wrap unexpected errors
        logger.error(f"Unexpected error starting KB scan for '{scan_code}': {e}", exc_info=True)
        raise WorkbenchAgentError(f"Unexpected error starting KB scan: {e}", details={"error": str(e)}) from e

    try:
        workbench.wait_for_scan_to_finish(
            "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
        )
        scan_completed = True
    except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
        # Re-raise specific known errors from wait_for_scan_to_finish
        raise
    except Exception as e:
        # Wrap unexpected errors
        logger.error(f"Unexpected error waiting for KB scan '{scan_code}': {e}", exc_info=True)
        raise WorkbenchAgentError(f"Unexpected error waiting for KB scan: {e}", details={"error": str(e)}) from e

    if scan_completed and params.run_dependency_analysis:
        print("\nStarting optional Dependency Analysis...")
        try:
            workbench.assert_dependency_analysis_can_start(scan_code)
            workbench.start_dependency_analysis(scan_code, import_only=False)
            workbench.wait_for_scan_to_finish(
                "DEPENDENCY_ANALYSIS", scan_code, params.scan_number_of_tries, params.scan_wait_time,
            )
            da_completed = True
            print("Dependency Analysis complete.")
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            # Re-raise specific known errors from dependency analysis
            raise
        except Exception as e:
            # Wrap unexpected errors
            logger.error(f"Unexpected error during dependency analysis for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during dependency analysis: {e}", details={"error": str(e)}) from e

    if scan_completed:
        _print_operation_summary(params, da_completed, project_code, scan_code)
        try:
            pending_files = workbench.get_pending_files(scan_code)
            print(f"KB Scan process complete! {len(pending_files)} files with Pending Identification.")
        except (ApiError, NetworkError) as e:
            # Log but don't fail for pending files - it's informational
            logger.warning(f"Could not retrieve pending file count for scan '{scan_code}': {e}")
            print(f"KB Scan process complete. Could not retrieve pending file count: {e}")
        except Exception as e:
            # Log but don't fail for unexpected errors in pending files - it's informational
            logger.warning(f"Unexpected error retrieving pending file count for scan '{scan_code}': {e}", exc_info=True)
            print(f"KB Scan process complete. Could not retrieve pending file count: {e}")
        print("--------------------\n")
        fetch_and_process_results(scan_code, params.output_dir)

def fetch_and_process_results(scan_code: str, output_dir: str = None) -> dict:
    """
    Fetches scan results and processes them into a structured format.
    
    Args:
        scan_code: The scan code identifier
        output_dir: Optional directory to save reports in
        
    Returns:
        dict: Processed scan results
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network connectivity issues
        FileSystemError: If there are file system related errors
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during processing
    """
    try:
        # Validate inputs
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Fetch results from API
        try:
            results = api.get_scan_results(scan_code)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching results for scan {scan_code}: {e}", exc_info=True)
            raise NetworkError(f"Failed to fetch scan results: {e}") from e
        except Exception as e:
            logger.error(f"API error fetching results for scan {scan_code}: {e}", exc_info=True)
            raise ApiError(f"Failed to fetch scan results: {e}") from e
            
        # Process results
        try:
            processed_results = {
                "scan_code": scan_code,
                "timestamp": datetime.now().isoformat(),
                "findings": [],
                "summary": {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }
            
            for finding in results.get("findings", []):
                severity = finding.get("severity", "unknown").lower()
                processed_results["findings"].append({
                    "id": finding.get("id"),
                    "title": finding.get("title"),
                    "severity": severity,
                    "description": finding.get("description"),
                    "location": finding.get("location"),
                    "recommendation": finding.get("recommendation")
                })
                processed_results["summary"][severity] += 1
                processed_results["summary"]["total"] += 1
                
        except Exception as e:
            logger.error(f"Error processing results for scan {scan_code}: {e}", exc_info=True)
            raise ValidationError(f"Failed to process scan results: {e}") from e
            
        # Save reports if output directory specified
        if output_dir:
            try:
                _save_report_content(
                    json.dumps(processed_results, indent=2),
                    output_dir,
                    "scan",
                    scan_code,
                    "results"
                )
            except Exception as e:
                logger.warning(f"Failed to save reports to {output_dir}: {e}", exc_info=True)
                # Don't fail the whole operation if report saving fails
                
        return processed_results
        
    except (ApiError, NetworkError, ValidationError, FileSystemError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing results for scan {scan_code}: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to process scan results: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e

def process_pending_files(scan_code: str) -> List[dict]:
    """
    Processes all pending files for a given scan.
    
    Args:
        scan_code: The scan code identifier
        
    Returns:
        List[dict]: List of processed file information
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network connectivity issues
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during processing
    """
    try:
        # Validate inputs
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Get pending files
        try:
            pending_files = api.get_pending_files(scan_code)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching pending files for scan {scan_code}: {e}", exc_info=True)
            raise NetworkError(f"Failed to fetch pending files: {e}") from e
        except Exception as e:
            logger.error(f"API error fetching pending files for scan {scan_code}: {e}", exc_info=True)
            raise ApiError(f"Failed to fetch pending files: {e}") from e
            
        if not pending_files:
            logger.info(f"No pending files found for scan {scan_code}")
            return []
            
        # Process each file
        processed_files = []
        for file_info in pending_files:
            try:
                file_id = file_info.get('id')
                if not file_id:
                    logger.warning(f"Skipping file with missing ID in scan {scan_code}")
                    continue
                    
                try:
                    api.process_pending_file(scan_code, file_id)
                    processed_files.append({
                        'id': file_id,
                        'name': file_info.get('name', 'unknown'),
                        'status': 'processed',
                        'timestamp': datetime.now().isoformat()
                    })
                except requests.exceptions.RequestException as e:
                    logger.error(f"Network error processing file {file_id}: {e}", exc_info=True)
                    processed_files.append({
                        'id': file_id,
                        'name': file_info.get('name', 'unknown'),
                        'status': 'failed',
                        'error': f"Network error: {str(e)}"
                    })
                except Exception as e:
                    logger.error(f"API error processing file {file_id}: {e}", exc_info=True)
                    processed_files.append({
                        'id': file_id,
                        'name': file_info.get('name', 'unknown'),
                        'status': 'failed',
                        'error': f"API error: {str(e)}"
                    })
                    
            except Exception as e:
                logger.error(f"Error processing file info: {e}", exc_info=True)
                continue
                
        return processed_files
        
    except (ApiError, NetworkError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing pending files for scan {scan_code}: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to process pending files: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e

def process_scan_status(scan_code: str) -> dict:
    """
    Processes and returns the status for a given scan.
    
    Args:
        scan_code: The scan code identifier
        
    Returns:
        dict: Processed scan status with progress information
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network connectivity issues
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during processing
    """
    try:
        # Validate inputs
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Get scan status
        try:
            status = api.get_scan_status(scan_code)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching status for scan {scan_code}: {e}", exc_info=True)
            raise NetworkError(f"Failed to fetch scan status: {e}") from e
        except Exception as e:
            logger.error(f"API error fetching status for scan {scan_code}: {e}", exc_info=True)
            raise ApiError(f"Failed to fetch scan status: {e}") from e
            
        if not status:
            logger.info(f"No status found for scan {scan_code}")
            return {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'status': 'unknown',
                'progress': 0,
                'details': {}
            }
            
        # Process status
        try:
            processed_status = {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'status': status.get('status', 'unknown'),
                'progress': status.get('progress', 0),
                'details': {
                    'started_at': status.get('started_at'),
                    'completed_at': status.get('completed_at'),
                    'total_files': status.get('total_files', 0),
                    'processed_files': status.get('processed_files', 0),
                    'failed_files': status.get('failed_files', 0),
                    'current_phase': status.get('current_phase'),
                    'error_message': status.get('error_message')
                }
            }
            
            return processed_status
            
        except Exception as e:
            logger.error(f"Error processing status for scan {scan_code}: {e}", exc_info=True)
            raise ValidationError(f"Failed to process scan status: {e}") from e
            
    except (ApiError, NetworkError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing status for scan {scan_code}: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to process scan status: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e

def process_scan_metrics(scan_code: str) -> dict:
    """
    Processes and returns the metrics for a given scan.
    
    Args:
        scan_code: The scan code identifier
        
    Returns:
        dict: Processed scan metrics with performance information
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network connectivity issues
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during processing
    """
    try:
        # Validate inputs
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Get scan metrics
        try:
            metrics = api.get_scan_metrics(scan_code)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching metrics for scan {scan_code}: {e}", exc_info=True)
            raise NetworkError(f"Failed to fetch scan metrics: {e}") from e
        except Exception as e:
            logger.error(f"API error fetching metrics for scan {scan_code}: {e}", exc_info=True)
            raise ApiError(f"Failed to fetch scan metrics: {e}") from e
            
        if not metrics:
            logger.info(f"No metrics found for scan {scan_code}")
            return {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'performance': {
                    'total_time': 0,
                    'average_time_per_file': 0,
                    'files_per_second': 0
                },
                'resource_usage': {
                    'cpu_percent': 0,
                    'memory_usage': 0,
                    'disk_usage': 0
                }
            }
            
        # Process metrics
        try:
            processed_metrics = {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'performance': {
                    'total_time': metrics.get('total_time', 0),
                    'average_time_per_file': metrics.get('average_time_per_file', 0),
                    'files_per_second': metrics.get('files_per_second', 0)
                },
                'resource_usage': {
                    'cpu_percent': metrics.get('cpu_percent', 0),
                    'memory_usage': metrics.get('memory_usage', 0),
                    'disk_usage': metrics.get('disk_usage', 0)
                }
            }
            
            return processed_metrics
            
        except Exception as e:
            logger.error(f"Error processing metrics for scan {scan_code}: {e}", exc_info=True)
            raise ValidationError(f"Failed to process scan metrics: {e}") from e
            
    except (ApiError, NetworkError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing metrics for scan {scan_code}: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to process scan metrics: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e

def process_scan_logs(scan_code: str) -> dict:
    """
    Processes and returns the logs for a given scan.
    
    Args:
        scan_code: The scan code identifier
        
    Returns:
        dict: Processed scan logs with detailed information
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network connectivity issues
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during processing
    """
    try:
        # Validate inputs
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Get scan logs
        try:
            logs = api.get_scan_logs(scan_code)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching logs for scan {scan_code}: {e}", exc_info=True)
            raise NetworkError(f"Failed to fetch scan logs: {e}") from e
        except Exception as e:
            logger.error(f"API error fetching logs for scan {scan_code}: {e}", exc_info=True)
            raise ApiError(f"Failed to fetch scan logs: {e}") from e
            
        if not logs:
            logger.info(f"No logs found for scan {scan_code}")
            return {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'log_entries': [],
                'summary': {
                    'total_entries': 0,
                    'error_count': 0,
                    'warning_count': 0,
                    'info_count': 0
                }
            }
            
        # Process logs
        try:
            processed_logs = {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'log_entries': [
                    {
                        'timestamp': entry.get('timestamp'),
                        'level': entry.get('level', 'INFO'),
                        'message': entry.get('message', ''),
                        'details': entry.get('details', {})
                    }
                    for entry in logs
                ],
                'summary': {
                    'total_entries': len(logs),
                    'error_count': sum(1 for entry in logs if entry.get('level') == 'ERROR'),
                    'warning_count': sum(1 for entry in logs if entry.get('level') == 'WARNING'),
                    'info_count': sum(1 for entry in logs if entry.get('level') == 'INFO')
                }
            }
            
            return processed_logs
            
        except Exception as e:
            logger.error(f"Error processing logs for scan {scan_code}: {e}", exc_info=True)
            raise ValidationError(f"Failed to process scan logs: {e}") from e
            
    except (ApiError, NetworkError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing logs for scan {scan_code}: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to process scan logs: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e

def process_scan_results(scan_code: str) -> dict:
    """
    Processes and returns the results for a given scan.
    
    Args:
        scan_code: The scan code identifier
        
    Returns:
        dict: Processed scan results with detailed information
        
    Raises:
        ApiError: If there are API-related errors
        NetworkError: If there are network connectivity issues
        ValidationError: If there are data validation issues
        WorkbenchAgentError: For unexpected errors during processing
    """
    try:
        # Validate inputs
        if not scan_code:
            raise ValidationError("Scan code is not specified")
            
        # Get scan results
        try:
            results = api.get_scan_results(scan_code)
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching results for scan {scan_code}: {e}", exc_info=True)
            raise NetworkError(f"Failed to fetch scan results: {e}") from e
        except Exception as e:
            logger.error(f"API error fetching results for scan {scan_code}: {e}", exc_info=True)
            raise ApiError(f"Failed to fetch scan results: {e}") from e
            
        if not results:
            logger.info(f"No results found for scan {scan_code}")
            return {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'findings': [],
                'summary': {
                    'total_findings': 0,
                    'critical_count': 0,
                    'high_count': 0,
                    'medium_count': 0,
                    'low_count': 0
                }
            }
            
        # Process results
        try:
            processed_results = {
                'scan_code': scan_code,
                'timestamp': datetime.now().isoformat(),
                'findings': [
                    {
                        'id': finding.get('id'),
                        'severity': finding.get('severity', 'UNKNOWN'),
                        'title': finding.get('title', ''),
                        'description': finding.get('description', ''),
                        'location': finding.get('location', {}),
                        'recommendation': finding.get('recommendation', ''),
                        'references': finding.get('references', [])
                    }
                    for finding in results
                ],
                'summary': {
                    'total_findings': len(results),
                    'critical_count': sum(1 for finding in results if finding.get('severity') == 'CRITICAL'),
                    'high_count': sum(1 for finding in results if finding.get('severity') == 'HIGH'),
                    'medium_count': sum(1 for finding in results if finding.get('severity') == 'MEDIUM'),
                    'low_count': sum(1 for finding in results if finding.get('severity') == 'LOW')
                }
            }
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Error processing results for scan {scan_code}: {e}", exc_info=True)
            raise ValidationError(f"Failed to process scan results: {e}") from e
            
    except (ApiError, NetworkError, ValidationError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error processing results for scan {scan_code}: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to process scan results: {e}", details={
            "error": str(e),
            "scan_code": scan_code
        }) from e
