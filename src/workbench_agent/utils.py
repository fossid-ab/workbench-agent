# workbench_agent/utils.py

import os
import sys
import json
import time
import logging
import argparse
import re
import requests
import builtins # Still needed as exceptions weren't refactored yet
from typing import Generator, Optional, Dict, Any, List, Union, Tuple

# Import Workbench class for type hinting and accessing constants/methods if needed
# Use relative import within the package
from .api import Workbench

# Assume logger is configured in main.py and get it
logger = logging.getLogger("log")

# --- Project and Scan Resolution ---

def _resolve_project(workbench: Workbench, project_name: str, create_if_missing: bool = False) -> str:
    """
    Finds a project by name, optionally creating it if it doesn't exist.

    Args:
        workbench: The initialized Workbench object.
        project_name: The name of the project to find or create.
        create_if_missing: If True, create the project if it's not found.
                           If False, raise an Exception if it's not found.

    Returns:
        The project_code (str) of the found or created project.

    Raises:
        builtins.Exception: If listing fails, or if create_if_missing is False
                            and the project is not found, or if creation fails.
    """
    print(f"Resolving project '{project_name}' (Create if missing: {create_if_missing})...")
    try:
        all_projects = workbench.list_projects()
    except Exception as e:
        raise builtins.Exception(f"Failed to list projects while resolving '{project_name}': {e}") from e

    found_project = next((p for p in all_projects if p.get('project_name') == project_name), None)

    if found_project:
        project_code = found_project.get('project_code')
        if project_code:
            print(f"Found existing project '{project_name}' with code '{project_code}'.")
            return project_code
        else:
            # Should not happen if list_projects is correct, but good practice
            raise builtins.Exception(f"Found project '{project_name}' but it is missing the 'project_code' field.")
    else:
        # Project not found
        if create_if_missing:
            print(f"Project '{project_name}' not found. Creating it...")
            try:
                # workbench.create_project already handles potential race conditions
                # and returns the code whether it created it or found it during its own check.
                project_code = workbench.create_project(project_name)
                # create_project prints its own success message
                return project_code
            except Exception as e:
                # Catch potential errors during creation
                raise builtins.Exception(f"Failed to create project '{project_name}': {e}") from e
        else:
            # Creation not allowed, raise error
            error_msg = f"Project '{project_name}' not found, and creation was not requested."
            logger.error(error_msg)
            raise builtins.Exception(error_msg)

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
        logger.error(f"Incompatible usage for existing scan '{scan_code}': {error_message}") # Use passed scan_code
        # Raise exception instead of sys.exit
        raise builtins.Exception(f"Incompatible usage for existing scan '{scan_code}': {error_message}")
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
        builtins.Exception: If listing fails, scan not found (and create_if_missing is False),
                            multiple scans found in global search, creation fails,
                            or compatibility check fails.
        ValueError: If create_if_missing is True but project_name is None.
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
            raise builtins.Exception(f"Failed to list scans {search_context} while resolving '{scan_name}': {e}") from e
    else:
        # Global search
        search_context = "globally"
        print(f"Resolving scan '{scan_name}' globally (Create if missing: {create_if_missing})...")
        if create_if_missing:
            # We cannot create a scan without a project context.
            raise ValueError("Cannot create a scan (create_if_missing=True) without specifying a --project-name.")
        try:
            scan_list = workbench.list_scans() # list_scans adds 'id' and 'code'
        except Exception as e:
            raise builtins.Exception(f"Failed to list all scans while resolving '{scan_name}' globally: {e}") from e

    # 2. Search for Scan by Name
    found_scans = [s for s in scan_list if s.get('name') == scan_name]

    # 3. Handle Search Results
    if len(found_scans) == 1:
        # Exactly one scan found
        scan_info = found_scans[0]
        scan_code = scan_info.get('code')
        scan_id_str = scan_info.get('id')
        resolved_project_code = scan_info.get('project_code', project_code) # Use project_code from scan info if available (global search)

        if not scan_code or scan_id_str is None:
            raise builtins.Exception(f"Found scan '{scan_name}' {search_context} but it's missing required 'code' or 'id' fields.")

        try:
            scan_id = int(scan_id_str)
            print(f"Found existing scan '{scan_name}' with code '{scan_code}' and ID {scan_id} (Project: {resolved_project_code}).")

            # Perform compatibility check ONLY if the scan existed AND creation was a possibility
            # (i.e., called from scan, import-da, scan-git)
            if create_if_missing:
                _ensure_scan_compatibility(params, scan_info, scan_code)

            return scan_code, scan_id
        except (ValueError, TypeError):
            raise builtins.Exception(f"Found scan '{scan_name}' {search_context} but its ID '{scan_id_str}' is not a valid integer.")

    elif len(found_scans) > 1:
        # Multiple scans found (only possible in global search)
        project_codes = [s.get('project_code', 'UnknownProject') for s in found_scans]
        raise builtins.Exception(
            f"Multiple scans found globally with the name '{scan_name}' in projects: {', '.join(project_codes)}. "
            f"Please specify the --project-name to disambiguate."
        )
    else:
        # No scan found
        if create_if_missing:
            # Creation is requested and allowed (project_name must be set, checked earlier)
            print(f"Scan '{scan_name}' not found {search_context}. Creating it...")
            if not project_code: # Should be impossible due to earlier checks, but safeguard
                 raise ValueError("Internal Error: project_code not resolved before scan creation attempt.")
            try:
                # Prepare Git details if needed
                create_git_url = getattr(params, 'git_url', None) if params.command == 'scan-git' else None
                create_git_branch = getattr(params, 'git_branch', None) if params.command == 'scan-git' else None
                create_git_tag = getattr(params, 'git_tag', None) if params.command == 'scan-git' else None
                create_git_depth = getattr(params, 'git_depth', None) if params.command == 'scan-git' else None

                # Trigger creation
                creation_triggered = workbench.create_webapp_scan(
                    scan_name,
                    project_code,
                    git_url=create_git_url,
                    git_branch=create_git_branch,
                    git_tag=create_git_tag,
                    git_depth=create_git_depth
                )

                # List again to find the code and ID (essential)
                print(f"Verifying scan details for '{scan_name}' in project '{project_code}' after creation attempt...")
                time.sleep(3) # Small delay for potential backend consistency
                project_scans_after_create = workbench.get_project_scans(project_code)
                scan_info_after_create = next((s for s in project_scans_after_create if s.get('name') == scan_name), None)

                if scan_info_after_create:
                    scan_code = scan_info_after_create.get('code')
                    scan_id_str = scan_info_after_create.get('id')
                    if not scan_code or not scan_id_str:
                        raise builtins.Exception(f"Found scan '{scan_name}' after creation attempt but it's missing required 'code' or 'id' fields.")
                    try:
                        scan_id = int(scan_id_str)
                        if creation_triggered:
                            print(f"Scan '{scan_name}' created successfully with code '{scan_code}' and ID {scan_id}.")
                        else:
                            print(f"Scan '{scan_name}' found after creation attempt (likely existed) with code '{scan_code}' and ID {scan_id}.")
                        # No compatibility check needed for newly created scan
                        return scan_code, scan_id
                    except (ValueError, TypeError):
                        raise builtins.Exception(f"Found scan '{scan_name}' after creation attempt but its ID '{scan_id_str}' is not a valid integer.")
                else:
                    # Critical error - creation reported success/existence but scan not found
                    raise builtins.Exception(f"Critical Error: Scan '{scan_name}' not found in project '{project_code}' after creation request.")

            except Exception as e:
                # Catch potential errors during creation trigger or the subsequent list/find
                raise builtins.Exception(f"Failed to create or verify scan '{scan_name}' {search_context}: {e}") from e
        else:
            # Creation not allowed, raise error
            error_msg = f"Scan '{scan_name}' not found {search_context}, and creation was not requested."
            logger.error(error_msg)
            raise builtins.Exception(error_msg)

# --- File Saving ---

def _save_report_content(
    response: requests.Response,
    output_path: str,
    report_scope: str,
    name_component: str, # Will be project_name or scan_name from params
    report_type: str
):
    """
    Handles saving report content from a requests.Response object into the specified directory.
    Constructs filename based on scope, name, and type.
    """
    logger.debug(f"Attempting to save report content to directory: {output_path}")

    final_output_path = None
    invalid_chars = r'[\\/*?:"<>|]'
    safe_name_component = re.sub(invalid_chars, '_', name_component) if name_component else "unknown_name"
    safe_report_type = re.sub(invalid_chars, '_', report_type)
    safe_report_scope = re.sub(invalid_chars, '_', report_scope)

    content_type = response.headers.get('content-type', '').split(';')[0].strip()
    extension_map = {
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
        'application/vnd.ms-excel': '.xls',
        'application/zip': '.zip',
        'application/spdx+json': '.spdx.json',
        'application/vnd.cyclonedx+json': '.cdx.json',
        'application/json': '.json',
        'text/html': '.html',
        'text/plain': '.txt',
        'application/pdf': '.pdf',
        'application/octet-stream': '.bin',
    }
    extension = extension_map.get(content_type, '.bin')
    logger.debug(f"Determined extension '{extension}' from Content-Type '{content_type}'")

    new_filename = f"{safe_report_scope}-{safe_name_component}-{safe_report_type}{extension}"
    final_output_path = os.path.join(output_path, new_filename)
    logger.info(f"Constructed report filename: {new_filename}")

    output_dir = os.path.dirname(final_output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    else:
         logger.error("Invalid output directory path derived for saving report.")
         raise ValueError("Invalid output directory path derived.")

    print(f"Saving report content to: {final_output_path}")
    bytes_written = 0
    try:
        with open(final_output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    bytes_written += len(chunk)
        if bytes_written == 0:
             logger.warning(f"Saved report file '{final_output_path}' is empty (0 bytes).")
    except IOError as write_err:
         logger.error(f"Failed to write report to file '{final_output_path}': {write_err}", exc_info=True)
         raise builtins.Exception(f"Failed to write report content to '{final_output_path}': {write_err}")
    except Exception as e:
         logger.error(f"Unexpected error saving report content: {e}", exc_info=True)
         raise

def save_results(save_path_arg: str, results_dict: dict, scan_code: str):
    """Saves the results dictionary to a specified path as a JSON file."""
    if not save_path_arg or not results_dict:
        logger.info("No save path provided or no results collected, skipping save.")
        return

    fname = None
    _folder = None
    base_filename = f"wb_results_{scan_code}.json"

    if os.path.isdir(save_path_arg):
        _folder = save_path_arg
        fname = os.path.join(_folder, base_filename)
    elif save_path_arg.endswith(os.path.sep) or save_path_arg.endswith('/'):
        _folder = save_path_arg
        fname = os.path.join(_folder, base_filename)
    else:
        _folder = os.path.dirname(save_path_arg)
        _basename = os.path.basename(save_path_arg)
        if not _basename:
             _folder = save_path_arg
             fname = os.path.join(_folder, base_filename)
        elif not _basename.lower().endswith(".json"):
             if os.path.exists(save_path_arg) and os.path.isdir(save_path_arg):
                  _folder = save_path_arg
                  fname = os.path.join(_folder, base_filename)
             else:
                  fname = save_path_arg if _folder else os.path.join(".", save_path_arg)
                  if not fname.lower().endswith(".json"):
                       fname += ".json"
                  _folder = os.path.dirname(fname)
        else:
             fname = save_path_arg
             _folder = os.path.dirname(fname)

    if not _folder:
        _folder = "."
        fname = os.path.join(_folder, fname)

    if not os.path.exists(_folder):
        try:
            os.makedirs(_folder, exist_ok=True)
            print(f"Created directory for results: {_folder}")
        except OSError as e:
            print(f"Error: Could not create directory '{_folder}': {e}")
            logger.error(f"Error creating directory {_folder}", exc_info=True)
            return

    try:
        with open(fname, "w", encoding='utf-8') as file:
            json.dump(results_dict, file, indent=4, ensure_ascii=False)
            print(f"Scan results saved to: {fname}")
            logger.info(f"Scan results saved to: {fname}")
    except IOError as e:
        print(f"Error: Could not write results to file '{fname}': {e}")
        logger.error(f"Error writing results to {fname}", exc_info=True)
    except TypeError as e:
         print(f"Error: Could not serialize results to JSON for saving to '{fname}': {e}")
         logger.error(f"Error serializing results to JSON", exc_info=True)

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
                 raise ValueError("Missing project name in --id-reuse-source for ID reuse type 'project'.")
            print(f"Retrieving project code for the ID Reuse source Project named: '{user_provided_name_for_reuse}'...")
            try:
                all_projects = workbench.list_projects()
                found_project = next((p for p in all_projects if p.get('project_name') == user_provided_name_for_reuse), None)
                if found_project and 'project_code' in found_project:
                    resolved_specific_code_for_reuse = found_project['project_code']
                    print(f"Found project code for reuse: '{resolved_specific_code_for_reuse}'")
                else:
                    raise builtins.Exception(f"The project source for identification reuse ('{user_provided_name_for_reuse}') was not found.")
            except Exception as e:
                raise builtins.Exception(f"Error looking up project code for reuse: {e}") from e

        elif user_reuse_type == "scan":
            if not user_provided_name_for_reuse:
                 raise ValueError("Missing scan name in --id-reuse-source for ID reuse type 'scan'.")
            print(f"Retrieving scan code for the ID Reuse source Scan named: '{user_provided_name_for_reuse}'...")
            try:
                all_scans = workbench.list_scans()
                found_scan = next((s for s in all_scans if s.get('name') == user_provided_name_for_reuse), None)
                if found_scan and 'code' in found_scan:
                    resolved_specific_code_for_reuse = found_scan['code']
                    print(f"Successfully retrieved scan code for ID Reuse Source Scan: '{resolved_specific_code_for_reuse}'")
                else:
                    raise builtins.Exception(f"The scan source for identification reuse ('{user_provided_name_for_reuse}') was not found.")
            except Exception as e:
                raise builtins.Exception(f"Error looking up scan code for reuse: {e}") from e

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
    except Exception as e:
        raise builtins.Exception(f"Failed to start KB scan: {e}")

    try:
        workbench.wait_for_scan_to_finish(
            "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
        )
        scan_completed = True
    except Exception as e:
        raise builtins.Exception(f"Error waiting for KB scan: {e}")

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
        except Exception as e:
            print(f"\nWarning: Optional Dependency Analysis failed: {e}")
            logger.warning(f"Optional DA failed for scan {scan_code}", exc_info=False)

    if scan_completed:
        _print_operation_summary(params, da_completed, project_code, scan_code)
        try:
            pending_files = workbench.get_pending_files(scan_code)
            print(f"KB Scan process complete! {len(pending_files)} files with Pending Identification.")
        except Exception as e:
            print(f"KB Scan process complete. Could not retrieve pending file count: {e}")
        print("--------------------\n")
        fetch_and_process_results(workbench, params, project_code, scan_code, scan_id)

def fetch_and_process_results(workbench: Workbench, params: argparse.Namespace, project_code: str, scan_code: str, scan_id: int):
    """
    Fetches requested scan results based on --show-* flags, displays them,
    and optionally saves all collected results to a JSON file.
    Requires scan_id for link generation.
    """
    print("\n--- Requested Scan Results ---")

    should_fetch_licenses = getattr(params, 'show_licenses', False)
    should_fetch_components = getattr(params, 'show_components', False)
    should_fetch_policy = getattr(params, 'show_policy_warnings', False)
    save_path = getattr(params, 'path_result', None)
    scan_name_for_summary = getattr(params, 'scan_name', scan_code)

    if not (should_fetch_licenses or should_fetch_components or should_fetch_policy):
        print("Nothing to show! Add (--show-licenses, --show-components, --show-policy-warnings) to see results.")
        main_scan_link = None
        if scan_id:
            try:
                base_url_for_link = re.sub(r'/api\.php$', '', params.api_url).rstrip('/')
                links = workbench.generate_links(base_url_for_link, scan_id)
                main_scan_link = links.get('main_scan_link')
            except Exception as link_err:
                logger.warning(f"Could not generate main scan link for scan ID {scan_id}: {link_err}")
        if main_scan_link:
            print(f"\nView scan '{scan_name_for_summary}' in Workbench here: {main_scan_link}")
        print("------------------------------------")
        return

    collected_results = {}
    da_results_data = None
    kb_licenses_data = None
    kb_components_data = None
    policy_warnings_data = None
    policy_details_list = None

    if should_fetch_licenses or should_fetch_components:
        try:
            print(f"Fetching Dependency Analysis results for '{scan_code}'...")
            da_results_data = workbench.get_dependency_analysis_results(scan_code)
            if da_results_data:
                print(f"Successfully fetched {len(da_results_data)} DA entries.")
                collected_results['dependency_analysis'] = da_results_data
            else:
                print("No Dependency Analysis data found or returned.")
        except Exception as e:
            print(f"Warning: Could not fetch Dependency Analysis results: {e}")
            logger.warning(f"Failed to fetch DA results for {scan_code}", exc_info=False)

    if should_fetch_licenses:
        try:
            print(f"Fetching KB Identified Licenses for '{scan_code}'...")
            kb_licenses_raw = workbench.get_scan_identified_licenses(scan_code)
            kb_licenses_data = sorted(kb_licenses_raw, key=lambda x: x.get('identifier', '').lower())
            if kb_licenses_data:
                print(f"Successfully fetched {len(kb_licenses_data)} unique KB licenses.")
                collected_results['kb_licenses'] = kb_licenses_data
            else:
                print("No KB Identified Licenses found.")
        except Exception as e:
            print(f"Warning: Could not fetch KB Identified Licenses: {e}")
            logger.warning(f"Failed to fetch KB licenses for {scan_code}", exc_info=False)

    if should_fetch_components:
        try:
            print(f"Fetching KB Identified Scan Components for '{scan_code}'...")
            kb_components_raw = workbench.get_scan_identified_components(scan_code)
            kb_components_data = sorted(kb_components_raw, key=lambda x: (x.get('name', '').lower(), x.get('version', '')))
            if kb_components_data:
                print(f"Successfully fetched {len(kb_components_data)} unique KB scan components.")
                collected_results['kb_components'] = kb_components_data
            else:
                print("No KB Identified Scan Components found.")
        except Exception as e:
            print(f"Warning: Could not fetch KB Identified Scan Components: {e}")
            logger.warning(f"Failed to fetch KB components for {scan_code}", exc_info=False)

    if should_fetch_policy:
        try:
            print(f"Fetching Scan Policy Warnings Counter for '{scan_code}'...")
            policy_warnings_data = workbench.scans_get_policy_warnings_counter(scan_code)
            print("Successfully fetched policy warnings counter.")
            collected_results['policy_warnings_summary'] = policy_warnings_data
        except Exception as e:
            print(f"Warning: Could not fetch Scan Policy Warnings Counter: {e}")
            logger.warning(f"Failed to fetch policy warnings counter for {scan_code}", exc_info=False)
            policy_warnings_data = None

        try:
            print(f"Fetching detailed policy warnings info for '{scan_code}'...")
            policy_details_data = workbench.get_policy_warnings_info(scan_code)
            policy_details_list = policy_details_data.get("policy_warnings_list")
            if policy_details_list:
                 print(f"Successfully fetched details for {len(policy_details_list)} policy violations.")
                 collected_results['policy_warnings_details'] = policy_details_list
            else:
                 print("No detailed policy violation information found.")
        except Exception as e:
            print(f"Warning: Could not fetch detailed policy warnings info: {e}")
            logger.warning(f"Failed to fetch policy details for {scan_code}", exc_info=False)
            policy_details_list = None # Ensure it's None on error

    print("\n--- Results Summary ---")
    displayed_something = False

    if should_fetch_licenses:
        print("\n=== License Findings ===")
        displayed_something = True
        kb_licenses_found = bool(kb_licenses_data)
        da_licenses_found = False

        if kb_licenses_found:
            print("From Signature Scanning (KB - Unique):")
            for lic in kb_licenses_data:
                identifier = lic.get('identifier', 'N/A')
                name = lic.get('name', 'N/A')
                print(f"  - {identifier}:{name}")
            print("-" * 25)

        if da_results_data:
            da_lic_names = sorted(list(set(
                comp.get('license_identifier', 'N/A') for comp in da_results_data if comp.get('license_identifier')
            )))
            if da_lic_names and any(name != 'N/A' for name in da_lic_names):
                print("From Dependency Analysis:")
                da_licenses_found = True
                for lic_name in da_lic_names:
                    if lic_name and lic_name != 'N/A':
                        print(f"  - {lic_name}")
                print("-" * 25)

        if not kb_licenses_found and not da_licenses_found:
            print("There are no licenses to show.")

    if should_fetch_components:
        print("\n=== Component Findings ===")
        displayed_something = True
        kb_components_found = bool(kb_components_data)
        da_components_found = bool(da_results_data)

        if kb_components_found:
            print("From Signature Scanning (KB):")
            for comp in kb_components_data:
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')}")
            print("-" * 25)

        if da_components_found:
            print("From Dependency Analysis:")
            da_results_data.sort(key=lambda x: (x.get('name', '').lower(), x.get('version', '')))
            for comp in da_results_data:
                scopes_display = "N/A"
                scopes_str = comp.get("projects_and_scopes")
                if scopes_str:
                    try:
                        scopes_data = json.loads(scopes_str)
                        scopes_list = sorted(list(set(
                            p_info.get("scope") for p_info in scopes_data.values() if isinstance(p_info, dict) and p_info.get("scope")
                        )))
                        if scopes_list: scopes_display = ", ".join(scopes_list)
                    except (json.JSONDecodeError, AttributeError, TypeError) as scope_err:
                        logger.debug(f"Could not parse scopes for DA component {comp.get('name')}: {scope_err}")
                        pass
                print(f"  - {comp.get('name', 'N/A')} : {comp.get('version', 'N/A')} "
                      f"(Scope: {scopes_display}, License: {comp.get('license_identifier', 'N/A')})")
            print("-" * 25)

        if not kb_components_found and not da_components_found:
            print("There are no components to show.")

    if should_fetch_policy:
        print("\n=== Scan Policy Warnings ===")
        displayed_something = True

        if policy_warnings_data is not None and isinstance(policy_warnings_data, dict):
            try: total_warnings = int(policy_warnings_data.get('policy_warnings_total', 0))
            except (ValueError, TypeError): total_warnings = 0
            try: files_warnings = int(policy_warnings_data.get('identified_files_with_warnings', 0))
            except (ValueError, TypeError): files_warnings = 0
            try: deps_warnings = int(policy_warnings_data.get('dependencies_with_warnings', 0))
            except (ValueError, TypeError): deps_warnings = 0

            summary_msg = (
                f"Summary: The '{scan_name_for_summary}' scan has {total_warnings} total policy warnings "
                f"({files_warnings} file findings, {deps_warnings} dependency findings)."
            )
            print(summary_msg)
        else:
            print("Summary: Policy warnings counter data could not be fetched or was invalid.")

        if policy_details_list:
            print("\n  Details:")
            policy_details_list.sort(key=lambda w: (
                w.get("type", ""),
                w.get("license_info", {}).get("rule_lic_identifier", "") if w.get("type") == "license" else w.get("license_category", "")
            ))
            for warning in policy_details_list:
                findings = warning.get("findings", "N/A")
                rule_type = warning.get("type")

                if rule_type == "license":
                    lic_info = warning.get("license_info", {})
                    identifier = lic_info.get("rule_lic_identifier", "Unknown License")
                    print(f"    - License Rule Violation: '{identifier}' ({findings} findings)")
                elif rule_type == "license_category":
                    category = warning.get("license_category", "Unknown Category")
                    print(f"    - Category Rule Violation: '{category}' ({findings} findings)")
                else:
                    print(f"    - Unknown Rule Type Violation: Type='{rule_type}' ({findings} findings)")
        elif policy_warnings_data is not None:
             print("\n  Details: No detailed policy violation information found.")

        policy_link = None
        if scan_id:
            try:
                base_url_for_link = re.sub(r'/api\.php$', '', params.api_url).rstrip('/')
                links = workbench.generate_links(base_url_for_link, scan_id)
                policy_link = links.get('policy_link')
            except Exception as link_err:
                logger.warning(f"Could not generate policy link for scan ID {scan_id}: {link_err}")

        if policy_link:
            print(f"\nReview Policy Violations in Workbench here: {policy_link}")
        else:
            print("\n(Could not generate direct link to policy review page.)")

        print("-" * 25)

    if not displayed_something:
        print("No results were successfully fetched or displayed for the specified flags.")

    print()
    main_scan_link = None
    if scan_id:
        try:
            base_url_for_link = re.sub(r'/api\.php$', '', params.api_url).rstrip('/')
            links = workbench.generate_links(base_url_for_link, scan_id)
            main_scan_link = links.get('main_scan_link')
        except Exception as link_err:
            logger.warning(f"Could not generate main scan link for scan ID {scan_id}: {link_err}")

    if main_scan_link:
        print(f"View more details in Workbench here: {main_scan_link}")
    else:
        print(f"(Could not generate direct link for scan '{scan_code}'.)")

    print("------------------------------------")

    if save_path:
        if collected_results:
            print(f"\nSaving collected results to '{save_path}'...")
            save_results(save_path, collected_results, scan_code)
        else:
            print("\nNo results were successfully collected, skipping save.")
