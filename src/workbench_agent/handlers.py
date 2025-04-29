# workbench_agent/handlers.py

import os
import time
import logging
import argparse
import requests
import re
import json # Needed for saving results
from typing import Dict, List, Optional, Union, Any

# Import necessary components from other modules in the package
from .api import Workbench

from .utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    _save_report_content,
    _ensure_scan_compatibility,
    _fetch_display_save_results,
    _print_operation_summary
)
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

# --- Command Handlers ---

def handle_scan(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'scan' command. Uploads code, runs KB scan, optional DA, shows/saves results.
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        # Validate scan parameters
        if not params.path:
            raise ValidationError("Path is required for scan command")
        if not os.path.exists(params.path):
            raise FileSystemError(f"Path does not exist: {params.path}")

        # Resolve project and scan (find or create)
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        print("\nUploading Code for Analysis...")
        try:
            workbench.upload_files(scan_code, params.path, is_da_import=False)
            print(f"Upload initiated for path: {params.path}")
        except FileSystemError as e:
            raise FileSystemError(f"Failed to upload files from '{params.path}': {e}", details=getattr(e, 'details', None))
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Error during file upload from '{params.path}': {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error during file upload from '{params.path}' for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during file upload: {e}",
                                    details={"error": str(e), "path": params.path, "scan_code": scan_code})

        print("\nTriggering Archive Extraction...")
        try:
            extraction_triggered = workbench.extract_archives(
                scan_code, params.recursively_extract_archives, params.jar_file_extraction
            )
            if extraction_triggered:
                if workbench._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
                    print("Waiting for archive extraction to complete (using check_status)...")
                    workbench.wait_for_archive_extraction(
                        scan_code,
                        params.scan_number_of_tries,
                        5
                    )
                    print("Archive extraction completed.")
                else:
                    print("Skipping archive extraction status check (likely older Workbench)...")
                    print("Waiting 5 seconds before starting KB scan...")
                    time.sleep(5)
            else:
                 print("Archive extraction was not triggered (possibly no archives or API indicated completion immediately).")

        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during archive extraction for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during archive extraction: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # Execute the main scan flow (KB Scan -> Wait -> Optional DA -> Wait -> Summary -> Results)
        _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)

    except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, ApiError,
            NetworkError, ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})

def handle_scan_git(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'scan-git' command. Clones repo, runs KB scan, optional DA, shows/saves results.
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        if not params.git_url:
            raise ValidationError("Git URL is required for scan-git command")

        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        ref_display = f"branch: {params.git_branch}" if params.git_branch else f"tag: {params.git_tag}"
        print(f"\nStarting Git Clone: {params.git_url} ({ref_display}) for scan '{scan_code}'")

        try:
            payload_dl = {
                "group": "scans",
                "action": "download_content_from_git", # Assumed correct
                "data": {"scan_code": scan_code}
            }
            response_dl = workbench._send_request(payload_dl)
            if response_dl.get("status") != "1":
                raise ApiError(f"Failed to initiate download from Git: {response_dl.get('error', 'Unknown error')}",
                             details=response_dl)
            print("Git Clone initiated via API.")
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Failed to initiate Git clone: {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error initiating Git clone for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during Git clone initiation: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        print("\nWaiting for Git Clone to complete...")
        try:
            workbench._wait_for_process(
                process_description=f"Git Clone for scan '{scan_code}'",
                check_function=workbench._send_request,
                check_args={
                    "payload": {
                        "group": "scans",
                        "action": "check_status_download_content_from_git",
                        "data": {"scan_code": scan_code}
                    }
                },
                status_accessor=lambda response: response.get("data", "UNKNOWN"),
                success_values={"FINISHED"},
                failure_values={"FAILED", "ERROR"},
                max_tries=params.scan_number_of_tries,
                wait_interval=10,
                progress_indicator=True
            )

            print("Git Clone completed.")
        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error waiting for Git clone for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during Git clone waiting: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # Execute the main scan flow
        # _execute_standard_scan_flow now handles results internally via _fetch_display_save_results
        _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})

def handle_import_da(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'import-da' command. Uploads DA results, runs import, shows/saves results.
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        if not params.path:
            raise ValidationError("Path to DA results file is required for import-da command")
        if not os.path.isfile(params.path):
            raise FileSystemError(f"DA results path is not a valid file: {params.path}")

        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        print(f"\nUploading DA Results File: {params.path} for scan '{scan_code}'...")
        try:
            workbench.upload_files(scan_code, params.path, is_da_import=True)
            print("DA results file upload initiated.")
        except FileSystemError as e:
            raise FileSystemError(f"Failed to upload DA results file '{params.path}': {e}", details=getattr(e, 'details', None))
        except (ApiError, NetworkError) as e:
            raise WorkbenchAgentError(f"Error during DA results file upload from '{params.path}': {e}", details=getattr(e, 'details', None))
        except Exception as e:
            logger.error(f"Unexpected error during DA results upload from '{params.path}' for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during DA results file upload: {e}",
                                    details={"error": str(e), "path": params.path, "scan_code": scan_code})

        print("\nStarting DA Import process...")
        da_completed = False # Initialize here
        try:
            workbench.start_dependency_analysis(scan_code, import_only=True)
            workbench.wait_for_scan_to_finish(
                "DEPENDENCY_ANALYSIS",
                scan_code,
                params.scan_number_of_tries,
                params.scan_wait_time
            )
            print("DA Import process complete.")
            da_completed = True

        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError, ScanNotFoundError) as e:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during DA import for scan '{scan_code}': {e}", exc_info=True)
            raise WorkbenchAgentError(f"Unexpected error during DA import: {e}",
                                    details={"error": str(e), "scan_code": scan_code})

        # --- Print Summary ---
        _print_operation_summary(params, da_completed, project_code, scan_code)

        # --- Fetch, Display, and Save Results using the utility function ---
        _fetch_display_save_results(workbench, params, scan_code)

    except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, ApiError,
            NetworkError, ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})

def handle_show_results(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'show-results' command. Fetches, displays, and saves results for an existing scan.
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=False,
            params=params
        )

        print(f"\n--- Fetching Results for Scan '{scan_code}' (Project '{project_code}') ---")

        # --- Fetch, Display, and Save Results using the new utility function ---
        _fetch_display_save_results(workbench, params, scan_code)

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        raise
    except Exception as e:
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})

def handle_evaluate_gates(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Handler for the 'evaluate-gates' command. Checks scan status, pending files,
    and policy violations. Sets exit code based on --fail-on flag.

    Returns:
        bool: True if gate checks pass according to --fail-on, False otherwise.
    """
    print(f"\n--- Running Command: {params.command} ---")
    # Initialize check results
    found_pending = False
    found_policy_violations = False
    pending_files_details = {}
    policy_violations_details = []
    api_check_error = False # Flag if checks couldn't be performed

    try:
        # --- Resolve Project and Scan ---
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=False,
            params=params
        )

        print(f"\nEvaluating gates for scan '{scan_code}' (Project: '{project_code}')...")

        # --- 1. Check Scan Completion Status ---
        print("\nChecking KB Scan status...")
        try:
             kb_status_data = workbench.get_scan_status("SCAN", scan_code)
             kb_status = kb_status_data.get("progress_state", "UNKNOWN").upper()
             print(f"Current KB Scan status: {kb_status}")
             if kb_status not in {"FINISHED", "FAILED", "CANCELLED"}:
                 print("KB Scan is not finished. Waiting...")
                 workbench.wait_for_scan_to_finish(
                     "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
                 )
                 print("KB Scan finished.")
                 # Re-check status after waiting
                 kb_status_data = workbench.get_scan_status("SCAN", scan_code)
                 kb_status = kb_status_data.get("progress_state", "UNKNOWN").upper()

             if kb_status in {"FAILED", "CANCELLED"}:
                  print(f"Error: KB Scan {kb_status}. Cannot evaluate gates.")
                  # If scan itself failed, the gates implicitly fail regardless of --fail-on
                  return False

        except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
             print(f"\nError checking/waiting for KB Scan completion: {e}")
             logger.error(f"Error checking/waiting for KB scan '{scan_code}' during gate evaluation: {e}", exc_info=True)
             # If we can't confirm scan completion, fail the gates
             return False
        except Exception as e:
             print(f"\nUnexpected error checking KB Scan status: {e}")
             logger.error(f"Unexpected error checking KB scan '{scan_code}' status: {e}", exc_info=True)
             return False

        # --- 2. Check for Pending Identifications ---
        print("\nChecking for Pending Identifications...")
        try:
            pending_files_details = workbench.get_pending_files(scan_code)
            if pending_files_details:
                found_pending = True
                num_pending = len(pending_files_details)
                print(f"Check Result: Found {num_pending} file(s) with Pending Identification.")
                if params.show_files:
                    print("Files with Pending IDs:")
                    count = 0
                    for file_id, file_path in pending_files_details.items():
                        print(f"  - {file_path} (ID: {file_id})")
                        count += 1
                        if count >= 20:
                            print(f"  ... and {num_pending - count} more.")
                            break
            else:
                print("Check Result: No files found with Pending Identification.")
        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for pending identifications due to API/Network error: {e}")
            logger.warning(f"API/Network error checking pending files for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for pending identifications: {e}")
            logger.warning(f"Unexpected error checking pending files for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 3. Check Policy Violations ---
        print("\nChecking for Policy Violations...")
        try:
            policy_violations_details = workbench.get_policy_violations(scan_code) # Returns list of dicts or []
            total_violations = 0
            if policy_violations_details:
                for violation in policy_violations_details:
                    total_violations += violation.get('count', 0)

            if total_violations > 0:
                found_policy_violations = True
                print(f"Check Result: Found {total_violations} policy violation(s).")
                if params.show_policy_summary:
                    print("Policy Violation Summary:")
                    for violation in policy_violations_details:
                         print(f"  - Level: {violation.get('level', 'N/A')}, Count: {violation.get('count', 0)}")
            else:
                print("Check Result: No policy violations found.")

        except (ApiError, NetworkError) as e:
            print(f"\nWarning: Could not check for policy violations due to API/Network error: {e}")
            logger.warning(f"API/Network error checking policy violations for scan '{scan_code}': {e}")
            api_check_error = True # Mark that a check failed
        except Exception as e:
            print(f"\nWarning: Unexpected error checking for policy violations: {e}")
            logger.warning(f"Unexpected error checking policy violations for scan '{scan_code}': {e}", exc_info=True)
            api_check_error = True # Mark that a check failed

        # --- 4. Determine Final Gate Status based on --fail-on ---
        final_gates_passed = True
        failure_reason = []

        if api_check_error:
             # If we couldn't perform the checks reliably, fail the gate unless --fail-on is 'none'
             if params.fail_on != 'none':
                 final_gates_passed = False
                 failure_reason.append("API error during checks")
             else:
                 print("\nWarning: API errors occurred during checks, but --fail-on=none specified. Passing gates.")

        else:
            # Apply failure conditions based on checks performed
            if params.fail_on in ['pending', 'both'] and found_pending:
                final_gates_passed = False
                failure_reason.append("pending identifications found")

            if params.fail_on in ['policy', 'both'] and found_policy_violations:
                final_gates_passed = False
                failure_reason.append("policy violations found")

        # --- 5. Print Final Status ---
        print("\n--- Final Gate Status ---")
        if final_gates_passed:
            print("Result: PASSED")
        else:
            print(f"Result: FAILED (Reason(s): {', '.join(failure_reason)})")
        print("-------------------------")

        return final_gates_passed

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError,
            ProcessError, ProcessTimeoutError, ValidationError, CompatibilityError) as e:
        # If resolution or fundamental API calls fail, re-raise to indicate command failure
        raise
    except Exception as e:
        # Wrap unknown exceptions
        logger.error(f"Failed to execute '{params.command}' command: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Failed to execute {params.command} command: {str(e)}",
                                details={"error": str(e)})

def handle_download_reports(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'download-reports' command. Generates and downloads reports.
    """
    print(f"\n--- Running Command: {params.command} ---")

    report_scope = params.report_scope.lower()
    project_code = None
    scan_code = None
    scan_id = None
    entity_name_log = ""
    name_for_file = ""

    try:
        if report_scope == "project":
            if not params.project_name:
                raise ValidationError("--project-name is required when --report-scope is 'project'.")
            project_name = params.project_name
            print(f"Resolving project '{project_name}' for report generation...")
            project_code = _resolve_project(workbench, project_name, create_if_missing=False)
            entity_name_log = f"Project '{project_code}'"
            name_for_file = project_name

        elif report_scope == "scan":
            if not params.scan_name:
                 raise ValidationError("--scan-name is required when --report-scope is 'scan'.")
            scan_name = params.scan_name
            if params.project_name:
                print(f"Resolving scan '{scan_name}' within project '{params.project_name}'...")
                project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
                scan_code, scan_id = _resolve_scan(
                    workbench, scan_name, params.project_name, create_if_missing=False, params=params
                )
                entity_name_log = f"Scan '{scan_code}' (ID: {scan_id}) in Project '{project_code}'"
            else:
                print(f"Resolving scan '{scan_name}' globally...")
                scan_code, scan_id = _resolve_scan(
                    workbench, scan_name, project_name=None, create_if_missing=False, params=params
                )
                try:
                    all_scans = workbench.list_scans()
                    scan_info = next((s for s in all_scans if s.get('code') == scan_code), None)
                    if scan_info and scan_info.get('project_code'):
                        project_code = scan_info['project_code']
                        logger.debug(f"Resolved project_code '{project_code}' for globally found scan '{scan_code}'.")
                        entity_name_log = f"Scan '{scan_code}' (ID: {scan_id}) in Project '{project_code}'"
                    else:
                        raise ProjectNotFoundError(f"Could not determine project context for globally found scan '{scan_code}'. Scan Info: {scan_info}")
                except Exception as proj_lookup_err:
                     raise ProjectNotFoundError(f"Failed to find project context for globally resolved scan '{scan_code}': {proj_lookup_err}")

            name_for_file = scan_name

        else:
            raise ValidationError(f"Invalid report scope: {report_scope}. Must be 'scan' or 'project'.")

    except (ProjectNotFoundError, ScanNotFoundError, ValidationError) as e:
        raise
    except Exception as e:
        logger.error(f"Error resolving project/scan for report download: {e}", exc_info=True)
        raise WorkbenchAgentError(f"Error resolving project/scan: {str(e)}",
                                details={"error": str(e)})

    print(f"\n--- Generating and Downloading Reports for {entity_name_log} ---")

    report_types_to_download = []
    requested_type_input = params.report_type

    allowed_types = Workbench.PROJECT_REPORT_TYPES if report_scope == "project" else Workbench.SCAN_REPORT_TYPES
    allowed_types_list = sorted(list(allowed_types))

    if requested_type_input.upper() == "ALL":
        report_types_to_download = allowed_types_list
        print(f"Report Scope is '{report_scope}'. All available reports will be downloaded: {', '.join(report_types_to_download)}")
    else:
        requested_types_list = [t.strip().lower() for t in requested_type_input.split(',') if t.strip()]
        if not requested_types_list:
             raise ValidationError("No valid report types provided in --report-type (or input was empty after splitting).")

        print(f"Requested report types: {', '.join(requested_types_list)}")
        invalid_types = [req_type for req_type in requested_types_list if req_type not in allowed_types]

        if invalid_types:
            raise ValidationError(
                f"Invalid report type(s) for '{report_scope}' scope: {', '.join(invalid_types)}. "
                f"Allowed types are: {', '.join(allowed_types_list)}"
            )

        report_types_to_download = sorted(list(set(requested_types_list)))
        print(f"Processing validated report types: {', '.join(report_types_to_download)}")

    output_directory = params.report_save_path
    try:
        os.makedirs(output_directory, exist_ok=True)
        print(f"Reports will be saved to directory: {os.path.abspath(output_directory)}")
    except OSError as e:
        raise FileSystemError(f"Could not create output directory '{output_directory}': {e}") from e

    successful_reports = []
    failed_reports = []

    for report_type in report_types_to_download:
        print(f"\nProcessing '{report_type}' report...")
        process_id = None
        try:
            print(f"Requesting generation of '{report_type}' report...")
            generation_result = workbench.generate_report(
                scope=report_scope,
                project_code=project_code,
                scan_code=scan_code,
                report_type=report_type,
                selection_type=params.selection_type,
                selection_view=params.selection_view,
                disclaimer=params.disclaimer,
                include_vex=params.include_vex
            )
            logger.debug(f"generate_report result type: {type(generation_result)}, value: {generation_result}")

            if isinstance(generation_result, requests.Response):
                print(f"Synchronous report '{report_type}' generated directly.")
                _save_report_content(
                    generation_result,
                    output_directory,
                    report_scope=report_scope,
                    name_component=name_for_file,
                    report_type=report_type
                )
                successful_reports.append(report_type)
                continue

            elif isinstance(generation_result, int) and generation_result > 0:
                process_id = generation_result
                print(f"Asynchronous report generation started (Process ID: {process_id}). Waiting for completion...")

                try:
                    workbench._wait_for_process(
                        process_description=f"'{report_type}' report generation (Process ID: {process_id})",
                        check_function=workbench.check_report_generation_status,
                        check_args={
                            "scope": report_scope,
                            "process_id": process_id,
                            "scan_code": scan_code,
                            "project_code": project_code
                        },
                        status_accessor=lambda data: data.get("progress_state", "UNKNOWN"),
                        success_values={"FINISHED"},
                        failure_values={"FAILED", "CANCELLED"},
                        max_tries=params.scan_number_of_tries,
                        wait_interval=5,
                        progress_indicator=True
                    )
                    print(f"Report generation complete (Process ID: {process_id}).")
                except (ProcessTimeoutError, ProcessError, ApiError, NetworkError) as e:
                    raise ProcessError(f"Failed waiting for '{report_type}' report (Process ID: {process_id}): {e}", details=getattr(e, 'details', None)) from e
                except Exception as e:
                    logger.error(f"Unexpected error waiting for report '{report_type}' (Process ID: {process_id}): {e}", exc_info=True)
                    raise WorkbenchAgentError(f"Unexpected error waiting for report '{report_type}': {e}",
                                            details={"error": str(e), "process_id": process_id}) from e

                print(f"Downloading report '{report_type}' (Process ID: {process_id})...")
                try:
                    download_response = workbench.download_report(report_scope, process_id)
                    _save_report_content(
                        download_response,
                        output_directory,
                        report_scope=report_scope,
                        name_component=name_for_file,
                        report_type=report_type
                    )
                    successful_reports.append(report_type)
                except (ApiError, NetworkError) as e:
                    raise ApiError(f"Failed to download report '{report_type}' (Process ID: {process_id}): {e}", details=getattr(e, 'details', None)) from e
                except Exception as e:
                    logger.error(f"Unexpected error downloading report '{report_type}' (Process ID: {process_id}): {e}", exc_info=True)
                    raise WorkbenchAgentError(f"Unexpected error downloading report '{report_type}': {e}",
                                            details={"error": str(e), "process_id": process_id}) from e

            else:
                raise ProcessError(f"Unexpected result received from generate_report for '{report_type}': {generation_result}",
                                 details={"result": generation_result})

        except (ApiError, NetworkError, ProcessError, ProcessTimeoutError, FileSystemError, ValidationError) as e:
            print(f"Error processing '{report_type}' report: {e}")
            logger.warning(f"Failed to generate/download '{report_type}' report for {entity_name_log}. Error: {e}", exc_info=False)
            failed_reports.append(report_type)
        except Exception as e:
            print(f"Unexpected error processing '{report_type}' report: {e}")
            logger.error(f"Unexpected error processing '{report_type}' report for {entity_name_log}.", exc_info=True)
            failed_reports.append(report_type)

    print("\n--- Report Download Summary ---")
    if successful_reports:
        print(f"Successfully processed {len(successful_reports)} report(s): {', '.join(successful_reports)}")
    else:
        print("No reports were successfully processed.")
    if failed_reports:
        print(f"Failed to process {len(failed_reports)} report(s): {', '.join(failed_reports)}")
    else:
        print("No reports failed to process.")
    print("-----------------------------")

    if failed_reports:
        raise ProcessError(f"Failed to process one or more reports: {', '.join(failed_reports)}",
                         details={"failed_reports": failed_reports, "successful_reports": successful_reports})

