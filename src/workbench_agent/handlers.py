# workbench_agent/handlers.py

import os
import sys
import time
import logging
import argparse
import re
import requests
import builtins # Still needed as exceptions weren't refactored yet
from typing import Generator, Optional, Dict, Any, List, Union, Tuple

# Import necessary components from other modules in the package
from .api import Workbench
from .utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    fetch_and_process_results,
    _save_report_content
)

# Assume logger is configured in main.py and get it
logger = logging.getLogger("log")

# --- Command Handlers ---

def handle_scan(workbench: Workbench, params: argparse.Namespace):
    """Handler for the 'scan' command."""
    print(f"\n--- Running Command: {params.command} ---")
    project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)

    scan_code, scan_id = _resolve_scan(
        workbench,
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params
    )

    print("Uploading Code for Analysis...")
    workbench.upload_files(scan_code, params.path, is_da_import=False)

    try:
        extraction_triggered = workbench.extract_archives(
            scan_code, params.recursively_extract_archives, params.jar_file_extraction
        )
        if extraction_triggered:
            if workbench._is_status_check_supported(scan_code, "EXTRACT_ARCHIVES"):
                print("Waiting for archive extraction to complete (new Workbench feature)...")
                workbench.wait_for_archive_extraction(
                    scan_code,
                    params.scan_number_of_tries,
                    5 # Use 5 seconds interval
                )
            else:
                print("Skipping archive extraction status check (likely older Workbench version).")
                print("Adding a short delay before starting KB scan...")
                time.sleep(10)

    except Exception as e:
        raise builtins.Exception(f"Error during archive extraction phase: {e}")

    _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)

def handle_scan_git(workbench: Workbench, params: argparse.Namespace):
    """Handler for the 'scan-git' command."""
    print(f"\n--- Running Command: {params.command} ---")
    project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
    scan_code, scan_id = _resolve_scan(
        workbench,
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params
    )

    ref_display = f"branch: {params.git_branch}" if params.git_branch else f"tag: {params.git_tag}"
    print(f"Starting Git Clone: {params.git_url} ({ref_display})")
    payload_dl = {
        "group": "scans",
        "action": "download_content_from_git",
        "data": {"scan_code": scan_code}
    }
    response_dl = workbench._send_request(payload_dl)
    if response_dl.get("status") != "1":
        raise Exception(f"Failed to download from Git: {response_dl.get('error', 'Unknown error')}")
    print("Git Clone initiated.")

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
            failure_values={"FAILED"},
            max_tries=params.scan_number_of_tries,
            wait_interval=3,
            progress_indicator=True
        )
    except Exception as wait_err:
        raise builtins.Exception(f"Waiting for Git download failed: {wait_err}")

    _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)

def handle_import_da(workbench: Workbench, params: argparse.Namespace):
    """Handler for the 'import-da' command."""
    print(f"\n--- Running Command: {params.command} ---")
    project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
    scan_code, scan_id = _resolve_scan(
        workbench,
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=True,
        params=params
    )

    print("Importing DA Results...")
    workbench.upload_files(scan_code, params.path, is_da_import=True)
    workbench.assert_dependency_analysis_can_start(scan_code)
    workbench.start_dependency_analysis(scan_code, import_only=True)

    da_import_check_interval = 5
    print(f"Using DA import status check interval: {da_import_check_interval}s")

    try:
        def da_import_status_accessor(data):
            status_val = data.get("status", "UNKNOWN")
            is_finished_flag = data.get("is_finished")
            is_finished = str(is_finished_flag).lower() == "true" or str(is_finished_flag) == "1"
            if is_finished and status_val not in ["FAILED", "CANCELLED"]:
                return "FINISHED"
            return status_val

        workbench._wait_for_process(
            process_description=f"Importing DA Results into the '{scan_code}' scan.",
            check_function=workbench.get_scan_status,
            check_args={"scan_type": "DEPENDENCY_ANALYSIS", "scan_code": scan_code},
            status_accessor=da_import_status_accessor,
            success_values={"FINISHED"},
            failure_values={"FAILED", "CANCELLED"},
            max_tries=params.scan_number_of_tries,
            wait_interval=da_import_check_interval,
            progress_indicator=True
        )
    except Exception as wait_err:
        raise builtins.Exception(f"Waiting for DA import failed: {wait_err}")

    print("\n--- Operation Summary ---")
    print(f"Dependency Analysis results were successfully added to Scan '{scan_code}'.")
    print("--------------------\n")

    fetch_and_process_results(workbench, params, project_code, scan_code, scan_id)

def handle_show_results(workbench: Workbench, params: argparse.Namespace):
    """Handler for the 'show-results' command."""
    print(f"\n--- Running Command: {params.command} ---")
    project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
    scan_code, scan_id = _resolve_scan(
        workbench,
        scan_name=params.scan_name,
        project_name=params.project_name,
        create_if_missing=False,
        params=params
    )

    print(f"\n--- Fetching Results for the Scan '{scan_code}' in the Project '{project_code}'...) ---")
    fetch_and_process_results(workbench, params, project_code, scan_code, scan_id)

def handle_evaluate_gates(workbench: Workbench, params: argparse.Namespace) -> bool:
    """
    Handler for the 'evaluate-gates' command.
    Waits for scan completion, checks pending IDs and policy violations.
    Returns True if gates pass, False otherwise.
    """
    print(f"\n--- Running Command: {params.command} ---")
    gate_failed = False
    scan_code = None
    scan_id = None
    links = {}

    try:
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=False,
            params=params
        )
        print(f"\n--- Evaluating Gates for Scan '{scan_code}' (ID: {scan_id}, Project: '{project_code}') ---")

        base_url_for_link = re.sub(r'/api\.php$', '', params.api_url).rstrip('/')
        links = workbench.generate_links(base_url_for_link, scan_id)
        print(f"\nScan Workbench URL: {links['main_scan_link']}")
        workbench.set_env_variable("FOSSID_SCAN_URL", links["main_scan_link"])

        print("\nChecking scan status and waiting for completion if necessary...")
        workbench.wait_for_scan_to_finish(
            "SCAN", scan_code, params.scan_number_of_tries, params.scan_wait_time
        )
        print("Scan status: FINISHED.")

        print("\nChecking for Pending Identifications...")
        pending_files_dict = workbench.get_pending_files(scan_code)
        if pending_files_dict:
            count = len(pending_files_dict)
            print(f"Result: {count} files found with Pending Identifications.")
            logger.warning(f"Gate Evaluation: {count} pending identifications found for scan '{scan_code}'.")
            gate_failed = True

            if params.show_files:
                print("Files with Pending Identifications:")
                try:
                    sorted_files = sorted(pending_files_dict.values())
                    for file_path in sorted_files:
                        print(f"  - {file_path}")
                except Exception as e:
                    print(f"\nWarning: Error occurred while listing pending files: {e}")
                    logger.warning(f"Error listing pending files for scan '{scan_code}'", exc_info=True)

            print(f"Review Pending Items in Workbench: {links['pending_link']}")
        else:
            print("Result: No files found with Pending Identifications.")

        if params.policy_check:
            print("\nChecking for Policy Violations...")
            policy_data = workbench.get_policy_warnings_info(scan_code)
            policy_warnings_list = policy_data.get("policy_warnings_list", [])

            if policy_warnings_list:
                total_violation_count = len(policy_warnings_list)
                print(f"Result: {total_violation_count} policies with violations!")
                logger.warning(f"Gate Evaluation: {total_violation_count} policy violations found for scan '{scan_code}'.")
                gate_failed = True

                for warning in policy_warnings_list:
                    findings = warning.get("findings", "N/A")
                    if warning.get("license_id"):
                        lic_info = warning.get("license_info", {})
                        identifier = lic_info.get("rule_lic_identifier", "Unknown License")
                        print(f"  - License Violation: {identifier} - {findings} files")
                    elif warning.get("license_category"):
                         category = warning.get("license_category", "Unknown Category")
                         print(f"  - Category Violation: {category} - {findings} files")
                    else:
                         print(f"  - Unknown Violation Type: Findings={findings}, Details={warning}")

                print(f"Review Policy Violations in Workbench: {links['policy_link']}")
            else:
                print("Result: No policy violations found.")
        else:
            print("\nPolicy violation check skipped as --policy-check was not specified.")

    except Exception as e:
        print(f"\nError during gate evaluation: {e}")
        logger.error(f"Gate evaluation failed for scan '{params.scan_name}':", exc_info=True)
        gate_failed = True

    print("\n--- Gate Evaluation Result ---")
    if gate_failed:
        print("Status: FAILED")
    else:
        print("Status: PASSED")
    print("----------------------------")

    return not gate_failed

def handle_download_reports(workbench: Workbench, params: argparse.Namespace):
    """Handler for the 'download-reports' command."""
    print(f"\n--- Running Command: {params.command} ---")

    report_scope = params.report_scope.lower()
    project_code = None
    scan_code = None
    scan_id = None
    entity_name_log = ""

    try:
        if report_scope == "scan":
            scan_name = params.scan_name
            scan_code, scan_id = _resolve_scan(
                workbench,
                scan_name=scan_name,
                project_name=params.project_name,
                create_if_missing=False,
                params=params
            )
            if params.project_name:
                project_code = _resolve_project(workbench, params.project_name, create_if_missing=False)
                entity_name_log = f"Scan '{scan_code}' (ID: {scan_id}) in Project '{project_code}'"
            else:
                entity_name_log = f"Scan '{scan_code}' (ID: {scan_id}, Project resolved internally)"
                try:
                    all_scans = workbench.list_scans()
                    scan_info = next((s for s in all_scans if s.get('code') == scan_code), None)
                    if scan_info and scan_info.get('project_code'):
                        project_code = scan_info['project_code']
                        logger.debug(f"Resolved project_code '{project_code}' for globally found scan '{scan_code}'.")
                    else:
                        raise builtins.Exception(f"Could not determine project_code for globally found scan '{scan_code}'.")
                except Exception as proj_lookup_err:
                     raise builtins.Exception(f"Failed to find project context for globally resolved scan '{scan_code}': {proj_lookup_err}")

        elif report_scope == "project":
            project_name = params.project_name
            print(f"Finding project '{project_name}'...")
            project_code = _resolve_project(workbench, project_name, create_if_missing=False)
            entity_name_log = f"Project '{project_code}'"

    except Exception as e:
        # Raise exception to be caught by main error handler
        raise builtins.Exception(f"Error resolving project/scan: {e}") from e

    print(f"\n--- Generating and Downloading Reports for {entity_name_log} ---")

    report_types_to_download = []
    requested_type_input = params.report_type

    if requested_type_input.upper() == "ALL":
        if report_scope == "project":
            allowed_types = Workbench.PROJECT_REPORT_TYPES
            report_types_to_download = sorted(list(allowed_types))
            print(f"Report Scope is 'project'. All available reports will be downloaded: {', '.join(report_types_to_download)}")
        else:
            allowed_types = Workbench.SCAN_REPORT_TYPES
            report_types_to_download = sorted(list(allowed_types))
            print(f"Report Scope is 'scan'. All available reports will be downloaded: {', '.join(report_types_to_download)}")
    else:
        requested_types_list = [t.strip().lower() for t in requested_type_input.split(',') if t.strip()]
        if not requested_types_list:
             raise ValueError("No valid report types provided in --report-type.")

        print(f"The following report types will be downloaded: {', '.join(requested_types_list)}")
        allowed_types = Workbench.PROJECT_REPORT_TYPES if report_scope == "project" else Workbench.SCAN_REPORT_TYPES
        invalid_types = [req_type for req_type in requested_types_list if req_type not in allowed_types]

        if invalid_types:
            raise ValueError(
                f"These report type(s) are not available for the '{report_scope}' scope: {', '.join(invalid_types)}. "
                f"Allowed types for '{report_scope}' scope are: {', '.join(sorted(list(allowed_types)))}"
            )

        report_types_to_download = sorted(list(set(requested_types_list)))
        print(f"Processing validated report types: {', '.join(report_types_to_download)}")

    output_directory = params.report_save_path
    try:
        os.makedirs(output_directory, exist_ok=True)
        print(f"Reports will be saved to directory: {output_directory}")
    except OSError as e:
        raise builtins.Exception(f"Could not create output directory '{output_directory}': {e}") from e

    successful_reports = []
    failed_reports = []

    for report_type in report_types_to_download:
        # Determine the name component for the filename
        name_for_file = params.project_name if report_scope == "project" else params.scan_name
        print(f"\nGenerating {report_type} Report...")
        try:
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
                if report_scope == "project":
                     logger.warning(f"Received synchronous response for project report '{report_type}', which was not expected. Processing anyway.")
                logger.debug("Synchronous report generation detected.")
                _save_report_content(
                    generation_result,
                    output_directory,
                    report_scope=report_scope,
                    name_component=name_for_file,
                    report_type=report_type
                )
                successful_reports.append(report_type)
                print(f"Synchronous report '{report_type}' saved.") # Add confirmation
                continue

            elif isinstance(generation_result, int) and generation_result > 0:
                process_id = generation_result
                logger.debug(f"Asynchronous report generation started (Process ID: {process_id}).")
                print(f"Waiting for report to be ready...")
                try:
                    workbench._wait_for_process(
                        process_description=f"The {report_type} report is generating. Monitoring Process ID: {process_id})",
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
                except Exception as wait_err:
                    raise builtins.Exception(f"Waiting for report generation failed: {wait_err}")

                logger.debug(f"Downloading Report for process ID: {process_id}")
                download_response = workbench.download_report(report_scope, process_id)
                _save_report_content(
                    download_response,
                    output_directory,
                    report_scope=report_scope,
                    name_component=name_for_file,
                    report_type=report_type
                )
                successful_reports.append(report_type)
                print(f"Asynchronous report '{report_type}' saved.") # Add confirmation

            else:
                raise builtins.Exception(f"Unexpected result from generate_report: {generation_result}")

        except Exception as e:
            print(f"Error processing '{report_type}' report: {e}")
            logger.warning(f"Failed to generate/download {entity_name_log} {report_type}.", exc_info=False)
            failed_reports.append(report_type)

    print("\n--- Download Summary ---")
    if successful_reports: print(f"Successfully processed {len(successful_reports)} report(s) ({', '.join(successful_reports)})")
    else: print("No reports were successfully processed.")
    if failed_reports: print(f"Failed to process: {len(failed_reports)} report(s) ({', '.join(failed_reports)})")
    else: print("No reports failed to process.")
    print("------------------------")
    if failed_reports:
        # Raise an exception if any reports failed, to signal overall failure
        raise builtins.Exception(f"Failed to process one or more reports: {', '.join(failed_reports)}")
