# workbench_agent/handlers.py

import os
import sys
import time
import logging
import argparse
import re
import requests
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
    Handler for the 'scan' command.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist and create_if_missing is False
        ScanNotFoundError: If the scan doesn't exist and create_if_missing is False
        FileSystemError: If there are issues accessing the files to upload
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If there are process-related errors
        ProcessTimeoutError: If a process times out
        ValidationError: If there are issues with scan parameters
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        # Validate scan parameters
        if not params.path:
            raise ValidationError("Path is required for scan command")
        if not os.path.exists(params.path):
            raise FileSystemError(f"Path does not exist: {params.path}")

        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        print("Uploading Code for Analysis...")
        try:
            workbench.upload_files(scan_code, params.path, is_da_import=False)
        except FileSystemError as e:
            raise FileSystemError(f"Failed to upload files: {e}", details=e.details)
        except ApiError as e:
            raise ApiError(f"API error during file upload: {e}", details=e.details)
        except NetworkError as e:
            raise NetworkError(f"Network error during file upload: {e}", details=e.details)
        except Exception as e:
            raise WorkbenchAgentError(f"Unexpected error during file upload: {e}", 
                                    details={"error": str(e)})

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
        except ProcessTimeoutError as e:
            raise ProcessTimeoutError(f"Archive extraction timed out: {e}", details=e.details)
        except ProcessError as e:
            raise ProcessError(f"Archive extraction failed: {e}", details=e.details)
        except Exception as e:
            raise WorkbenchAgentError(f"Unexpected error during archive extraction: {e}", 
                                    details={"error": str(e)})

        _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)
    except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, ApiError, 
            NetworkError, ProcessError, ProcessTimeoutError, ValidationError) as e:
        # Re-raise specific exceptions
        raise
    except Exception as e:
        # Wrap unknown exceptions
        raise WorkbenchAgentError(f"Failed to execute scan command: {str(e)}", 
                                details={"error": str(e)})

def handle_scan_git(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'scan-git' command.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist and create_if_missing is False
        ScanNotFoundError: If the scan doesn't exist and create_if_missing is False
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If there are process-related errors
        ProcessTimeoutError: If a process times out
        ValidationError: If there are issues with Git parameters
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        # Validate Git parameters
        if not params.git_url:
            raise ValidationError("Git URL is required for scan-git command")
        if params.git_branch and params.git_tag:
            raise ValidationError("Cannot specify both git branch and tag")
        if not (params.git_branch or params.git_tag):
            raise ValidationError("Must specify either git branch or tag")

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
        
        try:
            payload_dl = {
                "group": "scans",
                "action": "download_content_from_git",
                "data": {"scan_code": scan_code}
            }
            response_dl = workbench._send_request(payload_dl)
            if response_dl.get("status") != "1":
                raise ApiError(f"Failed to download from Git: {response_dl.get('error', 'Unknown error')}", 
                             details=response_dl)
            print("Git Clone initiated.")
        except ApiError as e:
            raise ApiError(f"Failed to initiate Git clone: {e}", details=e.details)
        except NetworkError as e:
            raise NetworkError(f"Network error during Git clone initiation: {e}", details=e.details)
        except Exception as e:
            raise WorkbenchAgentError(f"Unexpected error during Git clone initiation: {e}", 
                                    details={"error": str(e)})

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
        except ProcessTimeoutError as e:
            raise ProcessTimeoutError(f"Git clone operation timed out for scan '{scan_code}'", details=e.details)
        except ProcessError as e:
            raise ProcessError(f"Git clone operation failed for scan '{scan_code}'", details=e.details)
        except Exception as e:
            raise WorkbenchAgentError(f"Unexpected error during Git clone for scan '{scan_code}'", 
                                    details={"error": str(e)})

        _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)
    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError, 
            ProcessError, ProcessTimeoutError, ValidationError) as e:
        # Re-raise specific exceptions
        raise
    except Exception as e:
        # Wrap unknown exceptions
        raise WorkbenchAgentError(f"Failed to execute scan-git command: {str(e)}", 
                                details={"error": str(e)})

def handle_import_da(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'import-da' command.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist and create_if_missing is False
        ScanNotFoundError: If the scan doesn't exist and create_if_missing is False
        FileSystemError: If there are issues accessing the files to upload
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If there are process-related errors
        ProcessTimeoutError: If a process times out
    """
    print(f"\n--- Running Command: {params.command} ---")
    try:
        project_code = _resolve_project(workbench, params.project_name, create_if_missing=True)
        scan_code, scan_id = _resolve_scan(
            workbench,
            scan_name=params.scan_name,
            project_name=params.project_name,
            create_if_missing=True,
            params=params
        )

        print("Uploading DA Files for Analysis...")
        workbench.upload_files(scan_code, params.path, is_da_import=True)

        try:
            workbench._wait_for_process(
                process_description=f"DA Import for scan '{scan_code}'",
                check_function=workbench._send_request,
                check_args={
                    "payload": {
                        "group": "scans",
                        "action": "check_status_da_import",
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
        except ProcessTimeoutError as e:
            raise ProcessTimeoutError(f"DA import operation timed out for scan '{scan_code}'", details=e.details)
        except ProcessError as e:
            raise ProcessError(f"DA import operation failed for scan '{scan_code}'", details=e.details)
        except Exception as e:
            raise WorkbenchAgentError(f"Unexpected error during DA import for scan '{scan_code}'", 
                                    details={"error": str(e)})

        _execute_standard_scan_flow(workbench, params, project_code, scan_code, scan_id)
    except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, ApiError, 
            NetworkError, ProcessError, ProcessTimeoutError) as e:
        # Re-raise specific exceptions
        raise
    except Exception as e:
        # Wrap unknown exceptions
        raise WorkbenchAgentError(f"Failed to execute import-da command: {str(e)}", 
                                details={"error": str(e)})

def handle_show_results(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'show-results' command.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist
        ScanNotFoundError: If the scan doesn't exist
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If there are process-related errors
        ProcessTimeoutError: If a process times out
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

        print(f"\n--- Fetching Results for the Scan '{scan_code}' in the Project '{project_code}'...) ---")
        fetch_and_process_results(workbench, params, project_code, scan_code, scan_id)
    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError, 
            ProcessError, ProcessTimeoutError) as e:
        # Re-raise specific exceptions
        raise
    except Exception as e:
        # Wrap unknown exceptions
        raise WorkbenchAgentError(f"Failed to execute show-results command: {str(e)}", 
                                details={"error": str(e)})

def handle_evaluate_gates(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'evaluate-gates' command.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist
        ScanNotFoundError: If the scan doesn't exist
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If there are process-related errors
        ProcessTimeoutError: If a process times out
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

        print(f"Evaluating gates for scan '{scan_code}'...")
        try:
            workbench._wait_for_process(
                process_description=f"Gate evaluation for scan '{scan_code}'",
                check_function=workbench._send_request,
                check_args={
                    "payload": {
                        "group": "scans",
                        "action": "check_status_gate_evaluation",
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
        except ProcessTimeoutError as e:
            raise ProcessTimeoutError(f"Gate evaluation timed out for scan '{scan_code}'", details=e.details)
        except ProcessError as e:
            raise ProcessError(f"Gate evaluation failed for scan '{scan_code}'", details=e.details)
        except Exception as e:
            raise WorkbenchAgentError(f"Unexpected error during gate evaluation for scan '{scan_code}'", 
                                    details={"error": str(e)})

        print("\n--- Gate Evaluation Results ---")
        gates_result = workbench._send_request({
            "group": "scans",
            "action": "get_gates_result",
            "data": {"scan_code": scan_code}
        })

        if gates_result.get("status") != "1":
            raise ApiError(f"Failed to get gates result: {gates_result.get('error', 'Unknown error')}", 
                         details=gates_result)

        gates_data = gates_result.get("data", {})
        if not gates_data:
            print("No gate evaluation results available.")
            return

        for gate_name, gate_info in gates_data.items():
            status = gate_info.get("status", "UNKNOWN")
            details = gate_info.get("details", "")
            print(f"\nGate: {gate_name}")
            print(f"Status: {status}")
            if details:
                print(f"Details: {details}")

    except (ProjectNotFoundError, ScanNotFoundError, ApiError, NetworkError, 
            ProcessError, ProcessTimeoutError) as e:
        # Re-raise specific exceptions
        raise
    except Exception as e:
        # Wrap unknown exceptions
        raise WorkbenchAgentError(f"Failed to execute evaluate-gates command: {str(e)}", 
                                details={"error": str(e)})

def handle_download_reports(workbench: Workbench, params: argparse.Namespace):
    """
    Handler for the 'download-reports' command.
    
    Args:
        workbench: The Workbench API client instance
        params: Command line parameters
        
    Raises:
        ProjectNotFoundError: If the project doesn't exist
        ScanNotFoundError: If the scan doesn't exist
        FileSystemError: If there are issues accessing or creating directories
        ApiError: If there are API-related errors
        NetworkError: If there are network-related errors
        ProcessError: If there are process-related errors
        ProcessTimeoutError: If a process times out
        ValidationError: If there are issues with report type validation
    """
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
                        raise ProjectNotFoundError(f"Could not determine project_code for globally found scan '{scan_code}'.")
                except Exception as proj_lookup_err:
                     raise ProjectNotFoundError(f"Failed to find project context for globally resolved scan '{scan_code}': {proj_lookup_err}")

        elif report_scope == "project":
            project_name = params.project_name
            print(f"Finding project '{project_name}'...")
            project_code = _resolve_project(workbench, project_name, create_if_missing=False)
            entity_name_log = f"Project '{project_code}'"
        else:
            raise ValidationError(f"Invalid report scope: {report_scope}. Must be 'scan' or 'project'.")

    except (ProjectNotFoundError, ScanNotFoundError, ValidationError) as e:
        # Re-raise specific exceptions
        raise
    except Exception as e:
        # Wrap unknown exceptions
        raise WorkbenchAgentError(f"Error resolving project/scan: {str(e)}", 
                                details={"error": str(e)})

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
             raise ValidationError("No valid report types provided in --report-type.")

        print(f"The following report types will be downloaded: {', '.join(requested_types_list)}")
        allowed_types = Workbench.PROJECT_REPORT_TYPES if report_scope == "project" else Workbench.SCAN_REPORT_TYPES
        invalid_types = [req_type for req_type in requested_types_list if req_type not in allowed_types]

        if invalid_types:
            raise ValidationError(
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
        raise FileSystemError(f"Could not create output directory '{output_directory}': {e}") from e

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
                print(f"Synchronous report '{report_type}' saved.")
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
                except ProcessTimeoutError as e:
                    raise ProcessTimeoutError(f"Report generation timed out for {report_type}: {e}", details=e.details)
                except ProcessError as e:
                    raise ProcessError(f"Report generation failed for {report_type}: {e}", details=e.details)
                except Exception as e:
                    raise WorkbenchAgentError(f"Unexpected error during report generation for {report_type}: {e}", 
                                            details={"error": str(e)})

                logger.debug(f"Downloading Report for process ID: {process_id}")
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
                    print(f"Asynchronous report '{report_type}' saved.")
                except ApiError as e:
                    raise ApiError(f"Failed to download report {report_type}: {e}", details=e.details)
                except NetworkError as e:
                    raise NetworkError(f"Network error while downloading report {report_type}: {e}", details=e.details)
                except Exception as e:
                    raise WorkbenchAgentError(f"Unexpected error downloading report {report_type}: {e}", 
                                            details={"error": str(e)})

            else:
                raise ProcessError(f"Unexpected result from generate_report: {generation_result}", 
                                 details={"result": generation_result})

        except (ApiError, NetworkError, ProcessError, ProcessTimeoutError, FileSystemError) as e:
            print(f"Error processing '{report_type}' report: {e}")
            logger.warning(f"Failed to generate/download {entity_name_log} {report_type}.", exc_info=False)
            failed_reports.append(report_type)
            # Re-raise the specific exception
            raise
        except Exception as e:
            print(f"Error processing '{report_type}' report: {e}")
            logger.warning(f"Failed to generate/download {entity_name_log} {report_type}.", exc_info=False)
            failed_reports.append(report_type)
            # Wrap unknown exceptions
            raise WorkbenchAgentError(f"Unexpected error processing report {report_type}: {e}", 
                                    details={"error": str(e)})

    print("\n--- Download Summary ---")
    if successful_reports: 
        print(f"Successfully processed {len(successful_reports)} report(s) ({', '.join(successful_reports)})")
    else: 
        print("No reports were successfully processed.")
    if failed_reports: 
        print(f"Failed to process: {len(failed_reports)} report(s) ({', '.join(failed_reports)})")
    else: 
        print("No reports failed to process.")
    print("------------------------")
    if failed_reports:
        # Raise an exception if any reports failed, to signal overall failure
        raise ProcessError(f"Failed to process one or more reports: {', '.join(failed_reports)}", 
                         details={"reports": failed_reports})
