# tests/test_handlers.py

import pytest
from unittest.mock import MagicMock, patch, call
import argparse
import requests # For mocking generate_report response
import builtins # For asserting builtins.Exception

# Import handlers and dependencies to mock
from workbench_agent import handlers
from workbench_agent.api import Workbench
# Mock utils functions used by handlers
from workbench_agent import utils

# Fixture for mock Workbench instance
@pytest.fixture
def mock_workbench(mocker):
    # Mock methods used across handlers
    mock = mocker.MagicMock(spec=Workbench)
    mock._is_status_check_supported.return_value = True # Assume supported by default
    return mock

# Fixture for mock params object
@pytest.fixture
def mock_params(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Set common attributes needed by handlers
    params.api_url = "http://dummy.com/api.php"
    params.scan_number_of_tries = 10
    params.scan_wait_time = 1
    # Set defaults for flags often checked
    params.show_licenses = False
    params.show_components = False
    params.show_policy_warnings = False
    params.path_result = None
    params.policy_check = False
    params.show_files = False
    # Set command-specific attributes in each test
    return params

# --- Test handle_show_results ---
@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_show_results_success(mock_fetch, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True # Need at least one show flag
    mock_resolve_proj.return_value = "PROJ_A_CODE"
    mock_resolve_scan.return_value = ("SCAN_1_CODE", 123) # scan_code, scan_id

    # Call handler
    handlers.handle_show_results(mock_workbench, mock_params)

    # Assertions
    mock_resolve_proj.assert_called_once_with(mock_workbench, "ProjA", create_if_missing=False)
    mock_resolve_scan.assert_called_once_with(
        mock_workbench, scan_name="Scan1", project_name="ProjA", create_if_missing=False, params=mock_params
    )
    mock_fetch.assert_called_once_with(
        mock_workbench, mock_params, "PROJ_A_CODE", "SCAN_1_CODE", 123
    )

@patch('workbench_agent.handlers._resolve_project', side_effect=builtins.Exception("Proj Not Found"))
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_show_results_project_resolve_fails(mock_fetch, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True

    # Expect the exception from _resolve_project to propagate
    with pytest.raises(builtins.Exception, match="Proj Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called() # Should not be called if project fails
    mock_fetch.assert_not_called()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan', side_effect=builtins.Exception("Scan Not Found"))
@patch('workbench_agent.handlers.fetch_and_process_results')
def test_handle_show_results_scan_resolve_fails(mock_fetch, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'show-results'
    mock_params.project_name = "ProjA"
    mock_params.scan_name = "Scan1"
    mock_params.show_licenses = True
    mock_resolve_proj.return_value = "PROJ_A_CODE"

    with pytest.raises(builtins.Exception, match="Scan Not Found"):
        handlers.handle_show_results(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_fetch.assert_not_called() # Should not be called if scan fails

# --- Test handle_evaluate_gates ---
@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_pass(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for PASS scenario
    mock_params.command = 'evaluate-gates'
    mock_params.project_name = "ProjB"
    mock_params.scan_name = "ScanClean"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PROJ_B_CODE"
    mock_resolve_scan.return_value = ("SCAN_CLEAN_CODE", 456)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}
    mock_get_pending.return_value = {} # No pending files
    mock_get_policy.return_value = {"policy_warnings_list": []} # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is True # Should return True for PASS
    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_gen_links.assert_called_once_with(mock_params.api_url, 456)
    mock_set_env.assert_called_once_with("FOSSID_SCAN_URL", "http://main")
    mock_wait.assert_called_once_with("SCAN", "SCAN_CLEAN_CODE", mock_params.scan_number_of_tries, mock_params.scan_wait_time)
    mock_get_pending.assert_called_once_with("SCAN_CLEAN_CODE")
    mock_get_policy.assert_called_once_with("SCAN_CLEAN_CODE")

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_fail_pending(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (pending files)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.policy_check = True # Check policy too
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}
    mock_get_pending.return_value = {"1": "/file/a"} # PENDING FILES FOUND
    mock_get_policy.return_value = {"policy_warnings_list": []} # No policy violations

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_wait.assert_called_once()
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once() # Policy check should still happen

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish')
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_fail_policy(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (policy violations)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}
    mock_get_pending.return_value = {} # No pending
    mock_get_policy.return_value = {"policy_warnings_list": [{"type": "license"}]} # POLICY VIOLATION FOUND

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_wait.assert_called_once()
    mock_get_pending.assert_called_once()
    mock_get_policy.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.generate_links')
@patch('workbench_agent.handlers.Workbench.set_env_variable')
@patch('workbench_agent.handlers.Workbench.wait_for_scan_to_finish', side_effect=builtins.Exception("Scan Timed Out"))
@patch('workbench_agent.handlers.Workbench.get_pending_files')
@patch('workbench_agent.handlers.Workbench.get_policy_warnings_info')
def test_handle_evaluate_gates_fail_scan_wait(mock_get_policy, mock_get_pending, mock_wait, mock_set_env, mock_gen_links, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    # Setup mocks for FAIL scenario (scan wait fails)
    mock_params.command = 'evaluate-gates'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.policy_check = True
    mock_resolve_proj.return_value = "PC"; mock_resolve_scan.return_value = ("SC", 1)
    mock_gen_links.return_value = {"main_scan_link": "http://main", "pending_link": "http://pending", "policy_link": "http://policy"}

    result = handlers.handle_evaluate_gates(mock_workbench, mock_params)

    assert result is False # Should return False for FAIL
    mock_wait.assert_called_once()
    mock_get_pending.assert_not_called() # Should not check pending if wait fails
    mock_get_policy.assert_not_called() # Should not check policy if wait fails

# --- Test handle_scan ---
@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers.Workbench._is_status_check_supported', return_value=True) # Assume supported
@patch('workbench_agent.handlers.Workbench.wait_for_archive_extraction')
@patch('workbench_agent.handlers._execute_standard_scan_flow') # Mock the whole flow utility
def test_handle_scan_success(mock_exec_flow, mock_wait_extract, mock_is_supported, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'scan'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "/path"
    mock_params.recursively_extract_archives = True; mock_params.jar_file_extraction = False
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_extract.return_value = True # Simulate extraction triggered

    handlers.handle_scan(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_called_once()
    mock_upload.assert_called_once_with("SC", "/path", is_da_import=False)
    mock_extract.assert_called_once_with("SC", True, False)
    mock_is_supported.assert_called_once_with("SC", "EXTRACT_ARCHIVES")
    mock_wait_extract.assert_called_once()
    mock_exec_flow.assert_called_once_with(mock_workbench, mock_params, "PC", "SC", 1)

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files')
@patch('workbench_agent.handlers.Workbench.extract_archives')
@patch('workbench_agent.handlers.Workbench._is_status_check_supported', return_value=False) # Assume NOT supported
@patch('workbench_agent.handlers.Workbench.wait_for_archive_extraction')
@patch('workbench_agent.handlers._execute_standard_scan_flow')
@patch('time.sleep', return_value=None) # Mock sleep
def test_handle_scan_success_no_extract_wait(mock_sleep, mock_exec_flow, mock_wait_extract, mock_is_supported, mock_extract, mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'scan'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "/path"
    mock_params.recursively_extract_archives = True; mock_params.jar_file_extraction = False
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_extract.return_value = True

    handlers.handle_scan(mock_workbench, mock_params)

    mock_is_supported.assert_called_once_with("SC", "EXTRACT_ARCHIVES")
    mock_wait_extract.assert_not_called() # Wait should NOT be called
    mock_sleep.assert_called_once_with(10) # Sleep should be called
    mock_exec_flow.assert_called_once()

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('workbench_agent.handlers.Workbench.upload_files', side_effect=builtins.Exception("Upload Failed"))
# ... other mocks for functions after upload ...
def test_handle_scan_upload_fails(mock_upload, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'scan'; mock_params.project_name = "P"; mock_params.scan_name = "S"; mock_params.path = "/path"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    with pytest.raises(builtins.Exception, match="Upload Failed"):
        handlers.handle_scan(mock_workbench, mock_params)

    mock_upload.assert_called_once()
    # Assert subsequent functions (extract, wait, exec_flow) were NOT called

# --- Test handle_download_reports ---
@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_scan_sync(mock_save, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html'; mock_params.report_save_path = "/out"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)
    mock_response = MagicMock(spec=requests.Response) # Simulate sync response
    mock_gen_report.return_value = mock_response

    handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_scan.assert_called_once()
    mock_makedirs.assert_called_once_with("/out", exist_ok=True)
    mock_gen_report.assert_called_once_with(scope='scan', project_code='PC', scan_code='SC', report_type='html', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    mock_save.assert_called_once_with(mock_response, "/out", report_scope='scan', name_component='S', report_type='html')

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers.Workbench._wait_for_process') # Mock the generic waiter
@patch('workbench_agent.handlers.Workbench.download_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_project_async(mock_save, mock_download, mock_wait, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = None # Scan name not needed for project scope
    mock_params.report_scope = 'project'; mock_params.report_type = 'xlsx'; mock_params.report_save_path = "/out"
    mock_resolve_proj.return_value = "PC"
    # _resolve_scan should not be called for project scope
    mock_gen_report.return_value = 12345 # Simulate async process ID
    mock_download_response = MagicMock(spec=requests.Response)
    mock_download.return_value = mock_download_response

    handlers.handle_download_reports(mock_workbench, mock_params)

    mock_resolve_proj.assert_called_once()
    mock_resolve_scan.assert_not_called()
    mock_makedirs.assert_called_once()
    mock_gen_report.assert_called_once_with(scope='project', project_code='PC', scan_code=None, report_type='xlsx', selection_type=None, selection_view=None, disclaimer=None, include_vex=True)
    mock_wait.assert_called_once() # Check that waiting happened
    mock_download.assert_called_once_with('project', 12345)
    mock_save.assert_called_once_with(mock_download_response, "/out", report_scope='project', name_component='P', report_type='xlsx')

@patch('workbench_agent.handlers._resolve_project')
@patch('workbench_agent.handlers._resolve_scan')
@patch('os.makedirs')
@patch('workbench_agent.handlers.Workbench.generate_report')
@patch('workbench_agent.handlers.Workbench._wait_for_process')
@patch('workbench_agent.handlers.Workbench.download_report')
@patch('workbench_agent.handlers._save_report_content')
def test_handle_download_reports_multiple_one_fails(mock_save, mock_download, mock_wait, mock_gen_report, mock_makedirs, mock_resolve_scan, mock_resolve_proj, mock_workbench, mock_params):
    mock_params.command = 'download-reports'; mock_params.project_name = "P"; mock_params.scan_name = "S"
    mock_params.report_scope = 'scan'; mock_params.report_type = 'html,xlsx'; mock_params.report_save_path = "/out"
    mock_resolve_proj.return_value = "PC"
    mock_resolve_scan.return_value = ("SC", 1)

    # Simulate html (sync) succeeds, xlsx (async) wait fails
    mock_sync_response = MagicMock(spec=requests.Response)
    # TODO: Update exception type when ProcessError is implemented
    mock_wait.side_effect = builtins.Exception("Report generation failed")

    mock_gen_report.side_effect = [
        mock_sync_response, # html succeeds
        54321              # xlsx starts async
    ]

    # Expect the handler to raise an exception because one report failed
    # TODO: Update exception type when ProcessError is implemented
    with pytest.raises(builtins.Exception, match="Failed to process one or more reports: xlsx"):
        handlers.handle_download_reports(mock_workbench, mock_params)

    # Assertions
    assert mock_gen_report.call_count == 2
    mock_save.assert_called_once() # Only called for html
    mock_wait.assert_called_once() # Called for xlsx
    mock_download.assert_not_called() # Not called because wait failed

# Add tests for handle_scan_git, handle_import_da following similar patterns
