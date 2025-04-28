# tests/test_workbench.py

import pytest
import requests
import os
import json # Needed for JSONDecodeError test
from unittest.mock import MagicMock, patch, mock_open

# Import from the package structure
from workbench_agent.api import Workbench
from workbench_agent.utils import _save_report_content, _resolve_project, _resolve_scan, _ensure_scan_compatibility
from workbench_agent.exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ProjectExistsError,
    ScanExistsError,
    CompatibilityError
)

# --- Fixtures ---
@pytest.fixture
def mock_session(mocker):
    mock_sess = mocker.MagicMock(spec=requests.Session)
    mock_sess.post = mocker.MagicMock()
    mocker.patch('requests.Session', return_value=mock_sess)
    return mock_sess

@pytest.fixture
def workbench_inst(mock_session):
    return Workbench(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")

# --- Test Cases ---

# Test __init__ (remain the same)
def test_workbench_init_url_fix():
    wb = Workbench(api_url="http://dummy.com", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"

def test_workbench_init_url_correct():
    wb = Workbench(api_url="http://dummy.com/api.php", api_user="user", api_token="token")
    assert wb.api_url == "http://dummy.com/api.php"

# --- Test _send_request ---
def test_send_request_success(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'}
    mock_response.json.return_value = {"status": "1", "data": {"key": "value"}}
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "test"}
    result = workbench_inst._send_request(payload)
    mock_session.post.assert_called_once()
    assert result == {"status": "1", "data": {"key": "value"}}

def test_send_request_api_error():
    with patch('requests.Session.send') as mock_send:
        mock_send.return_value = MagicMock(
            status_code=500,
            json=lambda: {"error": "A generic failure"}
        )
        with pytest.raises(ApiError, match="API returned error: A generic failure"):
            Workbench()._send_request("GET", "/test")

def test_send_request_network_error():
    with patch('requests.Session.send') as mock_send:
        mock_send.side_effect = requests.exceptions.ConnectionError("Failed to connect")
        with pytest.raises(NetworkError, match="API request failed: Failed to connect"):
            Workbench()._send_request("GET", "/test")

def test_send_request_timeout():
    with patch('requests.Session.send') as mock_send:
        mock_send.side_effect = requests.exceptions.Timeout("Request timed out")
        with pytest.raises(NetworkError, match="API request failed: Request timed out"):
            Workbench()._send_request("GET", "/test")

def test_send_request_invalid_json():
    with patch('requests.Session.send') as mock_send:
        mock_send.return_value = MagicMock(
            status_code=200,
            json=lambda: {"invalid": "json"}
        )
        with pytest.raises(ApiError, match="API request failed"):
            Workbench()._send_request("GET", "/test")

def test_send_request_check_feature_support_scan_not_found():
    with patch('requests.Session.send') as mock_send:
        mock_send.return_value = MagicMock(
            status_code=404,
            json=lambda: {"error": "Scan not found"}
        )
        with pytest.raises(ApiError, match="API error during EXTRACT_ARCHIVES support check: Scan not found"):
            Workbench()._check_feature_support("EXTRACT_ARCHIVES", "test_scan")

def test_send_request_check_feature_support_network_error():
    with patch('requests.Session.send') as mock_send:
        mock_send.side_effect = NetworkError("Connection failed")
        with pytest.raises(NetworkError, match="Error during EXTRACT_ARCHIVES support check: Connection failed"):
            Workbench()._check_feature_support("EXTRACT_ARCHIVES", "test_scan")

def test_send_request_sync_response(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'text/html'}
    mock_response.content = b"<html>Report Content</html>"
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "sync"}
    result = workbench_inst._send_request(payload)
    assert "_raw_response" in result
    assert result["_raw_response"] == mock_response

def test_send_request_http_error(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 401 # Unauthorized
    mock_response.text = "Authentication required"
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "authfail"}
    with pytest.raises(NetworkError, match="API request failed"):
        workbench_inst._send_request(payload)

def test_send_request_json_decode_error(workbench_inst, mock_session):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_response.headers = {'content-type': 'application/json'} # Claims JSON
    mock_response.text = "This is not JSON"
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "This is not JSON", 0)
    mock_session.post.return_value = mock_response
    payload = {"group": "test", "action": "badjson"}
    with pytest.raises(ApiError, match="Invalid JSON received from API"):
        workbench_inst._send_request(payload)

# --- Test _is_status_check_supported ---
@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_yes(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1"}
    assert workbench_inst._is_status_check_supported("scan1", "SCAN") is True
    mock_send.assert_called_once()

@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_no_invalid_type(mock_send, workbench_inst):
    error_payload = { # Copied from test_send_request_non_fatal_invalid_type_probe
        "status": "0", "error": "RequestData.Base.issues_while_parsing_request",
        "data": [{"code": "RequestData.Base.field_not_valid_option", "message_parameters": {"fieldname": "type"}}]
    }
    mock_send.return_value = error_payload
    assert workbench_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES") is False
    mock_send.assert_called_once()

@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_api_error(mock_send, workbench_inst):
    # Simulate a different status 0 error
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    # Should raise the underlying API error
    with pytest.raises(ApiError, match="API error during EXTRACT_ARCHIVES support check: Scan not found"):
        workbench_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

@patch.object(Workbench, '_send_request')
def test_is_status_check_supported_network_error(mock_send, workbench_inst):
    # Simulate a network error during the probe
    mock_send.side_effect = NetworkError("Connection failed")
    with pytest.raises(NetworkError, match="Error during EXTRACT_ARCHIVES support check: Connection failed"):
        workbench_inst._is_status_check_supported("scan1", "EXTRACT_ARCHIVES")

# --- Test _wait_for_process ---
def test_wait_for_process_success(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        {"progress_state": "RUNNING"},
        {"progress_state": "RUNNING"},
        {"progress_state": "FINISHED"},
    ]
    success = workbench_inst._wait_for_process(
        process_description="Test Process",
        check_function=mock_check_func, check_args={"arg1": "val1"},
        status_accessor=lambda data: data.get("progress_state"),
        success_values={"FINISHED"}, failure_values={"FAILED"},
        max_tries=5, wait_interval=0.01, progress_indicator=False
    )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_timeout():
    with patch('time.sleep'):
        with pytest.raises(ProcessTimeoutError, match="Timeout waiting for Test Process"):
            Workbench()._wait_for_process(
                "Test Process",
                lambda x: x,
                ["test"],
                lambda x: x.get("status"),
                ["SUCCESS"],
                ["FAILURE"]
            )

def test_wait_for_process_failure():
    with patch('time.sleep'):
        with pytest.raises(ProcessError, match="The Test Process FAILED at 50%. The error returned by Workbench was: Disk full"):
            Workbench()._wait_for_process(
                "Test Process",
                lambda x: {"status": "FAILURE", "progress": 50, "error": "Disk full"},
                ["test"],
                lambda x: x.get("status"),
                ["SUCCESS"],
                ["FAILURE"]
            )

def test_wait_for_process_check_fails_retries(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.side_effect = [
        NetworkError("Network glitch"), # First call fails
        {"progress_state": "RUNNING"},        # Second call succeeds
        {"progress_state": "FINISHED"},       # Third call succeeds
    ]
    success = workbench_inst._wait_for_process(
        process_description="Test Retry",
        check_function=mock_check_func, check_args={},
        status_accessor=lambda data: data.get("progress_state"),
        success_values={"FINISHED"}, failure_values={"FAILED"},
        max_tries=5, wait_interval=0.01, progress_indicator=False
    )
    assert success is True
    assert mock_check_func.call_count == 3

def test_wait_for_process_accessor_fails(workbench_inst, mocker):
    mock_check_func = mocker.MagicMock()
    mock_check_func.return_value = {"wrong_key": "FINISHED"} # Status cannot be accessed
    # Should treat ACCESS_ERROR as non-terminal and eventually time out
    with pytest.raises(ProcessTimeoutError, match="Timeout waiting for Test Accessor.*Last Status: ACCESS_ERROR"):
        workbench_inst._wait_for_process(
            process_description="Test Accessor",
            check_function=mock_check_func, check_args={},
            status_accessor=lambda data: data["progress_state"], # This will raise KeyError
            success_values={"FINISHED"}, failure_values={"FAILED"},
            max_tries=3, wait_interval=0.01, progress_indicator=False
        )
    assert mock_check_func.call_count == 3

# --- Test upload_files ---
@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False) # Simulate file
@patch('os.path.getsize', return_value=1024) # Small file
@patch('builtins.open', new_callable=mock_open, read_data=b'file data')
@patch('requests.Session.post') # Patch post on the session instance
def test_upload_files_file_success(mock_post, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    workbench_inst.upload_files("scan1", "/path/to/file.zip")

    mock_exists.assert_called_once_with("/path/to/file.zip")
    mock_isdir.assert_called_once_with("/path/to/file.zip")
    mock_getsize.assert_called_once_with("/path/to/file.zip")
    mock_open_file.assert_called_once_with("/path/to/file.zip", "rb")
    mock_post.assert_called_once()
    # Check headers passed to post
    call_args, call_kwargs = mock_post.call_args
    headers = call_kwargs.get('headers', {})
    assert "FOSSID-SCAN-CODE" in headers
    assert "FOSSID-FILE-NAME" in headers
    assert headers.get("FOSSID-UPLOAD-TYPE") is None # Not DA import

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=True) # Simulate directory
@patch('tempfile.gettempdir', return_value='/tmp')
@patch('shutil.make_archive', return_value='/tmp/dir_temp.zip') # Mock archive creation
@patch('os.path.getsize', return_value=1024) # Small archive
@patch('builtins.open', new_callable=mock_open, read_data=b'zip data')
@patch('requests.Session.post')
@patch('os.remove') # Mock cleanup
def test_upload_files_dir_success(mock_remove, mock_post, mock_open_file, mock_getsize, mock_make_archive, mock_tempdir, mock_isdir, mock_exists, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    workbench_inst.upload_files("scan2", "/path/to/dir")

    mock_exists.assert_called_once_with("/path/to/dir")
    mock_isdir.assert_called_once_with("/path/to/dir")
    mock_make_archive.assert_called_once_with('/tmp/dir_temp', 'zip', root_dir='/path/to', base_dir='dir')
    mock_getsize.assert_called_once_with('/tmp/dir_temp.zip')
    mock_open_file.assert_called_once_with('/tmp/dir_temp.zip', "rb")
    mock_post.assert_called_once()
    mock_remove.assert_called_once_with('/tmp/dir_temp.zip')

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=20 * 1024 * 1024) # Large file
@patch('builtins.open', new_callable=mock_open, read_data=b'large data chunk')
@patch.object(Workbench, '_read_in_chunks', return_value=[b'chunk1', b'chunk2']) # Mock chunk reading
@patch.object(Workbench, '_chunked_upload_request') # Mock the chunk upload helper
def test_upload_files_chunked_success(mock_chunk_req, mock_read_chunks, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    workbench_inst.upload_files("scan3", "/path/to/largefile.bin")

    mock_exists.assert_called_once()
    mock_isdir.assert_called_once()
    mock_getsize.assert_called_once()
    mock_open_file.assert_called_once()
    mock_read_chunks.assert_called_once()
    # Check _chunked_upload_request was called for each chunk
    assert mock_chunk_req.call_count == 2
    # Check headers passed to first chunk request
    call_args, _ = mock_chunk_req.call_args_list[0]
    scan_code_arg, headers_arg, chunk_arg = call_args
    assert scan_code_arg == "scan3"
    assert headers_arg.get('Transfer-Encoding') == 'chunked'
    assert headers_arg.get('Content-Type') == 'application/octet-stream'
    assert chunk_arg == b'chunk1'

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=1024)
@patch('builtins.open', new_callable=mock_open, read_data=b'file data')
@patch('requests.Session.post')
def test_upload_files_da_import(mock_post, mock_open_file, mock_getsize, mock_isdir, mock_exists, workbench_inst):
    mock_response = MagicMock(spec=requests.Response)
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    workbench_inst.upload_files("scan4", "/path/to/results.json", is_da_import=True)

    mock_post.assert_called_once()
    call_args, call_kwargs = mock_post.call_args
    headers = call_kwargs.get('headers', {})
    assert headers.get("FOSSID-UPLOAD-TYPE") == "dependency_analysis"

@patch('os.path.exists', return_value=False)
def test_upload_files_path_not_found():
    with pytest.raises(FileSystemError, match="Path does not exist"):
        Workbench().upload_files("nonexistent_path", "test_scan")

@patch('os.path.exists', return_value=True)
@patch('os.path.isdir', return_value=False)
@patch('os.path.getsize', return_value=1024)
@patch('builtins.open', new_callable=mock_open, read_data=b'file data')
@patch('requests.Session.post')
def test_upload_files_network_error():
    with patch('requests.Session.send') as mock_send:
        mock_send.side_effect = NetworkError("Network Error")
        with pytest.raises(NetworkError, match="Failed to upload.*Network Error"):
            Workbench().upload_files("test_path", "test_scan")

# --- Test get_* methods ---
@patch.object(Workbench, '_send_request')
def test_get_pending_files_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"1": "/path/a", "2": "/path/b"}}
    result = workbench_inst.get_pending_files("scan1")
    assert result == {"1": "/path/a", "2": "/path/b"}
    mock_send.assert_called_once()

@patch.object(Workbench, '_send_request')
def test_get_pending_files_empty(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {}} # Empty dict
    result = workbench_inst.get_pending_files("scan1")
    assert result == {}

@patch.object(Workbench, '_send_request')
def test_get_pending_files_api_error(mock_send, workbench_inst):
    # Simulate API error (status 0) - should log and return empty dict
    mock_send.return_value = {"status": "0", "error": "Some API issue"}
    result = workbench_inst.get_pending_files("scan1")
    assert result == {} # Should not raise, just return empty

@patch.object(Workbench, '_send_request')
def test_get_scan_identified_components_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {
        "comp1": {"name": "Comp A", "version": "1.0"},
        "comp2": {"name": "Comp B", "version": "2.0"}
    }}
    result = workbench_inst.get_scan_identified_components("scan1")
    assert len(result) == 2
    assert {"name": "Comp A", "version": "1.0"} in result
    assert {"name": "Comp B", "version": "2.0"} in result

@patch.object(Workbench, '_send_request')
def test_get_scan_identified_components_fail():
    with patch('requests.Session.send') as mock_send:
        mock_send.side_effect = ApiError("API failed")
        with pytest.raises(ApiError, match="Error retrieving identified components"):
            Workbench().get_scan_identified_components("test_scan")

@patch.object(Workbench, '_send_request')
def test_get_dependency_analysis_results_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": [{"name": "Dep A", "version": "1.0"}]}
    result = workbench_inst.get_dependency_analysis_results("scan1")
    assert result == [{"name": "Dep A", "version": "1.0"}]

@patch.object(Workbench, '_send_request')
def test_get_dependency_analysis_results_not_run(mock_send, workbench_inst):
    # Simulate the specific "not run" error
    mock_send.return_value = {"status": "0", "error": "Dependency analysis has not been run"}
    result = workbench_inst.get_dependency_analysis_results("scan1")
    assert result == [] # Should return empty list, not raise

@patch.object(Workbench, '_send_request')
def test_get_dependency_analysis_results_other_error(mock_send, workbench_inst):
    # Simulate a different status 0 error
    mock_send.return_value = {"status": "0", "error": "Scan not found"}
    # Should raise exception
    with pytest.raises(ApiError, match="Error getting dependency analysis results.*Scan not found"):
        workbench_inst.get_dependency_analysis_results("scan1")

# --- Test create_project / create_webapp_scan ---
@patch.object(Workbench, '_send_request')
def test_create_project_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"project_code": "NEW_PROJ"}}
    result = workbench_inst.create_project("New Project")
    assert result == "NEW_PROJ"
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['action'] == 'create'
    assert payload['data']['project_name'] == 'New Project'

@patch.object(Workbench, '_send_request')
@patch.object(Workbench, 'list_projects') # Mock list_projects for the fallback
def test_create_project_already_exists(mock_list_proj, mock_send, workbench_inst):
    # First call to _send_request simulates "already exists"
    mock_send.side_effect = ProjectExistsError("Project code already exists: New Project")
    # Second call (list_projects) finds the existing project
    mock_list_proj.return_value = [{"project_name": "New Project", "project_code": "EXISTING_PROJ"}]

    result = workbench_inst.create_project("New Project")
    assert result == "EXISTING_PROJ"
    assert mock_send.call_count == 1 # Only create is attempted
    mock_list_proj.assert_called_once() # Fallback lookup is done

@patch.object(Workbench, '_send_request')
def test_create_webapp_scan_success(mock_send, workbench_inst):
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}
    result = workbench_inst.create_webapp_scan("New Scan", "PROJ1")
    assert result is True
    mock_send.assert_called_once()
    payload = mock_send.call_args[0][0]
    assert payload['action'] == 'create'
    assert payload['data']['scan_name'] == 'New Scan'
    assert payload['data']['project_code'] == 'PROJ1'

@patch.object(Workbench, '_send_request')
def test_create_webapp_scan_already_exists():
    with patch('requests.Session.send') as mock_send:
        mock_send.side_effect = ScanExistsError("Scan code already exists")
        with pytest.raises(ScanExistsError, match="Scan code already exists"):
            Workbench().create_webapp_scan("test_project", "test_scan")

# --- Test _resolve_scan (More Cases) ---
@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
@patch('workbench_agent.utils.Workbench.create_webapp_scan')
@patch('time.sleep', return_value=None) # Mock time.sleep
def test_resolve_scan_project_scope_create_success(mock_sleep, mock_create_scan, mock_get_scans, mock_resolve_proj, workbench_inst, mocker):
    mock_resolve_proj.return_value = "PROJ_Y"
    # First call to get_project_scans finds nothing
    # Second call after creation finds the new scan
    mock_get_scans.side_effect = [
        [], # Scan not found initially
        [{"name": "NewScan", "code": "NEW_SCAN_CODE", "id": 555}] # Found after creation
    ]
    mock_create_scan.return_value = True # Simulate successful trigger

    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = 'scan' # A command where create_if_missing is True

    code, scan_id = _resolve_scan(
        workbench_inst,
        scan_name="NewScan",
        project_name="ProjectY",
        create_if_missing=True,
        params=params
    )

    assert code == "NEW_SCAN_CODE"
    assert scan_id == 555
    mock_resolve_proj.assert_called_once_with(workbench_inst, "ProjectY", create_if_missing=True)
    assert mock_get_scans.call_count == 2
    mock_create_scan.assert_called_once_with("NewScan", "PROJ_Y", git_url=None, git_branch=None, git_tag=None, git_depth=None)

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
def test_resolve_scan_project_scope_not_found_no_create(mock_get_scans, mock_resolve_proj, workbench_inst, mocker):
    mock_resolve_proj.return_value = "PROJ_Z"
    mock_get_scans.return_value = [] # Scan not found

    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = 'show-results' # create_if_missing is False

    with pytest.raises(ScanNotFoundError, match="Scan 'MissingScan' not found"):
        _resolve_scan(
            workbench_inst,
            scan_name="MissingScan",
            project_name="ProjectZ",
            create_if_missing=False,
            params=params
        )
    mock_resolve_proj.assert_called_once()
    mock_get_scans.assert_called_once()

def test_resolve_scan_global_scope_create_error(workbench_inst, mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    # Cannot create in global scope
    with pytest.raises(ValueError, match="Cannot create a scan.*without specifying a --project-name"):
        _resolve_scan(
            workbench_inst,
            scan_name="AnyScan",
            project_name=None, # Global scope
            create_if_missing=True, # But create requested
            params=params
        )

@patch('workbench_agent.utils._resolve_project')
@patch('workbench_agent.utils.Workbench.get_project_scans')
@patch('workbench_agent.utils._ensure_scan_compatibility') # Mock compatibility check
def test_resolve_scan_triggers_compatibility_check(mock_compat_check, mock_get_scans, mock_resolve_proj, workbench_inst, mocker):
    mock_resolve_proj.return_value = "PROJ_W"
    existing_scan = {"name": "ScanCompat", "code": "SCAN_C", "id": 777}
    mock_get_scans.return_value = [existing_scan]

    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = 'scan' # create_if_missing is True

    code, scan_id = _resolve_scan(
        workbench_inst,
        scan_name="ScanCompat",
        project_name="ProjectW",
        create_if_missing=True, # Trigger check
        params=params
    )

    assert code == "SCAN_C"
    assert scan_id == 777
    mock_compat_check.assert_called_once_with(params, existing_scan, "SCAN_C")

# --- Test _ensure_scan_compatibility (More Cases) ---
def test_ensure_scan_compatibility_git_branch_mismatch(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = 'scan-git'
    params.git_url = "http://git.com"
    params.git_branch = "develop" # Requesting develop
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"} # Exists with main
    with pytest.raises(CompatibilityError, match="already exists with branch 'main'"):
        _ensure_scan_compatibility(params, existing_scan_info, "GITSCAN")

def test_ensure_scan_compatibility_git_tag_vs_branch(mocker):
    params = mocker.MagicMock(spec=argparse.Namespace)
    params.command = 'scan-git'
    params.git_url = "http://git.com"
    params.git_tag = "v1.0" # Requesting tag
    existing_scan_info = {"name": "GitScan", "code": "GITSCAN", "id": 1, "git_repo_url": "http://git.com", "git_branch": "main", "git_ref_type": "branch"} # Exists with branch
    with pytest.raises(CompatibilityError, match="exists with ref type 'branch'.*specified ref type 'tag'"):
        _ensure_scan_compatibility(params, existing_scan_info, "GITSCAN")

# --- Test _save_report_content (already covered) ---
# Tests test_save_report_content_scan_scope and test_save_report_content_project_scope_with_slash seem sufficient
