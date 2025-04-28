import pytest
from unittest.mock import MagicMock, patch

from workbench_agent.utils import (
    _resolve_project,
    _resolve_scan,
    _execute_standard_scan_flow,
    fetch_and_process_results,
    _save_report_content
)
from workbench_agent.exceptions import (
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

@pytest.fixture
def mock_workbench():
    workbench = MagicMock()
    workbench.list_projects.return_value = [
        {"name": "test_project", "code": "TEST_PROJECT"}
    ]
    workbench.list_scans.return_value = [
        {"name": "test_scan", "code": "TEST_SCAN", "id": "123"}
    ]
    return workbench

@pytest.fixture
def mock_params():
    params = MagicMock()
    params.scan_number_of_tries = 60
    params.scan_wait_time = 5
    return params

def test_resolve_project_success(mock_workbench):
    result = _resolve_project(mock_workbench, "test_project")
    assert result == "TEST_PROJECT"

def test_resolve_project_not_found(mock_workbench):
    with pytest.raises(ProjectNotFoundError) as exc_info:
        _resolve_project(mock_workbench, "nonexistent_project")
    assert "Project 'nonexistent_project' not found" in str(exc_info.value)

def test_resolve_project_exists(mock_workbench):
    with pytest.raises(ProjectExistsError) as exc_info:
        _resolve_project(mock_workbench, "test_project", create_if_missing=True)
    assert "Project 'test_project' already exists" in str(exc_info.value)

def test_resolve_project_api_error(mock_workbench):
    mock_workbench.list_projects.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        _resolve_project(mock_workbench, "test_project")
    assert "Failed to resolve project 'test_project'" in str(exc_info.value)

def test_resolve_project_network_error(mock_workbench):
    mock_workbench.list_projects.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        _resolve_project(mock_workbench, "test_project")
    assert "Network error while resolving project 'test_project'" in str(exc_info.value)

def test_resolve_scan_success(mock_workbench):
    result = _resolve_scan(mock_workbench, "test_scan", "test_project")
    assert result == ("TEST_SCAN", "123")

def test_resolve_scan_not_found(mock_workbench):
    with pytest.raises(ScanNotFoundError) as exc_info:
        _resolve_scan(mock_workbench, "nonexistent_scan", "test_project")
    assert "Scan 'nonexistent_scan' not found" in str(exc_info.value)

def test_resolve_scan_exists(mock_workbench):
    with pytest.raises(ScanExistsError) as exc_info:
        _resolve_scan(mock_workbench, "test_scan", "test_project", create_if_missing=True)
    assert "Scan 'test_scan' already exists" in str(exc_info.value)

def test_resolve_scan_api_error(mock_workbench):
    mock_workbench.list_scans.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        _resolve_scan(mock_workbench, "test_scan", "test_project")
    assert "Failed to resolve scan 'test_scan'" in str(exc_info.value)

def test_resolve_scan_network_error(mock_workbench):
    mock_workbench.list_scans.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        _resolve_scan(mock_workbench, "test_scan", "test_project")
    assert "Network error while resolving scan 'test_scan'" in str(exc_info.value)

def test_execute_standard_scan_flow_success(mock_workbench, mock_params):
    with patch("workbench_agent.utils.fetch_and_process_results") as mock_fetch_results:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
        mock_fetch_results.assert_called_once_with(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")

def test_execute_standard_scan_flow_api_error(mock_workbench, mock_params):
    mock_workbench.start_scan.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Failed to execute standard scan flow" in str(exc_info.value)

def test_execute_standard_scan_flow_network_error(mock_workbench, mock_params):
    mock_workbench.start_scan.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Network error during standard scan flow" in str(exc_info.value)

def test_execute_standard_scan_flow_process_error(mock_workbench, mock_params):
    mock_workbench.start_scan.side_effect = ProcessError("Process error")
    with pytest.raises(ProcessError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Process error during standard scan flow" in str(exc_info.value)

def test_execute_standard_scan_flow_process_timeout(mock_workbench, mock_params):
    mock_workbench.start_scan.side_effect = ProcessTimeoutError("Process timeout")
    with pytest.raises(ProcessTimeoutError) as exc_info:
        _execute_standard_scan_flow(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Process timeout during standard scan flow" in str(exc_info.value)

def test_fetch_and_process_results_success(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "FINISHED"}}
    fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")

def test_fetch_and_process_results_failed(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "FAILED"}}
    with pytest.raises(ProcessError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Scan failed" in str(exc_info.value)

def test_fetch_and_process_results_cancelled(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "CANCELLED"}}
    with pytest.raises(ProcessError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Scan was cancelled" in str(exc_info.value)

def test_fetch_and_process_results_unexpected_status(mock_workbench, mock_params):
    mock_workbench.get_scan_status.return_value = {"status": "1", "data": {"status": "UNKNOWN"}}
    with pytest.raises(ProcessError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Unexpected scan status" in str(exc_info.value)

def test_fetch_and_process_results_api_error(mock_workbench, mock_params):
    mock_workbench.get_scan_status.side_effect = ApiError("API error")
    with pytest.raises(ApiError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Failed to fetch and process results" in str(exc_info.value)

def test_fetch_and_process_results_network_error(mock_workbench, mock_params):
    mock_workbench.get_scan_status.side_effect = NetworkError("Network error")
    with pytest.raises(NetworkError) as exc_info:
        fetch_and_process_results(mock_workbench, mock_params, "TEST_PROJECT", "TEST_SCAN", "123")
    assert "Network error while fetching and processing results" in str(exc_info.value)

def test_save_report_content_success(mock_workbench):
    response = MagicMock()
    response.content = b"test content"
    
    with patch("builtins.open", MagicMock()) as mock_open:
        _save_report_content(response, ".", "scan", "test", "report")
        mock_open.assert_called_once()

def test_save_report_content_file_system_error(mock_workbench):
    response = MagicMock()
    response.content = b"test content"
    
    with patch("builtins.open", MagicMock()) as mock_open:
        mock_open.side_effect = IOError("File system error")
        with pytest.raises(FileSystemError) as exc_info:
            _save_report_content(response, ".", "scan", "test", "report")
        assert "Failed to save report" in str(exc_info.value) 