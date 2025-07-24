# tests/unit/api/test_scans_api.py

import pytest
import json
import builtins
import time
from unittest.mock import MagicMock, patch, Mock

# Import from our API structure
from workbench_agent.api.scans_api import ScansAPI


# --- Fixtures ---
@pytest.fixture
def scans_api_inst():
    """Create a ScansAPI instance for testing."""
    return ScansAPI(api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken")


# --- Test Cases ---


# --- Test create_webapp_scan ---
@patch.object(ScansAPI, "_send_request")
def test_create_webapp_scan_success(mock_send, scans_api_inst):
    """Test successful scan creation."""
    mock_send.return_value = {"status": "1", "data": {"scan_id": 999}}

    result = scans_api_inst.create_webapp_scan("test_scan", "test_project")

    assert result == 999
    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "scans"
    assert call_args["action"] == "create"
    assert call_args["data"]["scan_code"] == "test_scan"
    assert call_args["data"]["scan_name"] == "test_scan"
    assert call_args["data"]["project_code"] == "test_project"


@patch.object(ScansAPI, "_send_request")
def test_create_webapp_scan_failure(mock_send, scans_api_inst):
    """Test scan creation failure."""
    mock_send.return_value = {"status": "0", "error": "Scan already exists"}

    with pytest.raises(builtins.Exception) as exc_info:
        scans_api_inst.create_webapp_scan("existing_scan", "test_project")

    assert "Failed to create scan" in str(exc_info.value)







# --- Test get_scan_status ---
@patch.object(ScansAPI, "_send_request")
def test_get_scan_status_success(mock_send, scans_api_inst):
    """Test successful scan status retrieval."""
    mock_response = {
        "status": "1",
        "data": {"is_finished": "0", "percentage_done": "75%", "status": "RUNNING"},
    }
    mock_send.return_value = mock_response

    result = scans_api_inst.get_scan_status("SCAN", "test_scan")

    assert result == mock_response["data"]
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "scans"
    assert call_args["action"] == "check_status"
    assert call_args["data"]["scan_code"] == "test_scan"
    assert call_args["data"]["type"] == "SCAN"


@patch.object(ScansAPI, "_send_request")
def test_get_scan_status_failure(mock_send, scans_api_inst):
    """Test scan status retrieval failure."""
    from workbench_agent.exceptions import ScanNotFoundError
    mock_send.return_value = {"status": "0", "error": "Scan not found"}

    with pytest.raises(ScanNotFoundError):
        scans_api_inst.get_scan_status("SCAN", "nonexistent_scan")


# --- Test start_dependency_analysis ---
@patch.object(ScansAPI, "assert_dependency_analysis_can_start")
@patch.object(ScansAPI, "_send_request")
def test_start_dependency_analysis_success(mock_send, mock_assert, scans_api_inst):
    """Test successful dependency analysis start."""
    mock_send.return_value = {"status": "1", "data": {"message": "Started"}}
    mock_assert.return_value = None  # No exception means can start

    # Should not raise exception
    scans_api_inst.start_dependency_analysis("test_scan")

    mock_assert.assert_called_once_with("test_scan")
    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "scans"
    assert call_args["action"] == "run_dependency_analysis"
    assert call_args["data"]["scan_code"] == "test_scan"


@patch.object(ScansAPI, "_send_request")
def test_start_dependency_analysis_failure(mock_send, scans_api_inst):
    """Test dependency analysis start failure."""
    mock_send.return_value = {"status": "0", "error": "Cannot start analysis"}

    with pytest.raises(builtins.Exception) as exc_info:
        scans_api_inst.start_dependency_analysis("test_scan")

    assert "Failed to start dependency analysis" in str(exc_info.value)


# --- Test wait_for_scan_to_finish ---
@patch.object(ScansAPI, "check_status")
@patch("time.sleep")  # Mock sleep to speed up tests
@patch("builtins.print")  # Mock print to avoid output during tests
def test_wait_for_scan_to_finish_success(mock_print, mock_sleep, mock_get_status, scans_api_inst):
    """Test successful scan completion waiting."""
    # Mock scan progression: running -> finished
    # Note: is_finished="0" means not finished, is_finished="1" or "FINISHED" status means finished
    mock_get_status.side_effect = [
        {"is_finished": False, "percentage_done": "50%", "status": "RUNNING"},
        {"is_finished": "1", "percentage_done": "100%", "status": "FINISHED"},
    ]

    result = scans_api_inst.wait_for_scan_to_finish("SCAN", "test_scan", 5, 1)

    # The new implementation returns a tuple (status_data, duration)
    assert isinstance(result, tuple)
    status_data, duration = result
    assert status_data["status"] == "FINISHED"
    assert status_data["percentage_done"] == "100%"
    assert isinstance(duration, float)
    assert mock_get_status.call_count == 2
    mock_sleep.assert_called_once_with(1)


@patch.object(ScansAPI, "check_status")
@patch("time.sleep")
@patch("builtins.print")
def test_wait_for_scan_to_finish_timeout(mock_print, mock_sleep, mock_get_status, scans_api_inst):
    """Test scan waiting timeout."""
    from workbench_agent.exceptions import ProcessTimeoutError
    # Mock scan always running - is_finished=False means not finished
    mock_get_status.return_value = {
        "is_finished": False,
        "percentage_done": "50%",
        "status": "RUNNING",
    }

    with pytest.raises(ProcessTimeoutError) as exc_info:
        scans_api_inst.wait_for_scan_to_finish("SCAN", "test_scan", 2, 1)

    assert "Timeout waiting for" in str(exc_info.value)
    assert mock_get_status.call_count == 2


# --- Test get_scan_identified_licenses ---
@patch.object(ScansAPI, "_send_request")
def test_get_scan_identified_licenses_success(mock_send, scans_api_inst):
    """Test successful license retrieval."""
    mock_response = {
        "status": "1",
        "data": [{"license": "MIT", "count": 5}, {"license": "GPL-3.0", "count": 2}],
    }
    mock_send.return_value = mock_response

    result = scans_api_inst.get_scan_identified_licenses("test_scan")

    assert result == mock_response["data"]
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "scans"
    assert call_args["action"] == "get_scan_identified_licenses"
    assert call_args["data"]["unique"] == "1"


# --- Test extract_archives ---
@patch.object(ScansAPI, "_send_request")
def test_extract_archives_success(mock_send, scans_api_inst):
    """Test successful archive extraction."""
    mock_send.return_value = {"status": "1", "data": {"message": "Extracted"}}

    result = scans_api_inst.extract_archives("test_scan", True, False)

    assert result is True
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "scans"
    assert call_args["action"] == "extract_archives"
    assert call_args["data"]["recursively_extract_archives"] is True
    assert call_args["data"]["jar_file_extraction"] is False


@patch.object(ScansAPI, "_send_request")
def test_extract_archives_failure(mock_send, scans_api_inst):
    """Test archive extraction failure."""
    from workbench_agent.exceptions import ApiError
    mock_send.return_value = {"status": "0", "error": "Cannot extract"}

    with pytest.raises(ApiError) as exc_info:
        scans_api_inst.extract_archives("test_scan", True, False)

    assert "Failed to extract archives" in str(exc_info.value)
    assert "Cannot extract" in str(exc_info.value)


# --- Test remove_uploaded_content ---
@patch.object(ScansAPI, "_send_request")
@patch("builtins.print")
def test_remove_uploaded_content_success(mock_print, mock_send, scans_api_inst):
    """Test successful file content removal."""
    mock_send.return_value = {"status": "1", "data": {"message": "Removed"}}

    scans_api_inst.remove_uploaded_content("test.zip", "test_scan")

    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "scans"
    assert call_args["action"] == "remove_uploaded_content"
    assert call_args["data"]["filename"] == "test.zip"
    assert call_args["data"]["scan_code"] == "test_scan"

    # Should print the action being taken
    assert mock_print.call_count >= 1


@patch.object(ScansAPI, "_send_request")
@patch("builtins.print")
def test_remove_uploaded_content_failure(mock_print, mock_send, scans_api_inst):
    """Test file content removal failure."""
    mock_send.return_value = {"status": "0", "error": "File not found"}

    # Should not raise exception, just print warning
    scans_api_inst.remove_uploaded_content("test.zip", "test_scan")

    # Should print warning about failure
    assert any("Cannot delete file" in str(call) for call in mock_print.call_args_list)


# --- Test API Base Integration ---
def test_scans_api_inherits_from_api_base(scans_api_inst):
    """Test that ScansAPI properly inherits from APIBase."""
    # Check that it has the required attributes from APIBase
    assert hasattr(scans_api_inst, "api_url")
    assert hasattr(scans_api_inst, "api_user")
    assert hasattr(scans_api_inst, "api_token")
    assert hasattr(scans_api_inst, "_send_request")

    # Check that attributes are set correctly
    assert scans_api_inst.api_url == "http://dummy.com/api.php"
    assert scans_api_inst.api_user == "testuser"
    assert scans_api_inst.api_token == "testtoken"
