# tests/unit/api/test_vulnerabilities_api.py

import pytest
import json
import builtins
from unittest.mock import MagicMock, patch, Mock

# Import from our API structure
from api.vulnerabilities_api import VulnerabilitiesAPI


# --- Fixtures ---
@pytest.fixture
def vulnerabilities_api_inst():
    """Create a VulnerabilitiesAPI instance for testing."""
    return VulnerabilitiesAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )


# --- Test Cases ---


# --- Test list_vulnerabilities ---
@patch.object(VulnerabilitiesAPI, "_send_request")
@patch("builtins.print")
def test_list_vulnerabilities_success(mock_print, mock_send, vulnerabilities_api_inst):
    """Test successful vulnerability listing."""
    # Mock the count response and data response
    mock_send.side_effect = [
        {"status": "1", "data": {"count_results": 2}},  # Count request
        {
            "status": "1",
            "data": [  # Data request
                {"id": "CVE-2021-1234", "severity": "HIGH", "component": "openssl"},
                {"id": "CVE-2021-5678", "severity": "MEDIUM", "component": "curl"},
            ],
        },
    ]

    result = vulnerabilities_api_inst.list_vulnerabilities("test_scan")

    assert len(result) == 2
    assert result[0]["id"] == "CVE-2021-1234"
    assert result[0]["severity"] == "HIGH"
    assert result[1]["id"] == "CVE-2021-5678"
    assert result[1]["severity"] == "MEDIUM"

    # Should make two API calls (count + data)
    assert mock_send.call_count == 2

    # Check the first call (count)
    count_call_args = mock_send.call_args_list[0][0][0]
    assert count_call_args["group"] == "vulnerabilities"
    assert count_call_args["action"] == "list_vulnerabilities"
    assert count_call_args["data"]["scan_code"] == "test_scan"
    assert count_call_args["data"]["count_results"] == 1

    # Check the second call (data)
    data_call_args = mock_send.call_args_list[1][0][0]
    assert data_call_args["group"] == "vulnerabilities"
    assert data_call_args["action"] == "list_vulnerabilities"
    assert data_call_args["data"]["scan_code"] == "test_scan"
    assert data_call_args["data"]["limit"] == 100
    assert data_call_args["data"]["offset"] == 0


@patch.object(VulnerabilitiesAPI, "_send_request")
@patch("builtins.print")
def test_list_vulnerabilities_no_vulnerabilities(mock_print, mock_send, vulnerabilities_api_inst):
    """Test vulnerability listing when no vulnerabilities exist."""
    mock_send.return_value = {"status": "1", "data": {"count_results": 0}}

    result = vulnerabilities_api_inst.list_vulnerabilities("test_scan")

    assert result == []
    # Should only make one call (count), since count is 0
    assert mock_send.call_count == 1
    # Should print message about no vulnerabilities
    mock_print.assert_called_with("No vulnerabilities found for scan 'test_scan'.")


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_count_failure(mock_send, vulnerabilities_api_inst):
    """Test vulnerability listing when count request fails."""
    mock_send.return_value = {"status": "0", "error": "Scan not found"}

    with pytest.raises(builtins.Exception) as exc_info:
        vulnerabilities_api_inst.list_vulnerabilities("nonexistent_scan")

    assert "Failed to get vulnerability count" in str(exc_info.value)
    assert mock_send.call_count == 1


@patch.object(VulnerabilitiesAPI, "_send_request")
def test_list_vulnerabilities_data_failure(mock_send, vulnerabilities_api_inst):
    """Test vulnerability listing when data request fails."""
    mock_send.side_effect = [
        {"status": "1", "data": {"count_results": 1}},  # Count succeeds
        {"status": "0", "error": "Permission denied"},  # Data fails
    ]

    with pytest.raises(builtins.Exception) as exc_info:
        vulnerabilities_api_inst.list_vulnerabilities("test_scan")

    assert "Failed to fetch vulnerabilities" in str(exc_info.value)
    assert mock_send.call_count == 2


@patch.object(VulnerabilitiesAPI, "_send_request")
@patch("builtins.print")
def test_list_vulnerabilities_dict_response(mock_print, mock_send, vulnerabilities_api_inst):
    """Test vulnerability listing when API returns dict instead of list."""
    mock_send.side_effect = [
        {"status": "1", "data": {"count_results": 2}},  # Count request
        {
            "status": "1",
            "data": {  # Data as dict
                "123": {"severity": "HIGH", "component": "openssl"},
                "456": {"severity": "MEDIUM", "component": "curl"},
            },
        },
    ]

    result = vulnerabilities_api_inst.list_vulnerabilities("test_scan")

    assert len(result) == 2
    # Should add IDs from the dict keys
    ids = [vuln["id"] for vuln in result]
    assert "123" in ids
    assert "456" in ids


@patch.object(VulnerabilitiesAPI, "_send_request")
@patch("builtins.print")
def test_list_vulnerabilities_pagination(mock_print, mock_send, vulnerabilities_api_inst):
    """Test vulnerability listing with pagination."""
    mock_send.side_effect = [
        {"status": "1", "data": {"count_results": 150}},  # Count shows 150 vulnerabilities
        {"status": "1", "data": [{"id": f"CVE-{i}"} for i in range(100)]},  # First 100
        {"status": "1", "data": [{"id": f"CVE-{i}"} for i in range(100, 150)]},  # Remaining 50
    ]

    result = vulnerabilities_api_inst.list_vulnerabilities("test_scan")

    assert len(result) == 150
    assert mock_send.call_count == 3  # Count + 2 data calls

    # Check pagination parameters
    second_call_args = mock_send.call_args_list[1][0][0]
    assert second_call_args["data"]["offset"] == 0
    assert second_call_args["data"]["limit"] == 100

    third_call_args = mock_send.call_args_list[2][0][0]
    assert third_call_args["data"]["offset"] == 100
    assert third_call_args["data"]["limit"] == 100


# --- Test API Base Integration ---
def test_vulnerabilities_api_inherits_from_api_base(vulnerabilities_api_inst):
    """Test that VulnerabilitiesAPI properly inherits from APIBase."""
    # Check that it has the required attributes from APIBase
    assert hasattr(vulnerabilities_api_inst, "api_url")
    assert hasattr(vulnerabilities_api_inst, "api_user")
    assert hasattr(vulnerabilities_api_inst, "api_token")
    assert hasattr(vulnerabilities_api_inst, "_send_request")

    # Check that attributes are set correctly
    assert vulnerabilities_api_inst.api_url == "http://dummy.com/api.php"
    assert vulnerabilities_api_inst.api_user == "testuser"
    assert vulnerabilities_api_inst.api_token == "testtoken"
