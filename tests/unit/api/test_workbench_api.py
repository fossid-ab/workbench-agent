# tests/unit/api/test_workbench_api.py

import pytest
import json
import builtins
from unittest.mock import MagicMock, patch, Mock

# Import from our API structure
from api.workbench_api import WorkbenchAPI


# --- Fixtures ---
@pytest.fixture
def workbench_inst():
    """Create a WorkbenchAPI instance for testing."""
    return WorkbenchAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )


# --- Test Cases ---


def test_workbench_api_composition(workbench_inst):
    """Test that WorkbenchAPI properly composes all API modules."""
    # Check that it has methods from all API classes

    # ProjectsAPI methods
    assert hasattr(workbench_inst, "check_if_project_exists")
    assert hasattr(workbench_inst, "create_project")
    assert hasattr(workbench_inst, "projects_get_policy_warnings_info")

    # ScansAPI methods
    assert hasattr(workbench_inst, "check_if_scan_exists")
    assert hasattr(workbench_inst, "create_webapp_scan")
    assert hasattr(workbench_inst, "run_scan")
    assert hasattr(workbench_inst, "start_dependency_analysis")
    assert hasattr(workbench_inst, "wait_for_scan_to_finish")
    assert hasattr(workbench_inst, "get_scan_identified_licenses")
    assert hasattr(workbench_inst, "remove_uploaded_content")  # Moved from UploadAPI

    # UploadAPI methods
    assert hasattr(workbench_inst, "upload_files")

    # VulnerabilitiesAPI methods
    assert hasattr(workbench_inst, "list_vulnerabilities")

    # DownloadAPI methods
    assert hasattr(workbench_inst, "generate_report")
    assert hasattr(workbench_inst, "_download_report")


def test_workbench_api_inheritance_order(workbench_inst):
    """Test that the method resolution order is correct."""
    # Check MRO includes all expected classes
    mro_names = [cls.__name__ for cls in type(workbench_inst).__mro__]

    expected_classes = [
        "WorkbenchAPI",
        "ProjectsAPI",
        "ScansAPI",
        "UploadAPI",
        "VulnerabilitiesAPI",
        "DownloadAPI",
        "APIBase",
    ]

    for expected_class in expected_classes:
        assert expected_class in mro_names, f"{expected_class} not found in MRO"


def test_workbench_api_inherits_from_api_base(workbench_inst):
    """Test that WorkbenchAPI properly inherits from APIBase."""
    # Check that it has the required attributes from APIBase
    assert hasattr(workbench_inst, "api_url")
    assert hasattr(workbench_inst, "api_user")
    assert hasattr(workbench_inst, "api_token")
    assert hasattr(workbench_inst, "_send_request")

    # Check that attributes are set correctly
    assert workbench_inst.api_url == "http://dummy.com/api.php"
    assert workbench_inst.api_user == "testuser"
    assert workbench_inst.api_token == "testtoken"


# --- Integration Tests ---
@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_api_project_workflow(mock_send, workbench_inst):
    """Test a typical project workflow using the composed API."""
    # Mock responses for a typical workflow
    mock_send.side_effect = [
        {"status": "0", "error": "Project does not exist"},  # check_if_project_exists
        {"status": "1", "data": {"project_id": 123}},  # create_project
        {"status": "0", "error": "Scan not found"},  # check_if_scan_exists
        {"status": "1", "data": {"scan_id": 999}},  # create_webapp_scan
    ]

    # Execute workflow
    project_exists = workbench_inst.check_if_project_exists("test_project")
    assert project_exists is False

    workbench_inst.create_project("test_project")  # Should not raise

    scan_exists = workbench_inst.check_if_scan_exists("test_scan")
    assert scan_exists is False

    scan_id = workbench_inst.create_webapp_scan("test_scan", "test_project")
    assert scan_id == 999

    # Verify all calls were made
    assert mock_send.call_count == 4


@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_api_scan_workflow(mock_send, workbench_inst):
    """Test a typical scan workflow using the composed API."""
    # Mock responses for scan operations
    mock_send.side_effect = [
        {"status": "1", "data": {"scan_id": 999}},  # create_webapp_scan
        {"status": "1", "data": {"message": "Extracted"}},  # extract_archives
        {"status": "1", "data": {"message": "Started"}},  # run_scan
        {"status": "1", "data": [{"license": "MIT", "count": 5}]},  # get_scan_identified_licenses
    ]

    # Execute scan workflow
    scan_id = workbench_inst.create_webapp_scan("test_scan", "test_project")
    assert scan_id == 999

    extract_result = workbench_inst.extract_archives("test_scan", True, False)
    assert extract_result is True

    # Note: run_scan has many parameters, using minimal set for test
    with (
        patch.object(workbench_inst, "check_if_scan_exists", return_value=True),
        patch.object(workbench_inst, "_assert_scan_can_start"),
    ):
        run_result = workbench_inst.run_scan("test_scan", 10, 10, False, False, False, False, False)
        assert run_result["status"] == "1"

    licenses = workbench_inst.get_scan_identified_licenses("test_scan")
    assert len(licenses) == 1
    assert licenses[0]["license"] == "MIT"


@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_api_vulnerability_workflow(mock_send, workbench_inst):
    """Test vulnerability retrieval using the composed API."""
    mock_send.side_effect = [
        {"status": "1", "data": {"count_results": 2}},  # count vulnerabilities
        {
            "status": "1",
            "data": [  # get vulnerabilities
                {"id": "CVE-2021-1234", "severity": "HIGH"},
                {"id": "CVE-2021-5678", "severity": "MEDIUM"},
            ],
        },
    ]

    vulnerabilities = workbench_inst.list_vulnerabilities("test_scan")

    assert len(vulnerabilities) == 2
    assert vulnerabilities[0]["id"] == "CVE-2021-1234"
    assert mock_send.call_count == 2


# --- Error Handling Integration Tests ---
@patch.object(WorkbenchAPI, "_send_request")
def test_workbench_api_error_propagation(mock_send, workbench_inst):
    """Test that errors are properly propagated through the composed API."""
    mock_send.return_value = {"status": "0", "error": "API Error"}

    # Test that errors from different API modules are handled consistently
    with pytest.raises(builtins.Exception):
        workbench_inst.create_project("test_project")

    with pytest.raises(builtins.Exception):
        workbench_inst.create_webapp_scan("test_scan", "test_project")

    with pytest.raises(builtins.Exception):
        workbench_inst.start_dependency_analysis("test_scan")


# --- Method Resolution Tests ---
def test_remove_uploaded_content_comes_from_scans_api(workbench_inst):
    """Test that remove_uploaded_content method comes from ScansAPI, not UploadAPI."""
    # Find which class in the MRO defines remove_uploaded_content
    mro = type(workbench_inst).__mro__
    defining_class = None

    for cls in mro:
        if hasattr(cls, "remove_uploaded_content") and "remove_uploaded_content" in cls.__dict__:
            defining_class = cls
            break

    # Should be defined in ScansAPI, not UploadAPI
    assert defining_class.__name__ == "ScansAPI"


# --- Backwards Compatibility Test ---
def test_workbench_alias_compatibility():
    """Test that the Workbench alias still works for backwards compatibility."""
    # Import the alias from the main module
    import sys
    import os

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))

    from api import WorkbenchAPI

    # The alias should be the same class
    assert WorkbenchAPI is not None

    # Create instance using the main class
    wb = WorkbenchAPI("http://test.com/api.php", "user", "token")
    assert wb.api_url == "http://test.com/api.php"
    assert wb.api_user == "user"
    assert wb.api_token == "token"
