# tests/unit/api/test_projects_api.py

import pytest
import json
import builtins
from unittest.mock import MagicMock, patch, Mock

# Import from our API structure
from workbench_agent.api.projects_api import ProjectsAPI


# --- Fixtures ---
@pytest.fixture
def projects_api_inst():
    """Create a ProjectsAPI instance for testing."""
    return ProjectsAPI(
        api_url="http://dummy.com/api.php", api_user="testuser", api_token="testtoken"
    )


# --- Test Cases ---


# --- Test check_if_project_exists ---
@patch.object(ProjectsAPI, "_send_request")
def test_check_if_project_exists_true(mock_send, projects_api_inst):
    """Test project exists check when project exists."""
    mock_send.return_value = {"status": "1", "data": {"project_code": "test_project"}}

    result = projects_api_inst.check_if_project_exists("test_project")

    assert result is True
    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "projects"
    assert call_args["action"] == "get_information"
    assert call_args["data"]["project_code"] == "test_project"


@patch.object(ProjectsAPI, "_send_request")
def test_check_if_project_exists_false(mock_send, projects_api_inst):
    """Test project exists check when project doesn't exist."""
    mock_send.return_value = {"status": "0", "error": "Project does not exist"}

    result = projects_api_inst.check_if_project_exists("nonexistent_project")

    assert result is False
    mock_send.assert_called_once()


# --- Test create_project ---
@patch.object(ProjectsAPI, "_send_request")
@patch("builtins.print")  # Mock print to avoid output during tests
def test_create_project_success(mock_print, mock_send, projects_api_inst):
    """Test successful project creation."""
    mock_send.return_value = {"status": "1", "data": {"project_id": 123}}

    # Should not raise exception
    projects_api_inst.create_project("new_project")

    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "projects"
    assert call_args["action"] == "create"
    assert call_args["data"]["project_code"] == "new_project"
    assert call_args["data"]["project_name"] == "new_project"
    assert "Automatically created by Workbench Agent script" in call_args["data"]["description"]

    # Check print was called with success message
    mock_print.assert_called_once_with("Created project new_project")


@patch.object(ProjectsAPI, "_send_request")
def test_create_project_failure(mock_send, projects_api_inst):
    """Test project creation failure."""
    mock_send.return_value = {"status": "0", "error": "Project already exists"}

    with pytest.raises(builtins.Exception) as exc_info:
        projects_api_inst.create_project("existing_project")

    assert "Failed to create project" in str(exc_info.value)
    mock_send.assert_called_once()


# --- Test projects_get_policy_warnings_info ---
@patch.object(ProjectsAPI, "_send_request")
def test_projects_get_policy_warnings_info_success(mock_send, projects_api_inst):
    """Test successful retrieval of project policy warnings."""
    mock_response = {
        "status": "1",
        "data": {
            "warnings_count": 5,
            "warnings": [
                {"type": "license", "severity": "high", "message": "GPL license detected"}
            ],
        },
    }
    mock_send.return_value = mock_response

    result = projects_api_inst.projects_get_policy_warnings_info("test_project")

    assert result == mock_response["data"]
    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "projects"
    assert call_args["action"] == "get_policy_warnings_info"
    assert call_args["data"]["project_code"] == "test_project"


@patch.object(ProjectsAPI, "_send_request")
def test_projects_get_policy_warnings_info_failure(mock_send, projects_api_inst):
    """Test policy warnings retrieval failure."""
    from workbench_agent.exceptions import ApiError
    mock_send.return_value = {"status": "0", "error": "Project not found"}

    with pytest.raises(ApiError) as exc_info:
        projects_api_inst.projects_get_policy_warnings_info("nonexistent_project")

    assert "Failed to get policy warnings info" in str(exc_info.value)


@patch.object(ProjectsAPI, "_send_request")
def test_projects_get_policy_warnings_info_no_data(mock_send, projects_api_inst):
    """Test policy warnings retrieval when no data key in response."""
    from workbench_agent.exceptions import ApiError
    mock_send.return_value = {"status": "1"}  # No "data" key

    with pytest.raises(ApiError) as exc_info:
        projects_api_inst.projects_get_policy_warnings_info("test_project")

    assert "Failed to get policy warnings info" in str(exc_info.value)


# --- Test API Base Integration ---
def test_projects_api_inherits_from_api_base(projects_api_inst):
    """Test that ProjectsAPI properly inherits from APIBase."""
    # Check that it has the required attributes from APIBase
    assert hasattr(projects_api_inst, "api_url")
    assert hasattr(projects_api_inst, "api_user")
    assert hasattr(projects_api_inst, "api_token")
    assert hasattr(projects_api_inst, "_send_request")

    # Check that attributes are set correctly
    assert projects_api_inst.api_url == "http://dummy.com/api.php"
    assert projects_api_inst.api_user == "testuser"
    assert projects_api_inst.api_token == "testtoken"
