# tests/test_cli.py

import pytest
from unittest.mock import patch, MagicMock
import argparse
import os

# Import the function to test
from workbench_agent.cli import parse_cmdline_args, main
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

# --- Basic Command Parsing ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.'])
def test_parse_scan_command():
    args = parse_cmdline_args()
    assert args.command == 'scan'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.path == '.'
    assert args.api_url == 'X'
    assert args.api_user == 'Y'
    assert args.api_token == 'Z'
    assert args.limit == 10 # Check default
    assert args.log == 'INFO' # Check default log level

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--scan-name', 'S1', '--report-save-path', '/tmp/reports'])
def test_parse_download_reports_scan_scope():
    args = parse_cmdline_args()
    assert args.command == 'download-reports'
    assert args.report_scope == 'scan' # Check default scope
    assert args.scan_name == 'S1'
    assert args.project_name is None
    assert args.report_type == 'ALL' # Check default type
    assert args.report_save_path == '/tmp/reports' # Check non-default path

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--project-name', 'P1', '--report-scope', 'project', '--report-type', 'xlsx'])
def test_parse_download_reports_project_scope():
    args = parse_cmdline_args()
    assert args.command == 'download-reports'
    assert args.report_scope == 'project'
    assert args.project_name == 'P1'
    assert args.scan_name is None # scan-name is optional if scope is project
    assert args.report_type == 'xlsx'
    assert args.report_save_path == '.' # Check default path

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-branch', 'dev'])
def test_parse_scan_git_branch():
    args = parse_cmdline_args()
    assert args.command == 'scan-git'
    assert args.project_name == 'PG'
    assert args.scan_name == 'SG'
    assert args.git_url == 'http://git.com'
    assert args.git_branch == 'dev'
    assert args.git_tag is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-tag', 'v1.0'])
def test_parse_scan_git_tag():
    args = parse_cmdline_args()
    assert args.command == 'scan-git'
    assert args.git_tag == 'v1.0'
    assert args.git_branch is None

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'import-da', '--project-name', 'P', '--scan-name', 'S', '--path', 'results.json'])
def test_parse_import_da():
    args = parse_cmdline_args()
    assert args.command == 'import-da'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.path == 'results.json'

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'evaluate-gates', '--project-name', 'P', '--scan-name', 'S', '--policy-check', '--show-files'])
def test_parse_evaluate_gates():
    args = parse_cmdline_args()
    assert args.command == 'evaluate-gates'
    assert args.project_name == 'P'
    assert args.scan_name == 'S'
    assert args.policy_check is True
    assert args.show_files is True

# --- Test Flags and Defaults ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--log', 'DEBUG', '--delta-scan', '--autoid-pending-ids'])
def test_parse_flags_and_log_level():
    args = parse_cmdline_args()
    assert args.log == 'DEBUG'
    assert args.delta_scan is True
    assert args.autoid_pending_ids is True
    assert args.autoid_file_licenses is False # Check default
    assert args.run_dependency_analysis is False # Check default

# --- Test Validation Logic ---

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.', '--id-reuse', '--id-reuse-type', 'project'])
def test_parse_validation_id_reuse_missing_source():
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--report-scope', 'project'])
def test_parse_validation_download_missing_project():
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'download-reports', '--report-scope', 'scan'])
def test_parse_validation_download_missing_scan():
    # Scan name is now required if scope is scan
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'show-results', '--project-name', 'P', '--scan-name', 'S'])
def test_parse_validation_show_results_missing_show_flag():
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com', '--git-branch', 'dev', '--git-tag', 'v1'])
def test_parse_validation_scan_git_branch_and_tag():
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan-git', '--project-name', 'PG', '--scan-name', 'SG', '--git-url', 'http://git.com'])
def test_parse_validation_scan_git_missing_ref():
    # Branch or tag is required
    with pytest.raises(SystemExit):
         parse_cmdline_args()

@patch('sys.argv', ['workbench-agent', '--api-url', 'X', '--api-user', 'Y', '--api-token', 'Z', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '/non/existent/path'])
@patch('os.path.exists', return_value=False) # Mock os.path.exists
def test_parse_validation_scan_non_existent_path(mock_exists):
    with pytest.raises(SystemExit):
         parse_cmdline_args()
    mock_exists.assert_called_once_with('/non/existent/path')

# Test missing credentials (if not provided by env vars)
@patch.dict(os.environ, {"WORKBENCH_URL": "", "WORKBENCH_USER": "", "WORKBENCH_TOKEN": ""}, clear=True)
@patch('sys.argv', ['workbench-agent', 'scan', '--project-name', 'P', '--scan-name', 'S', '--path', '.'])
def test_parse_validation_missing_credentials():
    with pytest.raises(SystemExit):
         parse_cmdline_args()

def test_parse_args_no_command():
    with pytest.raises(ValidationError) as exc_info:
        parse_cmdline_args()
    assert "No command specified" in str(exc_info.value)

def test_parse_args_scan_no_path():
    with patch("sys.argv", ["workbench-agent", "scan", "--api-url", "http://example.com", "--api-key", "key"]):
        with pytest.raises(ValidationError) as exc_info:
            parse_cmdline_args()
        assert "Path is required for scan command" in str(exc_info.value)

def test_parse_args_scan_git_no_url():
    with patch("sys.argv", ["workbench-agent", "scan-git", "--api-url", "http://example.com", "--api-key", "key"]):
        with pytest.raises(ValidationError) as exc_info:
            parse_cmdline_args()
        assert "Git URL is required for scan-git command" in str(exc_info.value)

def test_parse_args_scan_git_branch_and_tag():
    with patch("sys.argv", ["workbench-agent", "scan-git", "--api-url", "http://example.com", "--api-key", "key", 
                           "--git-url", "http://example.com/repo.git", "--git-branch", "main", "--git-tag", "v1.0"]):
        with pytest.raises(ValidationError) as exc_info:
            parse_cmdline_args()
        assert "Cannot specify both git branch and tag" in str(exc_info.value)

def test_parse_args_scan_git_no_ref():
    with patch("sys.argv", ["workbench-agent", "scan-git", "--api-url", "http://example.com", "--api-key", "key", 
                           "--git-url", "http://example.com/repo.git"]):
        with pytest.raises(ValidationError) as exc_info:
            parse_cmdline_args()
        assert "Must specify either git branch or tag" in str(exc_info.value)

def test_parse_args_import_da_no_path():
    with patch("sys.argv", ["workbench-agent", "import-da", "--api-url", "http://example.com", "--api-key", "key"]):
        with pytest.raises(ValidationError) as exc_info:
            parse_cmdline_args()
        assert "Path is required for import-da command" in str(exc_info.value)

def test_parse_args_unknown_command():
    with patch("sys.argv", ["workbench-agent", "unknown", "--api-url", "http://example.com", "--api-key", "key"]):
        with pytest.raises(ValidationError) as exc_info:
            parse_cmdline_args()
        assert "Unknown command: unknown" in str(exc_info.value)

def test_main_success():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_args = MagicMock()
        mock_args.command = "scan"
        mock_parse_args.return_value = mock_args
        
        result = main()
        
        assert result == 0
        mock_parse_args.assert_called_once()
        mock_workbench.assert_called_once()
        mock_handle_scan.assert_called_once()

def test_main_validation_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args:
        mock_parse_args.side_effect = ValidationError("Invalid arguments")
        
        result = main()
        
        assert result == 1

def test_main_configuration_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench:
        
        mock_parse_args.return_value = MagicMock()
        mock_workbench.side_effect = ConfigurationError("Invalid configuration")
        
        result = main()
        
        assert result == 1

def test_main_authentication_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench:
        
        mock_parse_args.return_value = MagicMock()
        mock_workbench.side_effect = AuthenticationError("Invalid credentials")
        
        result = main()
        
        assert result == 1

def test_main_project_not_found():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = ProjectNotFoundError("Project not found")
        
        result = main()
        
        assert result == 1

def test_main_scan_not_found():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = ScanNotFoundError("Scan not found")
        
        result = main()
        
        assert result == 1

def test_main_api_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = ApiError("API error")
        
        result = main()
        
        assert result == 1

def test_main_network_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = NetworkError("Network error")
        
        result = main()
        
        assert result == 1

def test_main_process_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = ProcessError("Process error")
        
        result = main()
        
        assert result == 1

def test_main_process_timeout():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = ProcessTimeoutError("Process timeout")
        
        result = main()
        
        assert result == 1

def test_main_file_system_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = FileSystemError("File system error")
        
        result = main()
        
        assert result == 1

def test_main_compatibility_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = CompatibilityError("Compatibility error")
        
        result = main()
        
        assert result == 1

def test_main_unexpected_error():
    with patch("workbench_agent.cli.parse_args") as mock_parse_args, \
         patch("workbench_agent.cli.Workbench") as mock_workbench, \
         patch("workbench_agent.cli.handle_scan") as mock_handle_scan:
        
        mock_parse_args.return_value = MagicMock()
        mock_handle_scan.side_effect = Exception("Unexpected error")
        
        result = main()
        
        assert result == 1
