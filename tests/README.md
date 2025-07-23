# Workbench Agent API Tests

This directory contains unit tests for the workbench-agent API modules, adapted from the inspiration workbench-cli project.

## Test Structure

```
tests/
├── unit/
│   └── api/
│       ├── test_projects_api.py      # ProjectsAPI tests
│       ├── test_scans_api.py         # ScansAPI tests  
│       ├── test_upload_api.py        # UploadAPI tests (not yet implemented)
│       ├── test_vulnerabilities_api.py # VulnerabilitiesAPI tests
│       ├── test_download_api.py      # DownloadAPI tests (not yet implemented)
│       └── test_workbench_api.py     # Integration tests
└── README.md
```

## Running Tests

### Prerequisites

Install testing dependencies:
```bash
pip install -r requirements-test.txt
```

### Run All Tests
```bash
# Using pytest directly
python3 -m pytest tests/unit/api/ -v

# Using the test runner script
python3 run_tests.py
```

### Run Specific Test Modules
```bash
# Projects API tests
python3 run_tests.py projects

# Scans API tests  
python3 run_tests.py scans

# Workbench API integration tests
python3 run_tests.py workbench

# Vulnerabilities API tests
python3 run_tests.py vulnerabilities
```

### Run Individual Test Functions
```bash
python3 -m pytest tests/unit/api/test_projects_api.py::test_create_project_success -v
```

## Test Coverage

### ✅ Implemented Tests

- **ProjectsAPI** (8 tests)
  - `check_if_project_exists()` - success/failure cases
  - `create_project()` - success/failure cases  
  - `projects_get_policy_warnings_info()` - success/failure/no-data cases
  - API base integration

- **ScansAPI** (17 tests)
  - `create_webapp_scan()` - success/failure/target-path cases
  - `check_if_scan_exists()` - success/failure cases
  - `_get_scan_status()` - success/failure cases
  - `start_dependency_analysis()` - success/failure cases
  - `wait_for_scan_to_finish()` - success/timeout cases
  - `get_scan_identified_licenses()` - success case
  - `extract_archives()` - success/failure cases
  - `remove_uploaded_content()` - success/failure cases
  - API base integration

- **VulnerabilitiesAPI** (7 tests)
  - `list_vulnerabilities()` - success/pagination/dict-response/no-data/failure cases
  - API base integration

- **WorkbenchAPI** (9 tests)
  - API composition verification
  - Method resolution order testing
  - Integration workflow tests (project, scan, vulnerability workflows)
  - Error propagation testing
  - Method source verification (`remove_uploaded_content` from `ScansAPI`)
  - Backwards compatibility testing

### 🚧 TODO Tests

- **UploadAPI** - File upload testing (complex due to file I/O mocking)
- **DownloadAPI** - Report generation and download testing

## Test Patterns

### Mocking Strategy
- Uses `unittest.mock.patch` to mock `_send_request()` method
- Mocks `print()` and `time.sleep()` to avoid output and delays during tests
- Uses `pytest.fixture` for test instance setup

### Error Testing
- Tests both success and failure API responses
- Verifies proper exception raising with correct error messages
- Uses `builtins.Exception` (matches our simplified error handling)

### Integration Testing
- Tests typical workflows (create project → create scan → run scan)
- Verifies method composition through multiple inheritance
- Tests that methods come from the correct API classes

## Example Test Structure

```python
@patch.object(ProjectsAPI, '_send_request')
def test_create_project_success(mock_send, projects_api_inst):
    """Test successful project creation."""
    mock_send.return_value = {"status": "1", "data": {"project_id": 123}}
    
    projects_api_inst.create_project("new_project")
    
    # Verify API call
    mock_send.assert_called_once()
    call_args = mock_send.call_args[0][0]
    assert call_args["group"] == "projects"
    assert call_args["action"] == "create"
    assert call_args["data"]["project_code"] == "new_project"
```

## Current Test Results

All **41 tests** are currently passing:
- ✅ Projects API: 8 tests
- ✅ Scans API: 17 tests  
- ✅ Vulnerabilities API: 7 tests
- ✅ Workbench API: 9 tests

The test suite provides comprehensive coverage of the core API functionality and ensures that the refactored modular structure works correctly. 