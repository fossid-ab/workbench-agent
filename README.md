# Workbench Agent

[![Run Tests](https://github.com/your-org/workbench-agent/actions/workflows/tests.yml/badge.svg)](https://github.com/your-org/workbench-agent/actions/workflows/tests.yml)

A modular Python client for interacting with the FossID Workbench API. This project has been refactored from a monolithic script into a clean, modular API structure with comprehensive testing.

## Features

- 🧩 **Modular API Design**: Organized into specialized API modules (Projects, Scans, Uploads, Vulnerabilities, Downloads)
- 🔄 **Backward Compatibility**: Existing scripts continue to work with `Workbench` alias
- ✅ **Comprehensive Testing**: 41 unit tests with 100% API coverage
- 🚀 **CI/CD Ready**: GitHub Actions workflow for automated testing
- 📝 **Code Quality**: Black formatting, flake8 linting, isort import sorting
- 🔧 **Type Hints**: Basic type annotations for better development experience

## Quick Start

```python
from api import WorkbenchAPI

# Create API client
wb = WorkbenchAPI(
    api_url="https://your-fossid-instance.com/api.php",
    api_user="your_username", 
    api_token="your_api_token"
)

# Create project and scan
wb.create_project("my_project")
scan_id = wb.create_webapp_scan("my_scan", "my_project")

# Upload and scan files
wb.upload_files(["path/to/file.zip"], "my_scan")
wb.run_scan("my_scan", limit=1000, sensitivity=90, 
           auto_identification_detect_declaration=True,
           auto_identification_detect_copyright=True,
           auto_identification_resolve_pending_ids=True,
           delta_only=False, reuse_identification=False)

# Get results
licenses = wb.get_scan_identified_licenses("my_scan")
vulnerabilities = wb.list_vulnerabilities("my_scan")
```

## API Structure

```
api/
├── __init__.py                 # Main API exports
├── workbench_api.py           # Composed main API class
├── helpers/
│   ├── __init__.py
│   └── api_base.py            # Base class with _send_request method
├── projects_api.py            # Project management
├── scans_api.py               # Scan operations  
├── upload_api.py              # File uploads
├── vulnerabilities_api.py     # Vulnerability reporting
└── download_api.py            # Report generation and downloads
```

## Development

### Prerequisites

```bash
# Install dependencies (development + test)
pip install -e .[dev,test]

# Install pre-commit hooks (optional)
pre-commit install
```

### Running Tests

```bash
# Run all tests
python3 -m pytest tests/unit/ -v

# Run specific API tests
python3 -m pytest tests/unit/api/test_projects_api.py -v
python3 -m pytest tests/unit/api/test_scans_api.py -v
python3 -m pytest tests/unit/api/test_workbench_api.py -v
python3 -m pytest tests/unit/api/test_vulnerabilities_api.py -v

# Run with coverage
python3 -m pytest tests/unit/ --cov=api --cov-report=term-missing
```

### Code Quality

```bash
# Format code
python3 -m black api/ tests/

# Check linting  
python3 -m flake8 api/

# Sort imports
python3 -m isort api/ tests/

# Type checking
python3 -m mypy api/ --ignore-missing-imports
```

## CI/CD

The project includes a comprehensive GitHub Actions workflow (`.github/workflows/tests.yml`) that:

- ✅ **Unit Tests**: Runs all 41 tests across Python 3.9, 3.10, 3.11, 3.12
- ✅ **Code Quality**: flake8 linting, black formatting, isort import sorting
- ✅ **Functional Tests**: Import verification, instantiation testing, backward compatibility
- ✅ **Coverage Reporting**: Code coverage analysis with Codecov integration

### Test Results Summary

- **Projects API**: 8 tests ✅
- **Scans API**: 17 tests ✅  
- **Vulnerabilities API**: 7 tests ✅
- **Workbench API Integration**: 9 tests ✅
- **Total**: 41 tests passing

## API Methods

### Project Management
- `check_if_project_exists(project_code)` 
- `create_project(project_code)`
- `projects_get_policy_warnings_info(project_code)`

### Scan Operations  
- `check_if_scan_exists(scan_code)`
- `create_webapp_scan(scan_code, project_code, target_path=None)`
- `run_scan(scan_code, limit, sensitivity, ...)`
- `start_dependency_analysis(scan_code)`
- `wait_for_scan_to_finish(scan_type, scan_code, tries, wait_time)`
- `get_scan_identified_licenses(scan_code)`
- `extract_archives(scan_code, recursive=True, jar_extraction=False)`
- `remove_uploaded_content(filename, scan_code)`

### File Management
- `upload_files(file_paths, scan_code)`

### Vulnerability Analysis
- `list_vulnerabilities(scan_code)` - Returns all vulnerabilities with pagination

### Report Generation
- `generate_report(scan_code, report_type="SPDX")` - Generate downloadable reports
- `_download_report(report_entity, process_id)` - Download generated reports

## Backward Compatibility

Existing scripts continue to work unchanged:

```python
# This still works!
from workbench-agent import Workbench  # Alias to WorkbenchAPI

wb = Workbench(api_url, api_user, api_token)
wb.create_project("my_project")
# ... rest of your existing code
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite: `python3 -m pytest tests/unit/ -v`
5. Check code quality: `python3 -m black api/ tests/`
6. Submit a pull request

## License

See [LICENSE](LICENSE) file for details.
