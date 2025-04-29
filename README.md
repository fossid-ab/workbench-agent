# FossID Workbench Agent

A command-line tool for interacting with the FossID Workbench API, enabling automation of common scanning and reporting tasks.

## Features
Workbench Agent supports various operations for scanning your code and interacting with the results.

### Scanning Options
*   Upload code (directories or files) for scanning.
*   Scan Git repositories (branches or tags).
*   Import Dependency Analysis results (e.g., `analyzer-result.json`).

### Results Options
*   Fetch scan results (components, licenses, policy violations).
*   Check scan status, pending identifications, and policy violations (Gate Evaluation).
*   Generate and download reports (scan or project scope) with a simplified naming scheme.

## Prerequisites

*   **Python 3.9+**
*   **pip** (Python package installer, usually included with Python)
*   Access to a FossID Workbench instance (URL, Username, API Token)

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone github.com/fossid-ab/workbench-agent
    cd workbench-agent
    ```

2.  **Create and Activate a Virtual Environment (Recommended):**
    Using a virtual environment isolates the tool's dependencies from your global Python installation.

    *   **Create:**
        ```bash
        python3 -m venv .venv
        ```
    *   **Activate:**
        *   macOS / Linux:
            ```bash
            source .venv/bin/activate
            ```
        *   Windows (Git Bash/WSL):
            ```bash
            source .venv/Scripts/activate
            ```
        *   Windows (Command Prompt/PowerShell):
            ```bash
            .\.venv\Scripts\activate
            ```
        You should see `(.venv)` appear at the beginning of your terminal prompt.

3.  **Install the Package:**
    This command installs the `workbench-agent` tool and its dependencies (like `requests`) into your active virtual environment.

    ```bash
    pip install .
    ```
    *(You might need to use `pip3` instead of `pip` depending on your system configuration).*

    This makes the `workbench-agent` command available in your terminal while the virtual environment is active.

4.  **(Optional) Installation for Development:**
    If you plan to modify the agent's code, install it in "editable" mode. This links the installed command to your source code, so changes are reflected immediately without reinstalling.

    ```bash
    pip install -e .
    ```

## Configuration (Environment Variables)

The agent requires credentials to connect to the Workbench API. These can be provided via environment variables for convenience and security:

*   `WORKBENCH_URL`: API Endpoint URL (e.g., `https://workbench.example.com/api.php`)
*   `WORKBENCH_USER`: Workbench Username
*   `WORKBENCH_TOKEN`: Workbench API Token

You can also provide these using the `--api-url`, `--api-user`, and `--api-token` command-line arguments, which will override the environment variables if set.

## Usage

Run the agent using the `workbench-agent` command followed by the desired subcommand and its options. Make sure your virtual environment is activated.

```bash
workbench-agent <COMMAND> [OPTIONS...]
```

Use `workbench-agent --help` to see the main help message and workbench-agent <COMMAND> --help for help on a specific command.

## Commands:

scan: Upload local code, run KB scan, optionally run DA scan.
scan-git: Clone and scan a Git repository.
import-da: Import Dependency Analysis results.
show-results: Fetch and display results for an existing scan.
evaluate-gates: Check scan status, pending IDs, and policy violations.
download-reports: Generate and download reports for a scan or project.

## Examples:

(Ensure environment variables are set or use --api-url, --api-user, --api-token)

### Full scan uploading a directory, run DA, show results:

```bash
workbench-agent scan \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --path ./src \
    --run-dependency-analysis \
    --show-components --show-licenses --show-scan-metrics
```

### Scan using identification reuse from a specific project:

```bash
workbench-agent scan \
    --project-name MYPROJ --scan-name MYSCAN02 \
    --path ./src \
    --id-reuse --id-reuse-type project --id-reuse-source "MyBaseProject"
```

### Import DA results only:

```bash
workbench-agent import-da \
    --project-name MYPROJ --scan-name MYSCAN03 \
    --path ./ort-test-data/analyzer-result.json
```

### Show results for an existing scan:

```bash
workbench-agent show-results \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-licenses --show-components --show-dependencies --show-scan-metrics
```

### Evaluate gates for a scan (check pending IDs and policy violations):

```bash
workbench-agent evaluate-gates \
    --project-name MYPROJ --scan-name MYSCAN01 \
    --show-files --fail-on policy
```

(This command exits with code 0 if gates pass, 1 if they fail)


### Scan a Git repository branch:

```bash
workbench-agent scan-git \
    --project-name MYGITPROJ --scan-name MYGITSCAN01 \
    --git-url https://github.com/owner/repo.git --git-branch develop
```

### Download XLSX and SPDX reports for a project:

```bash
workbench-agent download-reports \
    --project-name MYPROJ --report-scope project \
    --report-type xlsx,spdx --report-save-path reports/
```

## Logging
The agent creates a log file named log-agent.txt in the directory where it's run. You can control the logging level using the --log argument (DEBUG, INFO, WARNING, ERROR). Console output is generally kept at INFO level unless --log is set higher.