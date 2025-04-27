# workbench_agent/cli.py

import argparse
import os
import sys
import re
import logging
from argparse import RawTextHelpFormatter

# Import Workbench to access report type constants
from .api import Workbench

logger = logging.getLogger(__name__)

# --- Helper functions for adding common arguments (moved outside parse_cmdline_args) ---
def add_common_scan_options(subparser):
    scan_options_args = subparser.add_argument_group("KB Scan Options")
    scan_options_args.add_argument("--limit", help="Limits KB scan results (Default: 10)", type=int, default=10)
    scan_options_args.add_argument("--sensitivity", help="Sets KB snippet sensitivity (Default: 10)", type=int, default=10)
    scan_options_args.add_argument("--autoid-file-licenses", help="Auto-detect license declarations.", action="store_true", default=False)
    scan_options_args.add_argument("--autoid-file-copyrights", help="Auto-detect copyright statements.", action="store_true", default=False)
    scan_options_args.add_argument("--autoid-pending-ids", help="Auto-resolve pending identifications.", action="store_true", default=False)
    scan_options_args.add_argument("--delta-scan", help="Scan only delta (new/modified files).", action="store_true", default=False)
    scan_options_args.add_argument("--id-reuse", help="Reuse existing identifications.", action="store_true", default=False)
    scan_options_args.add_argument(
        "--id-reuse-type",
        help="Type of identification reuse: 'any' (default), 'only_me', 'project' (reuse from specific project), 'scan' (reuse from specific scan).",
        choices=["any", "only_me", "project", "scan"],
        default="any"
    )
    scan_options_args.add_argument("--id-reuse-source", help="Project/Scan NAME for 'project' or 'scan' reuse type (required if id-reuse-type is 'project' or 'scan').", metavar="NAME")
    scan_options_args.add_argument("--run-dependency-analysis", help="Run dependency analysis *after* KB scan.", action="store_true", default=False)

def add_common_monitoring_options(subparser):
    monitor_args = subparser.add_argument_group("Scan Monitoring Options")
    monitor_args.add_argument("--scan-number-of-tries", help="Number of status checks before timeout (Default: 960)", type=int, default=960)
    monitor_args.add_argument("--scan-wait-time", help="Seconds between status checks (Default: 30)", type=int, default=30)

def add_common_result_options(subparser):
    results_display_args = subparser.add_argument_group("Result Display & Save Options")
    results_display_args.add_argument("--show-licenses", help="Display/Save identified licenses.", action="store_true", default=False)
    results_display_args.add_argument("--show-components", help="Display/Save identified components.", action="store_true", default=False)
    results_display_args.add_argument("--show-policy-warnings", help="Display/Save scan policy warnings count.", action="store_true", default=False)
    results_display_args.add_argument("--path-result", help="Save requested results to this file/directory (JSON format).", metavar="PATH")

# --- Main Parsing Function ---
def parse_cmdline_args():
    """Parses command line arguments using subparsers."""

    parser = argparse.ArgumentParser(
        description="FossID Workbench Agent - A command-line tool for interacting with FossID Workbench.",
        formatter_class=RawTextHelpFormatter,
        epilog="""
Environment Variables for Credentials:
  WORKBENCH_URL    : API Endpoint URL (e.g., https://workbench.example.com/api.php)
  WORKBENCH_USER   : Workbench Username
  WORKBENCH_TOKEN  : Workbench API Token

Example Usage:
  # Full scan uploading a directory, show results
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    scan --project-name MYPROJ --scan-name MYSCAN01 --path ./src --run-dependency-analysis --show-components --show-licenses

  # Scan using identification reuse from a specific project
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    scan --project-name MYPROJ --scan-name MYSCAN02 --path ./src --id-reuse --id-reuse-type project --id-reuse-source "MyBaseProject"

  # Import DA results only
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    import-da --project-name MYPROJ --scan-name MYSCAN03 --path ./ort-test-data/analyzer-result.json

  # Show results for an existing scan
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    show-results --project-name MYPROJ --scan-name MYSCAN01 --show-licenses --show-components

  # Evaluate gates for a scan
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    evaluate-gates --project-name MYPROJ --scan-name MYSCAN01 --policy-check --show-files

  # Scan a Git repository
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    scan-git --project-name MYGITPROJ --scan-name MYGITSCAN01 --git-url https://github.com/owner/repo.git --git-branch develop

  # Download reports for a project
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    download-reports --project-name MYPROJ --report-scope project --report-type xlsx,spdx --report-save-path reports/

  # Download reports for a specific scan (globally)
  workbench-agent.py --api-url <URL> --api-user <USER> --api-token <TOKEN> \\
    download-reports --scan-name MYSCAN01 --report-scope scan --report-type html --report-save-path reports/
"""
    )

    # --- Global Arguments (apply to all subcommands) ---
    global_args = parser.add_argument_group("Global Arguments")
    global_args.add_argument(
        "--api-url",
        help="API Endpoint URL (e.g., https://workbench.example.com/api.php). Overrides WORKBENCH_URL env var.",
        default=os.getenv("WORKBENCH_URL"),
        required=not os.getenv("WORKBENCH_URL"), # Required if not in env
        metavar="URL"
    )
    global_args.add_argument(
        "--api-user",
        help="Workbench Username. Overrides WORKBENCH_USER env var.",
        default=os.getenv("WORKBENCH_USER"),
        required=not os.getenv("WORKBENCH_USER"), # Required if not in env
        metavar="USER"
    )
    global_args.add_argument(
        "--api-token",
        help="Workbench API Token. Overrides WORKBENCH_TOKEN env var.",
        default=os.getenv("WORKBENCH_TOKEN"),
        required=not os.getenv("WORKBENCH_TOKEN"), # Required if not in env
        metavar="TOKEN"
    )
    global_args.add_argument(
        "--log",
        help="Logging level (Default: INFO)",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )

    # --- Subparsers ---
    subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True, metavar='COMMAND')

    # --- 'scan' Subcommand ---
    scan_parser = subparsers.add_parser(
        'scan',
        help='Run a standard scan by uploading code.',
        description='Run a standard scan by uploading a local directory or file to Workbench.',
        formatter_class=RawTextHelpFormatter
    )
    scan_parser.add_argument("--project-name", help="Project Name to associate the scan with.", required=True, metavar="NAME")
    scan_parser.add_argument("--scan-name", help="Scan Name to create or use.", required=True, metavar="NAME")
    scan_parser.add_argument("--path", help="Local directory/file to upload and scan.", required=True, metavar="PATH")
    scan_parser.add_argument("--recursively-extract-archives", help="Recursively extract nested archives (Default: True).", action=argparse.BooleanOptionalAction, default=True)
    scan_parser.add_argument("--jar-file-extraction", help="Control extraction of jar files (Default: False).", action=argparse.BooleanOptionalAction, default=False)
    add_common_scan_options(scan_parser)
    add_common_monitoring_options(scan_parser)
    add_common_result_options(scan_parser)

    # --- 'import-da' Subcommand ---
    import_da_parser = subparsers.add_parser(
        'import-da',
        help='Import Dependency Analysis results from a file.',
        description='Import Dependency Analysis results from an analyzer-result.json file.',
        formatter_class=RawTextHelpFormatter
    )
    import_da_parser.add_argument("--project-name", help="Project name for the scan.", type=str, required=True, metavar="NAME")
    import_da_parser.add_argument("--scan-name", help="Scan name for the scan.", type=str, required=True, metavar="NAME")
    import_da_parser.add_argument("--path", help="Path to the 'analyzer-result.json' file.", type=str, required=True)
    add_common_monitoring_options(import_da_parser)
    add_common_result_options(import_da_parser)

    # --- 'show-results' Subcommand ---
    show_results_parser = subparsers.add_parser(
        'show-results',
        help='Fetch and display results for an existing scan.',
        description='Fetch and display results for an existing scan, optionally saving them to a file.',
        formatter_class=RawTextHelpFormatter
    )
    show_results_parser.add_argument("--scan-name", help="Scan Name to fetch results for.", required=True, metavar="NAME")
    show_results_parser.add_argument("--project-name", help="Project Name containing the scan.", required=True, metavar="NAME")
    add_common_result_options(show_results_parser)

    # --- 'evaluate-gates' Subcommand ---
    evaluate_gates_parser = subparsers.add_parser(
        'evaluate-gates',
        help='Check scan status and policy violations.',
        description='Check if a scan has completed, has pending identifications, or policy violations.',
        formatter_class=RawTextHelpFormatter
    )
    evaluate_gates_parser.add_argument("--project-name", help="Project name containing the scan.", type=str, required=True, metavar="NAME")
    evaluate_gates_parser.add_argument("--scan-name", help="Scan name to evaluate gates for.", type=str, required=True, metavar="NAME")
    evaluate_gates_parser.add_argument("--policy-check", help="Check for policy violations after checking for pending identifications.", action="store_true", default=False)
    evaluate_gates_parser.add_argument("--show-files", help="Display the File Names with Pending IDs.", action="store_true", default=False)
    add_common_monitoring_options(evaluate_gates_parser)

    # --- 'download-reports' Subcommand ---
    download_reports_parser = subparsers.add_parser(
        'download-reports',
        help='Generate and download reports for a scan or project.',
        description='Generate and download reports for a completed scan or project.',
        formatter_class=RawTextHelpFormatter
    )
    download_reports_parser.add_argument(
        "--project-name",
        help="Name of the Project (required if --report-scope is 'project', optional otherwise).",
        metavar="NAME"
    )
    # scan-name is required unless scope is project (handled in post-parsing validation)
    download_reports_parser.add_argument(
        "--scan-name",
        help="Scan Name to generate reports for (required if --report-scope is 'scan').",
        metavar="NAME"
    )
    download_reports_parser.add_argument(
        "--report-scope",
        help="Scope of the report (Default: scan). Use 'project' for project-level reports.",
        choices=["scan", "project"],
        default="scan",
        metavar="SCOPE"
    )
    download_reports_parser.add_argument(
        "--report-type",
        help=f"""
             Type of report(s) to download (comma-separated, or ALL). Defaults to ALL. Support varies by Scope:
             For Scans (Default Scope): {', '.join(sorted(list(Workbench.SCAN_REPORT_TYPES)))}
             For Projects: {', '.join(sorted(list(Workbench.PROJECT_REPORT_TYPES)))}
             """,
        default="ALL",
        metavar="TYPE(S)"
    )
    download_reports_parser.add_argument("--report-save-path", help="Output directory for reports (Default: current dir).", default=".", metavar="PATH")
    gen_opts = download_reports_parser.add_argument_group("Report Generation Options")
    gen_opts.add_argument("--selection-type", help="Filter licenses included in the report.", choices=["include_foss", "include_marked_licenses", "include_copyleft", "include_all_licenses"], metavar="TYPE")
    gen_opts.add_argument("--selection-view", help="Filter report content by identification view.", choices=["pending_identification", "marked_as_identified", "all"], metavar="VIEW")
    gen_opts.add_argument("--disclaimer", help="Include custom text as a disclaimer in the report.", metavar="TEXT")
    gen_opts.add_argument("--include-vex", help="Include VEX data in CycloneDX/Excel reports (Default: True).", action=argparse.BooleanOptionalAction, default=True)
    add_common_monitoring_options(download_reports_parser)

    # --- 'scan-git' Subcommand ---
    scan_git_parser = subparsers.add_parser(
        'scan-git',
        help='Run a scan directly from a Git repository.',
        description='Clones a Branch or Tag directly from your Git SCM to the Workbench server and scans it.',
        formatter_class=RawTextHelpFormatter
    )
    scan_git_parser.add_argument("--project-name", help="Project name for the scan.", type=str, required=True, metavar="NAME")
    scan_git_parser.add_argument("--scan-name", help="Scan name for the scan.", type=str, required=True, metavar="NAME")
    scan_git_parser.add_argument("--git-url", help="URL of the Git repository to scan.", type=str, required=True)
    scan_git_parser.add_argument("--git-depth", help="Specify clone depth (integer, optional).", type=int, metavar="DEPTH")

    ref_group = scan_git_parser.add_mutually_exclusive_group(required=True)
    ref_group.add_argument("--git-branch", help="The git branch to scan.", type=str, metavar="BRANCH")
    ref_group.add_argument("--git-tag", help="The git tag to scan.", type=str, metavar="TAG")

    add_common_scan_options(scan_git_parser)
    add_common_monitoring_options(scan_git_parser)
    add_common_result_options(scan_git_parser)

    args = parser.parse_args()

    # --- Post-parsing Validation ---
    if not args.api_url or not args.api_user or not args.api_token:
        parser.error(
            "The Workbench URL, username, and token must be provided either as "
            "arguments (--api-url, --api-user, --api-token) or environment variables "
            "(WORKBENCH_URL, WORKBENCH_USER, WORKBENCH_TOKEN)."
        )

    # Command-specific validation
    if args.command in ['scan', 'import-da', 'scan-git']:
        if getattr(args, 'id_reuse', False):
             reuse_type = getattr(args, 'id_reuse_type', 'any')
             specific_code = getattr(args, 'id_reuse_source', None)
             if reuse_type in {"project", "scan"} and not specific_code:
                 parser.error(f"To reuse identifications from a '{reuse_type}', please provide the name of the '{reuse_type}' using --id-reuse-source.")

        if args.command == 'scan' and getattr(args, 'path', None):
             if not os.path.exists(args.path):
                 parser.error(f"Input path does not exist: {args.path}")

        elif args.command == 'import-da':
             if not os.path.isfile(args.path):
                 parser.error(f"Input path for import-da must be a file: {args.path}")
             if os.path.basename(args.path) != "analyzer-result.json":
                 print(f"Warning: Dependency Analysis results are typically named 'analyzer-result.json'. Will try with the provided {os.path.basename(args.path)}.")

    elif args.command == 'show-results':
        if not (args.show_licenses or args.show_components or args.show_policy_warnings):
            parser.error("The 'show-results' command requires at least one --show-* flag.")

    elif args.command == 'download-reports':
        if args.report_scope == 'project' and not args.project_name:
            parser.error("--project-name is required when --report-scope is 'project'.")
        elif args.report_scope == 'scan' and not args.scan_name:
             parser.error("--scan-name is required when --report-scope is 'scan'.")
        # If scope is project, scan-name is ignored, so no error if it's missing.
        # If scope is scan, project-name is optional.

    return args
