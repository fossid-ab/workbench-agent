# workbench_agent/cli.py

import argparse
import os
import sys
import logging
import warnings
from argparse import RawTextHelpFormatter

from .exceptions import ValidationError

logger = logging.getLogger(__name__)


def create_base_parser():
    """
    Create the base parser with common arguments.
    
    Returns:
        argparse.ArgumentParser: Base parser with common arguments
    """
    # Define a custom type function which will verify for empty string
    def non_empty_string(s):
        if not s.strip():
            raise argparse.ArgumentTypeError("Argument cannot be empty or just whitespace.")
        return s

    parser = argparse.ArgumentParser(
        description="FossID Workbench Agent - Modular API client for automated scanning",
        formatter_class=RawTextHelpFormatter,
        epilog="""
Environment Variables for Credentials:
  WORKBENCH_URL    : API Endpoint URL (e.g., https://workbench.example.com/api.php)
  WORKBENCH_USER   : Workbench Username
  WORKBENCH_TOKEN  : Workbench API Token

Example Usage (Recommended - using names):
  # Standard scan
  workbench-agent scan --project-name "My Project" --scan-name "v1.0.0-scan" --path ./src --run_dependency_analysis

  # Blind scan  
  workbench-agent blind-scan --project-name "My Project" --scan-name "v1.0.0-blind" --path ./src

  # Dependency analysis only
  workbench-agent scan --project-name "My Project" --scan-name "v1.0.0-deps" --run_only_dependency_analysis

Example Usage (Legacy - using codes):
  # Standard scan (deprecated)
  workbench-agent scan --project_code MYPROJ --scan_code MYSCAN01 --path ./src --run_dependency_analysis

  # Blind scan (deprecated)
  workbench-agent blind-scan --project_code MYPROJ --scan_code MYSCAN01 --path ./src

Example Usage (Legacy Style - maintains backwards compatibility):
  # Standard scan (same as before)
  workbench-agent --project_code MYPROJ --scan_code MYSCAN01 --path ./src --run_dependency_analysis

  # Blind scan (same as before)
  workbench-agent --project_code MYPROJ --scan_code MYSCAN01 --path ./src --blind_scan
"""
    )

    # Required arguments
    required = parser.add_argument_group("Required Arguments")
    required.add_argument(
        "--api_url",
        help="API Endpoint URL (e.g., https://workbench.example.com/api.php). Overrides WORKBENCH_URL env var.",
        default=os.getenv("WORKBENCH_URL"),
        required=not os.getenv("WORKBENCH_URL"),
        type=non_empty_string,
        metavar="URL"
    )
    required.add_argument(
        "--api_user",
        help="Workbench Username. Overrides WORKBENCH_USER env var.",
        default=os.getenv("WORKBENCH_USER"),
        required=not os.getenv("WORKBENCH_USER"),
        type=non_empty_string,
        metavar="USER"
    )
    required.add_argument(
        "--api_token",
        help="Workbench API Token. Overrides WORKBENCH_TOKEN env var.",
        default=os.getenv("WORKBENCH_TOKEN"),
        required=not os.getenv("WORKBENCH_TOKEN"),
        type=non_empty_string,
        metavar="TOKEN"
    )

    # Project identification arguments (new preferred way using names)
    project_group = parser.add_argument_group("Project Identification (choose one)")
    project_group.add_argument(
        "--project-name",
        help="Project name to associate the scan with. Projects are auto-created if they don't exist.",
        type=non_empty_string,
        metavar="NAME"
    )
    project_group.add_argument(
        "--project_code",
        help="[DEPRECATED] Project code to associate the scan with. Use --project-name instead.",
        type=non_empty_string,
        metavar="CODE"
    )

    # Scan identification arguments (new preferred way using names)
    scan_group = parser.add_argument_group("Scan Identification (choose one)")
    scan_group.add_argument(
        "--scan-name",
        help="Scan name to create or use. Scans are auto-created if they don't exist.",
        type=non_empty_string,
        metavar="NAME"
    )
    scan_group.add_argument(
        "--scan_code",
        help="[DEPRECATED] Scan code to create or use. Use --scan-name instead.",
        type=non_empty_string,
        metavar="CODE"
    )

    # Optional arguments
    optional = parser.add_argument_group("Optional Arguments")
    optional.add_argument(
        "--log",
        help="Logging level (Default: INFO)",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
    )
    optional.add_argument(
        "--path",
        help="Local directory/file to upload and scan.",
        type=str,
        metavar="PATH"
    )
    optional.add_argument(
        "--limit",
        help="Limits KB scan results (Default: 10)",
        type=int,
        default=10
    )
    optional.add_argument(
        "--sensitivity",
        help="Sets KB snippet sensitivity (Default: 10)",
        type=int,
        default=10
    )
    optional.add_argument(
        "--recursively_extract_archives",
        help="Recursively extract nested archives. Default false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--jar_file_extraction",
        help="Control default behavior related to extracting jar files. Default false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--run_dependency_analysis",
        help="Initiate dependency analysis after finishing scanning for matches in KB.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--run_only_dependency_analysis",
        help="Scan only for dependencies, no results from KB.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_declaration",
        help="Automatically detect license declaration inside files.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_copyright",
        help="Automatically detect copyright statements inside files.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_resolve_pending_ids",
        help="Automatically resolve pending identifications.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--delta_only",
        help="Scan only delta (newly added files from last scan).",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--reuse_identifications",
        help="If present, try to use an existing identification depending on parameter 'identification_reuse_type'.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--identification_reuse_type",
        help="Based on reuse type last identification found will be used for files with the same hash.",
        choices=["any", "only_me", "specific_project", "specific_scan"],
        default="any",
        type=str,
    )
    optional.add_argument(
        "--specific_code",
        help="The scan code used when creating the scan in Workbench.",
        type=str,
    )
    optional.add_argument(
        "--no_advanced_match_scoring",
        help="Disable advanced match scoring which by default is enabled.",
        dest="advanced_match_scoring",
        action="store_false",
    )
    optional.add_argument(
        "--match_filtering_threshold",
        help="Minimum length, in characters, of the snippet to be considered valid after applying match filtering.",
        type=int,
        default=-1,
    )

    optional.add_argument(
        "--chunked_upload",
        help="For files bigger than 8 MB uploading will be done using chunks.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--path-result",
        help="Save results to specified path",
        type=str,
    )

    # CLI options for blind scan
    cli_args = parser.add_argument_group("CLI Options (for blind scan)")
    cli_args.add_argument(
        "--cli_path",
        help="Path to fossid-cli executable (Default: /usr/bin/fossid-cli)",
        type=str,
        default="/usr/bin/fossid-cli"
    )
    cli_args.add_argument(
        "--config_path",
        help="Path to fossid.conf configuration file (Default: /etc/fossid.conf)",
        type=str,
        default="/etc/fossid.conf"
    )

    # Monitoring options
    monitor_args = parser.add_argument_group("Scan Monitoring Options")
    monitor_args.add_argument(
        "--scan_number_of_tries",
        help="Number of status checks before timeout (Default: 960)",
        type=int,
        default=960
    )
    monitor_args.add_argument(
        "--scan_wait_time",
        help="Seconds between status checks (Default: 30)",
        type=int,
        default=30
    )

    return parser


def parse_cmdline_args():
    """
    Parse command line arguments for the Workbench Agent.
    Supports both new subcommand style and legacy style for backwards compatibility.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
        
    Raises:
        ValidationError: If required arguments are missing or invalid
    """
    
    # Check if we're using the old-style arguments (backwards compatibility)
    # If first argument is not a known subcommand, assume legacy mode
    known_subcommands = {'scan', 'blind-scan'}
    use_subcommands = len(sys.argv) > 1 and sys.argv[1] in known_subcommands

    if use_subcommands:
        # New subcommand style
        main_parser = argparse.ArgumentParser(
            description="FossID Workbench Agent - Modular API client for automated scanning",
            formatter_class=RawTextHelpFormatter
        )
        
        # Add subcommands
        subparsers = main_parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan subcommand
        scan_parser = subparsers.add_parser(
            'scan', 
            parents=[create_base_parser()],
            add_help=False,
            help='Standard scan - upload files and run KB scan'
        )
        
        # Blind scan subcommand  
        blind_scan_parser = subparsers.add_parser(
            'blind-scan',
            parents=[create_base_parser()], 
            add_help=False,
            help='Blind scan - generate hashes using CLI and upload hash file'
        )
        
        args = main_parser.parse_args()
        
        # Set the command type for handlers
        if args.command == 'scan':
            args.scan_type = 'scan'
        elif args.command == 'blind-scan':
            args.scan_type = 'blind_scan'
        else:
            raise ValidationError("Please specify either 'scan' or 'blind-scan' command")
            
    else:
        # Legacy style - maintain backwards compatibility
        parser = create_base_parser()
        
        # Add the legacy blind_scan flag
        legacy_group = parser.add_argument_group("Legacy Options (backwards compatibility)")
        legacy_group.add_argument(
            "--blind_scan",
            help="Use CLI to generate file hashes and upload hash file (legacy mode).",
            action="store_true",
            default=False,
        )
        
        args = parser.parse_args()
        
        # Set command and scan_type based on legacy flags
        if args.blind_scan:
            args.command = 'blind-scan'
            args.scan_type = 'blind_scan'
        else:
            args.command = 'scan' 
            args.scan_type = 'scan'
    
    # Validate arguments
    if not args.api_url or not args.api_user or not args.api_token:
        raise ValidationError("API URL, user, and token must be provided")
    
    # Fix API URL if it doesn't end with '/api.php'
    if args.api_url and not args.api_url.endswith('/api.php'):
        if args.api_url.endswith('/'):
            args.api_url = args.api_url + 'api.php'
        else:
            args.api_url = args.api_url + '/api.php'
    
    # Validate project and scan identification
    project_name = getattr(args, 'project_name', None)
    project_code = getattr(args, 'project_code', None)
    scan_name = getattr(args, 'scan_name', None)
    scan_code = getattr(args, 'scan_code', None)
    
    # Check that either name-based or code-based arguments are provided
    if not (project_name or project_code):
        raise ValidationError("Either --project-name or --project_code must be provided")
    
    if not (scan_name or scan_code):
        raise ValidationError("Either --scan-name or --scan_code must be provided")
    
    # Check for conflicting arguments
    if project_name and project_code:
        raise ValidationError("Cannot use both --project-name and --project_code. Use --project-name (recommended)")
    
    if scan_name and scan_code:
        raise ValidationError("Cannot use both --scan-name and --scan_code. Use --scan-name (recommended)")
    
    # Track which style was used for proper resolution logic
    args.use_name_resolution = bool(project_name or scan_name)
    
    # Add deprecation warnings for old arguments
    if project_code:
        warnings.warn(
            "--project_code is deprecated and will be removed in a future version. "
            "Please use --project-name instead.",
            DeprecationWarning,
            stacklevel=2
        )
        
    if scan_code:
        warnings.warn(
            "--scan_code is deprecated and will be removed in a future version. "
            "Please use --scan-name instead.",
            DeprecationWarning,
            stacklevel=2
        )
    
    # Normalize attribute names for backwards compatibility
    # Only set missing attributes, don't override user's choice
    if not hasattr(args, 'project_code') or args.project_code is None:
        args.project_code = getattr(args, 'project_name', None)
    if not hasattr(args, 'scan_code') or args.scan_code is None:
        args.scan_code = getattr(args, 'scan_name', None)
    if not hasattr(args, 'project_name') or args.project_name is None:
        args.project_name = getattr(args, 'project_code', None)
    if not hasattr(args, 'scan_name') or args.scan_name is None:
        args.scan_name = getattr(args, 'scan_code', None)
    
    # Validate that path is provided unless it's dependency analysis only
    if (not args.run_only_dependency_analysis and 
        not args.path):
        raise ValidationError("Path is required unless using --run_only_dependency_analysis")
    
    # Validate path exists if provided
    if args.path and not os.path.exists(args.path):
        raise ValidationError(f"Path does not exist: {args.path}")
    
    # Validate mutually exclusive options
    if args.run_dependency_analysis and args.run_only_dependency_analysis:
        raise ValidationError("Cannot use both --run_dependency_analysis and --run_only_dependency_analysis")
    
    # Ensure path_result attribute exists for result handler compatibility
    if hasattr(args, 'path_result'):
        # Keep the existing name for compatibility
        pass
    else:
        args.path_result = None
    
    return args 