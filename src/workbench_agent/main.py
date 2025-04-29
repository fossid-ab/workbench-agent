import sys
import time
import logging
import argparse
from typing import Optional

# Import from other modules in the package
from .cli import parse_cmdline_args
from .api import Workbench
from . import handlers
from .exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError
)


def main() -> int:
    """
    Main function to parse arguments, set up logging, initialize the API client,
    and dispatch to the appropriate command handler.
    Returns an exit code (0 for success, non-zero for failure).
    """
    start_time = time.monotonic()
    exit_code = 1 # Default to failure

    try:
        params = parse_cmdline_args()

        # Setup logging
        log_level = getattr(logging, params.log.upper(), logging.INFO)
        # Configure file handler (overwrite mode) and stream handler
        logging.basicConfig(level=log_level,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            handlers=[logging.FileHandler("log-agent.txt", mode='w')],
                            force=True) # Use force=True to allow reconfiguration if run multiple times

        # Add console handler separately to control its level independently
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s') # Simpler format for console
        console_handler.setFormatter(console_formatter)
        # Set console level (e.g., INFO, unless global level is higher)
        console_handler.setLevel(logging.INFO if log_level <= logging.INFO else log_level)
        logging.getLogger().addHandler(console_handler)

        # Get the root logger for the application after configuration
        logger = logging.getLogger("log") # Use the same name as before for consistency

        print("--- Workbench Agent Configuration ---")
        print(f"Command: {params.command}")
        # Print parameters (mask token if not DEBUG)
        for k, v in sorted(params.__dict__.items()):
            if k == 'command': continue
            display_val = v
            if k == 'api_token' and params.log.upper() != 'DEBUG':
                 display_val = "****" if v else "Not Set"
            print(f"  {k:<30} = {display_val}")
        print("------------------------------------")
        logger.debug("Parsed parameters: %s", params)

        # Initialize Workbench API client
        try:
            workbench = Workbench(params.api_url, params.api_user, params.api_token)
            logger.info("Workbench client initialized.")
        except AuthenticationError as e:
            print(f"\nAuthentication Error: {e.message}")
            logger.error("Failed to authenticate with Workbench", exc_info=True)
            return 1
        except NetworkError as e:
            print(f"\nNetwork Error: {e.message}")
            logger.error("Failed to connect to Workbench", exc_info=True)
            return 1
        except Exception as e:
            print(f"\nError initializing Workbench connection: {e}")
            logger.critical("Failed to initialize Workbench connection", exc_info=True)
            return 1

        # --- Command Dispatch ---
        COMMAND_HANDLERS = {
            "scan": handlers.handle_scan,
            "import-da": handlers.handle_import_da,
            "show-results": handlers.handle_show_results,
            "evaluate-gates": handlers.handle_evaluate_gates,
            "download-reports": handlers.handle_download_reports,
            "scan-git": handlers.handle_scan_git,
        }

        handler = COMMAND_HANDLERS.get(params.command)

        if handler:
            # Execute the command handler
            result = handler(workbench, params) # Handlers raise exceptions on failure

            # Determine exit code based on command and result
            if params.command == 'evaluate-gates':
                # evaluate-gates returns True for PASS, False for FAIL
                exit_code = 0 if result else 1
                if exit_code == 0:
                    print("\nWorkbench Agent finished successfully (Gates Passed).")
                else:
                    # Don't print 'Error' here, just the status
                    print("\nWorkbench Agent finished (Gates FAILED).")
            else:
                # For other commands, success is assumed if no exception was raised
                exit_code = 0
                print("\nWorkbench Agent finished successfully.")

        else:
            # This case should ideally be caught by argparse, but handle defensively
            print(f"Error: Unknown command '{params.command}'.")
            logger.error(f"Unknown command '{params.command}' encountered in main dispatch.")
            exit_code = 1 # Failure

    # --- Unified Exception Handling ---
    except ConfigurationError as e:
        print(f"\nConfiguration Error: {e.message}")
        logger.error(f"Configuration error: {e.message}", exc_info=False)
        exit_code = 1
    except ValidationError as e:
        print(f"\nValidation Error: {e.message}")
        logger.error(f"Validation error: {e.message}", exc_info=False)
        exit_code = 1
    except ApiError as e:
        print(f"\nAPI Error: {e.message}")
        logger.error(f"API error: {e.message}", exc_info=True)
        exit_code = 1
    except NetworkError as e:
        print(f"\nNetwork Error: {e.message}")
        logger.error(f"Network error: {e.message}", exc_info=True)
        exit_code = 1
    except ProcessError as e:
        print(f"\nProcess Error: {e.message}")
        logger.error(f"Process error: {e.message}", exc_info=True)
        exit_code = 1
    except ProcessTimeoutError as e:
        print(f"\nProcess Timeout: {e.message}")
        logger.error(f"Process timeout: {e.message}", exc_info=True)
        exit_code = 1
    except FileSystemError as e:
        print(f"\nFile System Error: {e.message}")
        logger.error(f"File system error: {e.message}", exc_info=True)
        exit_code = 1
    except CompatibilityError as e:
        print(f"\nCompatibility Error: {e.message}")
        logger.error(f"Compatibility error: {e.message}", exc_info=False)
        exit_code = 1
    except WorkbenchAgentError as e:
        print(f"\nWorkbench Agent Error: {e.message}")
        logger.error(f"Workbench agent error: {e.message}", exc_info=True)
        exit_code = 1
    except Exception as e:
        print(f"\nUnexpected Error: {e}")
        logger.critical(f"Unexpected error: {e}", exc_info=True)
        exit_code = 1
    finally:
        # Calculate and print duration regardless of success/failure
        end_time = time.monotonic()
        duration_seconds = end_time - start_time
        # Use the static method from Workbench class for formatting
        duration_str = Workbench.format_duration(duration_seconds)
        print(f"\nTotal Execution Time: {duration_str}")

    return exit_code