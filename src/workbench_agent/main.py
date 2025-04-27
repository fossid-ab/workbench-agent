# workbench_agent/main.py

import sys
import time
import logging
import argparse
import builtins # Still needed as exceptions weren't refactored yet

# Import components from other modules in the package
from .cli import parse_cmdline_args
from .api import Workbench
# Import the handlers module itself to access functions via handlers.handle_scan etc.
from . import handlers
# Import specific exceptions if you defined them (e.g., from .exceptions import ApiError, ...)
# If not using custom exceptions yet, the generic except block will catch builtins.Exception

# --- Main Application Logic ---

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
            # Format nicely
            print(f"  {k:<30} = {display_val}")
        print("------------------------------------")
        logger.debug("Parsed parameters: %s", params)

        # Initialize Workbench API client
        try:
            workbench = Workbench(params.api_url, params.api_user, params.api_token)
            logger.info("Workbench client initialized.")
        except Exception as e:
             # Handle initialization errors separately
             print(f"\nError initializing Workbench connection: {e}")
             logger.critical("Failed to initialize Workbench connection", exc_info=True)
             # No need to calculate duration here, finally block will handle it
             return 1 # Return failure code

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
    # Catch specific custom exceptions first if defined (e.g., ApiError, CompatibilityError)
    # except (ApiError, NetworkError) as e:
    #     print(f"\n--- API or Network Error ---")
    #     logger.error(f"Script failed: {e}", exc_info=True)
    #     print(f"Error: {e}")
    #     print("----------------------------")
    #     exit_code = 1
    # except CompatibilityError as e:
    #      print(f"\n--- Compatibility Error ---")
    #      logger.error(f"Script failed: {e}", exc_info=False) # No traceback needed usually
    #      print(f"Error: {e}")
    #      print("----------------------------")
    #      exit_code = 1 # Or a specific code like 2
    except builtins.Exception as e: # Catch generic exceptions raised by handlers/utils
        print(f"\n--- An error occurred during execution ---")
        # Log the specific error message raised by the handlers/waiters
        # Include traceback in log for debugging runtime errors
        logger.error(f"Script failed during command '{getattr(params, 'command', 'N/A')}': {e}", exc_info=True)
        print(f"Error: {e}") # Print the concise error message to console
        print("------------------------------------")
        exit_code = 1 # General failure
    except Exception as e: # Catch any other unexpected errors (e.g., during setup)
        print(f"\n--- An unexpected critical error occurred ---")
        logger.critical(f"Script failed with unexpected error: {e}", exc_info=True)
        print(f"Unexpected Error: {e}")
        print("------------------------------------")
        exit_code = 1 # General failure
    finally:
        # Calculate and print duration regardless of success/failure
        end_time = time.monotonic()
        duration_seconds = end_time - start_time
        # Use the static method from Workbench class for formatting
        duration_str = Workbench.format_duration(duration_seconds)
        print(f"\nTotal Execution Time: {duration_str}")

    return exit_code

# Note: The if __name__ == "__main__": block is now in the top-level workbench-agent.py script.
