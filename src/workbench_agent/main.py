import sys
import time
import logging
import traceback
from typing import Optional

# Import from other modules in the package
from .api import WorkbenchAPI
from .cli import parse_cmdline_args
from .utilities.error_handling import agent_error_wrapper
from .utilities.scan_workflows import format_duration
from .exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    ProjectNotFoundError,
    ScanNotFoundError
)

# Import handlers
from .handlers.scan import handle_scan
from .handlers.blind_scan import handle_blind_scan


def setup_logging(log_level: str) -> logging.Logger:
    """
    Set up enhanced logging configuration with both file and console handlers.
    
    Args:
        log_level: The logging level (DEBUG, INFO, WARNING, ERROR)
        
    Returns:
        Configured logger instance
    """
    # Parse log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure basic logging (file handler)
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.FileHandler("workbench-agent-log.txt", mode='w')],
        force=True  # Allow reconfiguration if run multiple times
    )
    
    # Add console handler with simpler format
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)
    logging.getLogger().addHandler(console_handler)
    
    return logging.getLogger("workbench-agent")


def print_configuration(params) -> None:
    """
    Print configuration summary for verification.
    
    Args:
        params: Parsed command line parameters
    """
    print("--- Workbench Agent Configuration ---")
    print(f"Command: {getattr(params, 'command', getattr(params, 'scan_type', 'unknown'))}")
    
    # Sort and display all parameters
    for k, v in sorted(params.__dict__.items()):
        if k in ['command', 'scan_type']:
            continue
        display_val = v
        
        # Mask sensitive information unless in debug mode
        if k == 'api_token' and getattr(params, 'log', 'INFO').upper() != 'DEBUG':
            display_val = "****" if v else "Not Set"
        
        print(f"  {k:<30} = {display_val}")
    print("------------------------------------")


def main() -> int:
    """
    Main function to parse arguments, set up logging, initialize the API client,
    and execute the workbench agent operations using the appropriate handler.
    
    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    start_time = time.monotonic()
    exit_code = 1  # Default to failure
    logger = None  # Initialize logger variable

    try:
        # Parse command line arguments
        args = parse_cmdline_args()

        # Setup enhanced logging
        logger = setup_logging(args.log)
        
        # Print configuration for verification
        print_configuration(args)
        
        logger.info("FossID Workbench Agent starting...")
        logger.debug(f"Command line arguments: {vars(args)}")

        # Initialize API client
        logger.info("Initializing Workbench API client...")
        api = WorkbenchAPI(
            api_url=args.api_url,
            api_user=args.api_user,
            api_token=args.api_token
        )
        logger.info("Workbench API client initialized.")

        # Command handler dispatch
        COMMAND_HANDLERS = {
            'scan': handle_scan,
            'blind_scan': handle_blind_scan,
        }
        
        # Determine which handler to use
        command_key = getattr(args, 'scan_type', getattr(args, 'command', None))
        handler = COMMAND_HANDLERS.get(command_key)
        
        if not handler:
            raise ValidationError(f"Unknown command/scan type: {command_key}")
        
        # Execute the command handler
        logger.info(f"Executing {command_key} command...")
        success = handler(api, args)
        
        if success:
            exit_code = 0
            print("\nWorkbench Agent finished successfully.")
        else:
            logger.error("Handler reported failure")
            print("\nWorkbench Agent finished with errors.")
            exit_code = 1

    # Enhanced exception handling with detailed error information
    except (AuthenticationError, ValidationError) as e:
        # Errors typically due to user input/setup
        print(f"\nDetailed Error Information:")
        print(f"Configuration Error: {e}")
        if logger: 
            logger.error("%s: %s", type(e).__name__, e, exc_info=False)
        exit_code = 2
        
    except (ApiError, NetworkError) as e:
        # API and network related errors
        print(f"\nDetailed Error Information:")
        print(f"API/Network Error: {e}")
        if logger: 
            logger.error("%s: %s", type(e).__name__, e, exc_info=True)
        exit_code = 3
        
    except (ProcessError, ProcessTimeoutError) as e:
        # Process execution errors
        print(f"\nDetailed Error Information:")
        print(f"Process Error: {e}")
        if logger: 
            logger.error("%s: %s", type(e).__name__, e, exc_info=True)
        exit_code = 4
        
    except FileSystemError as e:
        # File system related errors
        print(f"\nDetailed Error Information:")
        print(f"File System Error: {e}")
        if logger: 
            logger.error("%s: %s", type(e).__name__, e, exc_info=True)
        exit_code = 5
        
    except (ProjectNotFoundError, ScanNotFoundError) as e:
        # Resource not found errors
        print(f"\nDetailed Error Information:")
        print(f"Resource Error: {e}")
        if logger: 
            logger.error("%s: %s", type(e).__name__, e, exc_info=True)
        exit_code = 6
        
    except WorkbenchAgentError as e:
        # General workbench agent errors
        print(f"\nDetailed Error Information:")
        print(f"Workbench Agent Error: {e}")
        if logger: 
            logger.error("%s: %s", type(e).__name__, e, exc_info=True)
        exit_code = 7
        
    except KeyboardInterrupt:
        print(f"\nOperation interrupted by user")
        if logger:
            logger.warning("Operation interrupted by user")
        exit_code = 130
        
    except Exception as e:
        # Catch truly unexpected errors
        print(f"\nDetailed Error Information:")
        print(f"Unexpected Error: {e}")
        # Format and print the traceback
        tb_lines = traceback.format_exception(type(e), e, e.__traceback__)
        print("".join(tb_lines).rstrip())
        if logger:
            logger.critical("Unexpected error occurred", exc_info=True)
        exit_code = 1

    finally:
        # Calculate and print duration regardless of success/failure
        end_time = time.monotonic()
        duration_seconds = end_time - start_time
        duration_str = format_duration(duration_seconds)
        print(f"\nTotal Execution Time: {duration_str}")
        if logger: 
            logger.info("Total execution time: %s", duration_str)

    return exit_code


if __name__ == "__main__":
    sys.exit(main()) 