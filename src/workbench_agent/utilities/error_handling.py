"""
Error handling utilities for the Workbench Agent.

This module provides standardized error handling and formatting
for better user experience in CI/CD pipeline scenarios.
"""

import logging
import argparse
import functools
from typing import Callable

from ..exceptions import (
    WorkbenchAgentError,
    ApiError,
    NetworkError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    ProjectNotFoundError,
    ScanNotFoundError,
    ConfigurationError,
    CompatibilityError
)

logger = logging.getLogger("workbench-agent")


def handler_error_wrapper(handler_func: Callable) -> Callable:
    """
    A simple decorator for handler functions that provides logging and re-raises exceptions.
    
    This wrapper ensures handler functions log their execution but lets exceptions
    bubble up to the main error handling logic.
    
    Args:
        handler_func: The handler function to wrap
        
    Returns:
        Wrapped handler function
    """
    @functools.wraps(handler_func)
    def wrapper(*args, **kwargs):
        handler_name = handler_func.__name__
        logger.debug(f"Starting handler: {handler_name}")
        
        try:
            result = handler_func(*args, **kwargs)
            logger.debug(f"Handler {handler_name} completed successfully")
            return result
        except Exception as e:
            logger.debug(f"Handler {handler_name} raised exception: {type(e).__name__}: {e}")
            raise  # Re-raise the exception to be handled by main error handling
    
    return wrapper


def format_and_print_error(error: Exception, params: argparse.Namespace):
    """
    Formats and prints a standardized error message for CI/CD users.
    
    This centralized function handles consistent error formatting,
    providing helpful guidance for common integration scenarios.
    
    Args:
        error: The exception that occurred
        params: Command line parameters
    """
    error_type = type(error).__name__
    
    # Get error details if available (for our custom errors)
    error_message = getattr(error, 'message', str(error))
    error_code = getattr(error, 'code', None)
    error_details = getattr(error, 'details', {})
    
    # Add context-specific help based on error type
    if isinstance(error, ProjectNotFoundError):
        print(f"\n❌ Project not found")
        print(f"   Project '{params.project_code}' does not exist in your Workbench instance.")
        print(f"\n💡 Possible solutions:")
        print(f"   • Check that the project name is spelled correctly")
        print(f"   • Verify the project exists in Workbench: {params.api_url}")
        print(f"   • Ensure your account has access to this project")
        print(f"   • The project will be created automatically if it doesn't exist")
    
    elif isinstance(error, ScanNotFoundError):
        print(f"\n❌ Scan not found")
        print(f"   Scan '{params.scan_code}' does not exist in project '{params.project_code}'.")
        print(f"\n💡 Possible solutions:")
        print(f"   • Check that the scan name is spelled correctly")
        print(f"   • Verify the scan exists in the specified project")
        print(f"   • The scan will be created automatically if it doesn't exist")
    
    elif isinstance(error, NetworkError):
        print(f"\n❌ Network connectivity issue")
        print(f"   Unable to connect to the Workbench server.")
        print(f"   Details: {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • The Workbench server is accessible from your CI/CD environment")
        print(f"   • The API URL is correct: {params.api_url}")
        print(f"   • Network firewalls allow outbound HTTPS connections")
        print(f"   • The server is not experiencing downtime")
    
    elif isinstance(error, ApiError):
        # Check for credential errors first
        if "user_not_found_or_api_key_is_not_correct" in error_message:
            print(f"\n❌ Invalid Workbench credentials")
            print(f"   The username or API token provided is incorrect.")
            print(f"\n💡 Please verify:")
            print(f"   • Username: {params.api_user}")
            print(f"   • API token is correct and not expired")
            print(f"   • Account has access to the Workbench instance")
            print(f"   • API URL is correct: {params.api_url}")
            print(f"\n🔧 In CI/CD pipelines:")
            print(f"   • Store credentials as secure environment variables")
            print(f"   • Ensure API tokens have sufficient permissions")
            return  # Exit early to avoid showing generic API error details
        
        print(f"\n❌ Workbench API error")
        print(f"   {error_message}")
        
        if error_code:
            print(f"   Error code: {error_code}")
        print(f"\n💡 The Workbench API reported an issue with your request")
    
    elif isinstance(error, ProcessTimeoutError):
        print(f"\n❌ Operation timed out")
        print(f"   {error_message}")
        print(f"\n💡 For CI/CD environments, consider:")
        print(f"   • Increasing timeout values:")
        print(f"     --scan-number-of-tries (current: {params.scan_number_of_tries})")
        print(f"     --scan-wait-time (current: {params.scan_wait_time})")
        print(f"   • Large codebases may require longer scan times")
        print(f"   • Check Workbench server performance and load")
    
    elif isinstance(error, ProcessError):
        print(f"\n❌ Workbench process failed")
        print(f"   {error_message}")
        print(f"\n💡 Common causes:")
        print(f"   • Scan conflicts with existing operations")
        print(f"   • Server resource limitations")
        print(f"   • Invalid scan configuration")
    
    elif isinstance(error, FileSystemError):
        print(f"\n❌ File system error")
        print(f"   {error_message}")
        print(f"\n💡 Please check:")
        print(f"   • File and directory permissions are correct")
        print(f"   • Specified paths exist and are accessible")
        if hasattr(params, 'path'):
            print(f"   • Source path: {params.path}")
        if hasattr(params, 'path_result'):
            print(f"   • Output path: {params.path_result}")
        print(f"\n🔧 In CI/CD pipelines:")
        print(f"   • Ensure the agent has read access to source files")
        print(f"   • Verify write permissions for output directories")
    
    elif isinstance(error, ValidationError):
        print(f"\n❌ Invalid configuration")
        print(f"   {error_message}")
        print(f"\n💡 Please check your command-line arguments:")
        print(f"   • All required parameters are provided")
        print(f"   • Parameter values are in the correct format")
        print(f"   • File paths are valid and accessible")
    
    elif isinstance(error, AuthenticationError):
        print(f"\n❌ Authentication failed")
        print(f"   {error_message}")
        print(f"\n💡 Authentication checklist:")
        print(f"   • API credentials are correct")
        print(f"   • Account has necessary permissions")
        print(f"   • API token is not expired")
        print(f"   • Account is not locked or disabled")
    
    elif isinstance(error, (ConfigurationError, CompatibilityError)):
        # These are usually handled gracefully, but just in case
        print(f"\n⚠️  Resource already exists")
        print(f"   {error_message}")
        print(f"   This is typically handled automatically - continuing with existing resource.")
    
    else:
        # Generic error formatting for unexpected errors
        print(f"\n❌ Unexpected error occurred")
        print(f"   {error_message}")
        print(f"   Error type: {error_type}")
    
    # Show error code if available (and not already shown)
    if error_code and not isinstance(error, (ApiError,)):
        print(f"\nError code: {error_code}")
    
    # Show details in verbose mode
    if getattr(params, 'log', 'ERROR') == 'DEBUG' and error_details:
        print("\n🔍 Detailed error information:")
        for key, value in error_details.items():
            print(f"   • {key}: {value}")
    
    # Add help text for debugging
    if getattr(params, 'log', 'ERROR') != 'DEBUG':
        print(f"\n🔧 For more detailed logs, run with --log DEBUG")


def agent_error_wrapper(parse_args_func: Callable) -> Callable:
    """
    A decorator that wraps the main agent function with standardized error handling.
    
    This wrapper ensures consistent error handling for the workbench-agent,
    providing user-friendly error messages while maintaining the same exit codes
    and behavior expected in CI/CD environments.
    
    Args:
        parse_args_func: Function to parse command line arguments for context
        
    Returns:
        Decorator function
    
    Example:
        @agent_error_wrapper(parse_cmdline_args)
        def main():
            # Implementation without try/except blocks
            ...
    """
    def decorator(main_func: Callable) -> Callable:
        @functools.wraps(main_func)
        def wrapper():
            try:
                logger.debug("Starting Workbench Agent execution")
                
                # Call the actual main function
                return main_func()
                
            except (ProjectNotFoundError, ScanNotFoundError, FileSystemError, 
                    ApiError, NetworkError, ProcessError, ProcessTimeoutError, 
                    ValidationError, AuthenticationError, ConfigurationError,
                    CompatibilityError) as e:
                # These exceptions are expected and should be handled gracefully
                logger.debug(f"Expected error in workbench-agent: {type(e).__name__}: {getattr(e, 'message', str(e))}")
                
                # Parse command line args to get context for error formatting
                try:
                    params = parse_args_func()
                except Exception:
                    # Fallback if we can't parse args
                    params = argparse.Namespace()
                    params.api_url = '<unknown>'
                    params.api_user = '<unknown>'
                    params.project_code = '<unknown>'
                    params.scan_code = '<unknown>'
                    params.scan_number_of_tries = '<unknown>'
                    params.scan_wait_time = '<unknown>'
                    params.log = 'ERROR'
                
                # Format and display error message
                format_and_print_error(e, params)
                
                # Exit with appropriate code (1 for errors, maintaining CI/CD compatibility)
                logger.debug(f"Exiting with error code 1 due to {type(e).__name__}")
                exit(1)
                
            except KeyboardInterrupt:
                print(f"\n⚠️  Operation cancelled by user")
                logger.debug("Operation cancelled by user (KeyboardInterrupt)")
                exit(130)  # Standard exit code for SIGINT
                
            except Exception as e:
                # Unexpected errors get special handling
                logger.error(f"Unexpected error in workbench-agent: {e}", exc_info=True)
                
                # Try to get params for context
                try:
                    params = parse_args_func()
                except Exception:
                    # Fallback if we can't parse args
                    params = argparse.Namespace()
                    params.log = 'ERROR'
                
                print(f"\n❌ Unexpected error occurred")
                print(f"   {str(e)}")
                print(f"   This may indicate a bug in the workbench-agent")
                
                if getattr(params, 'log', 'ERROR') == 'DEBUG':
                    print(f"\n🔍 Full error details:")
                    import traceback
                    traceback.print_exc()
                else:
                    print(f"\n🔧 For full error details, run with --log DEBUG")
                
                # Exit with error code 2 for unexpected errors
                logger.debug(f"Exiting with error code 2 due to unexpected error: {e}")
                exit(2)
                
        return wrapper
    return decorator 