import logging
from typing import Callable

logger = logging.getLogger("workbench-agent")


def check_if_project_exists(send_request_func: Callable, project_code: str) -> bool:
    """
    Check if project exists.

    Args:
        send_request_func: Function to send API requests (typically _send_request from API class)
        project_code: The unique identifier for the project

    Returns:
        bool: True if project exists, False otherwise
    """
    from .exceptions import ProjectNotFoundError

    logger.debug(f"Checking if project '{project_code}' exists")

    payload = {
        "group": "projects",
        "action": "get_information",
        "data": {
            "project_code": project_code,
        },
    }

    try:
        response = send_request_func(payload)
        # If we get a successful response, the project exists
        if response.get("status") == "1":
            logger.debug(f"Project '{project_code}' exists")
            return True
        else:
            logger.debug(
                f"Project '{project_code}' does not exist (status: {response.get('status')})"
            )
            return False
    except ProjectNotFoundError:
        # This is expected when project doesn't exist
        logger.debug(f"Project '{project_code}' does not exist")
        return False
    except Exception as e:
        # For any other exception, log it and re-raise
        logger.error(f"Error checking if project '{project_code}' exists: {e}")
        raise


def check_if_scan_exists(send_request_func: Callable, scan_code: str) -> bool:
    """
    Check if scan exists.

    Args:
        send_request_func: Function to send API requests (typically _send_request from API class)
        scan_code: The unique identifier for the scan

    Returns:
        bool: True if scan exists, False otherwise
    """
    from .exceptions import ScanNotFoundError

    logger.debug(f"Checking if scan '{scan_code}' exists")

    payload = {
        "group": "scans",
        "action": "get_information",
        "data": {
            "scan_code": scan_code,
        },
    }

    try:
        response = send_request_func(payload)
        # If we get a successful response, the scan exists
        if response.get("status") == "1":
            logger.debug(f"Scan '{scan_code}' exists")
            return True
        else:
            logger.debug(f"Scan '{scan_code}' does not exist (status: {response.get('status')})")
            return False
    except ScanNotFoundError:
        # This is expected when scan doesn't exist
        logger.debug(f"Scan '{scan_code}' does not exist")
        return False
    except Exception as e:
        # For any other exception, log it and re-raise
        logger.error(f"Error checking if scan '{scan_code}' exists: {e}")
        raise
