import logging
from typing import Dict, Any, List, Optional, Tuple
from .helpers.api_base import APIBase
from .helpers.process_waiters import ProcessWaiters
from .helpers.status_checkers import StatusCheckers
from ..exceptions import ApiError, ScanNotFoundError, ScanExistsError, ValidationError

logger = logging.getLogger("workbench-agent")


class ScansAPI(APIBase, ProcessWaiters, StatusCheckers):
    """
    API client for scan-related operations on the Workbench platform.
    
    This class provides methods for creating, managing, and monitoring scans,
    including uploading files, running analyses, and retrieving results.
    Inherits from ProcessWaiters and StatusCheckers mixins for status checking and waiting capabilities.
    """

    # --- Enhanced Validation Methods ---
    
    def _validate_scan_parameters(self, scan_code: str, **kwargs) -> None:
        """
        Validates scan parameters before API operations.
        
        Args:
            scan_code: The scan code to validate
            **kwargs: Additional parameters to validate
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not scan_code or not scan_code.strip():
            raise ValidationError("Scan code cannot be empty")
            
        # Validate limit parameter
        limit = kwargs.get('limit')
        if limit is not None and (not isinstance(limit, int) or limit < 1):
            raise ValidationError("Limit must be a positive integer")
            
        # Validate sensitivity parameter
        sensitivity = kwargs.get('sensitivity')
        if sensitivity is not None and (not isinstance(sensitivity, int) or sensitivity < 1):
            raise ValidationError("Sensitivity must be a positive integer")
            
        # Validate match filtering threshold
        threshold = kwargs.get('match_filtering_threshold')
        if threshold is not None and not isinstance(threshold, int):
            raise ValidationError("Match filtering threshold must be an integer")

    def _validate_reuse_parameters(self, reuse_identification: bool, identification_reuse_type: str = None, specific_code: str = None) -> None:
        """
        Validates identification reuse parameters.
        
        Args:
            reuse_identification: Whether identification reuse is enabled
            identification_reuse_type: Type of reuse
            specific_code: Specific code for reuse
            
        Raises:
            ValidationError: If reuse parameters are invalid
        """
        if reuse_identification:
            valid_reuse_types = {"any", "only_me", "specific_project", "specific_scan"}
            if identification_reuse_type and identification_reuse_type not in valid_reuse_types:
                raise ValidationError(f"Invalid identification_reuse_type. Must be one of: {valid_reuse_types}")
                
            if identification_reuse_type in {"specific_project", "specific_scan"} and not specific_code:
                raise ValidationError(f"specific_code is required when using {identification_reuse_type}")

    # --- Scan Information Methods ---
    
    def get_scan_information(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieves detailed information about a scan.
        
        Args:
            scan_code: Code of the scan to get information for
            
        Returns:
            Dict containing scan information
            
        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting scan information for '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_information", 
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "row_not_found" in error_msg or "Scan not found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get scan information for '{scan_code}': {error_msg}",
                details=response,
            )

    def check_if_scan_exists(self, scan_code: str) -> bool:
        """
        Check if scan exists (backwards compatibility with original agent).
        
        Args:
            scan_code: The unique identifier for the scan
            
        Returns:
            bool: True if scan exists, False otherwise
        """
        try:
            self.get_scan_information(scan_code)
            return True
        except ScanNotFoundError:
            return False
        except (ApiError, Exception):
            # On other errors, assume scan doesn't exist for safety
            return False

    # --- Existing Methods with Enhanced Organization ---

    def list_scans(self) -> List[Dict[str, Any]]:
        """
        List all scans accessible to the current user.

        Returns:
            List[Dict]: List of scan dictionaries with keys like code, name, project_code, etc.

        Raises:
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug("Listing all scans")

        payload = {
            "group": "scans",
            "action": "get_all_scans",
            "data": {}
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            scans = response["data"]
            if isinstance(scans, list):
                logger.debug(f"Found {len(scans)} scans")
                return scans
            elif isinstance(scans, dict):
                # Sometimes API returns dict instead of list
                logger.debug(f"Found {len(scans)} scans (as dict)")
                return list(scans.values()) if scans else []
            else:
                logger.warning(f"Expected list or dict for scans, got {type(scans)}")
                return []
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise ApiError(f"Failed to list scans: {error_msg}", details=response)

    def create_webapp_scan(
        self, scan_code: str, project_code: str = None, target_path: str = None
    ) -> int:
        """
        Creates a Scan in Workbench. The scan can optionally be created inside a Project.
        Enhanced with better validation and error handling.

        Args:
            scan_code: The unique identifier for the scan
            project_code: The project code within which to create the scan
            target_path: Optional target path where scan is stored (for server-side scanning)

        Returns:
            int: The scan ID of the created scan

        Raises:
            ScanExistsError: If a scan with this code already exists
            ValidationError: If parameters are invalid
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        # Enhanced validation
        if not scan_code or not scan_code.strip():
            raise ValidationError("Scan code cannot be empty")
            
        logger.debug(f"Creating webapp scan '{scan_code}' in project '{project_code}'")

        payload = {
            "group": "scans",
            "action": "create",
            "data": {
                "scan_code": scan_code,
                "scan_name": scan_code,
                "project_code": project_code,
                "description": "Scan created using the Workbench Agent.",
            },
        }
        
        # Add target_path only if provided (backwards compatibility)
        if target_path:
            payload["data"]["target_path"] = target_path

        try:
            response = self._send_request(payload)
            if response.get("status") == "1" and "data" in response:
                scan_id = response["data"].get("scan_id")
                if scan_id is None:
                    raise ApiError("Scan created but no scan_id returned", details=response)
                logger.debug(f"Successfully created scan '{scan_code}' with ID {scan_id}")
                return int(scan_id)
            else:
                error_msg = response.get("error", f"Unexpected response: {response}")
                raise ApiError(
                    f"Failed to create scan '{scan_code}': {error_msg}", details=response
                )
        except ScanExistsError:
            raise  # Re-raise specific errors
        except Exception as e:
            if isinstance(e, (ApiError, ScanExistsError)):
                raise
            raise ApiError(f"Failed to create scan '{scan_code}': {e}", details={"error": str(e)})

    def start_dependency_analysis(self, scan_code: str):
        """
        Initiate dependency analysis for a scan.

        Args:
            scan_code: The unique identifier for the scan

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ProcessError: If dependency analysis cannot be started
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug(f"Starting dependency analysis for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to start dependency analysis for scan '{scan_code}': {error_msg}",
                details=response,
            )

        logger.info(f"Dependency analysis started for scan '{scan_code}'")

    def get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Call API scans -> get_pending_files.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            dict: Dictionary of pending files

        Raises:
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting pending files for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_pending_files",
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            data = response["data"]
            if isinstance(data, dict):
                logger.debug(f"Found {len(data)} pending files for scan '{scan_code}'")
                return data
            else:
                logger.warning(f"Expected dict for pending files, got {type(data)}")
                return {}
        else:
            error_msg = response.get("error", f"Unexpected response: {response}")
            logger.error(f"Failed to get pending files for scan '{scan_code}': {error_msg}")
            return {}  # Return empty dict instead of raising exception

    def get_policy_warnings_counter(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve policy warnings information at scan level.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            dict: The policy warnings data

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting policy warnings counter for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get policy warnings counter for scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_identified_components(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve the list of identified components from one scan.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            dict: The identified components data

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting identified components for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get identified components for scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_scan_identified_licenses(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve the list of identified licenses from one scan.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            dict: The identified licenses data

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting identified licenses for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "scan_code": scan_code,
                "unique": "1",
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get identified licenses for scan '{scan_code}': {error_msg}",
                details=response,
            )

    def get_results(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve the list matches from one scan.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            dict: The scan results data

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting scan results for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_results",
            "data": {
                "scan_code": scan_code,
                "unique": "1",
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get scan results for scan '{scan_code}': {error_msg}", details=response
            )

    def get_dependency_analysis_result(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve dependency analysis results.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            dict: The dependency analysis results

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If there are API issues
            NetworkError: If there are network issues
        """
        logger.debug(f"Getting dependency analysis results for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") == "1" and "data" in response:
            return response["data"]
        else:
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to get dependency analysis results for scan '{scan_code}': {error_msg}",
                details=response,
            )

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ) -> bool:
        """
        Extract archive

        Args:
            scan_code: The unique identifier for the scan
            recursively_extract_archives: Yes or no
            jar_file_extraction: Yes or no

        Returns:
            bool: True for successful API call

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug(f"Extracting archives for scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "extract_archives",
            "data": {
                "scan_code": scan_code,
                "recursively_extract_archives": recursively_extract_archives,
                "jar_file_extraction": jar_file_extraction,
            },
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            if "Scan not found" in error_msg or "row_not_found" in error_msg:
                raise ScanNotFoundError(f"Scan '{scan_code}' not found")
            raise ApiError(
                f"Failed to extract archives for scan '{scan_code}': {error_msg}", details=response
            )

        logger.info(f"Archive extraction completed for scan '{scan_code}'")
        return True



    def run_scan(
        self,
        scan_code: str,
        limit: int,
        sensitivity: int,
        auto_identification_detect_declaration: bool,
        auto_identification_detect_copyright: bool,
        auto_identification_resolve_pending_ids: bool,
        delta_only: bool,
        reuse_identification: bool,
        identification_reuse_type: str = None,
        specific_code: str = None,
        advanced_match_scoring: bool = True,
        match_filtering_threshold: int = -1,
    ):
        """
        Run a scan with the specified parameters.
        Enhanced with parameter validation and better error handling.

        Args:
            scan_code: Unique scan identifier
            limit: Limit the number of matches against the KB
            sensitivity: Result sensitivity
            auto_identification_detect_declaration: Automatically detect license declaration inside files
            auto_identification_detect_copyright: Automatically detect copyright statements inside files
            auto_identification_resolve_pending_ids: Automatically resolve pending identifications
            delta_only: Scan only new or modified files
            reuse_identification: Reuse previous identifications
            identification_reuse_type: Possible values: any,only_me,specific_project,specific_scan
            specific_code: Fill only when reuse type: specific_project or specific_scan
            advanced_match_scoring: If true, scan will run with advanced match scoring
            match_filtering_threshold: Minimum length (in characters) of snippet to be considered valid

        Raises:
            ScanNotFoundError: If the scan doesn't exist
            ValidationError: If parameters are invalid
            ProcessError: If the scan cannot be started
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        # Enhanced parameter validation
        self._validate_scan_parameters(
            scan_code=scan_code,
            limit=limit,
            sensitivity=sensitivity,
            match_filtering_threshold=match_filtering_threshold
        )
        self._validate_reuse_parameters(
            reuse_identification=reuse_identification,
            identification_reuse_type=identification_reuse_type,
            specific_code=specific_code
        )
        
        logger.info(f"Starting scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "run",
            "data": {
                "scan_code": scan_code,
                "limit": limit,
                "sensitivity": sensitivity,
                "auto_identification_detect_declaration": int(
                    auto_identification_detect_declaration
                ),
                "auto_identification_detect_copyright": int(auto_identification_detect_copyright),
                "auto_identification_resolve_pending_ids": int(
                    auto_identification_resolve_pending_ids
                ),
                "delta_only": int(delta_only),
                "advanced_match_scoring": int(advanced_match_scoring),
            },
        }

        if match_filtering_threshold > -1:
            payload["data"]["match_filtering_threshold"] = match_filtering_threshold

        if reuse_identification:
            data = payload["data"]
            data["reuse_identification"] = "1"
            # 'any', 'only_me', 'specific_project', 'specific_scan'
            if identification_reuse_type in {"specific_project", "specific_scan"}:
                data["identification_reuse_type"] = identification_reuse_type
                data["specific_code"] = specific_code
            else:
                data["identification_reuse_type"] = identification_reuse_type

        response = self._send_request(payload)
        if response.get("status") != "1":
            error_msg = response.get("error", "Unknown error")
            logger.error(f"Failed to start scan '{scan_code}': {error_msg} payload {payload}")
            raise ApiError(f"Failed to start scan '{scan_code}': {error_msg}", details=response)

        logger.info(f"Scan '{scan_code}' started successfully")
        return response

    # --- Backwards Compatibility Methods ---
    
    def _get_scan_status(self, scan_type: str, scan_code: str) -> Dict[str, Any]:
        """
        Calls API scans -> check_status (backwards compatibility with original agent).
        
        Args:
            scan_type: One of these: SCAN, DEPENDENCY_ANALYSIS
            scan_code: The unique identifier for the scan
            
        Returns:
            dict: The data section from the JSON response returned from API
            
        Raises:
            ApiError: If the API call fails
            ScanNotFoundError: If the scan doesn't exist
        """
        return self.check_status(scan_type, scan_code)



    def _get_pending_files(self, scan_code: str) -> Dict[str, str]:
        """
        Call API scans -> get_pending_files (backwards compatibility with original agent).
        
        Args:
            scan_code: The unique identifier for the scan
            
        Returns:
            dict: Dictionary of pending files
            
        Raises:
            Exception: If there are API issues (original agent behavior)
        """
        try:
            return self.get_pending_files(scan_code)
        except Exception as e:
            # Match original agent behavior - raise Exception instead of specific errors
            raise Exception(f"Error getting pending files result: {e}")

    def _get_dependency_analysis_result(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve dependency analysis results (backwards compatibility with original agent).
        
        Args:
            scan_code: The unique identifier for the scan
            
        Returns:
            dict: The dependency analysis results
            
        Raises:
            Exception: If there are API issues (original agent behavior)
        """
        try:
            return self.get_dependency_analysis_result(scan_code)
        except Exception as e:
            # Match original agent behavior - raise Exception instead of specific errors
            raise Exception(f"Error getting dependency analysis result: {e}")

    def _cancel_scan(self, scan_code: str) -> None:
        """
        Cancel a scan (backwards compatibility with original agent).
        
        Args:
            scan_code: The unique identifier for the scan
            
        Raises:
            Exception: If cancellation fails (original agent behavior)
        """
        logger.debug(f"Cancelling scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "cancel_run",
            "data": {
                "scan_code": scan_code,
            },
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            # Match original agent behavior - raise Exception with specific message
            raise Exception(f"Error cancelling scan: {response}")

        logger.info(f"Successfully cancelled scan '{scan_code}'")

    def scans_get_policy_warnings_counter(self, scan_code: str) -> Dict[str, Any]:
        """
        Retrieve policy warnings information at scan level (backwards compatibility).
        
        Args:
            scan_code: The unique identifier for the scan
            
        Returns:
            dict: The policy warnings data
            
        Raises:
            Exception: If there are API issues (original agent behavior)
        """
        try:
            return self.get_policy_warnings_counter(scan_code)
        except Exception as e:
            # Match original agent behavior - raise Exception instead of specific errors
            raise Exception(f"Error getting project policy warnings information result: {e}")



    def remove_uploaded_content(self, filename: str, scan_code: str):
        """
        When using chunked uploading every new chunk is appended to existing file, for this reason we need to make sure
        that initially there is no file (from previous uploading).

        Args:
            filename: The file to be deleted
            scan_code: The unique identifier for the scan
        """
        logger.debug(f"Removing uploaded content '{filename}' from scan '{scan_code}'")
        print(
            f"Called scans->remove_uploaded_content on file {filename}"
        )  # Match original behavior

        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": {
                "scan_code": scan_code,
                "filename": filename,
            },
        }

        response = self._send_request(payload)
        if response.get("status") != "1":
            warning_msg = f"Cannot delete file {filename}, maybe is the first time when uploading this file? API response {response}."
            print(warning_msg)  # Match original behavior
            logger.warning(
                f"Cannot delete file '{filename}' from scan '{scan_code}', maybe is the first time uploading? API response: {response}"
            )
        else:
            logger.debug(f"Successfully removed '{filename}' from scan '{scan_code}'")
