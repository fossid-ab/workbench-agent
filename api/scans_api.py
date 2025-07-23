import logging
from typing import Dict, Any
from .helpers.api_base import APIBase
from .helpers.exceptions import ApiError, ScanNotFoundError, ScanExistsError
from .helpers.project_scan_checks import check_if_scan_exists

logger = logging.getLogger("workbench-agent")


class ScansAPI(APIBase):
    """
    Workbench API Scans Operations.
    """

    def create_webapp_scan(
        self, scan_code: str, project_code: str = None, target_path: str = None
    ) -> int:
        """
        Creates a Scan in Workbench. The scan can optionally be created inside a Project.

        Args:
            scan_code: The unique identifier for the scan
            project_code: The project code within which to create the scan
            target_path: The target path where scan is stored

        Returns:
            int: The scan ID of the created scan

        Raises:
            ScanExistsError: If a scan with this code already exists
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        logger.debug(f"Creating webapp scan '{scan_code}' in project '{project_code}'")

        payload = {
            "group": "scans",
            "action": "create",
            "data": {
                "scan_code": scan_code,
                "scan_name": scan_code,
                "project_code": project_code,
                "target_path": target_path,
                "description": "Scan created using the Workbench Agent.",
            },
        }

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

        # Check if dependency analysis can start
        self.assert_dependency_analysis_can_start(scan_code)

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

    def check_if_scan_exists(self, scan_code: str) -> bool:
        """
        Check if scan exists.

        Args:
            scan_code: The unique identifier for the scan

        Returns:
            bool: True if scan exists, False otherwise
        """
        return check_if_scan_exists(self._send_request, scan_code)

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
            ProcessError: If the scan cannot be started
            ApiError: If the API call fails
            NetworkError: If there are network issues
        """
        scan_exists = self.check_if_scan_exists(scan_code)
        if not scan_exists:
            raise ScanNotFoundError(f"Scan '{scan_code}' doesn't exist")

        self.assert_scan_can_start(scan_code)
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

    def check_status(self, scan_type: str, scan_code: str) -> Dict[str, Any]:
        """
        Calls API scans -> check_status to determine if the process is finished.

        Args:
            scan_type: One of these: SCAN, DEPENDENCY_ANALYSIS
            scan_code: The unique identifier for the scan

        Returns:
            dict: The data section from the JSON response returned from API

        Raises:
            ApiError: If the API call fails
            ScanNotFoundError: If the scan doesn't exist
        """
        logger.debug(f"Checking status for {scan_type} on scan '{scan_code}'")

        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": scan_type,
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
                f"Failed to check status for {scan_type} on scan '{scan_code}': {error_msg}",
                details=response,
            )

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
