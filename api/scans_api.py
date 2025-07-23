import builtins
import time
from typing import Dict, Any
from .helpers.api_base import APIBase


class ScansAPI(APIBase):
    """
    Workbench API Scans Operations.
    """

    def _delete_existing_scan(self, scan_code: str):
        """
        Deletes a scan

        Args:
            scan_code (str): The code of the scan to be deleted

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "delete",
            "data": {
                "scan_code": scan_code,
                "delete_identifications": "true",
            },
        }
        return self._send_request(payload)

    def create_webapp_scan(self, scan_code: str, project_code: str = None, target_path: str = None) -> bool:
        """
        Creates a Scan in Workbench. The scan can optionally be created inside a Project.

        Args:
            scan_code (str): The unique identifier for the scan.
            project_code (str, optional): The project code within which to create the scan.
            target_path (str, optional): The target path where scan is stored.

        Returns:
            bool: True if the scan was successfully created, False otherwise.
        """
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
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception(
                "Failed to create scan {}: {}".format(scan_code, response)
            )
        if "error" in response.keys():
            raise builtins.Exception(
                "Failed to create scan {}: {}".format(scan_code, response["error"])
            )
        return response["data"]["scan_id"]

    def _get_scan_status(self, scan_type: str, scan_code: str):
        """
        Calls API scans -> check_status to determine if the process is finished.

        Args:
            scan_type (str): One of these: SCAN, REPORT_IMPORT, DEPENDENCY_ANALYSIS, REPORT_GENERATION, DELETE_SCAN.
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The data section from the JSON response returned from API.
        """
        payload = {
            "group": "scans",
            "action": "check_status",
            "data": {
                "scan_code": scan_code,
                "type": scan_type,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception(
                "Failed to retrieve scan status from \
                scan {}: {}".format(
                    scan_code, response["error"]
                )
            )
        return response["data"]

    def start_dependency_analysis(self, scan_code: str):
        """
        Initiate dependency analysis for a scan.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        payload = {
            "group": "scans",
            "action": "run_dependency_analysis",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception(
                "Failed to start dependency analysis scan {}: {}".format(
                    scan_code, response["error"]
                )
            )

    def wait_for_scan_to_finish(
        self,
        scan_type: str,
        scan_code: str,
        scan_number_of_tries: int,
        scan_wait_time: int,
    ):
        """
        Check if the scan finished after each 'scan_wait_time' seconds for 'scan_number_of_tries' number of tries.
        If the scan is finished return true. If the scan is not finished after all tries throw Exception.

        Args:
            scan_type (str): Types: SCAN, REPORT_IMPORT, DEPENDENCY_ANALYSIS, REPORT_GENERATION, DELETE_SCAN
            scan_code (str): Unique scan identifier.
            scan_number_of_tries (int): Number of calls to "check_status" till declaring the scan failed.
            scan_wait_time (int): Time interval between calling "check_status", expressed in seconds

        Returns:
            bool
        """
        # pylint: disable-next=unused-variable
        for x in range(scan_number_of_tries):
            scan_status = self._get_scan_status(scan_type, scan_code)
            is_finished = (
                scan_status["is_finished"]
                or scan_status["is_finished"] == "1"
                or scan_status["status"] == "FAILED"
                or scan_status["status"] == "FINISHED"
            )
            if is_finished:
                if (
                    scan_status["percentage_done"] == "100%"
                    or scan_status["percentage_done"] == 100
                    or (
                        scan_type == "DEPENDENCY_ANALYSIS"
                        and (
                            scan_status["percentage_done"] == "0%"
                            or scan_status["percentage_done"] == "0%%"
                        )
                    )
                ):
                    print(
                        "Scan percentage_done = 100%, scan has finished. Status: {}".format(
                            scan_status["status"]
                        )
                    )
                    return True
                raise builtins.Exception(
                    "Scan finished with status: {}  percentage: {} ".format(
                        scan_status["status"], scan_status["percentage_done"]
                    )
                )
            # If scan did not finished, print info about progress
            print(
                "Scan {} is running. Percentage done: {}%  Status: {}".format(
                    scan_code, scan_status["percentage_done"], scan_status["status"]
                )
            )
            # Wait given time
            time.sleep(scan_wait_time)
        # If this code is reached it means the scan didn't finished after  scan_number_of_tries X scan_wait_time
        print("{} timeout: {}".format(scan_type, scan_code))
        raise builtins.Exception("scan timeout")

    def _get_pending_files(self, scan_code: str):
        """
        Call API scans -> get_pending_files.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_pending_files",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        # all other situations
        raise builtins.Exception(
            "Error getting pending files \
            result: {}".format(
                response
            )
        )

    def scans_get_policy_warnings_counter(self, scan_code: str):
        """
        Retrieve policy warnings information at scan level.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_policy_warnings_counter",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting project policy warnings information \
            result: {}".format(
                response
            )
        )

    def get_scan_identified_components(self, scan_code: str):
        """
        Retrieve the list of identified components from one scan.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_components",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting identified components \
            result: {}".format(
                response
            )
        )

    def get_scan_identified_licenses(self, scan_code: str):
        """
        Retrieve the list of identified licenses from one scan.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_scan_identified_licenses",
            "data": {
                "scan_code": scan_code,
                "unique": "1",
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting identified licenses \
            result: {}".format(
                response
            )
        )

    def get_results(self, scan_code: str):
        """
        Retrieve the list matches from one scan.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_results",
            "data": {
                "scan_code": scan_code,
                "unique": "1",
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]
        raise builtins.Exception(
            "Error getting scans ->get_results \
            result: {}".format(
                response
            )
        )

    def _get_dependency_analysis_result(self, scan_code: str):
        """
        Retrieve dependency analysis results.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "scans",
            "action": "get_dependency_analysis_results",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1" and "data" in response.keys():
            return response["data"]

        raise builtins.Exception(
            "Error getting dependency analysis \
            result: {}".format(
                response
            )
        )

    def _cancel_scan(self, scan_code: str):
        """
        Cancel a scan.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        payload = {
            "group": "scans",
            "action": "cancel_run",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception("Error cancelling scan: {}".format(response))

    def _assert_scan_can_start(self, scan_code: str):
        """
        Verify if a new scan can be initiated.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        scan_status = self._get_scan_status("SCAN", scan_code)
        #  List of possible scan statuses taken from Workbench code:
        #     public const NEW = 'NEW';
        #     public const QUEUED = 'QUEUED';
        #     public const STARTING = 'STARTING';
        #     public const RUNNING = 'RUNNING';
        #     public const FINISHED = 'FINISHED';
        #     public const FAILED = 'FAILED';
        if scan_status["status"] not in ["NEW", "FINISHED", "FAILED"]:
            raise builtins.Exception(
                "Cannot start scan. Current status of the scan is {}.".format(
                    scan_status["status"]
                )
            )

    def assert_dependency_analysis_can_start(self, scan_code: str):
        """
        Verify if a new dependency analysis scan can be initiated.

        Args:
            scan_code (str): The unique identifier for the scan.
        """
        scan_status = self._get_scan_status("DEPENDENCY_ANALYSIS", scan_code)
        #  List of possible scan statuses taken from Workbench code:
        #     public const NEW = 'NEW';
        #     public const QUEUED = 'QUEUED';
        #     public const STARTING = 'STARTING';
        #     public const RUNNING = 'RUNNING';
        #     public const FINISHED = 'FINISHED';
        #     public const FAILED = 'FAILED';
        if scan_status["status"] not in ["NEW", "FINISHED", "FAILED"]:
            raise builtins.Exception(
                "Cannot start dependency analysis. Current status of the scan is {}.".format(
                    scan_status["status"]
                )
            )

    def extract_archives(
        self,
        scan_code: str,
        recursively_extract_archives: bool,
        jar_file_extraction: bool,
    ):
        """
        Extract archive

         Args:
             scan_code (str): The unique identifier for the scan.
             recursively_extract_archives (bool): Yes or no
             jar_file_extraction (bool): Yes or no

         Returns:
             bool: true for successful API call
        """
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
        if response["status"] == "0":
            raise builtins.Exception(
                "Call extract_archives returned error: {}".format(response)
            )
        return True

    def check_if_scan_exists(self, scan_code: str):
        """
        Check if scan exists.

        Args:
            scan_code (str): The unique identifier for the scan.

        Returns:
            bool: Yes or no.
        """
        payload = {
            "group": "scans",
            "action": "get_information",
            "data": {
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1":
            return True
        else:
            return False

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
        match_filtering_threshold: int = -1
    ):
        """

        Args:
            scan_code (str):                                Unique scan identifier
            limit (int):                                    Limit the number of matches against the KB
            sensitivity (int):                              Result sensitivity
            auto_identification_detect_declaration (bool):  Automatically detect license declaration inside files
            auto_identification_detect_copyright (bool):    Automatically detect copyright statements inside files
            auto_identification_resolve_pending_ids (bool): Automatically resolve pending identifications
            delta_only (bool):                              Scan only new or modified files
            reuse_identification (bool):                    Reuse previous identifications
            identification_reuse_type (str):                Possible values: any,only_me,specific_project,specific_scan
            specific_code (str):                            Fill only when reuse type: specific_project or specific_scan
            advanced_match_scoring (bool):                  If true, scan will run with advanced match scoring.
            match_filtering_threshold (int):                Minimum length (in characters) of snippet to be considered
                                                            valid after applying intelligent match filtering.
        Returns:

        """
        scan_exists = self.check_if_scan_exists(scan_code)
        if not scan_exists:
            raise builtins.Exception(
                "Scan with scan_code: {} doesn't exist when calling 'run' action!".format(
                    scan_code
                )
            )

        self._assert_scan_can_start(scan_code)
        print("Starting scan {}".format(scan_code))
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
                "auto_identification_detect_copyright": int(
                    auto_identification_detect_copyright
                ),
                "auto_identification_resolve_pending_ids": int(
                    auto_identification_resolve_pending_ids
                ),
                "delta_only": int(delta_only),
                "advanced_match_scoring": int(advanced_match_scoring),
            },
        }
        if match_filtering_threshold > -1:
            payload["data"]['match_filtering_threshold'] = match_filtering_threshold
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
        if response["status"] != "1":
            import logging
            logger = logging.getLogger("log")
            logger.error(
                "Failed to start scan {}: {} payload {}".format(
                    scan_code, response, payload
                )
            )
            raise builtins.Exception(
                "Failed to start scan {}: {}".format(scan_code, response["error"])
            )
        return response

    def remove_uploaded_content(self, filename: str, scan_code: str):
        """
        When using chunked uploading every new chunk is appended to existing file, for this reason we need to make sure
        that initially there is no file (from previous uploading).

        Args:
            filename (str): The file to be deleted
            scan_code (str): The unique identifier for the scan.
        """
        print("Called scans->remove_uploaded_content on file {}".format(filename))
        payload = {
            "group": "scans",
            "action": "remove_uploaded_content",
            "data": {
                "scan_code": scan_code,
                "filename": filename,
            },
        }
        resp = self._send_request(payload)
        if resp["status"] != "1":
            print(
                f"Cannot delete file {filename}, maybe is the first time when uploading this file? API response {resp}."
            ) 