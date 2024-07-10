#!/usr/bin/env python3

# Copyright: FossID AB 2022

import builtins
import json
import time
import logging
import argparse
import random
import base64
import io
import os
import subprocess
from argparse import RawTextHelpFormatter
import sys
import traceback
import requests

# from dotenv import load_dotenv
logger = logging.getLogger("log")


class Workbench:
    """
    A class to interact with the FossID Workbench API for managing scans and projects.

    Attributes:
        api_url (str): The base URL of the Workbench API.
        api_user (str): The username used for API authentication.
        api_token (str): The API token for authentication.
    """

    def __init__(self, api_url: str, api_user: str, api_token: str):
        """
        Initializes the Workbench object with API credentials and endpoint.

        Args:
            api_url (str): The base URL of the Workbench API.
            api_user (str): The username used for API authentication.
            api_token (str): The API token for authentication.
        """
        self.api_url = api_url
        self.api_user = api_user
        self.api_token = api_token

    def _send_request(self, payload: dict) -> dict:
        """
        Sends a request to the Workbench API.

        Args:
            payload (dict): The payload of the request.

        Returns:
            dict: The JSON response from the API.
        """
        url = self.api_url
        headers = {
            "Accept": "*/*",
            "Content-Type": "application/json; charset=utf-8",
        }
        req_body = json.dumps(payload)
        logger.debug("url %s", url)
        logger.debug("url %s", headers)
        logger.debug(req_body)
        response = requests.request(
            "POST", url, headers=headers, data=req_body, timeout=1800
        )
        logger.debug(response.text)
        try:
            # Attempt to parse the JSON
            parsed_json = json.loads(response.text)
            return parsed_json
        except json.JSONDecodeError as e:
            # If an error occurs, catch it and display the message along with the problematic JSON
            print("Failed to decode JSON")
            print(f"Error message: {e.msg}")
            print(f"At position: {e.pos}")
            print("Problematic JSON:")
            print(response.text)

    def _read_in_chunks(self,file_object: io.BufferedReader, chunk_size=5242880):
        """
        Generator to read a file piece by piece.

        Args:
            file_object (io.BufferedReader) : The payload of the request.
            chunk_size (int): Size of the chunk. Default chunk size is 5MB
        """
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def _chunked_upload_request(self, scan_code: str, headers: dict, chunk: bytes):
        """
        This function will make sure Content-Length header is not sent by Requests library
        Args:
            scan_code (str): The scan code where the file or files will be uploaded.
            headers (dict) : Headers for HTTP request
            chunk (bytes): Chunk read from large file
        """
        try:
            req = requests.Request(
                'POST',
                self.api_url,
                headers=headers,
                data=chunk,
                auth=(self.api_user, self.api_token),
            )
            s = requests.Session()
            prepped = s.prepare_request(req)
            # Remove the unwanted header  'Content-Length' !!!
            if 'Content-Length' in prepped.headers:
                del prepped.headers['Content-Length']

            # Send HTTP request and retrieve response
            response = s.send(prepped)
            # print(f"Sent headers: {response.request.headers}")
            # print(f"response headers: {response.headers}")
            # Retrieve the HTTP status code
            status_code = response.status_code
            print(f"HTTP Status Code: {status_code}")

            # Check if the request was successful (status code 200)
            if status_code == 200:
                # Parse the JSON response
                try:
                    response.json()
                except:
                    print(f"Failed to decode json {response.text}")
                    print(traceback.print_exc())
                    sys.exit(1)
            else:
                print(f"Request failed with status code {status_code}")
                reason = response.reason
                print(f"Reason: {reason}")
                response_text = response.text
                print(f"Response Text: {response_text}")
                sys.exit(1)
        except IOError:
            # Error opening file
            print(f"Failed to upload files to the scan {scan_code}.")
            print(traceback.print_exc())
            sys.exit(1)

    def upload_files(self, scan_code: str, path: str, chunked_upload: bool = False):
        """
        Uploads files to the Workbench using the API's File Upload endpoint.

        Args:
            scan_code (str): The scan code where the file or files will be uploaded.
            path (str): Path to the file or files to upload.
            chunked_upload (bool): Enable/disable chunk upload.
        """
        file_size = os.path.getsize(path)
        size_limit = 8 * 1024 * 1024  # 8MB in bytes. Based on the default value of post_max_size in php.ini
        # Prepare parameters
        filename = os.path.basename(path)
        filename_base64 = base64.b64encode(filename.encode()).decode("utf-8")
        scan_code_base64 = base64.b64encode(scan_code.encode()).decode("utf-8")

        if chunked_upload and (file_size > size_limit):
            print(f"Uploading {filename} using 'Transfer-encoding: chunks' due to file size {file_size}.")
            # Use chunked upload for files bigger than size_limit
            # First delete possible existing files because chunk uploading works by appending existing file on disk.
            self.remove_uploaded_content(filename, scan_code)
            print("Uploading using Transfer-encoding: chunked...")
            headers = {
                "FOSSID-SCAN-CODE": scan_code_base64,
                "FOSSID-FILE-NAME": filename_base64,
                'Transfer-Encoding': 'chunked',
                'Content-Type': 'application/octet-stream'
            }
            try:
                with open(path, "rb") as file:
                    for chunk in self._read_in_chunks(file, 5242880):
                        # Upload each chunk
                        self._chunked_upload_request(scan_code, headers, chunk)
            except IOError:
                # Error opening file
                print(f"Failed to upload files to the scan {scan_code}.")
                print(traceback.print_exc())
                sys.exit(1)
            print("Finished uploading.")
        else:
            # Regular upload, no chunk upload
            headers = {
                "FOSSID-SCAN-CODE": scan_code_base64,
                "FOSSID-FILE-NAME": filename_base64
            }
            print("Uploading...")
            try:
                with open(path, "rb") as file:
                    resp = requests.post(
                        self.api_url,
                        headers=headers,
                        data=file,
                        auth=(self.api_user, self.api_token),
                        timeout=1800,
                    )
                    # Retrieve the HTTP status code
                    status_code = resp.status_code
                    print(f"HTTP Status Code: {status_code}")

                    # Check if the request was successful (status code 200)
                    if status_code == 200:
                        # Parse the JSON response
                        try:
                            resp.json()
                        except:
                            print(f"Failed to decode json {resp.text}")
                            print(traceback.print_exc())
                            sys.exit(1)
                    else:
                        print(f"Request failed with status code {status_code}")
                        reason = resp.reason
                        print(f"Reason: {reason}")
                        response_text = resp.text
                        print(f"Response Text: {response_text}")
                        sys.exit(1)
            except IOError:
                # Error opening file
                print(f"Failed to upload files to the scan {scan_code}.")
                print(traceback.print_exc())
                sys.exit(1)
            print("Finished uploading.")

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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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

    def projects_get_policy_warnings_info(self, project_code: str):
        """
        Retrieve policy warnings information at project level.

        Args:
            project_code (str): The unique identifier for the project.

        Returns:
            dict: The JSON response from the API.
        """
        payload = {
            "group": "projects",
            "action": "get_policy_warnings_info",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "1":
            return True
        else:
            return False

    def check_if_project_exists(self, project_code: str):
        """
        Check if project exists.

        Args:
            project_code (str): The unique identifier for the scan.

        Returns:
            bool: Yes or no.
        """
        payload = {
            "group": "projects",
            "action": "get_information",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
            },
        }
        response = self._send_request(payload)
        if response["status"] == "0":
            return False
        # if response["status"] == "0":
        #     raise builtins.Exception("Failed to get project status: {}".format(response))
        return True

    def create_project(self, project_code: str):
        """
        Create new project

        Args:
            project_code (str): The unique identifier for the scan.
        """
        payload = {
            "group": "projects",
            "action": "create",
            "data": {
                "username": self.api_user,
                "key": self.api_token,
                "project_code": project_code,
                "project_name": project_code,
                "description": "Automatically created by Workbench Agent script",
            },
        }
        response = self._send_request(payload)
        if response["status"] != "1":
            raise builtins.Exception("Failed to create project: {}".format(response))
        print("Created project {}".format(project_code))

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
                "username": self.api_user,
                "key": self.api_token,
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
                "username": self.api_user,
                "key": self.api_token,
                "scan_code": scan_code,
                "filename": filename,
            },
        }
        resp = self._send_request(payload)
        if resp["status"] != "1":
            print(
                f"Cannot delete file {filename}, maybe is the first time when uploading this file? API response {resp}."
            )


class CliWrapper:
    """
    A class to interact with the FossID CLI.

    Attributes:
        cli_path (string): Path to the executable file "fossid"
        config_path (string): Path to the configuration file "fossid.conf"
        timeout (int): timeout for CLI expressed in seconds
    """

    # __parameters (dictionary): Dictionary of parameters passed to 'fossid-cli'
    __parameters = {}

    def __init__(self, cli_path, config_path, timeout="120"):
        self.cli_path = cli_path
        self.config_path = config_path
        self.timeout = timeout

    # Executes  fossid-cli --version
    # Returns string
    def get_version(self):
        """
        Get CLI version

        Args:
            self

        Returns:
            str
        """
        args = ["timeout", self.timeout, self.cli_path, "--version"]
        try:
            result = subprocess.check_output(args, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            return (
                "Calledprocerr: "
                + str(e.cmd)
                + " "
                + str(e.returncode)
                + " "
                + str(e.output)
            )
        # pylint: disable-next=broad-except
        except Exception as e:
            return "Error: " + str(e)

        return result

    def blind_scan(self, path):
        """
        Call fossid-cli on a given path in order to generate hashes of the files from that path

        Args:
            path (str): path of the code to be scanned

        Returns:
            str: path to temporary .fossid file containing generated hashes
        """
        temporary_file_path = "/tmp/blind_scan_result_" + self.randstring(8) + ".fossid"
        # Create temporary file, make it empty if already exists
        # pylint: disable-next=consider-using-with,unspecified-encoding
        open(temporary_file_path, "w").close()
        my_cmd = f"timeout {self.timeout} {self.cli_path} --local --enable-sha1=1 {path} > {temporary_file_path}"
        try:
            # pylint: disable-next=unspecified-encoding
            with open(temporary_file_path, "w") as outfile:
                subprocess.check_output(my_cmd, shell=True, stderr=outfile)
            # result = subprocess.check_output(args, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(
                "Calledprocerr: "
                + str(e.cmd)
                + " "
                + str(e.returncode)
                + " "
                + str(e.output)
            )
            print(traceback.format_exc())
            sys.exit()
        # pylint: disable-next=broad-except
        except Exception as e:
            print("Error: " + str(e))
            print(traceback.format_exc())
            sys.exit()

        return temporary_file_path

    @staticmethod
    def randstring(length=10):
        """
        Generate a random string of a given length

        Parameters:
            length (int): Length of the generated string

        Returns:
            str
        """
        valid_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return "".join((random.choice(valid_letters) for i in range(0, length)))


def parse_cmdline_args():
    """
    Parses command line arguments for the script.

    Returns:
        argparse.Namespace: An object containing the parsed command line arguments.
    """

    # Define a custom type function which will verify for empty string
    def non_empty_string(s):
        if not s.strip():
            raise argparse.ArgumentTypeError("Argument cannot be empty or just whitespace.")
        return s

    parser = argparse.ArgumentParser(
        add_help=False,
        description="Run FossID Workbench Agent",
        formatter_class=RawTextHelpFormatter,
    )
    required = parser.add_argument_group("required arguments")
    optional = parser.add_argument_group("optional arguments")

    # Add back help
    optional.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="show this help message and exit",
    )

    required.add_argument(
        "--api_url",
        help="URL of the Workbench API instance, Ex:  https://myserver.com/api.php",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--api_user",
        help="Workbench user that will make API calls",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--api_token",
        help="Workbench user API token (Not the same with user password!!!)",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--project_code",
        help="Name of the project inside Workbench where the scan will be created.\n"
        "If the project doesn't exist, it will be created",
        type=non_empty_string,
        required=True,
    )
    required.add_argument(
        "--scan_code",
        help="The scan code user when creating the scan in Workbench. It can be based on some env var,\n"
        "for example:  ${BUILD_NUMBER}",
        type=non_empty_string,
        required=True,
    )
    optional.add_argument(
        "--limit",
        help="Limits CLI results to N most significant matches (default: 10)",
        type=int,
        default=10,
    )
    optional.add_argument(
        "--sensitivity",
        help="Sets snippet sensitivity to a minimum of N lines (default: 10)",
        type=int,
        default=10,
    )
    optional.add_argument(
        "--recursively_extract_archives",
        help="Recursively extract nested archives. Default true.",
        action="store_true",
        default=True,
    )
    optional.add_argument(
        "--jar_file_extraction",
        help="Control default behavior related to extracting jar files. Default false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--blind_scan",
        help="Call CLI and generate file hashes. Upload hashes and initiate blind scan.",
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
        help="Automatically detect license declaration inside files. This argument expects no value, not passing\n"
        "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_detect_copyright",
        help="Automatically detect copyright statements inside files. This argument expects no value, not passing\n"
        "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--auto_identification_resolve_pending_ids",
        help="Automatically resolve pending identifications. This argument expects no value, not passing\n"
        "this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--delta_only",
        help="""Scan only delta (newly added files from last scan).""",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--reuse_identifications",
        help="If present, try to use an existing identification depending on parameter ‘identification_reuse_type‘.",
        action="store_true",
        default=False,
        required=False,
    )
    optional.add_argument(
        "--identification_reuse_type",
        help="Based on reuse type last identification found will be used for files with the same hash.",
        choices=["any", "only_me", "specific_project", "specific_scan"],
        default="any",
        type=str,
        required=False,
    )
    optional.add_argument(
        "--specific_code",
        help="The scan code used when creating the scan in Workbench. It can be based on some env var,\n"
        "for example:  ${BUILD_NUMBER}",
        type=str,
        required=False,
    )
    optional.add_argument(
        '--no_advanced_match_scoring',
        help='Disable advanced match scoring which by default is enabled.',
        dest='advanced_match_scoring',
        action='store_false',
    )
    optional.add_argument(
        "--match_filtering_threshold",
        help="Minimum length, in characters, of the snippet to be considered valid after applying match filtering.\n"
            "Set to 0 to disable intelligent match filtering for current scan.",
        type=int,
        default=-1,
    )
    optional.add_argument(
        "--target_path",
        help="The path on the Workbench server where the code to be scanned is stored.\n"
             "No upload is done in this scenario.",
        type=str,
        required=False,
    )
    optional.add_argument(
        "--chunked_upload",
        help="For files bigger than 8 MB (which is default post_max_size in php.ini) uploading will be done using\n"
             "the header Transfer-encoding: chunked with chunks of 5MB.",
        action="store_true",
        default=False,
        required=False,
    )
    required.add_argument(
        "--scan_number_of_tries",
        help="""Number of calls to 'check_status' till declaring the scan failed from the point of view of the agent""",
        type=int,
        default=960,  # This means 8 hours when --scan_wait_time has default value 30 seconds
        required=False,
    )
    required.add_argument(
        "--scan_wait_time",
        help="Time interval between calling 'check_status', expressed in seconds (default 30 seconds)",
        type=int,
        default=30,
        required=False,
    )
    required.add_argument(
        "--path",
        help="Path of the directory where the files to be scanned reside",
        type=str,
        required=True,
    )

    optional.add_argument(
        "--log",
        help="specify logging level. Allowed values: DEBUG, INFO, WARNING, ERROR",
        default="ERROR",
    )

    optional.add_argument(
        "--path-result",
        help="Save results to specified path",
        type=str,
        required=False,
    )

    optional.add_argument(
        "--get_scan_identified_components",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return the list of identified components instead.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--scans_get_policy_warnings_counter",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return information about policy warnings found in this scan\n"
        "based on policy rules set at Project level.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--projects_get_policy_warnings_info",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return information about policy warnings for project,\n"
        "including the warnings counter.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )
    optional.add_argument(
        "--scans_get_results",
        help="By default at the end of scanning the list of licenses identified will be retrieved.\n"
        "When passing this parameter the agent will return information about policy warnings found in this scan\n"
        "based on policy rules set at Project level.\n"
        "This argument expects no value, not passing this argument is equivalent to assigning false.",
        action="store_true",
        default=False,
    )

    args = parser.parse_args()
    return args


def save_results(params, results):
    """
    Saves the scanning results to a specified path.

    Parameters:
        params (argparse.Namespace): Parsed command line parameters.
        results (dict): The scan results to be saved.
    """
    if params.path_result:
        if os.path.isdir(params.path_result):
            fname = os.path.join(params.path_result, "wb_results.json")
            try:
                with open(fname, "w") as file:
                    file.write(json.dumps(results, indent=4))
                    print(f"Results saved to: {fname}")
            except builtins.Exception:
                logger.debug(f"Error trying to write results to {fname}")
                print(f"Error trying to write results to {fname}")
        elif os.path.isfile(params.path_result):
            fname = params.path_result
            _folder = os.path.dirname(params.path_result)
            _fname = os.path.basename(params.path_result)
            if _fname:
                if not _fname.endswith(".json"):
                    try:
                        extension = _fname.split(".")[-1]
                        _fname = _fname.replace(extension, "json")
                    except (TypeError, IndexError):
                        _fname = f"{_fname.replace('.', '_')}.json"
            else:
                _fname = "wb_results.json"
            try:
                os.makedirs(_folder, exist_ok=True)
                try:
                    with open(fname, "w") as file:
                        file.write(json.dumps(results, indent=4))
                        print(f"Results saved to: {fname}")
                except builtins.Exception:
                    logger.debug(f"Error trying to write results to {fname}")
            except PermissionError:
                logger.debug(f"Error trying to create folder: {_folder}")
        else:
            logger.debug(f"Folder or file does not exist: {params.path_result}")
            try:
                fname = params.path_result
                if fname.endswith(".json"):
                    _folder = os.path.dirname(fname)
                else:
                    if "." in fname:
                        _folder = os.path.dirname(fname)
                    else:
                        _folder = fname
                    fname = os.path.join(_folder, "wb_results.json")
                try:
                    os.makedirs(_folder, exist_ok=True)
                    try:
                        with open(fname, "w") as file:
                            file.write(json.dumps(results, indent=4))
                        print(f"Results saved to: {fname}")
                    except builtins.Exception:
                        logger.debug(f"Error trying to write results to {fname}")
                except builtins.Exception:
                    logger.debug(f"Error trying to create folder: {_folder}")
            except builtins.Exception:
                logger.debug(f"Error trying to create report: {params.path_result}")


def main():
    # Retrieve parameters from command line
    params = parse_cmdline_args()
    logger.setLevel(params.log)
    f_handler = logging.FileHandler("log-agent.txt")
    logger.addHandler(f_handler)

    # Display parsed parameters
    print("Parsed parameters: ")
    for k, v in params.__dict__.items():
        print("{} = {}".format(k, v))

    if params.blind_scan:
        cli_wrapper = CliWrapper("/usr/bin/fossid-cli", "/etc/fossid.conf")
        # Display fossid-cli version just to validate the path to CLI
        print(cli_wrapper.get_version())

        # Run scan and save .fossid file as temporary file
        blind_scan_result_path = cli_wrapper.blind_scan(params.path)
        print(
            "Temporary file containing hashes generated at path: {}".format(
                blind_scan_result_path
            )
        )

    # Create Project if it doesn't exist
    workbench = Workbench(params.api_url, params.api_user, params.api_token)
    if not workbench.check_if_project_exists(params.project_code):
        workbench.create_project(params.project_code)
    # Create scan if it doesn't exist
    scan_exists = workbench.check_if_scan_exists(params.scan_code)
    if not scan_exists:
        print(
            f"Scan with code {params.scan_code} does not exist. Calling API to create it..."
        )
        workbench.create_webapp_scan(params.scan_code, params.project_code, params.target_path)
    else:
        print(
            f"Scan with code {params.scan_code} already exists. Proceeding to upload..."
        )
    # Handle blind scan differently from regular scan
    if params.blind_scan:
        # Upload temporary file with blind scan hashes
        print("Parsed path: ", params.path)
        workbench.upload_files(params.scan_code, blind_scan_result_path)

        # delete .fossid file containing hashes (after upload to scan)
        if os.path.isfile(blind_scan_result_path):
            os.remove(blind_scan_result_path)
        else:
            print(
                "Can not delete the file {} as it doesn't exists".format(
                    blind_scan_result_path
                )
            )
    # Handle normal scanning (directly uploading files at given path instead of generating hashes with CLI)
    # There is no file upload when scanning from target path
    elif not params.target_path:
        if not os.path.isdir(params.path):
            # The given path is an actual file path. Only this file will be uploaded
            print(
                "Uploading file indicated in --path parameter: {}".format(params.path)
            )
            workbench.upload_files(params.scan_code, params.path, params.chunked_upload)
        else:
            # Get all files found at given path (including in subdirectories). Exclude directories
            print(
                "Uploading files found in directory indicated in --path parameter: {}".format(
                    params.path
                )
            )
            counter_files = 0
            for root, directories, filenames in os.walk(params.path):
                for filename in filenames:
                    if not os.path.isdir(os.path.join(root, filename)):
                        counter_files = counter_files + 1
                        workbench.upload_files(
                            params.scan_code, os.path.join(root, filename), params.chunked_upload
                        )
            print("A total of {} files uploaded".format(counter_files))
        print("Calling API scans->extracting_archives")
        workbench.extract_archives(
            params.scan_code,
            params.recursively_extract_archives,
            params.jar_file_extraction,
        )

    # If --run_only_dependency_analysis parameter is true ONLY run dependency analysis, no KB scanning
    if params.run_only_dependency_analysis:
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print("Starting dependency analysis for scan: {}".format(params.scan_code))
        workbench.start_dependency_analysis(params.scan_code)
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS",
            params.scan_code,
            params.scan_number_of_tries,
            params.scan_wait_time,
        )
    # Run scan
    else:
        workbench.run_scan(
            params.scan_code,
            params.limit,
            params.sensitivity,
            params.auto_identification_detect_declaration,
            params.auto_identification_detect_copyright,
            params.auto_identification_resolve_pending_ids,
            params.delta_only,
            params.reuse_identifications,
            params.identification_reuse_type,
            params.specific_code,
            params.advanced_match_scoring,
            params.match_filtering_threshold
         )
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "SCAN", params.scan_code, params.scan_number_of_tries, params.scan_wait_time
        )

    # If --run_dependency_analysis parameter is true run also dependency analysis
    if params.run_dependency_analysis:
        workbench.assert_dependency_analysis_can_start(params.scan_code)
        print("Starting dependency analysis for scan: {}".format(params.scan_code))
        workbench.start_dependency_analysis(params.scan_code)
        # Check if finished based on: scan_number_of_tries X scan_wait_time until throwing an error
        workbench.wait_for_scan_to_finish(
            "DEPENDENCY_ANALYSIS",
            params.scan_code,
            params.scan_number_of_tries,
            params.scan_wait_time,
        )

    # When scan finished retrieve licenses list by default of if parameter --get_scan_identified_components is True call
    # scans -> get_scan_identified_components
    if params.get_scan_identified_components:
        print("Identified components: ")
        identified_components = workbench.get_scan_identified_components(
            params.scan_code
        )
        print(json.dumps(identified_components))
        save_results(params=params, results=identified_components)
        sys.exit(0)

        # projects ->  get_policy_warnings_info
    elif params.scans_get_policy_warnings_counter:
        if params.project_code is None or params.project_code == "":
            print(
                "Parameter project_code missing!\n"
                "In order for the scans->get_policy_warnings_counter to be called a project code is required."
            )
            sys.exit(1)
        print(f"Scan: {params.scan_code} policy warnings info: ")
        info_policy = workbench.scans_get_policy_warnings_counter(params.scan_code)
        print(json.dumps(info_policy))
        save_results(params=params, results=info_policy)
        sys.exit(0)
    # When scan finished retrieve project policy warnings info
    # projects ->  get_policy_warnings_info
    elif params.projects_get_policy_warnings_info:
        if params.project_code is None or params.project_code == "":
            print(
                "Parameter project_code missing!\n"
                "In order for the projects->get_policy_warnings_info to be called a project code is required."
            )
            sys.exit(1)
        print(f"Project {params.project_code} policy warnings info: ")
        info_policy = workbench.projects_get_policy_warnings_info(params.project_code)
        print(json.dumps(info_policy))
        save_results(params=params, results=info_policy)
        sys.exit(0)
    # When scan finished retrieve project policy warnings info
    # projects ->  get_policy_warnings_info
    elif params.scans_get_results:

        print(f"Scan {params.scan_code} results: ")
        results = workbench.get_results(params.scan_code)
        print(json.dumps(results))
        save_results(params=params, results=results)
        sys.exit(0)
    else:
        print("Identified licenses: ")
        identified_licenses = workbench.get_scan_identified_licenses(params.scan_code)
        print(json.dumps(identified_licenses))
        save_results(params=params, results=identified_licenses)


main()
