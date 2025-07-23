import builtins
import json
import logging
from typing import Dict, Any
from .helpers.api_base import APIBase

logger = logging.getLogger("log")


class DownloadAPI(APIBase):
    """
    Workbench API Download Operations.
    """

    def _download_report(self, report_entity: str, process_id: int):
        """
        Downloads a generated report using its process ID.
        Returns the requests.Response object containing the report content.
        
        Args:
            report_entity (str): The type of report entity
            process_id (int): The process ID of the generated report
            
        Returns:
            requests.Response: The response object containing the report content
        """
        logger.debug(f"Attempting to download report for process ID '{process_id}' (entity: {report_entity})...")

        payload = {
            "group": "download",
            "action": "download_report",
            "data": {
                "report_entity": report_entity,
                "process_id": str(process_id)
            }
        }
        req_body = json.dumps(payload)
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "*/*",
        }
        
        # Add authentication to payload
        payload.setdefault("data", {})
        payload["data"]["username"] = self.api_user
        payload["data"]["key"] = self.api_token

        logger.debug("Download API URL: %s", self.api_url)
        logger.debug("Download Request Headers: %s", headers)
        logger.debug("Download Request Body: %s", req_body)

        try:
            logger.debug(f"Initiating download request for process ID: {process_id}")
            import requests
            response = requests.post(
                self.api_url,
                headers=headers,
                data=req_body,
                stream=True,
                timeout=1800
            )
            logger.debug(f"Download Response Status Code: {response.status_code}")
            
            if response.status_code != 200:
                raise builtins.Exception(f"Download failed with status code {response.status_code}")
                
            return response
            
        except Exception as e:
            logger.error(f"Error downloading report: {e}")
            raise builtins.Exception(f"Failed to download report: {e}")

    def generate_report(self, scan_code: str, report_type: str = "SPDX") -> int:
        """
        Generates a report for a scan and returns the process ID.
        
        Args:
            scan_code (str): The scan code to generate report for
            report_type (str): Type of report to generate (default: SPDX)
            
        Returns:
            int: The process ID of the generated report
        """
        payload = {
            "group": "reports", 
            "action": "generate",
            "data": {
                "scan_code": scan_code,
                "report_type": report_type
            }
        }
        
        response = self._send_request(payload)
        
        if response.get("status") != "1":
            error_msg = response.get("error", f"Unexpected response: {response}")
            raise builtins.Exception(f"Failed to generate report for scan '{scan_code}': {error_msg}")
            
        if "data" in response and "process_id" in response["data"]:
            process_id = int(response["data"]["process_id"])
            logger.debug(f"Report generation started with process ID: {process_id}")
            return process_id
        else:
            raise builtins.Exception(f"No process ID returned in response: {response}") 