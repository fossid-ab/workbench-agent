import builtins
from typing import Dict, Any, List
from .helpers.api_base import APIBase


class VulnerabilitiesAPI(APIBase):
    """
    Workbench API Vulnerability Operations.
    """

    def list_vulnerabilities(self, scan_code: str) -> List[Dict[str, Any]]:
        """
        Retrieves the list of vulnerabilities associated with a scan.

        Args:
            scan_code (str): Code of the scan to get vulnerabilities for.

        Returns:
            List[Dict[str, Any]]: List of vulnerability details.
        """
        # Step 1: Get the total count of vulnerabilities
        count_payload = {
            "group": "vulnerabilities",
            "action": "list_vulnerabilities",
            "data": {"scan_code": scan_code, "count_results": 1},
        }
        count_response = self._send_request(count_payload)

        if count_response.get("status") != "1":
            error_msg = count_response.get("error", f"Unexpected response format or status: {count_response}")
            raise builtins.Exception(f"Failed to get vulnerability count for scan '{scan_code}': {error_msg}")

        # Get the total count from the response
        total_count = 0
        if isinstance(count_response.get("data"), dict) and "count_results" in count_response["data"]:
            total_count = int(count_response["data"]["count_results"])

        if total_count == 0:
            print(f"No vulnerabilities found for scan '{scan_code}'.")
            return []

        # Step 2: Fetch all vulnerabilities with pagination
        vulnerabilities = []
        page_size = 100  # Adjust as needed
        offset = 0

        while offset < total_count:
            payload = {
                "group": "vulnerabilities",
                "action": "list_vulnerabilities",
                "data": {
                    "scan_code": scan_code,
                    "limit": page_size,
                    "offset": offset,
                },
            }
            response = self._send_request(payload)

            if response.get("status") != "1":
                error_msg = response.get("error", f"Unexpected response: {response}")
                raise builtins.Exception(f"Failed to fetch vulnerabilities for scan '{scan_code}': {error_msg}")

            # Extract vulnerabilities from response
            if "data" in response and isinstance(response["data"], list):
                vulnerabilities.extend(response["data"])
            elif "data" in response and isinstance(response["data"], dict):
                # If the API returns a dict instead of a list
                for vuln_id, vuln_data in response["data"].items():
                    if isinstance(vuln_data, dict):
                        vuln_data["id"] = vuln_id
                        vulnerabilities.append(vuln_data)

            offset += page_size

        print(f"Retrieved {len(vulnerabilities)} vulnerabilities for scan '{scan_code}'.")
        return vulnerabilities 