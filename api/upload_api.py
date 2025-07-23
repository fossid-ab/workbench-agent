import builtins
import base64
import io
import os
import sys
import traceback
import requests
from .helpers.api_base import APIBase


class UploadAPI(APIBase):
    """
    Workbench API Upload Operations - handles file uploads.
    """

    def _read_in_chunks(self, file_object: io.BufferedReader, chunk_size=5242880):
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
                "POST",
                self.api_url,
                headers=headers,
                data=chunk,
                auth=(self.api_user, self.api_token),
            )
            s = requests.Session()
            prepped = s.prepare_request(req)
            # Remove the unwanted header  'Content-Length' !!!
            if "Content-Length" in prepped.headers:
                del prepped.headers["Content-Length"]

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
        size_limit = (
            8 * 1024 * 1024
        )  # 8MB in bytes. Based on the default value of post_max_size in php.ini
        # Prepare parameters
        filename = os.path.basename(path)
        filename_base64 = base64.b64encode(filename.encode()).decode("utf-8")
        scan_code_base64 = base64.b64encode(scan_code.encode()).decode("utf-8")

        if chunked_upload and (file_size > size_limit):
            print(
                f"Uploading {filename} using 'Transfer-encoding: chunks' due to file size {file_size}."
            )
            # Use chunked upload for files bigger than size_limit
            # First delete possible existing files because chunk uploading works by appending existing file on disk.
            self.remove_uploaded_content(filename, scan_code)
            print("Uploading using Transfer-encoding: chunked...")
            headers = {
                "FOSSID-SCAN-CODE": scan_code_base64,
                "FOSSID-FILE-NAME": filename_base64,
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/octet-stream",
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
            headers = {"FOSSID-SCAN-CODE": scan_code_base64, "FOSSID-FILE-NAME": filename_base64}
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
