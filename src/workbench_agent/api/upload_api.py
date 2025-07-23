import base64
import os
import logging
from .helpers.upload_helpers import UploadHelper
from ..exceptions import FileSystemError

logger = logging.getLogger("workbench-agent")


class UploadAPI(UploadHelper):
    """
    Workbench API Upload Operations - handles file uploads with enhanced reliability.
    """

    def upload_files(self, scan_code: str, path: str, chunked_upload: bool = False):
        """
        Uploads files to the Workbench using the API's File Upload endpoint with enhanced reliability.

        Args:
            scan_code: The scan code where the file or files will be uploaded
            path: Path to the file or files to upload
            chunked_upload: Enable/disable chunk upload

        Raises:
            FileSystemError: If there are file system errors
            NetworkError: If there are network issues
            ApiError: If the upload fails
            ScanNotFoundError: If the scan doesn't exist
        """
        logger.info(f"Uploading file '{path}' to scan '{scan_code}'")

        if not os.path.exists(path):
            raise FileSystemError(f"File '{path}' does not exist")

        file_size = os.path.getsize(path)
        filename = os.path.basename(path)

        # Prepare parameters
        filename_base64 = base64.b64encode(filename.encode()).decode("utf-8")
        scan_code_base64 = base64.b64encode(scan_code.encode()).decode("utf-8")

        # Check if we should use chunked upload
        use_chunked = chunked_upload and (file_size > self.CHUNKED_UPLOAD_THRESHOLD)

        if use_chunked:
            # First delete possible existing files because chunk uploading works by appending existing file on disk
            if hasattr(self, "remove_uploaded_content"):
                self.remove_uploaded_content(filename, scan_code)
            else:
                logger.debug(
                    f"remove_uploaded_content not available - chunked upload may append to existing file"
                )

        # Prepare headers
        headers = {
            "FOSSID-SCAN-CODE": scan_code_base64,
            "FOSSID-FILE-NAME": filename_base64,
        }

        # Use the helper's unified upload method
        self._perform_upload(path, headers)
