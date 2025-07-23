from .projects_api import ProjectsAPI
from .scans_api import ScansAPI
from .upload_api import UploadAPI
from .vulnerabilities_api import VulnerabilitiesAPI
from .download_api import DownloadAPI


class WorkbenchAPI(ProjectsAPI, ScansAPI, UploadAPI, VulnerabilitiesAPI, DownloadAPI):
    """
    A class to interact with the FossID Workbench API for managing scans and projects.
    This class composes all the individual API parts into a single client.

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
        super().__init__(api_url, api_user, api_token) 