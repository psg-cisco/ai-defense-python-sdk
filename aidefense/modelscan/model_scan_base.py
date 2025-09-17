# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from typing import Optional, Tuple, Dict

from aidefense.client import BaseClient
from aidefense.config import Config
from aidefense.runtime.auth import RuntimeAuth


class ModelScan(BaseClient):
    """
    Client for scanning AI/ML model files with Cisco AI Defense.

    The ModelScan class provides methods to upload, scan, and manage security scans of AI/ML model files.
    It communicates with the AI Defense model scanning API endpoints to detect potential security threats,
    malicious code, or other risks in model files.

    Typical usage:
        client = ModelScan(api_key="your_api_key")
        scan_result = client.scan("/path/to/model.pkl")
        if scan_result["scan_status_info"]["status"] == ScanStatus.COMPLETED:
            print("Scan completed successfully")

    Args:
        api_key (str): Your Cisco AI Defense API key for authentication.
        config (Config, optional): SDK configuration for endpoints, logging, retries, etc.
            If not provided, a default Config is used.

    Attributes:
        auth (RuntimeAuth): Authentication handler for API requests.
        config (Config): SDK configuration instance.
        api_key (str): The API key used for authentication.
        endpoint_prefix (str): Base URL prefix for all model scan API endpoints.
    """

    def __init__(self, api_key: str, config: Optional[Config] = None):
        """
        Initialize a ModelScan client instance.

        Args:
            api_key (str): Your Cisco AI Defense API key for authentication.
            config (Config, optional): SDK-level configuration for endpoints, logging, retries, etc.
                If not provided, a default Config instance is created.
        """
        config = config or Config()
        super().__init__(config)
        self.auth = RuntimeAuth(api_key, is_tenant_api_key=True)
        self.config = config
        self.api_key = api_key
        self.endpoint_prefix = f"{self.config.runtime_base_url}/api/ai-defense/v1"

    @property
    def _default_headers(self) -> Dict[str, str]:
        """Default headers for API requests."""
        return {"Content-Type": "application/json"}

    def create_scan_object(
            self, scan_id: str, file_name: str, size: int = 0, object_config: Optional[Dict] = None) -> Tuple[str, str]:
        """
        Create a scan object for a file within an existing scan.

        This method registers a file to be scanned within a scan session and returns
        the object ID and upload URL for the file.

        Args:
            scan_id (str): The unique identifier of the scan session.
            file_name (str): The name of the file to be scanned.
            size (int, optional): The size of the file in bytes. Defaults to 0.
            object_config (Dict, optional): Additional configuration for the scan object.

        Returns:
            Tuple[str, str]: A tuple containing (object_id, upload_url) where:
                - object_id: Unique identifier for the scan object
                - upload_url: Pre-signed URL for uploading the file

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            scan_id = client.register_scan()
            object_id, upload_url = client.create_scanobject(
                scan_id=scan_id,
                file_name="model.pkl",
                size=1024000
            )
            ```
        """
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/objects",
            auth=self.auth,
            headers=self._default_headers,
            json_data={"file_name": file_name, "size":size, "scan_object": object_config},
        )
        self.config.logger.debug(f"Raw API response: {result}")

        return result["object_id"], result["upload_url"]

    def upload_scan_result(self, scan_id: str, scan_object_id: str, scan_result: dict) -> None:
        """
        Upload scan results for a specific scan object.

        This method is used to submit the results of a scan operation back to the AI Defense service.

        Args:
            scan_id (str): The unique identifier of the scan session.
            scan_object_id (str): The unique identifier of the scan object.
            scan_result (dict): Dictionary containing the scan results and findings.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            scan_result = {
                "threats_found": False,
                "scan_details": {"file_type": "pickle", "threats": []}
            }
            client.upload_scan_result(
                scan_id="scan_123",
                scan_object_id="obj_456",
                scan_result=scan_result
            )
            ```
        """
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/objects/{scan_object_id}/results",
            auth=self.auth,
            headers=self._default_headers,
            json_data={"scan_result": scan_result},
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def mark_scan_completed(self, scan_id: str, errors: str = "") -> None:
        """
        Mark a scan as completed, optionally with error information.

        This method finalizes a scan session, indicating that all scanning operations
        have been completed. Any errors encountered during scanning can be reported.

        Args:
            scan_id (str): The unique identifier of the scan session to mark as completed.
            errors (str, optional): Any error messages or details encountered during scanning.
                Defaults to empty string if no errors occurred.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            # After completing all scan operations
            client.mark_scan_completed(scan_id="scan_123")
            
            # Or with errors
            client.mark_scan_completed(
                scan_id="scan_123",
                errors="Failed to process file: corrupted data"
            )
            ```
        """
        result = self.request(
            method="PUT",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/complete",
            auth=self.auth,
            headers=self._default_headers,
            json_data={"errors": errors},
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def register_scan(self) -> str:
        """
        Register a new scan session with the AI Defense service.

        This method creates a new scan session and returns a unique scan ID that can be used
        for subsequent operations like uploading files and triggering scans.

        Returns:
            str: The unique scan ID for the newly created scan session.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            scan_id = client.register_scan()
            print(f"Created new scan with ID: {scan_id}")
            ```
        """
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/register",
            auth=self.auth,
            headers=self._default_headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")
        return result["scan_id"]

    def upload_file(self, scan_id: str, file_path: Path) -> bool:
        """
        Upload a file to be scanned within an existing scan session.

        This method handles the complete file upload process: creating a scan object,
        getting the upload URL, and uploading the file content.

        Args:
            scan_id (str): The unique identifier of the scan session.
            file_path (Path): Path to the file to be uploaded and scanned.

        Returns:
            bool: True if the file was successfully uploaded, False otherwise.

        Example:
            ```python
            from pathlib import Path
            
            client = ModelScan(api_key="your_api_key")
            scan_id = client.register_scan()
            success = client.upload_file(
                scan_id=scan_id,
                file_path=Path("/path/to/model.pkl")
            )
            if success:
                print("File uploaded successfully")
            ```
        """
        file_size = file_path.stat().st_size
        _, upload_url = self.create_scan_object(scan_id, file_path.name, file_size)

        with open(file_path, 'rb') as f:
            result = self.request(
                method="PUT",
                url=upload_url,
                auth=None,
                headers=self._default_headers,
                data=f
            )
        self.config.logger.debug(f"Raw API response: {result}")
        return True

    def trigger_scan(self, scan_id: str) -> None:
        """
        Trigger the execution of a scan for all uploaded files in a scan session.

        This method starts the actual scanning process for all files that have been
        uploaded to the specified scan session.

        Args:
            scan_id (str): The unique identifier of the scan session to execute.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            scan_id = client.register_scan()
            client.upload_file(scan_id, Path("model.pkl"))
            client.trigger_scan(scan_id)
            print("Scan started")
            ```
        """
        result = self.request(
            method="PUT",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/run",
            auth=self.auth,
            headers=self._default_headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def list_scans(self, limit: int = 10, offset: int = 0) -> Dict:
        """
        List all scans with pagination support.

        Retrieve a paginated list of all scan sessions associated with the current API key.

        Args:
            limit (int, optional): Maximum number of scans to return per page. Defaults to 10.
            offset (int, optional): Number of scans to skip (for pagination). Defaults to 0.

        Returns:
            Dict: Dictionary containing the list of scans and pagination information.
                Typically includes 'scans' list and metadata like 'total_count'.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            
            # Get first 10 scans
            scans = client.list_scans()
            
            # Get next 10 scans
            more_scans = client.list_scans(limit=10, offset=10)
            
            for scan in scans.get('scans', []):
                print(f"Scan ID: {scan['scan_id']}, Status: {scan['status']}")
            ```
        """
        params = {
            "limit": limit,
            "offset": offset
        }
        result = self.request(
            method="GET",
            url=f"{self.endpoint_prefix}/scans",
            auth=self.auth,
            headers=self._default_headers,
            params=params,
        )
        self.config.logger.debug(f"Raw API response: {result}")
        return result

    def get_scan(self, scan_id: str, limit: int = 10, offset: int = 0) -> Dict:
        """
        Get detailed information about a specific scan with pagination support for results.

        Retrieve comprehensive information about a scan session, including its status,
        results, and associated files.

        Args:
            scan_id (str): The unique identifier of the scan to retrieve.
            limit (int, optional): Maximum number of scan results to return per page. Defaults to 10.
            offset (int, optional): Number of results to skip (for pagination). Defaults to 0.

        Returns:
            Dict: Dictionary containing detailed scan information including:
                - scan_id: The scan identifier
                - scan_status_info: Current status and progress
                - results: List of scan results (paginated)
                - metadata: Additional scan metadata

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            scan_info = client.get_scan("scan_123")
            
            status = scan_info.get("scan_status_info", {}).get("status")
            if status == ScanStatus.COMPLETED:
                results = scan_info.get("results", [])
                for result in results:
                    print(f"File: {result['file_name']}, Threats: {result['threats_found']}")
            ```
        """
        params = {
            "limit": limit,
            "offset": offset
        }
        result = self.request(
            method="GET",
            url=f"{self.endpoint_prefix}/scans/{scan_id}",
            auth=self.auth,
            headers=self._default_headers,
            params=params,
        )
        self.config.logger.debug(f"Raw API response: {result}")
        return result

    def delete_scan(self, scan_id: str) -> None:
        """
        Delete a scan session and all associated data.

        This method permanently removes a scan session, including all uploaded files,
        scan results, and metadata. This action cannot be undone.

        Args:
            scan_id (str): The unique identifier of the scan session to delete.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            
            # Delete a completed scan
            client.delete_scan("scan_123")
            print("Scan deleted successfully")
            ```
        """
        result = self.request(
            method="DELETE",
            url=f"{self.endpoint_prefix}/scans/{scan_id}",
            auth=self.auth,
            headers=self._default_headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def cancel_scan(self, scan_id: str) -> None:
        """
        Cancel a running scan session.

        This method stops a scan that is currently in progress.
        The scan status will be updated to CANCELED.

        Args:
            scan_id (str): The unique identifier of the scan session to cancel.

        Example:
            ```python
            client = ModelScan(api_key="your_api_key")
            
            # Cancel a running scan
            client.cancel_scan("scan_123")
            print("Scan canceled")
            ```
        """
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/cancel",
            auth=self.auth,
            headers=self._default_headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def validate_scan_url(self, scan_id: str, url: str, url_type: str, repo_auth: Dict) -> None:
        """
        Validate a repository URL for scanning with the AI Defense service.

        This method validates that a repository URL is accessible and properly configured
        for scanning. It checks the URL format, repository type, and authentication
        credentials to ensure the scan can proceed successfully.

        Args:
            scan_id (str): The unique identifier of the scan session to associate
                with this URL validation.
            url (str): The repository URL to validate. Must be a valid repository URL
                from a supported platform (e.g., HuggingFace).
            url_type (str): The type of repository platform. Supported values include
                "HUGGING_FACE" for HuggingFace repositories.
            repo_auth (Dict): Authentication configuration for accessing the repository.
                The structure depends on the repository type:
                - For HuggingFace: {"access_token": "your_token"}
                - For other platforms: platform-specific auth structure

        Returns:
            TODO add the return details, include error message

        Raises:
            RequestException: If the API request fails due to network issues.
            ValidationError: If the URL format is invalid or authentication fails.
            AuthenticationError: If the provided credentials are invalid or insufficient.

        Example:
            ```python
            from aidefense.modelscan import ModelScan, RepoConfig, HuggingfaceRepoAuth
            
            client = ModelScan(api_key="your_api_key")
            
            # Register a scan first
            scan_id = client.register_scan()
            
            # Validate a HuggingFace repository
            repo_auth = {"access_token": "hf_your_token_here"}
            client.validate_scan_url(
                scan_id=scan_id,
                url="https://huggingface.co/username/model-name",
                url_type="HUGGING_FACE",
                repo_auth=repo_auth
            )
            
            # If validation succeeds, proceed with the scan
            client.trigger_scan(scan_id)
            ```
        """
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/validate_url",
            auth=self.auth,
            json_data={"url": url, "type": url_type, "auth": repo_auth},
            headers=self._default_headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")
