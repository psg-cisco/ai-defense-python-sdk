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
from enum import Enum
from pathlib import Path
from time import sleep
from typing import Optional, Tuple, Dict, Union
import os

from aidefense.config import Config
from aidefense.runtime.auth import RuntimeAuth
from aidefense.client import BaseClient
from aidefense.exceptions import ValidationError

RETRY_COUNT_FOR_SCANNING = 30
WAIT_TIME_SECS_SUCCESSIVE_SCAN_INFO_CHECK = 2

class ScanStatus(str, Enum):
    """
    Enumeration of possible scan status values.

    This enum defines all possible states that a model scan can be in during its lifecycle,
    from initial creation through completion or failure.

    Attributes:
        NONE_SCAN_STATUS: Default/uninitialized scan status.
        PENDING: Scan has been created but not yet started.
        IN_PROGRESS: Scan is currently running.
        COMPLETED: Scan has finished successfully.
        FAILED: Scan encountered an error and failed.
        CANCELED: Scan was manually canceled before completion.
    """
    NONE_SCAN_STATUS = "NONE_SCAN_STATUS"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"

END_SCAN_STATUS = [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED]

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
            self, scan_id: str, file_name: str, size: int = 0) -> Tuple[str, str]:
        """
        Create a scan object for a file within an existing scan.

        This method registers a file to be scanned within a scan session and returns
        the object ID and upload URL for the file.

        Args:
            scan_id (str): The unique identifier of the scan session.
            file_name (str): The name of the file to be scanned.
            size (int, optional): The size of the file in bytes. Defaults to 0.

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
            json_data={"file_name": file_name, "size":size},
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

    def __get_scan_info_wait_until_status(self, scan_id: str, status: [str]) -> Dict:  # type: ignore
        """
        Wait for a scan to reach one of the specified status values.

        This private method polls the scan status at regular intervals until it reaches
        one of the target statuses or times out.

        Args:
            scan_id (str): The unique identifier of the scan to monitor.
            status (List[str]): List of acceptable status values to wait for.

        Returns:
            Dict: The scan information when the target status is reached.

        Raises:
            Exception: If the scan times out before reaching the target status.
        """
        for _ in range(RETRY_COUNT_FOR_SCANNING):
            info = self.get_scan(scan_id)
            if info and info.get("scan_status_info", {}).get("status") in status:
                return info

            sleep(WAIT_TIME_SECS_SUCCESSIVE_SCAN_INFO_CHECK)

        raise Exception("Scan timed out")

    def scan(self, file_path: Union[Path, str]) -> Dict:
        """
        Run a complete security scan on a model file using the AI Defense service.

        This is the main method for scanning files. It handles the entire scan workflow:
        registering a scan, uploading the file, triggering the scan, waiting for completion,
        and returning the results. If any errors occur, it automatically cleans up by
        canceling and deleting the scan.

        Args:
            file_path (Union[Path, str]): Path to the model file to be scanned.
                Can be a string path or pathlib.Path object.

        Returns:
            Dict: Complete scan information including:
                - scan_id: The scan session identifier
                - scan_status_info: Final status and completion details
                - results: List of scan results and findings
                - metadata: Additional scan metadata

        Raises:
            Exception: If the scan fails, times out, or encounters any errors during processing.
                The scan will be automatically canceled and cleaned up before raising the exception.

        Example:
            ```python
            from pathlib import Path
            
            client = ModelScan(api_key="your_api_key")
            
            try:
                # Scan a pickle file
                result = client.scan("/path/to/suspicious_model.pkl")
                
                # Check the results
                status = result["scan_status_info"]["status"]
                if status == ScanStatus.COMPLETED:
                    print("Scan completed successfully")
                    
                    # Check for threats
                    results = result.get("results", [])
                    for file_result in results:
                        if file_result.get("threats_found"):
                            print(f"⚠️  Threats found in {file_result['file_name']}")
                            for threat in file_result.get("threats", []):
                                print(f"   - {threat['type']}: {threat['description']}")
                        else:
                            print(f"✅ {file_result['file_name']} is clean")
                            
                elif status == ScanStatus.FAILED:
                    print(f"Scan failed: {result.get('error_message', 'Unknown error')}")
                    
            except Exception as e:
                print(f"Scan error: {e}")
            ```
        """
        scan_id = self.register_scan()
        file_path = Path(file_path)
        try:
            self.upload_file(scan_id, file_path)
            self.trigger_scan(scan_id)
            scan_info = self.__get_scan_info_wait_until_status(scan_id, END_SCAN_STATUS)
        except Exception as e:
            if scan_id:
                self.cancel_scan(scan_id)
                self.__get_scan_info_wait_until_status(scan_id, ScanStatus.CANCELED)
                self.delete_scan(scan_id)
            raise e

        return scan_info
