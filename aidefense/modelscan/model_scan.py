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
from time import sleep
from typing import Dict, Union

from .model_scan_base import ModelScan
from .config import ScanStatus, RepoConfig

RETRY_COUNT_FOR_SCANNING = 30
WAIT_TIME_SECS_SUCCESSIVE_SCAN_INFO_CHECK = 2
END_SCAN_STATUS = [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED]

class ModelScanClient(ModelScan):
    """
    High-level client for AI Defense model scanning operations.

    ModelScanClient extends the base ModelScan class to provide convenient methods
    for scanning both individual files and entire repositories. It handles the complete
    scan workflow including registration, upload, execution, monitoring, and cleanup.

    This client automatically manages scan lifecycle, including error handling and
    resource cleanup to ensure scans don't leave orphaned resources in the system.

    Typical Usage:
        ```python
        from aidefense.modelscan import ModelScanClient, RepoConfig, HuggingfaceRepoAuth
        from aidefense import Config
        
        # Initialize the client
        client = ModelScanClient(
            api_key="your_api_key",
            config=Config(runtime_base_url="https://api.security.cisco.com")
        )
        
        # Scan a local file
        file_result = client.scan_file("/path/to/model.pkl")
        
        # Scan a repository
        repo_config = RepoConfig(
            url="https://huggingface.co/username/model-name",
            auth=HuggingfaceRepoAuth(token="hf_token")
        )
        repo_result = client.scan_repo(repo_config)
        ```

    Attributes:
        Inherits all attributes from the base ModelScan class including:
        - api_key: The API key for authentication
        - config: Configuration object with service settings
        - auth: Authentication handler
        - endpoint_prefix: Base URL for API endpoints
    """
    def __get_scan_info_wait_until_status(self, scan_id: str, status: [str]) -> Dict:
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

    def cleanup_scan_data(self, scan_id: str) -> None:
        self.cancel_scan(scan_id)
        self.__get_scan_info_wait_until_status(scan_id, ScanStatus.CANCELED)
        self.delete_scan(scan_id)


    def scan_file(self, file_path: Union[Path, str]) -> Dict:
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
                self.cleanup_scan_data(scan_id)
            raise e

        return scan_info

    def scan_repo(self, repo_config: RepoConfig) -> Dict:
        """
        Run a complete security scan on a model repository using the AI Defense service.

        This method handles the entire repository scan workflow: registering a scan,
        validating the repository URL and credentials, triggering the scan, waiting
        for completion, and returning the results. If any errors occur, it automatically
        cleans up by canceling and deleting the scan.

        Args:
            repo_config (RepoConfig): Configuration object containing the repository
                URL, authentication credentials, and other scan parameters. The config
                automatically determines the repository type based on the URL.

        Returns:
            Dict: Complete scan information including:
                - scan_id: The scan session identifier
                - scan_status_info: Final status and completion details
                - analysis_results: Repository analysis results with file-by-file findings
                - repository_info: Metadata about the scanned repository

        Raises:
            Exception: If the scan fails, times out, or encounters any errors during processing.
                The scan will be automatically canceled and cleaned up before raising the exception.
            ValidationError: If the repository URL is invalid or inaccessible.
            AuthenticationError: If the provided repository credentials are invalid.

        Example:
            ```python
            from aidefense.modelscan import ModelScanClient, RepoConfig, HuggingfaceRepoAuth
            
            client = ModelScanClient(api_key="your_api_key")
            
            try:
                # Configure repository scan
                repo_config = RepoConfig(
                    url="https://huggingface.co/username/suspicious-model",
                    auth=HuggingfaceRepoAuth(token="hf_your_token_here")
                )
                
                # Run the scan
                result = client.scan_repo(repo_config)
                
                # Check the results
                status = result["scan_status_info"]["status"]
                if status == ScanStatus.COMPLETED:
                    print("Repository scan completed successfully")
                    
                    # Check analysis results
                    analysis = result.get("analysis_results", {})
                    items = analysis.get("items", [])
                    
                    for item in items:
                        file_name = item["name"]
                        file_status = item["status"]
                        threats = item.get("threats", {}).get("items", [])
                        
                        if threats:
                            print(f"⚠️  Threats found in {file_name}:")
                            for threat in threats:
                                severity = threat["severity"]
                                threat_type = threat["threat_type"]
                                description = threat["description"]
                                print(f"   - {severity}: {threat_type} - {description}")
                        elif file_status == "COMPLETED":
                            print(f"✅ {file_name} is clean")
                        else:
                            print(f"ℹ️  {file_name} was {file_status.lower()}")
                            
                elif status == ScanStatus.FAILED:
                    print(f"Repository scan failed: {result.get('error_message', 'Unknown error')}")
                    
            except Exception as e:
                print(f"Repository scan error: {e}")
            ```
        """
        scan_id = self.register_scan()
        try:
            self.validate_scan_url(scan_id, repo_config.url, repo_config.url_type, repo_config.config)
            self.trigger_scan(scan_id)
            scan_info = self.__get_scan_info_wait_until_status(scan_id, END_SCAN_STATUS)
        except Exception as e:
            if scan_id:
                self.cleanup_scan_data(scan_id)
            raise e

        return scan_info
