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

from aidefense.config import Config
from aidefense.runtime.auth import RuntimeAuth
from aidefense.client import BaseClient

RETRY_COUNT_FOR_SCANNING = 30
WAIT_TIME_SECS_SUCCESSIVE_SCAN_INFO_CHECK = 2

class ScanStatus(str, Enum):
    """Enum for scan status"""
    NONE_SCAN_STATUS = "NONE_SCAN_STATUS"
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"

END_SCAN_STATUS = [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED]

class ModelScan(BaseClient):
    def __init__(self, api_key: str, config: Optional[Config] = None):
        config = config or Config()
        super().__init__(config)
        self.auth = RuntimeAuth(api_key, is_tenant_api_key=True)
        self.config = config
        self.api_key = api_key
        self.endpoint_prefix = f"{self.config.runtime_base_url}/api/ai-defense/v1"

    def create_scanobject(
            self, scan_id: str, file_name: str, size: int = 0) -> Tuple[str, str]:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/objects",
            auth=self.auth,
            headers=headers,
            json_data={"file_name": file_name, "size":size},
        )
        self.config.logger.debug(f"Raw API response: {result}")

        return result["object_id"], result["upload_url"]

    def upload_scan_result(self, scan_id: str, scan_object_id: str, scan_result: dict, size: int = 0) -> None:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/objects/{scan_object_id}/results",
            auth=self.auth,
            headers=headers,
            json_data={"scan_result": scan_result, "size": size},
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def mark_scan_completed(self, scan_id: str, errors: str = "") -> None:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="PUT",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/complete",
            auth=self.auth,
            headers=headers,
            json_data={"errors": errors},
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def register_scan(self) -> str:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/register",
            auth=self.auth,
            headers=headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")
        return result["scan_id"]

    def upload_file(self, scan_id: str, file_path: Path) -> bool:
        file_size = file_path.stat().st_size
        _, upload_url = self.create_scanobject(scan_id, file_path.name, file_size)

        headers = {"Content-Type": "application/json"}
        with open(file_path, 'rb') as f:
            result = self.request(
                method="PUT",
                url=upload_url,
                auth=None,
                headers=headers,
                data=f
            )
        self.config.logger.debug(f"Raw API response: {result}")
        return True

    def trigger_scan(self, scan_id: str) -> None:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="PUT",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/run",
            auth=self.auth,
            headers=headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def list_scans(self, limit: int = 10, offset: int = 0) -> Dict:
        """List scans with pagination support"""
        headers = {"Content-Type": "application/json"}
        params = {
            "limit": limit,
            "offset": offset
        }
        result = self.request(
            method="GET",
            url=f"{self.endpoint_prefix}/scans",
            auth=self.auth,
            headers=headers,
            params=params,
        )
        self.config.logger.debug(f"Raw API response: {result}")
        return result

    def get_scan(self, scan_id: str, limit: int = 10, offset: int = 0) -> Dict:
        """Get scan with pagination support for scan results"""
        headers = {"Content-Type": "application/json"}
        params = {
            "limit": limit,
            "offset": offset
        }
        result = self.request(
            method="GET",
            url=f"{self.endpoint_prefix}/scans/{scan_id}",
            auth=self.auth,
            headers=headers,
            params=params,
        )
        self.config.logger.debug(f"Raw API response: {result}")
        return result

    def delete_scan(self, scan_id: str) -> None:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="DELETE",
            url=f"{self.endpoint_prefix}/scans/{scan_id}",
            auth=self.auth,
            headers=headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def cancel_scan(self, scan_id: str) -> None:
        headers = {"Content-Type": "application/json"}
        result = self.request(
            method="POST",
            url=f"{self.endpoint_prefix}/scans/{scan_id}/cancel",
            auth=self.auth,
            headers=headers,
        )
        self.config.logger.debug(f"Raw API response: {result}")

    def __get_scan_info_wait_until_status(self, scan_id: str, status: [str]) -> Dict:  # type: ignore
        for _ in range(RETRY_COUNT_FOR_SCANNING):
            info = self.get_scan(scan_id)
            if info and info.get("scan_status_info", {}).get("status") in status:
                return info

            sleep(WAIT_TIME_SECS_SUCCESSIVE_SCAN_INFO_CHECK)

        raise Exception("Scan timed out")

    def scan(self, file_path: Union[Path, str]) -> Dict:
        """Run a security scan on a file using AI Defense server"""
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
