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

"""
Example: Using inspect_conversation for chat conversation inspection
"""
from aidefense import Config
from aidefense.modelscan import ModelScanClient
from aidefense.modelscan.models import GetScanStatusRequest

# Initialize the client
client = ModelScanClient(
    api_key="<YOUR_API_KEY>",
    config=Config(management_base_url="<YOUR_BASE_URL>")
)

# Get detailed information about a specific scan
scan_id = "1d35f2b3-87cb-4e13-9849-c6aaa942648f"
request = GetScanStatusRequest(file_limit=10, file_offset=0)
response = client.get_scan(scan_id, request)

# Extract scan status info
scan_info = response.scan_status_info
print(f"📊 Scan Details for {scan_id}:")
print(f"  Status: {scan_info.status}")
print(f"  Type: {scan_info.type}")
print(f"  Created: {scan_info.created_at}")
print(f"  Completed: {scan_info.completed_at}")

# Repository info (if applicable)
if scan_info.repository:
    print(f"  Repository: {scan_info.repository.url}")
    print(f"  Files Scanned: {scan_info.repository.files_scanned}")

# Check analysis results with pagination
analysis_results = scan_info.analysis_results
print(f"  Results: {len(analysis_results.items)} items (total: {analysis_results.paging.total})")
print()

for item in analysis_results.items:
    # Determine status icon
    if item.status == "SKIPPED":
        status_icon = "⏭️"
    elif item.threats.items:
        status_icon = "⚠️"
    else:
        status_icon = "✅"

    print(f"    {status_icon} {item.name} ({item.size} bytes)")
    print(f"       Status: {item.status}")

    if item.reason:
        print(f"       Reason: {item.reason}")

    if item.threats.items:
        threat_counts = {}
        for threat in item.threats.items:
            severity = threat.severity.value
            threat_counts[severity] = threat_counts.get(severity, 0) + 1

        threat_summary = ", ".join([f"{severity}: {count}" for severity, count in threat_counts.items()])
        print(f"       Threats: {threat_summary}")

    print()

if __name__ == "__main__":
    pass
