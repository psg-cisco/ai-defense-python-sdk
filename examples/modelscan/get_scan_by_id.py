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

# Initialize the client
client = ModelScanClient(
    api_key="<YOUR_API_KEY>",
    config=Config(runtime_base_url="<YOUR_BASE_URL>")
)

# Get detailed information about a specific scan
scan_id = "1d35f2b3-87cb-4e13-9849-c6aaa942648f"
scan_info = client.get_scan(scan_id)
# Extract scan status info
scan_status_info = scan_info.get("scan_status_info", {})
print(f"📊 Scan Details for {scan_id}:")
print(f"  Status: {scan_status_info.get('status', 'Unknown')}")
print(f"  Type: {scan_status_info.get('type', 'Unknown')}")
print(f"  Created: {scan_status_info.get('created_at', 'Unknown')}")
print(f"  Completed: {scan_status_info.get('completed_at', 'Not completed')}")

# Repository info (if applicable)
repo_info = scan_status_info.get("repository_info")
if repo_info:
    print(f"  Repository: {repo_info.get('url', 'Unknown')}")
    print(f"  Files Scanned: {repo_info.get('files_scanned', 0)}")

# Check analysis results with pagination
analysis_results = scan_status_info.get("analysis_results", {})
items = analysis_results.get("items", [])
paging = analysis_results.get("paging", {})
print(f"  Results: {len(items)} items (total: {paging.get('total', 'Unknown')})")
print()

for item in items:
    file_name = item.get("name", "Unknown")
    file_status = item.get("status", "Unknown")
    file_size = item.get("size", "Unknown")
    threats = item.get("threats", {}).get("items", [])
    reason = item.get("reason", "")

    # Determine status icon
    if file_status == "SKIPPED":
        status_icon = "⏭️"
    elif threats:
        status_icon = "⚠️"
    else:
        status_icon = "✅"

    print(f"    {status_icon} {file_name} ({file_size} bytes)")
    print(f"       Status: {file_status}")

    if reason:
        print(f"       Reason: {reason}")

    if threats:
        threat_counts = {}
        for threat in threats:
            severity = threat.get("severity", "Unknown")
            threat_counts[severity] = threat_counts.get(severity, 0) + 1

        threat_summary = ", ".join([f"{severity}: {count}" for severity, count in threat_counts.items()])
        print(f"       Threats: {threat_summary}")

    print()

if __name__ == "__main__":
    pass
