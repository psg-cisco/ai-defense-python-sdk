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

# Get first 10 scans
scans_response = client.list_scans(limit=10, offset=0)
scans_data = scans_response.get("scans", {})
scans = scans_data.get("items", [])
paging = scans_data.get("paging", {})

print(f"📋 Found {len(scans)} scans (total: {paging.get('total', 'Unknown')}):")
for scan in scans:
    scan_id = scan.get("scan_id", "Unknown")
    name = scan.get("name", "Unknown")
    scan_type = scan.get("type", "Unknown")
    status = scan.get("status", "Unknown")
    created_at = scan.get("created_at", "Unknown")
    files_scanned = scan.get("files_scanned", 0)
    issues = scan.get("issues_by_severity", {})

    # Create issue summary
    issue_summary = []
    for severity, count in issues.items():
        if count > 0:
            issue_summary.append(f"{severity}: {count}")
    issue_text = ", ".join(issue_summary) if issue_summary else "No issues"

    print(f"  • {scan_id}")
    print(f"    Name: {name} | Type: {scan_type} | Status: {status}")
    print(f"    Files: {files_scanned} | Issues: {issue_text}")
    print(f"    Created: {created_at}")
    print()

# Get next page of scans
more_scans = client.list_scans(limit=10, offset=10)

if __name__ == "__main__":
    pass
