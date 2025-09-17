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
from aidefense.modelscan import ModelScanClient, RepoConfig, HuggingfaceRepoAuth, ScanStatus

# Initialize the client
client = ModelScanClient(
    api_key="<YOUR_API_KEY>",
    config=Config(runtime_base_url="<YOUR_BASE_URL>")
)

# Configure repository scan with authentication
repo_config = RepoConfig(
    url="<REPO_URL>",
    auth=HuggingfaceRepoAuth(token="<YOUR_TOKEN>")
)

# Scan the repository
result = client.scan_repo(repo_config)

# Process results
status = result["scan_status_info"]["status"]
if status == ScanStatus.COMPLETED:
    print("✅ Repository scan completed successfully")

    # Check analysis results
    analysis = result["scan_status_info"].get("analysis_results", {})
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
    print(f"❌ Repository scan failed: {result.get('error_message', 'Unknown error')}")

if __name__ == "__main__":
    pass
