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
from aidefense.modelscan.models import (
    ModelRepoConfig, HuggingFaceAuth, Auth, URLType, ScanStatus
)

# Initialize the client
client = ModelScanClient(
    api_key="<YOUR_API_KEY>",
    config=Config(management_base_url="<YOUR_BASE_URL>")
)

# Configure repository scan with authentication
repo_config = ModelRepoConfig(
    url="<REPO_URL>",
    type=URLType.HUGGING_FACE,
    auth=Auth(huggingface=HuggingFaceAuth(access_token="<YOUR_TOKEN>"))
)

# Scan the repository
result = client.scan_repo(repo_config)

# Process results
if result.status == ScanStatus.COMPLETED:
    print("✅ Repository scan completed successfully")

    # Check analysis results
    for item in result.analysis_results.items:
        if item.threats.items:
            print(f"⚠️  Threats found in {item.name}:")
            for threat in item.threats.items:
                print(f"   - {threat.severity.value}: {threat.threat_type.value} - {threat.description}")
        elif item.status == ScanStatus.COMPLETED:
            print(f"✅ {item.name} is clean")
        else:
            print(f"ℹ️  {item.name} was {item.status.value.lower()}")
elif result.status == ScanStatus.FAILED:
    print(f"❌ Repository scan failed")

if __name__ == "__main__":
    pass
