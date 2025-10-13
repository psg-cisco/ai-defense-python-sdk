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
from aidefense.modelscan.models import ScanStatus

# Initialize the client
client = ModelScanClient(
    api_key="YOUR_MANAGEMENT_API_KEY",
    config=Config(management_base_url="https://api.security.cisco.com")
)

# Scan a local file
result = client.scan_file("<FILE_PATH>")

# Check the results
if result.status == ScanStatus.COMPLETED:
    print("✅ Scan completed successfully")

    # Check for threats in analysis results
    for item in result.analysis_results.items:
        if item.threats.items:
            print(f"⚠️  Threats found in {item.name}:")
            for threat in item.threats.items:
                print(f"   - {threat.severity.value}: {threat.threat_type.value}")
                print(f"     Description: {threat.description}")
                if threat.details:
                    print(f"     Details: {threat.details}")
        elif item.status == ScanStatus.COMPLETED:
            print(f"✅ {item.name} is clean")
        else:
            print(f"ℹ️  {item.name} status: {item.status.value}")
elif result.status == ScanStatus.FAILED:
    print(f"❌ Scan failed")

if __name__ == "__main__":
    pass
