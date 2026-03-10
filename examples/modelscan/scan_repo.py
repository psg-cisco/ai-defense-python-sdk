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
Example: Scan a Hugging Face repository for AI/ML model threats using the AI Defense Python SDK.

This example demonstrates how to scan a Hugging Face repository for potential AI/ML model threats
using the hierarchical threat classification system.
"""
from aidefense import Config
from aidefense.modelscan import ModelScanClient
from aidefense.modelscan.models import (
    ModelRepoConfig, HuggingFaceAuth, Auth, URLType, ScanStatus
)

# Import utility functions for displaying results
from examples.modelscan.utils import enum_or_str_value, print_analysis_results

def main():
    # Initialize the client
    client = ModelScanClient(
        api_key="YOUR_MANAGEMENT_API_KEY",
        config=Config(management_base_url="https://api.security.cisco.com")
    )

    # Configure repository scan with authentication
    repo_config = ModelRepoConfig(
        url="HUGGINGFACE_REPO_URL",
        type=URLType.HUGGING_FACE,
        auth=Auth(huggingface=HuggingFaceAuth(access_token="YOUR_HUGGINGFACE_TOKEN"))
    )

    print(f"🔍 Scanning repository: {repo_config.url}")
    
    try:
        # Scan the repository
        result = client.scan_repo(repo_config)
        print("\n📊 Scan Results:")
        print("=" * 50)
        
        # Display scan ID if available
        if hasattr(result, 'scan_id') and result.scan_id:
            print(f"🔑 Scan ID:     {result.scan_id}")

        status_value = enum_or_str_value(result.status)

        if status_value == ScanStatus.COMPLETED.value:
            print("✅ Repository scan completed successfully\n")
            
            # Display analysis results using the utility function
            print_analysis_results(result.analysis_results)
                    
        elif status_value == ScanStatus.FAILED.value:
            print("❌ Repository scan failed")
            if hasattr(result, 'error_message') and result.error_message:
                print(f"Error: {result.error_message}")
        else:
            print(f"ℹ️  Scan status: {status_value}")
            
    except Exception as e:
        print(f"\n❌ An error occurred during scanning:")
        print(f"   {str(e)}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
            print(f"   Response: {e.response.text}")

if __name__ == "__main__":
    main()
