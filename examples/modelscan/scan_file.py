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

from aidefense import ModelScanClient, Config

client = ModelScanClient(
    api_key="YOUR_API_KEY",
    config=Config(runtime_base_url="YOUR_AI_DEFENSE_REST_API_BASE_URL"),
)

result = client.scan_file(file_path="PATH_TO_YOUR_FILE")
print("Scan result:", result)
