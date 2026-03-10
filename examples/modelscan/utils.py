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
Utility functions for displaying scan results in the AI Defense Python SDK examples.
"""
from typing import Any, List

from aidefense.modelscan.models import (
    Technique,
    Severity,
    ScanStatus,
    AnalysisResult,
    FileInfo,
)


def format_severity(severity: Severity) -> str:
    """Format severity with appropriate emoji and color."""
    severity_value = enum_or_str_value(severity)

    if severity_value == Severity.CRITICAL.value:
        return f"🔴 {severity_value}"
    elif severity_value == Severity.HIGH.value:
        return f"🟠 {severity_value}"
    elif severity_value == Severity.MEDIUM.value:
        return f"🟡 {severity_value}"
    elif severity_value == Severity.LOW.value:
        return f"🔵 {severity_value}"
    else:
        return f"⚪ {severity_value}"


def enum_or_str_value(value: Any) -> str:
    """Return a display value for enum-like objects or plain strings."""
    return value.value if hasattr(value, "value") else str(value)


def print_threats(techniques: List[Technique], indent: int = 0) -> None:
    """Recursively print threat information from the hierarchical structure."""
    indent_str = "  " * indent
    for technique in techniques:
        print(f"{indent_str}🔍 {technique.technique_name} ({technique.technique_id})")

        for sub_technique in technique.items:
            print(f"{indent_str}  │")
            print(
                f"{indent_str}  ├─ 🎯 {sub_technique.sub_technique_name} ({sub_technique.sub_technique_id})"
            )
            print(
                f"{indent_str}  │  ├─ Severity: {format_severity(sub_technique.max_severity)}"
            )

            if sub_technique.description:
                print(f"{indent_str}  │  ├─ Description: {sub_technique.description}")

            if sub_technique.indicators:
                print(f"{indent_str}  │  ├─ Indicators:")
                for indicator in sub_technique.indicators:
                    print(f"{indent_str}  │  │  • {indicator}")

            if sub_technique.items:
                print(f"{indent_str}  │  └─ Detections:")
                for threat in sub_technique.items:
                    print(
                        f"{indent_str}  │     • {enum_or_str_value(threat.threat_type)}: {threat.description}"
                    )
                    if threat.details:
                        print(f"{indent_str}  │       Details: {threat.details}")
            print(f"{indent_str}  │")


def print_file_info(file_info: FileInfo) -> None:
    """Print information about a scanned file and its threats."""
    status_value = enum_or_str_value(file_info.status)

    # Determine status icon
    if status_value == ScanStatus.SKIPPED.value:
        status_icon = "⏭️"
    elif file_info.threats.items:
        status_icon = "⚠️"
    else:
        status_icon = "✅"

    print(f"\n{status_icon} {file_info.name} ({file_info.size} bytes)")
    print(f"  Status: {status_value}")

    if file_info.reason:
        print(f"  Reason: {file_info.reason}")

    # Display threat information if available
    if file_info.threats.items:
        print("\n  🚨 Threats Detected:")
        print("  " + "-" * 45)
        print_threats(file_info.threats.items, indent=2)
    elif status_value == ScanStatus.COMPLETED.value:
        print("  ✅ No threats detected")


def print_analysis_results(
    analysis_results: AnalysisResult, scan_id: str = None
) -> None:
    """Print analysis results with pagination information.

    Args:
        analysis_results: The analysis results to display
        scan_id: Optional scan ID to display in the results
    """
    total_files = analysis_results.paging.total
    print(f"📂 Files Analyzed: {len(analysis_results.items)} of {total_files}")
    print("=" * 50)

    for item in analysis_results.items:
        print_file_info(item)

    # Handle pagination if there are more results
    paging = analysis_results.paging
    if paging.offset + len(analysis_results.items) < paging.total:
        remaining = paging.total - (paging.offset + len(analysis_results.items))
        print(
            f"\n📄 {remaining} more files available. Use file_offset to retrieve additional results."
        )
