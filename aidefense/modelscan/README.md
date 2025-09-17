# AI Defense ModelScan Module

The AI Defense ModelScan module provides comprehensive security scanning capabilities for AI/ML model files and repositories. It offers both high-level convenience methods and granular step-by-step control for scanning operations.

## Features

- **File Scanning**: Scan individual model files for security threats and malicious code
- **Repository Scanning**: Scan entire model repositories from platforms like HuggingFace
- **Multiple Scan Approaches**: High-level client for convenience or granular control for custom workflows
- **Comprehensive Results**: Detailed threat detection and analysis results

## Installation

```bash
pip install cisco-aidefense-sdk
```

## Quick Start

### Basic File Scanning with ModelScanClient

```python
from aidefense.modelscan import ModelScanClient, ScanStatus
from aidefense import Config

# Initialize the client
client = ModelScanClient(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
)

# Scan a local file
result = client.scan_file("/path/to/model.pkl")

# Check the results
status = result["scan_status_info"]["status"]
if status == ScanStatus.COMPLETED:
    print("✅ Scan completed successfully")
    
    # Check for threats in analysis results
    analysis_results = result["scan_status_info"].get("analysis_results", {})
    items = analysis_results.get("items", [])
    
    for item in items:
        file_name = item["name"]
        file_status = item["status"]
        threats = item.get("threats", {}).get("items", [])
        
        if threats:
            print(f"⚠️  Threats found in {file_name}:")
            for threat in threats:
                threat_type = threat["threat_type"]
                severity = threat["severity"]
                description = threat["description"]
                details = threat.get("details", "")
                print(f"   - {severity}: {threat_type}")
                print(f"     Description: {description}")
                if details:
                    print(f"     Details: {details}")
        elif file_status == "COMPLETED":
            print(f"✅ {file_name} is clean")
        else:
            print(f"ℹ️  {file_name} status: {file_status}")
elif status == ScanStatus.FAILED:
    print(f"❌ Scan failed: {result.get('error_message', 'Unknown error')}")
```

### Repository Scanning with ModelScanClient

```python
from aidefense.modelscan import ModelScanClient, RepoConfig, HuggingfaceRepoAuth, ScanStatus
from aidefense import Config

# Initialize the client
client = ModelScanClient(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
)

# Configure repository scan with authentication
repo_config = RepoConfig(
    url="https://huggingface.co/username/model-name",
    auth=HuggingfaceRepoAuth(token="hf_your_token_here")
)

# Scan the repository
result = client.scan_repo(repo_config)

# Process results
status = result["scan_status_info"]["status"]
if status == ScanStatus.COMPLETED:
    print("✅ Repository scan completed successfully")
    
    # Check analysis results
    analysis = result.get("analysis_results", {})
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
```

### Public Repository Scanning (No Authentication)

```python
from aidefense.modelscan import ModelScanClient, RepoConfig
from aidefense import Config

client = ModelScanClient(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
)

# Scan a public repository without authentication
public_repo_config = RepoConfig(
    url="https://huggingface.co/username/public-model"
)

result = client.scan_repo(public_repo_config)
print("Public repository scan result:", result)
```

## Granular File Scanning with ModelScan

For more control over the scanning process, you can use the base `ModelScan` class to perform step-by-step operations:

### Step-by-Step File Scanning

```python
from pathlib import Path
from time import sleep
from aidefense.modelscan import ModelScan, ScanStatus
from aidefense import Config

# Initialize the base client
client = ModelScan(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
)

# Step 1: Register a new scan
scan_id = client.register_scan()
print(f"📝 Registered scan with ID: {scan_id}")

try:
    # Step 2: Upload the file
    file_path = Path("/path/to/model.pkl")
    success = client.upload_file(scan_id, file_path)
    if success:
        print(f"📤 Successfully uploaded {file_path.name}")
    
    # Step 3: Trigger the scan
    client.trigger_scan(scan_id)
    print("🚀 Scan triggered, processing...")
    
    # Step 4: Monitor scan progress
    max_retries = 30
    wait_time = 2
    
    for attempt in range(max_retries):
        scan_info = client.get_scan(scan_id)
        status = scan_info.get("scan_status_info", {}).get("status")
        
        print(f"📊 Scan status: {status}")
        
        if status == ScanStatus.COMPLETED:
            print("✅ Scan completed successfully!")
            
            # Process results
            analysis_results = scan_info.get("analysis_results", {})
            items = analysis_results.get("items", [])
            
            for item in items:
                file_name = item.get("name", "Unknown")
                file_status = item.get("status", "Unknown")
                threats = item.get("threats", {}).get("items", [])
                
                if threats:
                    print(f"⚠️  Threats detected in {file_name}")
                    for threat in threats:
                        threat_type = threat.get("threat_type", "Unknown")
                        severity = threat.get("severity", "Unknown")
                        description = threat.get("description", "No description")
                        details = threat.get("details", "")
                        print(f"   - {severity}: {threat_type}")
                        print(f"   - Description: {description}")
                        if details:
                            print(f"   - Details: {details}")
                elif file_status == "COMPLETED":
                    print(f"✅ {file_name} is clean")
                else:
                    print(f"ℹ️  {file_name} status: {file_status}")
            break
            
        elif status == ScanStatus.FAILED:
            error_msg = scan_info.get("error_message", "Unknown error")
            print(f"❌ Scan failed: {error_msg}")
            break
            
        elif status == ScanStatus.CANCELED:
            print("🚫 Scan was canceled")
            break
            
        elif status in [ScanStatus.PENDING, ScanStatus.IN_PROGRESS]:
            print(f"⏳ Scan in progress... (attempt {attempt + 1}/{max_retries})")
            sleep(wait_time)
        else:
            print(f"❓ Unknown status: {status}")
            sleep(wait_time)
    else:
        print("⏰ Scan timed out")
        # Cancel the scan if it times out
        client.cancel_scan(scan_id)

except Exception as e:
    print(f"❌ Error during scan: {e}")
    # Clean up on error
    try:
        client.cancel_scan(scan_id)
        print("🧹 Scan canceled due to error")
    except:
        pass

finally:
    # Optional: Clean up the scan data
    try:
        client.delete_scan(scan_id)
        print("🗑️  Scan data cleaned up")
    except Exception as e:
        print(f"⚠️  Could not delete scan: {e}")
```

## Scan Management Operations

### List All Scans

```python
from aidefense import Config
from aidefense.modelscan import ModelScanClient

client = ModelScanClient(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
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
```

### Get Detailed Scan Information

```python
from aidefense import Config
from aidefense.modelscan import ModelScanClient

client = ModelScanClient(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
)

# Get detailed information about a specific scan
scan_id = "your_scan_id_here"
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
```

### Cancel and Delete Scans

```python
from aidefense import Config
from aidefense.modelscan import ModelScanClient

client = ModelScanClient(
    api_key="your_api_key",
    config=Config(runtime_base_url="https://api.security.cisco.com")
)

scan_id = "your_scan_id_here"

# Cancel a running scan
try:
    client.cancel_scan(scan_id)
    print(f"🚫 Canceled scan {scan_id}")
    
    # Wait a moment for cancellation to process
    import time
    time.sleep(2)
    
    # Delete the scan data
    client.delete_scan(scan_id)
    print(f"🗑️  Deleted scan {scan_id}")
    
except Exception as e:
    print(f"❌ Error managing scan: {e}")
```

## Configuration and Authentication

### Repository Authentication

Currently supported repository types and their authentication methods:

#### HuggingFace Repositories

```python
from aidefense.modelscan import HuggingfaceRepoAuth, RepoConfig

# Create HuggingFace authentication
auth = HuggingfaceRepoAuth(token="hf_your_access_token_here")

# Use with repository configuration
repo_config = RepoConfig(
    url="https://huggingface.co/username/model-name",
    auth=auth
)

# The RepoConfig automatically detects the repository type
print(f"Repository type: {repo_config.url_type}")  # UrlType.HUGGING_FACE
print(f"Auth config: {repo_config.config}")  # {"huggingface": {"access_token": "hf_..."}}
```

## Scan Status Reference

The `ScanStatus` enum provides the following status values:

- `NONE_SCAN_STATUS`: Default/uninitialized status
- `PENDING`: Scan registered but not yet started
- `IN_PROGRESS`: Scan is currently running
- `COMPLETED`: Scan finished successfully
- `FAILED`: Scan encountered an error
- `CANCELED`: Scan was manually canceled

## Best Practices

### 1. Resource Management

Always clean up scan resources, especially when using the granular `ModelScan` class:

```python
scan_id = None
try:
    scan_id = client.register_scan()
    # ... perform scan operations
except Exception as e:
    if scan_id:
        client.cancel_scan(scan_id)
        # wait for cancel task to complete, get the scan info to check the status
        sleep(10)
        client.delete_scan(scan_id)
    raise e
```

### 2. Timeout Handling

Implement appropriate timeouts for long-running scans:

```python
import time

def wait_for_scan_completion(client, scan_id, max_wait_time=300, check_interval=5):
    """Wait for scan completion with timeout."""
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        scan_info = client.get_scan(scan_id)
        status = scan_info.get("scan_status_info", {}).get("status")
        
        if status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELED]:
            return scan_info
            
        time.sleep(check_interval)
    
    # Timeout reached
    client.cancel_scan(scan_id)
    raise TimeoutError(f"Scan {scan_id} timed out after {max_wait_time} seconds")
```

### 3. Batch Processing

For multiple files, use the high-level client for simplicity:

```python
import os
from pathlib import Path

def scan_directory(client, directory_path):
    """Scan all model files in a directory."""
    directory = Path(directory_path)
    model_extensions = ['.pkl', '.joblib', '.h5', '.pb', '.onnx', '.pt', '.pth']
    
    results = {}
    
    for file_path in directory.rglob('*'):
        if file_path.suffix.lower() in model_extensions:
            try:
                print(f"Scanning {file_path.name}...")
                result = client.scan_file(file_path)
                results[str(file_path)] = result
            except Exception as e:
                print(f"Failed to scan {file_path.name}: {e}")
                results[str(file_path)] = {"error": str(e)}
    
    return results

# Usage
results = scan_directory(client, "/path/to/models/")
```
