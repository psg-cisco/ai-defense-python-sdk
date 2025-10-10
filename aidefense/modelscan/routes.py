SCANS = "scans"
SCAN_OBJECTS = "objects"


def scan_by_id(scan_id: str) -> str:
    return f"{SCANS}/{scan_id}"

def object_by_id(scan_id: str, object_id: str) -> str:
    return f"{scan_by_id(scan_id)}/{SCAN_OBJECTS}/{object_id}"
