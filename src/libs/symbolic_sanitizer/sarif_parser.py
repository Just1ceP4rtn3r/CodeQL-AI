"""
SARIF Parser - Extract function location from CodeQL SARIF results

Simplified version that delegates function extraction to lib_sanitizer.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class FunctionLocation:
    """Represents a function location extracted from SARIF"""
    file_path: str
    line_number: int
    function_name: Optional[str] = None
    column: Optional[int] = None
    rule_id: Optional[str] = None
    message: Optional[str] = None


def parse_sarif_result(sarif_data: Dict[str, Any]) -> List[FunctionLocation]:
    """
    Parse SARIF JSON data and extract function locations.

    Args:
        sarif_data: Parsed SARIF JSON dictionary

    Returns:
        List of FunctionLocation objects
    """
    results = []

    for run in sarif_data.get("runs", []):
        for result_data in run.get("results", []):
            loc = _parse_result(result_data)
            if loc:
                results.append(loc)

    return results


def _parse_result(result_data: Dict[str, Any]) -> Optional[FunctionLocation]:
    """Parse a single SARIF result entry"""
    rule_id = result_data.get("ruleId", "")
    message = result_data.get("message", {}).get("text", "")

    # Get primary location
    locations = result_data.get("locations", [])
    if not locations:
        return None

    loc_data = locations[0]
    physical = loc_data.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})

    file_path = artifact.get("uri", "")
    line_number = region.get("startLine", 0)

    if not file_path or not line_number:
        return None

    return FunctionLocation(
        file_path=file_path,
        line_number=line_number,
        rule_id=rule_id,
        message=message
    )


def load_sarif_from_file(sarif_path: str) -> Dict[str, Any]:
    """Load and parse SARIF file"""
    with open(sarif_path, 'r', encoding='utf-8') as f:
        return json.load(f)
