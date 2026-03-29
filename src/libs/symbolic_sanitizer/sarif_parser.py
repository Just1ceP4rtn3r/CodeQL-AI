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


@dataclass
class TaintPath:
    """
    Represents a complete taint path extracted from SARIF codeFlows.

    A taint path traces data flow from a source (entry point) through
    intermediate locations to a sink (vulnerable location).
    """
    path_id: str
    source: Dict  # {file_path, line_number, function_name, column}
    sink: Dict    # {file_path, line_number, function_name, column}
    intermediate_locations: List[Dict]
    rule_id: str
    message: str


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


def extract_taint_paths(sarif_data: dict) -> List[TaintPath]:
    """
    Extract complete taint paths from SARIF 2.1.0 codeFlows/threadFlows structure.

    Args:
        sarif_data: Parsed SARIF JSON dictionary

    Returns:
        List of TaintPath objects representing data flow paths
    """
    taint_paths = []
    path_counter = 0

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            code_flows = result.get("codeFlows", [])
            for code_flow in code_flows:
                thread_flows = code_flow.get("threadFlows", [])
                for thread_flow in thread_flows:
                    locations = thread_flow.get("locations", [])
                    if len(locations) < 2:
                        continue

                    path_nodes = [_parse_location_node(loc) for loc in locations]
                    path_nodes = [node for node in path_nodes if node is not None]

                    if len(path_nodes) < 2:
                        continue

                    path_counter += 1
                    path_id = f"path_{path_counter:04d}"

                    source = path_nodes[0]
                    sink = path_nodes[-1]
                    intermediate = path_nodes[1:-1] if len(path_nodes) > 2 else []

                    taint_path = TaintPath(
                        path_id=path_id,
                        source=source,
                        sink=sink,
                        intermediate_locations=intermediate,
                        rule_id=rule_id,
                        message=message
                    )
                    taint_paths.append(taint_path)

    return taint_paths


def _parse_location_node(location_data: dict) -> Optional[dict]:
    """Parse a single location node from threadFlow locations."""
    physical = location_data.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    logical = location_data.get("logicalLocation", {})

    file_path = artifact.get("uri", "")
    line_number = region.get("startLine", 0)

    if not file_path or not line_number:
        return None

    return {
        "file_path": file_path,
        "line_number": line_number,
        "function_name": logical.get("name") or logical.get("fullyQualifiedName"),
        "column": region.get("startColumn")
    }
