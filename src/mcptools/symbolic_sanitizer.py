#!/usr/bin/env python3
"""
MCP Server: Symbolic Sanitizer Pipeline
包含所有符号执行验证相关的工具：parse_sarif, generate_harness, compile_harness, verify_sanitization
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastmcp import FastMCP
from libs.symbolic_sanitizer import (
    parse_sarif_result,
    load_sarif_from_file,
    generate_harness,
    compile_harness,
    verify_sanitization,
)

mcp = FastMCP(
    name="symbolic_sanitizer",
    instructions="CodeQL Symbolic Sanitizer - Verify function sanitization using angr"
)

@mcp.tool()
def parse_sarif(sarif_path: str) -> dict:
    """Parse SARIF file and extract function locations."""
    try:
        sarif_data = load_sarif_from_file(sarif_path)
        locations = parse_sarif_result(sarif_data)
        return {
            "success": True,
            "count": len(locations),
            "locations": [
                {
                    "file_path": loc.file_path,
                    "line_number": loc.line_number,
                    "rule_id": loc.rule_id,
                    "message": loc.message
                }
                for loc in locations
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def generate_harness(function_name: str, source_file: str) -> dict:
    """Generate C++ harness for symbolic execution."""
    result = generate_harness(function_name, source_file)
    return {
        "success": result.success,
        "harness_code": result.harness_code,
        "error": result.error
    }

@mcp.tool()
def compile_harness(harness_code: str, source_file: str) -> dict:
    """Compile harness with original source file."""
    result = compile_harness(harness_code, source_file)
    return {
        "success": result.success,
        "binary_path": result.binary_path,
        "harness_path": result.harness_path,
        "error": result.error
    }

@mcp.tool()
def verify_sanitization(binary_path: str, timeout: int = 60) -> dict:
    """Run symbolic execution to verify sanitization."""
    result = verify_sanitization(binary_path, timeout)
    return result.to_dict()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host="127.0.0.1", port=8000)
