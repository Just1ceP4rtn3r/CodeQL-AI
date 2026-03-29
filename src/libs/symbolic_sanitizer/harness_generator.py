"""
Harness Generator - Create C/C++ harness for symbolic execution
"""

import tempfile
import subprocess
import shutil
import os
import logging
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class HarnessResult:
    """Result of harness generation and compilation"""
    success: bool
    harness_code: str
    harness_path: Optional[str] = None
    binary_path: Optional[str] = None
    error: Optional[str] = None


def generate_harness(function_name: str, source_file: str) -> HarnessResult:
    """
    Generate a C++ harness for class constructor/destructor analysis.
    """
    # Parse function_name: Namespace::ClassName::~ClassName or Namespace::ClassName
    parts = function_name.split('::')

    if len(parts) >= 3 and parts[-1].startswith('~'):
        # Namespace::ClassName::~ClassName format (destructor)
        namespace = '::'.join(parts[:-2])
        class_name = parts[-2]
        full_class = f"{namespace}::{class_name}"
    elif len(parts) >= 2:
        # Namespace::ClassName format
        full_class = function_name
    else:
        # Just function name
        full_class = function_name

    header_file = _find_header_file(source_file)

    harness_code = f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
{f'#include "{header_file}"' if header_file else ''}

char symbolic_input[64];

int main(int argc, char** argv) {{
    {full_class} obj(symbolic_input[0]);
    return 0;
}}
'''

    return HarnessResult(success=True, harness_code=harness_code)


def _find_header_file(source_file: str) -> Optional[str]:
    """Find corresponding header file"""
    path = Path(source_file)
    base_name = path.stem

    for suffix in ['_goodB2G', '_goodG2B', '_bad']:
        if base_name.endswith(suffix):
            base_name = base_name[:-len(suffix)]
            break

    header = path.parent / f"{base_name}.h"
    if header.exists():
        return header.name

    return None


def compile_harness(harness_code: str, source_file: str, compiler: str = "g++") -> HarnessResult:
    """Compile harness with original source"""
    temp_dir = tempfile.mkdtemp(prefix="symbolic_harness_")

    try:
        harness_path = os.path.join(temp_dir, "harness.cpp")
        with open(harness_path, 'w') as f:
            f.write(harness_code)

        output_path = os.path.join(temp_dir, "harness_bin")
        include_paths = _detect_include_paths(source_file)

        cmd = [compiler, "-O0", "-g", "-fno-stack-protector", "-o", output_path]

        for inc_path in include_paths:
            cmd.extend(["-I", inc_path])

        cmd.extend([harness_path, source_file])

        io_c = _find_io_c(include_paths)
        if io_c:
            cmd.append(io_c)

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            return HarnessResult(
                success=False,
                harness_code=harness_code,
                harness_path=None,
                error=f"Compilation failed: {result.stderr}"
            )

        return HarnessResult(
            success=True,
            harness_code=harness_code,
            harness_path=harness_path,
            binary_path=output_path
        )

    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return HarnessResult(
            success=False,
            harness_code=harness_code,
            error=f"Compilation error: {str(e)}"
        )


def _detect_include_paths(source_file: str) -> List[str]:
    """Auto-detect include paths"""
    include_paths = []
    source_path = Path(source_file).resolve()

    include_paths.append(str(source_path.parent))

    for parent in source_path.parents:
        testcase_support = parent / "testcasesupport"
        if testcase_support.exists():
            include_paths.append(str(testcase_support))
            break

    return include_paths


def _find_io_c(include_paths: List[str]) -> Optional[str]:
    """Find io.c file"""
    for inc_path in include_paths:
        io_c = Path(inc_path) / "io.c"
        if io_c.exists():
            return str(io_c)
    return None
