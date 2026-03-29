"""
Sanitization Verifier - High-level verification API for taint analysis
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path

from .sarif_parser import parse_sarif_result, FunctionLocation
from .symbolic_sanitizer import SymbolicExecutor, SymbolicExecutionResult
from .harness_generator import generate_harness, compile_harness, HarnessResult


@dataclass
class VerificationResult:
    """Complete verification result for a SARIF finding"""
    success: bool
    rule_id: str
    message: str
    function_name: Optional[str]
    file_path: Optional[str]
    line_number: int
    sanitized: bool
    sink_type: str
    constraint_description: str
    symbolic_result: Optional[SymbolicExecutionResult] = None
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "rule_id": self.rule_id,
            "message": self.message,
            "function_name": self.function_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "sanitized": self.sanitized,
            "sink_type": self.sink_type,
            "constraint_description": self.constraint_description,
            "symbolic_result": self.symbolic_result.to_dict() if self.symbolic_result else None,
            "errors": self.errors
        }


class SanitizationVerifier:
    """
    High-level verifier that orchestrates the full verification pipeline:
    SARIF → Constraints → Harness → Symbolic Execution → Verdict
    """
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
    
    def verify_from_sarif(
        self,
        sarif_data: Dict[str, Any],
        source_root: Optional[str] = None
    ) -> List[VerificationResult]:
        """
        Verify all findings in a SARIF result
        
        Args:
            sarif_data: Parsed SARIF JSON
            source_root: Root directory for source files
            
        Returns:
            List of VerificationResult for each finding
        """
        results = []
        sarif_results = parse_sarif_result(sarif_data)
        
        for sarif_result in sarif_results:
            result = self._verify_single_result(sarif_result, source_root)
            results.append(result)
        
        return results
    
    def verify_function(
        self,
        function_name: str,
        file_path: str,
        constraints: Dict[str, List[Dict]],
        rule_id: str = "",
        message: str = "",
        line_number: int = 0
    ) -> VerificationResult:
        """
        Verify a single function's sanitization behavior
        
        Args:
            function_name: Name of function to verify
            file_path: Path to source file
            constraints: Dict with input_constraints and output_constraints
            rule_id: SARIF rule ID for reference
            message: SARIF message for reference
            line_number: Line number of function
            
        Returns:
            VerificationResult with verdict
        """
        # Step 1: Generate harness
        harness_result = generate_harness(
            function_name=function_name,
            source_file=file_path
        )
        
        if not harness_result.success:
            return VerificationResult(
                success=False,
                rule_id=rule_id,
                message=message,
                function_name=function_name,
                file_path=file_path,
                line_number=line_number,
                sanitized=False,
                sink_type="unknown",
                constraint_description="Harness generation failed",
                errors=[f"Harness failed: {harness_result.error}"]
            )
        
        # Step 2: Compile harness
        compile_result = compile_harness(
            harness_code=harness_result.harness_code,
            source_file=file_path
        )
        
        if not compile_result.success:
            return VerificationResult(
                success=False,
                rule_id=rule_id,
                message=message,
                function_name=function_name,
                file_path=file_path,
                line_number=line_number,
                sanitized=False,
                sink_type="unknown",
                constraint_description="Harness compilation failed",
                errors=[f"Compilation failed: {compile_result.error}"]
            )
        
        # Step 3: Run symbolic execution with constraints
        executor = SymbolicExecutor(compile_result.binary_path)
        symbolic_result = executor.execute_with_constraints(constraints, self.timeout)
        
        return VerificationResult(
            success=symbolic_result.success,
            rule_id=rule_id,
            message=message,
            function_name=function_name,
            file_path=file_path,
            line_number=line_number,
            sanitized=symbolic_result.sanitized,
            sink_type=constraints.get("sink_type", "unknown"),
            constraint_description=constraints.get("description", ""),
            symbolic_result=symbolic_result,
            errors=symbolic_result.errors
        )
    
    def _verify_single_result(
        self,
        func_location: FunctionLocation,
        source_root: Optional[str],
        constraints: Optional[Dict[str, List[Dict]]] = None
    ) -> VerificationResult:
        """Verify a single SARIF result"""
        
        # Resolve file path
        file_path = func_location.file_path
        if source_root and not Path(file_path).is_absolute():
            file_path = str(Path(source_root) / file_path)
        
        # Use provided constraints or default empty constraints
        if constraints is None:
            constraints = {
                "input_constraints": [],
                "output_constraints": [],
                "sink_type": "unknown",
                "description": "No constraints provided"
            }
        
        return self.verify_function(
            function_name=func_location.function_name or "unknown",
            file_path=file_path,
            constraints=constraints,
            rule_id=func_location.rule_id or "",
            message=func_location.message or "",
            line_number=func_location.line_number
        )


def quick_verify(
    sarif_path: str,
    source_root: Optional[str] = None,
    timeout: int = 300
) -> List[VerificationResult]:
    """
    Quick verification from SARIF file path
    
    Args:
        sarif_path: Path to SARIF file
        source_root: Root directory for source files
        timeout: Symbolic execution timeout
        
    Returns:
        List of VerificationResult
    """
    import json
    
    with open(sarif_path, 'r', encoding='utf-8') as f:
        sarif_data = json.load(f)
    
    verifier = SanitizationVerifier(timeout=timeout)
    return verifier.verify_from_sarif(sarif_data, source_root)