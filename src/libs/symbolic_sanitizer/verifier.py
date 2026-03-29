"""
Sanitization Verifier - High-level verification API for taint analysis
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path

from .sarif_parser import parse_sarif_result, extract_function_location, SarifResult
from .constraint_generator import generate_taint_constraints, TaintConstraint
from .harness_generator import generate_harness, compile_harness, generate_and_compile
from .symbolic_sanitizer import analyze_function_sanitization, SymbolicExecutionResult


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
        rule_id: str,
        message: str,
        line_number: int = 0
    ) -> VerificationResult:
        """
        Verify a single function's sanitization behavior
        
        Args:
            function_name: Name of function to verify
            file_path: Path to source file
            rule_id: SARIF rule ID for constraint generation
            message: SARIF message for context
            line_number: Line number of function
            
        Returns:
            VerificationResult with verdict
        """
        # Generate taint constraints based on sink type
        taint_constraint = generate_taint_constraints(
            rule_id=rule_id,
            message=message,
            sink_name=function_name
        )
        
        # Generate and compile harness
        harness_result = generate_and_compile(
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
                sink_type=taint_constraint.sink_type.value,
                constraint_description=taint_constraint.description,
                errors=[f"Harness failed: {harness_result.error}"]
            )
        
        # Run symbolic execution
        symbolic_result = analyze_function_sanitization(
            binary_path=harness_result.binary_path,
            function_name=function_name,
            taint_constraint=taint_constraint,
            timeout=self.timeout
        )
        
        return VerificationResult(
            success=symbolic_result.success,
            rule_id=rule_id,
            message=message,
            function_name=function_name,
            file_path=file_path,
            line_number=line_number,
            sanitized=symbolic_result.sanitized,
            sink_type=taint_constraint.sink_type.value,
            constraint_description=taint_constraint.description,
            symbolic_result=symbolic_result,
            errors=symbolic_result.errors
        )
    
    def _verify_single_result(
        self,
        sarif_result: SarifResult,
        source_root: Optional[str]
    ) -> VerificationResult:
        """Verify a single SARIF result"""
        
        # Get sink location
        sink = sarif_result.sink_location or sarif_result.locations[0] if sarif_result.locations else None
        
        if not sink:
            return VerificationResult(
                success=False,
                rule_id=sarif_result.rule_id,
                message=sarif_result.message,
                function_name=None,
                file_path=None,
                line_number=0,
                sanitized=False,
                sink_type="unknown",
                constraint_description="No sink location found",
                errors=["No sink location in SARIF result"]
            )
        
        # Resolve file path
        file_path = sink.file_path
        if source_root and not Path(file_path).is_absolute():
            file_path = str(Path(source_root) / file_path)
        
        return self.verify_function(
            function_name=sink.function_name or "unknown",
            file_path=file_path,
            rule_id=sarif_result.rule_id,
            message=sarif_result.message,
            line_number=sink.line_number
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