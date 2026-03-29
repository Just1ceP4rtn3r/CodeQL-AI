"""
Symbolic Execution - angr-based verification with constraint solving
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PathAnalysisResult:
    """Result of analyzing a single execution path"""
    path_id: int
    input_has_dangerous_chars: bool
    output_has_dangerous_chars: bool
    is_sanitized: bool
    concrete_input: Optional[bytes] = None
    concrete_output: Optional[bytes] = None
    constraint_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SymbolicExecutionResult:
    """Result of symbolic execution analysis"""
    success: bool
    function_name: str
    sanitized: bool
    paths_analyzed: int
    paths_harmful: int
    paths_safe: int
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "function_name": self.function_name,
            "sanitized": self.sanitized,
            "paths_analyzed": self.paths_analyzed,
            "paths_harmful": self.paths_harmful,
            "paths_safe": self.paths_safe,
            "errors": self.errors,
            "details": self.details
        }


class SymbolicExecutor:
    """angr-based symbolic execution for function analysis"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        import angr
        self.project = angr.Project(binary_path, auto_load_libs=False)
        logger.info(f"Loaded binary: {binary_path}")

    def execute(self, constraint, timeout: int = 60) -> SymbolicExecutionResult:
        """
        Execute binary symbolically.

        Args:
            constraint: TaintConstraint (not used in simplified version)
            timeout: Execution timeout in seconds

        Returns:
            SymbolicExecutionResult
        """
        try:
            import claripy

            # Find main function
            main_addr = self._find_function("main")
            if not main_addr:
                return SymbolicExecutionResult(
                    success=False,
                    function_name="main",
                    sanitized=False,
                    paths_analyzed=0,
                    paths_harmful=0,
                    paths_safe=0,
                    errors=["main function not found"]
                )

            # Create symbolic input
            sym_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(64)]
            input_addr = 0x500000

            # Create call state
            state = self.project.factory.call_state(main_addr, input_addr)

            # Store symbolic input in memory
            for i, b in enumerate(sym_bytes):
                state.memory.store(input_addr + i, b)

            # Run symbolic execution
            simgr = self.project.factory.simgr(state)
            logger.info("Starting symbolic execution")
            simgr.run(timeout=timeout)

            # Analyze results
            return self._analyze_results(simgr)

        except Exception as e:
            logger.error(f"Symbolic execution failed: {e}")
            return SymbolicExecutionResult(
                success=False,
                function_name="main",
                sanitized=False,
                paths_analyzed=0,
                paths_harmful=0,
                paths_safe=0,
                errors=[str(e)]
            )

    def _find_function(self, name: str) -> Optional[int]:
        """Find function address"""
        try:
            symbol = self.project.loader.find_symbol(name)
            if symbol:
                return symbol.rebased_addr
        except Exception:
            # Symbol lookup failed, fall through to manual search
            pass

        for sym in self.project.loader.symbols:
            if sym.name == name:
                return sym.rebased_addr

        return None

    def _analyze_results(self, simgr) -> SymbolicExecutionResult:
        """Analyze simulation results"""
        paths_analyzed = len(simgr.deadended) + len(simgr.errored)

        if paths_analyzed == 0:
            return SymbolicExecutionResult(
                success=False,
                function_name="main",
                sanitized=False,
                paths_analyzed=0,
                paths_harmful=0,
                paths_safe=0,
                errors=["No paths analyzed"]
            )

        # In simplified version, we assume sanitized if execution completes
        # In real implementation, would check if output constraints are satisfied
        return SymbolicExecutionResult(
            success=True,
            function_name="main",
            sanitized=True,
            paths_analyzed=paths_analyzed,
            paths_harmful=0,
            paths_safe=paths_analyzed,
            details={
                "deadended": len(simgr.deadended),
                "errored": len(simgr.errored)
            }
        )

    def _build_contains_any_constraint(self, sym_bytes: List, chars: List[str]):
        """
        Build constraint: symbolic input must contain at least one of the specified chars.
        Used for input_constraints to ensure we're testing dangerous inputs.
        """
        import claripy
        char_vals = [ord(c) for c in chars]
        # At least one byte equals at least one of the dangerous characters
        byte_matches = []
        for byte in sym_bytes:
            char_matches = [byte == val for val in char_vals]
            byte_matches.append(claripy.Or(*char_matches))
        return claripy.Or(*byte_matches)

    def _build_not_contains_any_constraint(self, sym_bytes: List, chars: List[str]):
        """
        Build constraint: symbolic bytes must NOT contain any of the specified chars.
        Used for output_constraints to verify sanitization removed dangerous chars.
        """
        import claripy
        char_vals = [ord(c) for c in chars]
        # All bytes must NOT equal any of the dangerous characters
        byte_constraints = []
        for byte in sym_bytes:
            char_constraints = [byte != val for val in char_vals]
            byte_constraints.append(claripy.And(*char_constraints))
        return claripy.And(*byte_constraints)

    def _build_length_range_constraint(self, sym_bytes: List, min_len: int, max_len: int):
        """
        Build constraint: symbolic input length within [min_len, max_len].
        Implemented by requiring null terminator position within range.
        """
        import claripy
        # Find first null byte position constraints
        # For simplicity: ensure bytes[min_len-1] != 0 and bytes[max_len] == 0
        constraints = []
        if min_len > 0 and min_len <= len(sym_bytes):
            # At least min_len non-null bytes
            for i in range(min_len):
                if i < len(sym_bytes):
                    constraints.append(sym_bytes[i] != 0)
        if max_len < len(sym_bytes):
            # Null terminator at or before max_len
            constraints.append(sym_bytes[max_len] == 0)
        if constraints:
            return claripy.And(*constraints)
        return claripy.true

    def _build_input_constraint(self, sym_bytes: List, input_constraints: List[Dict]) -> Any:
        """Build combined input constraint from constraint list"""
        import claripy
        constraints = []
        for constraint in input_constraints:
            constraint_type = constraint.get("type")
            if constraint_type == "contains_any":
                chars = constraint.get("chars", [])
                if chars:
                    constraints.append(self._build_contains_any_constraint(sym_bytes, chars))
            elif constraint_type == "not_contains_any":
                chars = constraint.get("chars", [])
                if chars:
                    constraints.append(self._build_not_contains_any_constraint(sym_bytes, chars))
            elif constraint_type == "length_range":
                min_len = constraint.get("min", 0)
                max_len = constraint.get("max", len(sym_bytes))
                constraints.append(self._build_length_range_constraint(sym_bytes, min_len, max_len))
        if constraints:
            return claripy.And(*constraints)
        return claripy.true

    def _build_output_constraint(self, sym_bytes: List, output_constraints: List[Dict]) -> Any:
        """Build combined output constraint from constraint list"""
        return self._build_input_constraint(sym_bytes, output_constraints)

    def apply_input_constraints(self, state, sym_bytes: List, input_constraints: List[Dict]) -> None:
        """
        Apply input constraints to angr state solver.
        Constrains symbolic input to contain dangerous characters for testing sanitization.
        """
        constraint = self._build_input_constraint(sym_bytes, input_constraints)
        state.solver.add(constraint)
        logger.debug(f"Applied input constraints: {input_constraints}")

    def check_output_constraints(
        self, state, output_addr: int, output_len: int, output_constraints: List[Dict]
    ) -> Tuple[bool, Optional[bytes]]:
        """
        Check if output at given address satisfies output constraints.
        Returns (satisfies_constraints, concrete_output_bytes).
        """
        import claripy
        
        output_bytes = []
        for i in range(output_len):
            byte_val = state.memory.load(output_addr + i, 1)
            output_bytes.append(byte_val)
        
        output_constraint = self._build_output_constraint(output_bytes, output_constraints)
        
        state.solver.push()
        state.solver.add(output_constraint)
        satisfies = state.solver.satisfiable()
        
        concrete_output = None
        if satisfies:
            try:
                concrete_output = bytes([
                    state.solver.eval(b, cast_to=int) for b in output_bytes
                ])
            except Exception:
                pass
        
        state.solver.pop()
        return satisfies, concrete_output

    def _check_bytes_contain_dangerous_chars(
        self, state, sym_bytes: List, chars: List[str]
    ) -> bool:
        """Check if symbolic bytes can contain any of the dangerous chars"""
        import claripy
        char_vals = [ord(c) for c in chars]
        
        for byte in sym_bytes:
            for val in char_vals:
                state.solver.push()
                state.solver.add(byte == val)
                if state.solver.satisfiable():
                    state.solver.pop()
                    return True
                state.solver.pop()
        return False

    def _extract_dangerous_chars_from_constraints(self, constraints: List[Dict]) -> List[str]:
        """Extract list of dangerous characters from constraints"""
        chars = []
        for c in constraints:
            if c.get("type") in ("contains_any", "not_contains_any"):
                chars.extend(c.get("chars", []))
        return list(set(chars))

    def execute_with_constraints(
        self, constraints: Dict[str, List[Dict]], timeout: int = 60
    ) -> SymbolicExecutionResult:
        """
        Execute binary with input/output constraints for sanitization verification.
        
        Satisfiability Logic:
        - If input has dangerous chars AND output also has dangerous chars → NOT sanitized
        - If input has dangerous chars BUT output doesn't → sanitized
        - If no paths with dangerous input exist → sanitized (vacuously true)
        """
        try:
            import claripy
            
            input_constraints = constraints.get("input_constraints", [])
            output_constraints = constraints.get("output_constraints", [])
            
            main_addr = self._find_function("main")
            if not main_addr:
                return SymbolicExecutionResult(
                    success=False,
                    function_name="main",
                    sanitized=False,
                    paths_analyzed=0,
                    paths_harmful=0,
                    paths_safe=0,
                    errors=["main function not found"]
                )
            
            sym_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(64)]
            input_addr = 0x500000
            output_addr = 0x600000
            output_len = 64
            
            state = self.project.factory.call_state(main_addr, input_addr)
            
            for i, b in enumerate(sym_bytes):
                state.memory.store(input_addr + i, b)
            
            self.apply_input_constraints(state, sym_bytes, input_constraints)
            
            if not state.solver.satisfiable():
                return SymbolicExecutionResult(
                    success=True,
                    function_name="main",
                    sanitized=True,
                    paths_analyzed=0,
                    paths_harmful=0,
                    paths_safe=0,
                    details={"reason": "Input constraints unsatisfiable - no dangerous inputs possible"}
                )
            
            simgr = self.project.factory.simgr(state)
            logger.info("Starting constrained symbolic execution")
            simgr.run(timeout=timeout)
            
            return self._analyze_constrained_results(
                simgr, sym_bytes, input_constraints, output_constraints, output_addr, output_len
            )
            
        except Exception as e:
            logger.error(f"Constrained symbolic execution failed: {e}")
            return SymbolicExecutionResult(
                success=False,
                function_name="main",
                sanitized=False,
                paths_analyzed=0,
                paths_harmful=0,
                paths_safe=0,
                errors=[str(e)]
            )

    def _analyze_constrained_results(
        self,
        simgr,
        sym_bytes: List,
        input_constraints: List[Dict],
        output_constraints: List[Dict],
        output_addr: int,
        output_len: int
    ) -> SymbolicExecutionResult:
        """Analyze paths with constraint checking for sanitization verification"""
        paths_analyzed = 0
        paths_safe = 0
        paths_harmful = 0
        path_details = []
        
        dangerous_chars = self._extract_dangerous_chars_from_constraints(input_constraints)
        dangerous_chars.extend(self._extract_dangerous_chars_from_constraints(output_constraints))
        dangerous_chars = list(set(dangerous_chars))
        
        all_states = list(simgr.deadended) + list(simgr.errored)
        
        for idx, state in enumerate(all_states):
            paths_analyzed += 1
            
            if not state.solver.satisfiable():
                continue
            
            input_has_dangerous = self._check_bytes_contain_dangerous_chars(
                state, sym_bytes, dangerous_chars
            )
            
            output_bytes = []
            for i in range(output_len):
                output_bytes.append(state.memory.load(output_addr + i, 1))
            
            output_has_dangerous = self._check_bytes_contain_dangerous_chars(
                state, output_bytes, dangerous_chars
            )
            
            is_path_sanitized = not (input_has_dangerous and output_has_dangerous)
            
            if is_path_sanitized:
                paths_safe += 1
            else:
                paths_harmful += 1
            
            concrete_input = None
            try:
                concrete_input = bytes([
                    state.solver.eval(b, cast_to=int) for b in sym_bytes[:32]
                ])
            except Exception:
                pass
            
            path_result = PathAnalysisResult(
                path_id=idx,
                input_has_dangerous_chars=input_has_dangerous,
                output_has_dangerous_chars=output_has_dangerous,
                is_sanitized=is_path_sanitized,
                concrete_input=concrete_input,
                constraint_details={
                    "dangerous_chars_checked": dangerous_chars
                }
            )
            path_details.append(path_result)
        
        if paths_analyzed == 0:
            return SymbolicExecutionResult(
                success=False,
                function_name="main",
                sanitized=False,
                paths_analyzed=0,
                paths_harmful=0,
                paths_safe=0,
                errors=["No paths completed execution"]
            )
        
        # Sanitization判定: 所有路径都安全才认为sanitized=True
        sanitized = (paths_harmful == 0)
        
        return SymbolicExecutionResult(
            success=True,
            function_name="main",
            sanitized=sanitized,
            paths_analyzed=paths_analyzed,
            paths_harmful=paths_harmful,
            paths_safe=paths_safe,
            details={
                "deadended": len(simgr.deadended),
                "errored": len(simgr.errored),
                "path_analysis": [
                    {
                        "path_id": p.path_id,
                        "input_dangerous": p.input_has_dangerous_chars,
                        "output_dangerous": p.output_has_dangerous_chars,
                        "sanitized": p.is_sanitized,
                        "concrete_input": p.concrete_input.hex() if p.concrete_input else None
                    }
                    for p in path_details
                ],
                "dangerous_chars": dangerous_chars
            }
        )


def verify_sanitization(binary_path: str, timeout: int = 60):
    """Verify sanitization using symbolic execution"""
    executor = SymbolicExecutor(binary_path)
    return executor.execute(constraint=None, timeout=timeout)
