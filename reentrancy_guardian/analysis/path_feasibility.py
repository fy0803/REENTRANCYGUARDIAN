#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ast
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    from z3 import And, ArithRef, BoolRef, BoolVal, Int, IntVal, Not, Or, Solver, sat
except ImportError:  # pragma: no cover - exercised only when z3 is unavailable
    And = ArithRef = BoolRef = BoolVal = Int = IntVal = Not = Or = Solver = sat = None


@dataclass
class PathConstraintResult:
    feasible: bool = True
    reduced_precision: bool = False
    tracked_vars: Set[str] = field(default_factory=set)
    tainted_constraint_vars: Set[str] = field(default_factory=set)
    condition_vars_by_node: Dict[int, Set[str]] = field(default_factory=dict)
    skipped_constraints_by_node: Dict[int, str] = field(default_factory=dict)


class PathFeasibilityChecker:
    """Use Z3 to check whether a node path is satisfiable under lightweight constraints."""

    def __init__(self, icfg_builder: Any, timeout_ms: int = 1500):
        self.icfg = icfg_builder
        self.timeout_ms = timeout_ms
        self.available = Solver is not None
        self._scientific_literal = re.compile(r"\b(\d+)e(\d+)\b", re.IGNORECASE)

    def is_path_feasible(self, node_path: Sequence[int]) -> bool:
        return self.analyze_path(node_path).feasible

    def analyze_path(
        self,
        node_path: Sequence[int],
        tracked_vars: Optional[Set[str]] = None,
    ) -> PathConstraintResult:
        if not node_path or not self.available:
            return PathConstraintResult(feasible=True, tracked_vars=set(tracked_vars or set()))

        solver = Solver()
        solver.set(timeout=self.timeout_ms)
        env: Dict[str, Any] = {}
        symbolic_counter = 0
        result = PathConstraintResult(feasible=True, tracked_vars=set(tracked_vars or set()))

        for node_id in node_path:
            node = self.icfg.nodes.get(node_id)
            if not node:
                continue

            expression = (node.expression or "").strip()
            if not expression:
                continue

            condition = self._extract_guard_condition(expression)
            if condition is not None:
                condition_symbols = set(self._extract_expression_symbols(condition))
                if condition_symbols:
                    result.condition_vars_by_node[node_id] = condition_symbols
                    result.tainted_constraint_vars.update(condition_symbols & result.tracked_vars)

            try:
                constraints, env, symbolic_counter = self._constraints_from_expression(
                    expression,
                    env,
                    symbolic_counter,
                )
            except (SyntaxError, ValueError) as exc:
                result.reduced_precision = True
                result.skipped_constraints_by_node[node_id] = str(exc)
                continue
            for constraint in constraints:
                solver.add(constraint)

        result.feasible = solver.check() == sat
        return result

    def _constraints_from_expression(
        self,
        expression: str,
        env: Dict[str, Any],
        symbolic_counter: int,
    ) -> Tuple[List[Any], Dict[str, Any], int]:
        constraints: List[Any] = []

        condition = self._extract_guard_condition(expression)
        if condition is not None:
            parsed = self._parse_expression(condition, env, constraints)
            constraints.append(self._as_bool(parsed))
            return constraints, env, symbolic_counter

        assignment = self._parse_assignment(expression)
        if assignment is None:
            return constraints, env, symbolic_counter

        lhs_vars, operator, rhs = assignment
        if not lhs_vars:
            return constraints, env, symbolic_counter

        if operator in {"=", ":="} and self._looks_like_symbolic_call(rhs):
            for var_name in lhs_vars:
                symbolic_counter += 1
                symbol = Int(f"{var_name}_{symbolic_counter}")
                env[var_name] = symbol
                constraints.extend(self._bool_like_constraints(var_name, symbol))
            return constraints, env, symbolic_counter

        if operator in {"=", ":="}:
            try:
                rhs_expr = self._parse_expression(rhs, env, constraints)
            except Exception:
                rhs_expr = None
            if rhs_expr is None:
                for var_name in lhs_vars:
                    symbolic_counter += 1
                    symbol = Int(f"{var_name}_{symbolic_counter}")
                    env[var_name] = symbol
                    constraints.extend(self._bool_like_constraints(var_name, symbol))
                return constraints, env, symbolic_counter

            env[lhs_vars[0]] = rhs_expr
            return constraints, env, symbolic_counter

        base_var = lhs_vars[0]
        if base_var not in env:
            current = self._fresh_symbol(base_var, env, constraints)
        else:
            current = env[base_var]
        rhs_expr = self._parse_expression(rhs, env, constraints)
        if operator == "+=":
            env[base_var] = current + rhs_expr
        elif operator == "-=":
            env[base_var] = current - rhs_expr
        elif operator == "*=":
            env[base_var] = current * rhs_expr
        elif operator == "/=":
            constraints.append(rhs_expr != 0)
            env[base_var] = current / rhs_expr
        return constraints, env, symbolic_counter

    def _parse_assignment(self, expression: str) -> Optional[Tuple[List[str], str, str]]:
        for operator in ("+=", "-=", "*=", "/=", ":=", "="):
            if operator not in expression:
                continue
            lhs, rhs = expression.split(operator, 1)
            lhs_vars = self._extract_lhs_variables(lhs)
            return lhs_vars, operator, rhs.strip()
        return None

    def _extract_guard_condition(self, expression: str) -> Optional[str]:
        stripped = expression.strip()
        for keyword in ("require", "assert"):
            if not stripped.startswith(keyword):
                continue
            if ")(" in stripped:
                call_site = stripped.index(")(") + 2
                args = stripped[call_site:-1]
            else:
                call_site = stripped.index("(") + 1
                args = stripped[call_site:-1]
            parts = self._split_args(args)
            return parts[0].strip() if parts else None
        if stripped.startswith("if "):
            return stripped[3:].strip()
        if stripped.startswith("if(") and stripped.endswith(")"):
            return stripped[3:-1].strip()
        return None

    def _extract_lhs_variables(self, lhs: str) -> List[str]:
        tokens = self._extract_expression_symbols(lhs)
        ignored = {
            "abi",
            "address",
            "bool",
            "bytes",
            "int",
            "none",
            "string",
            "uint",
            "uint256",
        }
        return [token for token in tokens if token.lower() not in ignored]

    def _extract_expression_symbols(self, expression: str) -> List[str]:
        cleaned = self._sanitize_expression(expression)
        return re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", cleaned)

    def _parse_expression(self, expression: str, env: Dict[str, Any], constraints: List[Any]) -> Any:
        sanitized = self._sanitize_expression(expression)
        parsed = ast.parse(sanitized, mode="eval")
        return self._eval_ast(parsed.body, env, constraints)

    def _eval_ast(self, node: ast.AST, env: Dict[str, Any], constraints: List[Any]) -> Any:
        if isinstance(node, ast.Name):
            if node.id not in env:
                return self._fresh_symbol(node.id, env, constraints)
            return env[node.id]
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return BoolVal(node.value)
            if isinstance(node.value, int):
                return IntVal(node.value)
            raise ValueError(f"Unsupported constant: {node.value!r}")
        if isinstance(node, ast.UnaryOp):
            operand = self._eval_ast(node.operand, env, constraints)
            if isinstance(node.op, ast.USub):
                return -operand
            if isinstance(node.op, ast.UAdd):
                return operand
            if isinstance(node.op, ast.Not):
                return Not(self._as_bool(operand))
            raise ValueError(f"Unsupported unary operator: {node.op!r}")
        if isinstance(node, ast.BinOp):
            left = self._eval_ast(node.left, env, constraints)
            right = self._eval_ast(node.right, env, constraints)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, (ast.Div, ast.FloorDiv)):
                constraints.append(right != 0)
                return left / right
            if isinstance(node.op, ast.Mod):
                constraints.append(right != 0)
                return left % right
            raise ValueError(f"Unsupported binary operator: {node.op!r}")
        if isinstance(node, ast.BoolOp):
            values = [self._as_bool(self._eval_ast(value, env, constraints)) for value in node.values]
            if isinstance(node.op, ast.And):
                return And(*values)
            if isinstance(node.op, ast.Or):
                return Or(*values)
            raise ValueError(f"Unsupported boolean operator: {node.op!r}")
        if isinstance(node, ast.Compare):
            left = self._eval_ast(node.left, env, constraints)
            comparisons: List[Any] = []
            current_left = left
            for operator, comparator in zip(node.ops, node.comparators):
                right = self._eval_ast(comparator, env, constraints)
                comparisons.append(self._compare(current_left, operator, right))
                current_left = right
            return And(*comparisons)
        raise ValueError(f"Unsupported AST node: {node!r}")

    def _compare(self, left: Any, operator: ast.cmpop, right: Any) -> Any:
        if isinstance(operator, ast.Eq):
            return left == right
        if isinstance(operator, ast.NotEq):
            return left != right
        if isinstance(operator, ast.Gt):
            return left > right
        if isinstance(operator, ast.GtE):
            return left >= right
        if isinstance(operator, ast.Lt):
            return left < right
        if isinstance(operator, ast.LtE):
            return left <= right
        raise ValueError(f"Unsupported comparator: {operator!r}")

    def _sanitize_expression(self, expression: str) -> str:
        sanitized = expression.strip()
        sanitized = self._scientific_literal.sub(
            lambda match: str(int(match.group(1)) * (10 ** int(match.group(2)))),
            sanitized,
        )
        sanitized = re.sub(r"([A-Za-z_][A-Za-z0-9_]*)\[(.*?)\]", self._replace_index_access, sanitized)
        sanitized = sanitized.replace("msg.sender", "msg_sender")
        sanitized = sanitized.replace("msg.value", "msg_value")
        sanitized = sanitized.replace("tx.origin", "tx_origin")
        sanitized = sanitized.replace("block.timestamp", "block_timestamp")
        sanitized = sanitized.replace("block.number", "block_number")
        sanitized = sanitized.replace(".", "_")
        sanitized = sanitized.replace("&&", " and ")
        sanitized = sanitized.replace("||", " or ")
        sanitized = sanitized.replace(" true", " True")
        sanitized = sanitized.replace(" false", " False")
        sanitized = re.sub(r"\btrue\b", "True", sanitized)
        sanitized = re.sub(r"\bfalse\b", "False", sanitized)
        return sanitized

    def _replace_index_access(self, match: re.Match[str]) -> str:
        base = match.group(1)
        index = re.sub(r"[^A-Za-z0-9_]+", "_", match.group(2)).strip("_") or "index"
        return f"{base}_{index}"

    def _split_args(self, arg_text: str) -> List[str]:
        args: List[str] = []
        current: List[str] = []
        depth = 0
        for char in arg_text:
            if char == "," and depth == 0:
                args.append("".join(current).strip())
                current = []
                continue
            if char in "([":
                depth += 1
            elif char in ")]":
                depth = max(0, depth - 1)
            current.append(char)
        if current:
            args.append("".join(current).strip())
        return args

    def _looks_like_symbolic_call(self, expression: str) -> bool:
        lowered = expression.lower()
        if "call" in lowered or "delegatecall" in lowered or "staticcall" in lowered:
            return True
        return bool(re.search(r"[A-Za-z_][A-Za-z0-9_\.]*\s*\(", expression))

    def _fresh_symbol(self, name: str, env: Dict[str, Any], constraints: List[Any]) -> Any:
        symbol = Int(name)
        env[name] = symbol
        constraints.extend(self._bool_like_constraints(name, symbol))
        return symbol

    def _bool_like_constraints(self, name: str, symbol: Any) -> List[Any]:
        lowered = name.lower()
        if lowered in {"ok", "success"} or lowered.startswith("is_") or lowered.startswith("has_"):
            return [Or(symbol == 0, symbol == 1)]
        return []

    def _as_bool(self, value: Any) -> Any:
        if BoolRef is not None and isinstance(value, BoolRef):
            return value
        if ArithRef is not None and isinstance(value, ArithRef):
            return value != 0
        return value
