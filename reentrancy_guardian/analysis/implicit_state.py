#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Iterable, Set


CONTRACT_BALANCE_STATE = "contract_balance"

_VALUE_TRANSFER_MARKERS = (
    ".call.value(",
    "call{value:",
    ".transfer(",
    ".send(",
)


def node_reads_implicit_states(node: Any) -> Set[str]:
    expression = str(getattr(node, "expression", "") or "")
    lowered = expression.replace(" ", "").lower()
    states: Set[str] = set()
    if "address(this).balance" in lowered or "selfbalance()" in lowered:
        states.add(CONTRACT_BALANCE_STATE)
    return states


def node_has_value_transfer(node: Any) -> bool:
    expression = str(getattr(node, "expression", "") or "")
    lowered = expression.replace(" ", "").lower()
    return any(marker in lowered for marker in _VALUE_TRANSFER_MARKERS)


def function_access_with_implicit_state(icfg: Any, func_key: str) -> Set[str]:
    reads, writes = icfg.get_function_state_access(func_key)
    access = set(reads) | set(writes)
    for node_id in icfg.get_function_nodes(func_key):
        node = icfg.nodes.get(node_id)
        if node:
            access.update(node_reads_implicit_states(node))
    return access


def has_post_call_balance_dependency(
    icfg: Any,
    post_states: Iterable[tuple[int, tuple[int, ...]]],
) -> bool:
    balance_nodes: Set[int] = set()
    value_transfer_nodes: Set[int] = set()

    for node_id, _ in post_states:
        node = icfg.nodes.get(node_id)
        if not node:
            continue
        if CONTRACT_BALANCE_STATE in node_reads_implicit_states(node):
            balance_nodes.add(node_id)
        if node_has_value_transfer(node):
            value_transfer_nodes.add(node_id)

    if not balance_nodes:
        return False
    if not value_transfer_nodes:
        return True

    return any(
        balance_node == transfer_node
        or icfg.execution_path_exists(balance_node, transfer_node)
        for balance_node in balance_nodes
        for transfer_node in value_transfer_nodes
    )
