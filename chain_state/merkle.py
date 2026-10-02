"""Merkle helpers for an ordered list of leaves.

The tree duplicates the last node of an odd level, so every level has an even count and the
shape depends only on the number of leaves. Leaf and internal hashes are domain-separated.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

__all__ = ["leaf_hash", "node_hash", "merkle_root", "merkle_proof", "verify_proof",
           "merkle_multiproof", "merkle_verify_multiproof"]


def leaf_hash(data: bytes) -> bytes:
    """Hash one leaf, domain-separated from internal nodes."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash one internal node from its two children."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _levels(leaves: Sequence[bytes]) -> list[list[bytes]]:
    if not leaves:
        return [[leaf_hash(b"")]]
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        if len(current) % 2:
            current = current + [current[-1]]
        levels.append([node_hash(current[i], current[i + 1]) for i in range(0, len(current), 2)])
    return levels


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Root of the tree over ``leaves``; an empty list has the root of one empty leaf."""
    return _levels(leaves)[-1][0]


def merkle_proof(leaves: Sequence[bytes], index: int) -> list[dict[str, str]]:
    """Sibling path for ``index``, ordered from the leaf level upwards."""
    if not 0 <= index < len(leaves):
        raise ValueError("leaf index out of range")
    levels, path, position = _levels(leaves), [], index
    for level in levels[:-1]:
        padded = level + [level[-1]] if len(level) % 2 else level
        sibling = position + 1 if position % 2 == 0 else position - 1
        path.append({"side": "right" if position % 2 == 0 else "left", "hash": padded[sibling].hex()})
        position //= 2
    return path


def verify_proof(leaf: bytes, index: int, path: Iterable[dict[str, str]], root: str) -> bool:
    """Recompute the root from one leaf and its sibling path."""
    current = leaf
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        current = node_hash(current, sibling) if step["side"] == "right" else node_hash(sibling, current)
    return current.hex() == root


def merkle_multiproof(leaves: Sequence[bytes], indices: Iterable[int]) -> list[tuple[int, int, str]]:
    """Compact set of sibling nodes connecting the leaves at ``indices`` to the root.

    Returns ``(level, index, hash_hex)`` triples for every real sibling node needed to
    connect the chosen leaves to the root, sorted by level then index. A node is emitted
    only when it is neither a chosen leaf nor reconstructable from lower levels; the
    duplicated tail of an odd level is never emitted, since the verifier reproduces it
    from the last real node. Choosing every leaf yields an empty list.
    """
    levels = _levels(leaves)
    chosen = set(indices)
    if not all(0 <= position < len(leaves) for position in chosen):
        raise ValueError("leaf index out of range")
    nodes: list[tuple[int, int, str]] = []
    seen: set[tuple[int, int]] = set()
    for level_index, level in enumerate(levels[:-1]):
        width = len(level)
        for position in sorted(chosen):
            sibling = position ^ 1
            if sibling in chosen:
                continue
            if width % 2 and sibling == width:
                continue  # duplicated tail node, reproduced from the last real node
            key = (level_index, sibling)
            if key not in seen:
                seen.add(key)
                nodes.append((level_index, sibling, level[sibling].hex()))
        chosen = {position // 2 for position in chosen}
    nodes.sort()
    return nodes


def merkle_verify_multiproof(
    leaves: dict[int, bytes], nodes: dict[tuple[int, int], bytes], size: int
) -> bytes | None:
    """Recompute the root from chosen leaves and a compact sibling-node set.

    ``leaves`` maps a leaf position to its hash; ``nodes`` maps ``(level, index)`` to a
    real sibling hash. Returns the root bytes, or None when a node sits outside the
    tree shape implied by ``size``, a needed sibling is missing, or a supplied node is
    never consumed (duplicate or reconstructable from lower levels).
    """
    widths = [size]
    while widths[-1] > 1:
        widths.append((widths[-1] + 1) // 2)
    depth = len(widths) - 1
    for level, index in nodes:
        if not 0 <= level < depth or not 0 <= index < widths[level]:
            return None
    current = dict(leaves)
    used: set[tuple[int, int]] = set()
    for level in range(depth):
        width = widths[level]
        parents: dict[int, bytes] = {}
        for position, node in current.items():
            sibling = position ^ 1
            if sibling in current:
                sibling_hash = current[sibling]
            elif width % 2 and sibling == width:
                sibling_hash = current[width - 1]  # the duplicated tail is its own sibling
            else:
                key = (level, sibling)
                if key not in nodes:
                    return None
                sibling_hash = nodes[key]
                used.add(key)
            if position % 2 == 0:
                parents[position // 2] = node_hash(node, sibling_hash)
            else:
                parents[position // 2] = node_hash(sibling_hash, node)
        current = parents
    if used != set(nodes) or set(current) != {0}:
        return None
    return current[0]
