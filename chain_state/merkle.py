"""Merkle helpers for an ordered list of leaves.

The tree duplicates the last node of an odd level, so every level has an even count and the
shape depends only on the number of leaves. Leaf and internal hashes are domain-separated.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

__all__ = ["leaf_hash", "node_hash", "merkle_root", "merkle_proof", "verify_proof"]


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
