"""The account state machine.

State is a mapping of account name to non-negative balance, persisted as one JSON file inside
the state directory. The state root is computed over accounts sorted by name, so it depends on
the contents and not on the order in which accounts were written.
"""

from __future__ import annotations

import bisect
import json
import re
from pathlib import Path

from .merkle import leaf_hash, merkle_proof, merkle_root, node_hash

__all__ = ["State"]

STATE_FILE = "state.json"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _leaf(account: str, balance: int) -> bytes:
    return leaf_hash(f"{account}:{balance}".encode("utf-8"))


def _is_int(value: object) -> bool:
    """A JSON integer: ``int`` but never ``bool`` (``true``/``false`` are not numbers)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex64(value: object) -> bool:
    """Exactly 64 lowercase hexadecimal characters, as produced by ``bytes.hex()``."""
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _proof_path(index: int, size: int, path: object) -> list[dict] | None:
    """Validate a sibling path isomorphic to one :func:`merkle_proof` emits.

    The duplicated-last-node tree over ``size`` leaves has exactly
    ``(size - 1).bit_length()`` levels (for a positive size). Each level must be an object
    carrying only ``side`` and ``hash``: a lowercase 64-char hex hash on the exact side the
    generator picks for ``index`` at that level. Returns the steps in proof order, or None
    when the shape is wrong.
    """
    if not isinstance(path, list):
        return None
    depth = (size - 1).bit_length()
    if len(path) != depth:
        return None
    steps: list[dict] = []
    position = index
    for step in path:
        if not isinstance(step, dict) or set(step) != {"side", "hash"}:
            return None
        side = step["side"]
        expected_side = "right" if position % 2 == 0 else "left"
        if side != expected_side or not _is_hex64(step["hash"]):
            return None
        steps.append(step)
        position //= 2
    return steps


def _recompute_root(leaf: bytes, index: int, path: list[dict], root: str) -> bool:
    """Recompute the root from the leaf and a validated sibling path."""
    current = leaf
    for step in path:
        sibling = bytes.fromhex(step["hash"])
        current = node_hash(current, sibling) if step["side"] == "right" else node_hash(sibling, current)
    return current.hex() == root


def _check_boundary(boundary: dict, index: int, relation: str, account: str, root: str, size: int) -> bool:
    """Validate one absence-proof boundary: a genuine inclusion proof strictly bracketing account."""
    name = boundary["account"]
    balance = boundary["balance"]
    if not isinstance(name, str) or not name or not _is_int(balance) or balance < 0:
        return False
    if relation == "prev":
        if not name < account:
            return False
    elif not name > account:
        return False
    path = _proof_path(index, size, boundary["path"])
    if path is None:
        return False
    return _recompute_root(_leaf(name, balance), index, path, root)


class State:
    """A single-process account state machine rooted at ``root``."""

    def __init__(self, root: str | Path) -> None:
        self.directory = Path(root)
        self.path = self.directory / STATE_FILE

    # -- persistence ------------------------------------------------------------------

    def init(self) -> None:
        """Create an empty state, replacing any existing one."""
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write({"version": 0, "accounts": {}})

    def _read(self) -> dict:
        if not self.path.is_file():
            raise FileNotFoundError(f"no state at {self.path}; run init first")
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, document: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(document, sort_keys=True, indent=2), encoding="utf-8")

    # -- public interface -------------------------------------------------------------

    def set(self, account: str, balance: int) -> int:
        """Write ``balance`` for ``account`` and return the new version number."""
        if not isinstance(account, str) or not account:
            raise ValueError("account must be a non-empty string")
        if not isinstance(balance, int) or isinstance(balance, bool) or balance < 0:
            raise ValueError("balance must be a non-negative integer")
        document = self._read()
        document["accounts"][account] = balance
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def get(self, account: str) -> int:
        """Balance of ``account``, or 0 when the account is unknown or was deleted."""
        return int(self._read()["accounts"].get(account, 0))

    def delete(self, account: str) -> int:
        """Remove an existing ``account`` and return the new version number.

        Deleting an unknown account raises ``KeyError``; writing a zero balance is not a
        deletion, so a zero-balance account must be removed explicitly.
        """
        if not isinstance(account, str) or not account:
            raise ValueError("account must be a non-empty string")
        document = self._read()
        if account not in document["accounts"]:
            raise KeyError(f"unknown account {account!r}")
        del document["accounts"][account]
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def apply(self, transaction: dict) -> int:
        """Apply one transaction of batched ``set`` writes and ``delete`` removals.

        ``transaction`` is a JSON object with exactly two optional fields: ``set`` maps
        non-empty account names to non-negative integer balances (booleans are not
        integers), ``delete`` is an array of unique non-empty account names, none of
        which may also appear in ``set``. Every check runs before anything is written,
        so a rejected transaction leaves no visible change: malformed structure raises
        ``ValueError``; deleting an unknown account raises ``KeyError``. A non-empty
        batch commits atomically and adds exactly one version; an empty batch (both
        fields omitted or empty) returns the current version without writing.
        """
        if not isinstance(transaction, dict):
            raise ValueError("transaction must be a JSON object")
        extra = set(transaction) - {"set", "delete"}
        if extra:
            raise ValueError(f"unexpected transaction fields: {', '.join(sorted(extra))}")
        writes = transaction.get("set", {})
        removals = transaction.get("delete", [])
        if not isinstance(writes, dict):
            raise ValueError("transaction 'set' must be a JSON object")
        if not isinstance(removals, list):
            raise ValueError("transaction 'delete' must be a JSON array")

        for account, balance in writes.items():
            if not isinstance(account, str) or not account:
                raise ValueError("account must be a non-empty string")
            if not isinstance(balance, int) or isinstance(balance, bool) or balance < 0:
                raise ValueError("balance must be a non-negative integer")

        seen: set[str] = set()
        for account in removals:
            if not isinstance(account, str) or not account:
                raise ValueError("account must be a non-empty string")
            if account in seen:
                raise ValueError(f"duplicate delete for account {account!r}")
            if account in writes:
                raise ValueError(f"account {account!r} appears in both set and delete")
            seen.add(account)

        document = self._read()
        accounts = document["accounts"]
        if not writes and not removals:
            return int(document["version"])
        for account in removals:
            if account not in accounts:
                raise KeyError(f"unknown account {account!r}")
        for account, balance in writes.items():
            accounts[account] = balance
        for account in removals:
            del accounts[account]
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def version(self) -> int:
        """Current version number; 0 for an untouched state."""
        return int(self._read()["version"])

    def state_root(self) -> str:
        """Hex state root over every account, sorted by name."""
        accounts = self._read()["accounts"]
        leaves = [_leaf(name, int(accounts[name])) for name in sorted(accounts)]
        return merkle_root(leaves).hex()

    def prove(self, account: str) -> dict:
        """Inclusion proof for ``account``."""
        document = self._read()
        accounts = document["accounts"]
        if account not in accounts:
            raise KeyError(f"unknown account {account!r}")
        names = sorted(accounts)
        balance = int(accounts[account])
        return {"account": account, "balance": balance, "index": names.index(account), "size": len(names),
                "root": self.state_root(), "path": merkle_proof([_leaf(n, int(accounts[n])) for n in names], names.index(account))}

    def verify(self, account: str, balance: int, proof: object) -> bool:
        """Verify ``account``/``balance`` against ``proof`` alone, without reading the state.

        Only a proof isomorphic to one :meth:`prove` emits is accepted: a JSON object with
        exactly ``account``, ``balance``, ``index``, ``size``, ``root`` and ``path``, all
        numeric fields non-boolean integers (balance non-negative, size positive, index in
        range), hashes as 64 lowercase hex characters, and a sibling path whose depth and
        sides match the tree shape ``size`` implies. Any mismatch, type confusion, encoding
        oddity, out-of-range index or non-closing path returns False.
        """
        try:
            if not isinstance(proof, dict) or set(proof) != {
                "account", "balance", "index", "size", "root", "path"
            }:
                return False
            if not isinstance(account, str) or not account or proof["account"] != account:
                return False
            proven_balance = proof["balance"]
            if (not _is_int(balance) or balance < 0 or not _is_int(proven_balance)
                    or proven_balance < 0 or proven_balance != balance):
                return False
            index, size = proof["index"], proof["size"]
            if not _is_int(index) or not _is_int(size) or size <= 0 or not 0 <= index < size:
                return False
            root = proof["root"]
            if not _is_hex64(root):
                return False
            path = _proof_path(index, size, proof["path"])
            if path is None:
                return False
            return _recompute_root(_leaf(account, balance), index, path, root)
        except (KeyError, TypeError, ValueError):
            return False

    def prove_prefix(self, count: int) -> dict:
        """Inclusion proof for the first ``count`` accounts in ascending name order.

        The proof carries the state root, the full tree size, and one inclusion item per
        account: exactly ``account``, ``balance``, ``index`` and ``path``, with indices
        running continuously from 0. ``count`` must be a non-negative JSON integer no
        larger than the number of accounts. A non-empty state cannot prove a zero-length
        prefix because nothing anchors the root; only an empty state may prove count 0,
        against the empty-tree root with no items.
        """
        if not _is_int(count) or count < 0:
            raise ValueError("count must be a non-negative integer")
        document = self._read()
        accounts = document["accounts"]
        names = sorted(accounts)
        root = self.state_root()
        if count == 0:
            if names:
                raise ValueError("cannot prove an empty prefix over a non-empty state")
            return {"count": 0, "root": root, "size": 0, "items": []}
        if count > len(names):
            raise ValueError(f"only {len(names)} accounts, cannot prove a prefix of {count}")
        leaves = [_leaf(n, int(accounts[n])) for n in names]
        items = [{"account": names[i], "balance": int(accounts[names[i]]), "index": i,
                  "path": merkle_proof(leaves, i)} for i in range(count)]
        return {"count": count, "root": root, "size": len(names), "items": items}

    def verify_prefix(self, count: int, proof: object) -> bool:
        """Verify an ascending name-prefix proof using the proof alone; no state is read.

        Only a proof isomorphic to one :meth:`prove_prefix` emits is accepted: a JSON
        object with exactly ``count``, ``root``, ``size`` and ``items``. The argument
        ``count`` must be a non-negative JSON integer matching ``proof["count"]``,
        ``size`` must be at least ``count``, and items must be strictly ascending by
        non-empty name with continuous indices 0..count-1, non-negative integer
        balances, and sibling paths that each recompute the one root over a tree of
        ``size`` leaves. A zero count is anchored solely by the empty-tree root (size 0
        and no items). Any mismatch, type confusion or broken path returns False.
        """
        try:
            if not _is_int(count) or count < 0:
                return False
            if not isinstance(proof, dict) or set(proof) != {"count", "root", "size", "items"}:
                return False
            proven_count = proof["count"]
            if not _is_int(proven_count) or proven_count != count:
                return False
            size = proof["size"]
            if not _is_int(size) or size < count:
                return False
            root = proof["root"]
            if not _is_hex64(root):
                return False
            items = proof["items"]
            if not isinstance(items, list) or len(items) != count:
                return False
            if count == 0:
                return size == 0 and root == merkle_root([]).hex()
            previous: str | None = None
            for position, item in enumerate(items):
                if not isinstance(item, dict) or set(item) != {"account", "balance", "index", "path"}:
                    return False
                name = item["account"]
                if not isinstance(name, str) or not name or (previous is not None and not previous < name):
                    return False
                balance = item["balance"]
                index = item["index"]
                if not _is_int(balance) or balance < 0:
                    return False
                if not _is_int(index) or index != position:
                    return False
                path = _proof_path(index, size, item["path"])
                if path is None or not _recompute_root(_leaf(name, balance), index, path, root):
                    return False
                previous = name
            return True
        except (KeyError, TypeError, ValueError):
            return False

    def prove_range(self, start: int, end: int) -> dict:
        """Inclusion proof for accounts at indices ``[start, end)`` in ascending name order.

        The proof carries the state root, the full tree size, and one inclusion item per
        account: exactly ``account``, ``balance``, ``index`` and ``path``, with indices
        running continuously from ``start`` to ``end - 1``. Both bounds must be non-negative
        JSON integers with ``start < end`` and ``end`` no larger than the number of
        accounts; anything else raises ``ValueError``.
        """
        if not _is_int(start) or not _is_int(end) or start < 0 or end < 0 or start >= end:
            raise ValueError("range requires non-negative integers with start < end")
        document = self._read()
        accounts = document["accounts"]
        names = sorted(accounts)
        if end > len(names):
            raise ValueError(f"only {len(names)} accounts, cannot prove a range ending at {end}")
        root = self.state_root()
        leaves = [_leaf(n, int(accounts[n])) for n in names]
        items = [{"account": names[i], "balance": int(accounts[names[i]]), "index": i,
                  "path": merkle_proof(leaves, i)} for i in range(start, end)]
        return {"start": start, "end": end, "root": root, "size": len(names), "items": items}

    def verify_range(self, start: int, end: int, proof: object) -> bool:
        """Verify an ascending index-range proof using the proof alone; no state is read.

        Only a proof isomorphic to one :meth:`prove_range` emits is accepted: a JSON
        object with exactly ``start``, ``end``, ``root``, ``size`` and ``items``. The
        arguments ``start``/``end`` must be non-negative JSON integers with
        ``start < end`` and match the proof's own bounds, ``size`` must be at least
        ``end``, and items must be strictly ascending by non-empty name with continuous
        indices ``start..end-1``, non-negative integer balances, and sibling paths that
        each recompute the one root over a tree of ``size`` leaves. Any mismatch, type
        confusion, encoding oddity or broken path returns False.
        """
        try:
            if (not _is_int(start) or not _is_int(end) or start < 0 or end < 0
                    or start >= end):
                return False
            if not isinstance(proof, dict) or set(proof) != {"start", "end", "root", "size", "items"}:
                return False
            proven_start, proven_end = proof["start"], proof["end"]
            if not _is_int(proven_start) or not _is_int(proven_end):
                return False
            if proven_start != start or proven_end != end:
                return False
            size = proof["size"]
            if not _is_int(size) or size < end:
                return False
            root = proof["root"]
            if not _is_hex64(root):
                return False
            items = proof["items"]
            if not isinstance(items, list) or len(items) != end - start:
                return False
            previous: str | None = None
            for position, item in enumerate(items):
                index = start + position
                if not isinstance(item, dict) or set(item) != {"account", "balance", "index", "path"}:
                    return False
                name = item["account"]
                if not isinstance(name, str) or not name or (previous is not None and not previous < name):
                    return False
                balance = item["balance"]
                if not _is_int(balance) or balance < 0:
                    return False
                if not _is_int(item["index"]) or item["index"] != index:
                    return False
                path = _proof_path(index, size, item["path"])
                if path is None or not _recompute_root(_leaf(name, balance), index, path, root):
                    return False
                previous = name
            return True
        except (KeyError, TypeError, ValueError):
            return False

    def prove_absence(self, account: str) -> dict:
        """Absence proof for an account that does not currently exist.

        The proof carries the state root, the tree size, and the predecessor/successor
        accounts bracketing ``account`` in name order, each with its own inclusion path.
        An empty state needs no boundaries. A present account (including one with a zero
        balance) raises ``KeyError``.
        """
        if not isinstance(account, str) or not account:
            raise ValueError("account must be a non-empty string")
        document = self._read()
        accounts = document["accounts"]
        if account in accounts:
            raise KeyError(f"account already exists {account!r}")
        names = sorted(accounts)
        position = bisect.bisect_left(names, account)
        root = self.state_root()

        def boundary(index: int) -> dict | None:
            if not 0 <= index < len(names):
                return None
            name = names[index]
            leaves = [_leaf(n, int(accounts[n])) for n in names]
            return {"account": name, "balance": int(accounts[name]), "index": index,
                    "path": merkle_proof(leaves, index)}

        previous = boundary(position - 1)
        following = boundary(position)
        return {"account": account, "root": root, "size": len(names),
                "prev": previous, "next": following}

    def verify_absence(self, account: str, proof: object) -> bool:
        """Verify an absence proof using the proof alone; no state directory is read.

        The proof is a JSON object with exactly ``account``, ``root``, ``size``, ``prev``
        and ``next``. Each boundary is either null or an object holding exactly
        ``account``, ``balance``, ``index`` and ``path``, validated by the same rules as an
        inclusion proof. With ``size`` 0 both boundaries must be null and the root must be
        the empty-tree root. With a positive size a missing boundary means the target lies
        beyond that end of the account order; any present boundary must hold a genuine
        account strictly bracketing the target, the indices must be adjacent (or pinned to
        the first/last slot), and both paths must recompute the one root. Every
        inconsistency, tampering, type confusion or encoding oddity returns False.
        """
        try:
            if not isinstance(proof, dict) or set(proof) != {"account", "root", "size", "prev", "next"}:
                return False
            if not isinstance(account, str) or not account or proof["account"] != account:
                return False
            size = proof["size"]
            if not _is_int(size) or size < 0:
                return False
            root = proof["root"]
            if not _is_hex64(root):
                return False
            previous, following = proof["prev"], proof["next"]

            if size == 0:
                return previous is None and following is None and root == merkle_root([]).hex()

            # A null boundary means the target is beyond that end; both ends null is impossible.
            if previous is None and following is None:
                return False
            prev_index = -1 if previous is None else previous["index"] if isinstance(previous, dict) else None
            next_index = size if following is None else following["index"] if isinstance(following, dict) else None
            if not _is_int(prev_index) or not _is_int(next_index) or next_index != prev_index + 1:
                return False

            if previous is not None:
                if set(previous) != {"account", "balance", "index", "path"} or previous["index"] != prev_index:
                    return False
                if not 0 <= prev_index < size:
                    return False
                if not _check_boundary(previous, prev_index, "prev", account, root, size):
                    return False
            if following is not None:
                if set(following) != {"account", "balance", "index", "path"} or following["index"] != next_index:
                    return False
                if not 0 <= next_index < size:
                    return False
                if not _check_boundary(following, next_index, "next", account, root, size):
                    return False
            return True
        except (KeyError, TypeError, ValueError):
            return False
