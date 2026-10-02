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

from .merkle import (leaf_hash, merkle_multiproof, merkle_proof, merkle_root,
                     merkle_verify_multiproof, node_hash)

__all__ = ["State"]

STATE_FILE = "state.json"
SNAPSHOTS_KEY = "snapshots"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _leaf(account: str, balance: int) -> bytes:
    return leaf_hash(f"{account}:{balance}".encode("utf-8"))


def _root_for(accounts: dict) -> str:
    """Hex state root over ``accounts`` sorted by name; the root depends only on contents."""
    leaves = [_leaf(name, int(accounts[name])) for name in sorted(accounts)]
    return merkle_root(leaves).hex()


def _validate_snapshot(snapshot: object) -> dict:
    """Validate one persisted snapshot and return an independent, normalized copy.

    A snapshot carries exactly ``accounts`` (non-empty account names to non-negative
    JSON integers), ``version`` (a non-negative JSON integer) and ``root`` (64 lowercase
    hex characters that recomputes from ``accounts``). Missing fields, type confusion
    or a mismatched root raise ``ValueError``.
    """
    if not isinstance(snapshot, dict) or set(snapshot) != {"accounts", "version", "root"}:
        raise ValueError("corrupt snapshot: expected exactly accounts, version and root")
    raw_accounts = snapshot["accounts"]
    if not isinstance(raw_accounts, dict):
        raise ValueError("corrupt snapshot: accounts must be a JSON object")
    accounts: dict[str, int] = {}
    for name, balance in raw_accounts.items():
        if not isinstance(name, str) or not name or not _is_int(balance) or balance < 0:
            raise ValueError("corrupt snapshot: accounts must map non-empty names to non-negative integers")
        accounts[name] = balance
    version = snapshot["version"]
    if not _is_int(version) or version < 0:
        raise ValueError("corrupt snapshot: version must be a non-negative integer")
    root = snapshot["root"]
    if not _is_hex64(root):
        raise ValueError("corrupt snapshot: root must be 64 lowercase hexadecimal characters")
    if _root_for(accounts) != root:
        raise ValueError("corrupt snapshot: root does not match accounts")
    return {"accounts": accounts, "version": version, "root": root}


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


def _validate_account_set(accounts: object) -> list[str]:
    """Validate a query set: a non-empty JSON array of unique non-empty strings.

    Returns the names in their given order; malformed structure, wrong element types,
    empty names or duplicates raise ``ValueError``.
    """
    if not isinstance(accounts, list) or not accounts:
        raise ValueError("accounts must be a non-empty array")
    normalized: list[str] = []
    seen: set[str] = set()
    for account in accounts:
        if not isinstance(account, str) or not account:
            raise ValueError("accounts must be non-empty strings")
        if account in seen:
            raise ValueError(f"duplicate account {account!r}")
        seen.add(account)
        normalized.append(account)
    return normalized


def _validate_updates(updates: object) -> dict[str, int]:
    """Validate a balance-update object: a non-empty object of non-empty names to non-negative ints.

    Booleans are not integers. Returns an independent normalized dict; malformed
    structure or types raise ``ValueError``.
    """
    if not isinstance(updates, dict) or not updates:
        raise ValueError("updates must be a non-empty object")
    normalized: dict[str, int] = {}
    for account, balance in updates.items():
        if not isinstance(account, str) or not account:
            raise ValueError("account must be a non-empty string")
        if not _is_int(balance) or balance < 0:
            raise ValueError("balance must be a non-negative integer")
        normalized[account] = balance
    return normalized


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

    @staticmethod
    def _snapshots(document: dict) -> dict:
        """The snapshot collection, treating a state file without one as empty.

        A missing key is added to ``document`` so callers can persist new snapshots;
        a present-but-wrong-typed value is treated as corruption.
        """
        if SNAPSHOTS_KEY not in document:
            document[SNAPSHOTS_KEY] = {}
        snapshots = document[SNAPSHOTS_KEY]
        if not isinstance(snapshots, dict):
            raise ValueError("corrupt snapshots: expected a JSON object")
        return snapshots

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

    def transfer(self, source: str, target: str, amount: int) -> int:
        """Atomically move ``amount`` from ``source`` to ``target`` and return the new version.

        ``source`` and ``target`` must be distinct non-empty strings and ``amount`` a
        positive JSON integer (booleans are not integers). ``source`` must already hold
        at least ``amount``; an unknown source raises ``KeyError`` and insufficient funds
        raise ``ValueError``. ``target`` is created with ``amount`` when absent or has it
        added to its balance; a source drained to zero keeps its account record. Every
        check runs before anything is written, so a rejected transfer leaves the
        accounts, version and state root untouched. A successful transfer adds exactly
        one version.
        """
        if not isinstance(source, str) or not source:
            raise ValueError("source must be a non-empty string")
        if not isinstance(target, str) or not target:
            raise ValueError("target must be a non-empty string")
        if source == target:
            raise ValueError("source and target must be different accounts")
        if not _is_int(amount) or amount <= 0:
            raise ValueError("amount must be a positive integer")
        document = self._read()
        accounts = document["accounts"]
        if source not in accounts:
            raise KeyError(f"unknown account {source!r}")
        source_balance = int(accounts[source])
        if source_balance < amount:
            raise ValueError(
                f"insufficient funds: {source!r} has {source_balance}, needs {amount}"
            )
        accounts[source] = source_balance - amount
        accounts[target] = int(accounts.get(target, 0)) + amount
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def version(self) -> int:
        """Current version number; 0 for an untouched state."""
        return int(self._read()["version"])

    def state_root(self) -> str:
        """Hex state root over every account, sorted by name."""
        return _root_for(self._read()["accounts"])

    def create_snapshot(self, label: str) -> int:
        """Save the current accounts under ``label`` and return the pre-call version.

        The snapshot holds an independent copy of the accounts together with the
        version and state root in effect before the call; it never alters the current
        accounts, version or root. ``label`` must be a non-empty string and a second
        snapshot with the same name raises ``ValueError``.
        """
        if not isinstance(label, str) or not label:
            raise ValueError("label must be a non-empty string")
        document = self._read()
        accounts = document["accounts"]
        snapshots = self._snapshots(document)
        if label in snapshots:
            raise ValueError(f"snapshot {label!r} already exists")
        version = int(document["version"])
        snapshots[label] = {"accounts": {name: int(balance) for name, balance in accounts.items()},
                            "version": version, "root": _root_for(accounts)}
        self._write(document)
        return version

    def restore_snapshot(self, label: str) -> int:
        """Replace the current accounts with the snapshot named ``label`` and return the new version.

        The restored root strictly equals the snapshot root and the version advances
        exactly once even when the accounts are unchanged; the snapshot itself is
        never modified and may be restored repeatedly. An unknown label raises
        ``KeyError``; a non-string or empty label raises ``ValueError``, as does a
        snapshot missing fields, carrying wrong types or whose root does not
        recompute from its accounts. Every check runs before the write, so a failed
        restore changes neither the accounts, version, root nor the snapshots.
        """
        if not isinstance(label, str) or not label:
            raise ValueError("label must be a non-empty string")
        document = self._read()
        snapshots = self._snapshots(document)
        if label not in snapshots:
            raise KeyError(f"unknown snapshot {label!r}")
        saved = _validate_snapshot(snapshots[label])
        document["accounts"] = {name: balance for name, balance in saved["accounts"].items()}
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def list_snapshots(self) -> dict:
        """Independent copies of every snapshot, keyed by label and sorted by name.

        Each value holds exactly ``accounts`` (name to non-negative integer balance),
        ``version`` (the version when the snapshot was taken) and ``root`` (64
        lowercase hex characters); the returned mapping is read from but never
        aliases persisted state.
        """
        snapshots = self._snapshots(self._read())
        return {label: _validate_snapshot(snapshots[label]) for label in sorted(snapshots)}

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

    def prove_name_range(self, start: str, end: str) -> dict:
        """Inclusion proof for every account whose name lies in ``[start, end)``.

        Unlike :meth:`prove_range`, the interval may be empty: the accounts inside are
        anchored by the immediate predecessor of ``start`` and the first account at or
        past ``end`` (each null beyond its end of the order), and ``items`` fills the
        whole index gap between them with continuous full-list indices. An empty state
        yields no boundaries and no items. Both bounds must be non-empty strings with
        ``start < end``; anything else raises ``ValueError``.
        """
        if (not isinstance(start, str) or not start or not isinstance(end, str)
                or not end or start >= end):
            raise ValueError("name range requires non-empty strings with start < end")
        document = self._read()
        accounts = document["accounts"]
        names = sorted(accounts)
        first = bisect.bisect_left(names, start)
        after = bisect.bisect_left(names, end)
        root = self.state_root()
        leaves = [_leaf(n, int(accounts[n])) for n in names]

        def boundary(index: int) -> dict | None:
            if not 0 <= index < len(names):
                return None
            name = names[index]
            return {"account": name, "balance": int(accounts[name]), "index": index,
                    "path": merkle_proof(leaves, index)}

        items = [{"account": names[i], "balance": int(accounts[names[i]]), "index": i,
                  "path": merkle_proof(leaves, i)} for i in range(first, after)]
        return {"start": start, "end": end, "root": root, "size": len(names),
                "prev": boundary(first - 1), "next": boundary(after), "items": items}

    def verify_name_range(self, start: str, end: str, proof: object) -> bool:
        """Verify a name half-range proof using the proof alone; no state is read.

        The proof is a JSON object with exactly ``start``, ``end``, ``root``, ``size``,
        ``prev``, ``next`` and ``items``. The arguments must be non-empty strings with
        ``start < end`` matching the proof's own bounds. ``items`` lists strictly
        ascending accounts with ``start <= name < end`` and continuous full-list
        indices, each with a non-negative integer balance and a path recomputing the
        one root. ``prev`` (null before the first slot) must name an account strictly
        below ``start``, ``next`` (null past the last slot) an account at or above
        ``end``, and items must fill the whole index gap between them; an empty
        interval is thus anchored by adjacent boundaries or a null end. With size 0
        both boundaries must be null, items empty and the root the empty-tree root.
        Any mismatch, type confusion, encoding oddity, gap or broken path returns
        False.
        """
        try:
            if (not isinstance(start, str) or not start or not isinstance(end, str)
                    or not end or start >= end):
                return False
            if not isinstance(proof, dict) or set(proof) != {
                "start", "end", "root", "size", "prev", "next", "items"
            }:
                return False
            if proof["start"] != start or proof["end"] != end:
                return False
            size = proof["size"]
            if not _is_int(size) or size < 0:
                return False
            root = proof["root"]
            if not _is_hex64(root):
                return False
            previous, following, items = proof["prev"], proof["next"], proof["items"]
            if not isinstance(items, list):
                return False

            if size == 0:
                return (previous is None and following is None and not items
                        and root == merkle_root([]).hex())

            def check_boundary(boundary: object, relation: str, bound: str) -> int | None:
                """Return the boundary's index when it is a genuine inclusion proof on the right side."""
                if not isinstance(boundary, dict) or set(boundary) != {
                    "account", "balance", "index", "path"
                }:
                    return None
                name = boundary["account"]
                balance = boundary["balance"]
                index = boundary["index"]
                if not isinstance(name, str) or not name:
                    return None
                if relation == "prev":
                    if not name < bound:
                        return None
                elif not name >= bound:
                    return None
                if not _is_int(balance) or balance < 0 or not _is_int(index):
                    return None
                if not 0 <= index < size:
                    return None
                path = _proof_path(index, size, boundary["path"])
                if path is None or not _recompute_root(_leaf(name, balance), index, path, root):
                    return None
                return index

            prev_index = -1
            if previous is not None:
                prev_index = check_boundary(previous, "prev", start)
                if prev_index is None:
                    return False
            next_index = size
            if following is not None:
                next_index = check_boundary(following, "next", end)
                if next_index is None:
                    return False

            first_index, last_index = prev_index + 1, next_index - 1
            if len(items) != last_index - first_index + 1:
                return False
            last_name: str | None = None
            for position, item in enumerate(items):
                index = first_index + position
                if not isinstance(item, dict) or set(item) != {"account", "balance", "index", "path"}:
                    return False
                name = item["account"]
                if not isinstance(name, str) or not name or not start <= name < end:
                    return False
                if last_name is not None and not last_name < name:
                    return False
                balance = item["balance"]
                if not _is_int(balance) or balance < 0 or not _is_int(item["index"]):
                    return False
                if item["index"] != index:
                    return False
                path = _proof_path(index, size, item["path"])
                if path is None or not _recompute_root(_leaf(name, balance), index, path, root):
                    return False
                last_name = name
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

    def prove_many(self, accounts: object) -> dict:
        """Compact inclusion proof for an arbitrary non-empty set of accounts.

        ``accounts`` must be an array of unique non-empty strings (order is free).
        Malformed structure, wrong types or duplicate names raise ``ValueError``; an
        unknown account raises ``KeyError``. The proof carries the state root, the
        full tree size, one item per account sorted by name (with its full-sorted
        index), and exactly the real sibling nodes needed to connect the items to the
        root -- never nodes reconstructable from the chosen accounts or lower levels,
        and never the duplicated tail of an odd level. Proving every account yields an
        empty node set. Reading the state never mutates it, so zero-balance accounts
        are provable and accounts, version and snapshots are left untouched.
        """
        normalized = _validate_account_set(accounts)
        document = self._read()
        state_accounts = document["accounts"]
        for account in normalized:
            if account not in state_accounts:
                raise KeyError(f"unknown account {account!r}")
        names = sorted(state_accounts)
        chosen = sorted(names.index(account) for account in normalized)
        leaves = [_leaf(n, int(state_accounts[n])) for n in names]
        items = [{"account": names[index], "balance": int(state_accounts[names[index]]),
                  "index": index} for index in chosen]
        nodes = [{"level": level, "index": index, "hash": hash_value}
                 for level, index, hash_value in merkle_multiproof(leaves, chosen)]
        return {"root": _root_for(state_accounts), "size": len(names),
                "items": items, "nodes": nodes}

    def verify_many(self, accounts: object, expected_root: object, proof: object) -> bool:
        """Verify a compact multi-account inclusion proof using the proof alone.

        Only a proof isomorphic to one :meth:`prove_many` emits is accepted: a JSON
        object with exactly ``root``, ``size``, ``items`` and ``nodes``. The query
        ``accounts`` must be a non-empty array of unique non-empty strings equal as a
        set to the proven accounts; ``expected_root`` must equal the proof root. Items
        must be strictly ascending by name and by in-range index with non-negative
        integer balances, and nodes must be strictly ascending ``(level, index)``
        positions carrying 64 lowercase hex hashes. Every node must be a valid
        position, be consumed exactly once while recomputing the root and leave no
        surplus; duplicate or reconstructable nodes, out-of-range positions, a query
        mismatch or any root discrepancy return False. The state directory is never
        read.
        """
        try:
            normalized = _validate_account_set(accounts)
            if not _is_hex64(expected_root):
                return False
            if not isinstance(proof, dict) or set(proof) != {"root", "size", "items", "nodes"}:
                return False
            root = proof["root"]
            if not _is_hex64(root) or root != expected_root:
                return False
            size = proof["size"]
            if not _is_int(size) or size <= 0:
                return False
            raw_items = proof["items"]
            raw_nodes = proof["nodes"]
            if not isinstance(raw_items, list) or not isinstance(raw_nodes, list):
                return False
            if len(raw_items) != len(normalized):
                return False

            leaves: dict[int, bytes] = {}
            previous_name: str | None = None
            previous_index = -1
            for item in raw_items:
                if not isinstance(item, dict) or set(item) != {"account", "balance", "index"}:
                    return False
                name = item["account"]
                index = item["index"]
                if not isinstance(name, str) or not name:
                    return False
                if previous_name is not None and not previous_name < name:
                    return False
                if not _is_int(item["balance"]) or item["balance"] < 0:
                    return False
                if not _is_int(index) or not previous_index < index < size:
                    return False
                leaves[index] = _leaf(name, item["balance"])
                previous_name, previous_index = name, index
            if {item["account"] for item in raw_items} != set(normalized):
                return False

            nodes: dict[tuple[int, int], bytes] = {}
            previous_position: tuple[int, int] | None = None
            for node in raw_nodes:
                if not isinstance(node, dict) or set(node) != {"level", "index", "hash"}:
                    return False
                level, index = node["level"], node["index"]
                if not _is_int(level) or not _is_int(index) or level < 0 or index < 0:
                    return False
                position = (level, index)
                if previous_position is not None and not previous_position < position:
                    return False
                if not _is_hex64(node["hash"]):
                    return False
                nodes[position] = bytes.fromhex(node["hash"])
                previous_position = position

            recomputed = merkle_verify_multiproof(leaves, nodes, size)
            return recomputed is not None and recomputed.hex() == root
        except (KeyError, TypeError, ValueError):
            return False

    def prove_lookup(self, accounts: object) -> dict:
        """Compact existence/absence lookup proof for a non-empty set of accounts.

        ``accounts`` must be an array of unique non-empty strings (order is free);
        malformed structure, wrong types or duplicate names raise ``ValueError``.
        Unknown accounts are a normal result rather than an error. The proof carries
        the state root, the full tree ``size``, one ``result`` per queried account in
        ascending name order, and the same compact ``items``/``nodes`` layout as
        :meth:`prove_many`: items cover the de-duplicated union of the existing
        queries and the predecessor/successor boundaries the absent queries need,
        and one shared multi-proof connects every item to the root. An existing
        account (zero balance included) yields its full-sorted index with null
        ``prev``/``next``; an absent one yields null ``index`` and the immediate
        neighbour indices (null past either end). An empty state yields the
        empty-tree root, size 0 and no items or nodes. Generation never mutates
        accounts, versions, the root or snapshots.
        """
        normalized = _validate_account_set(accounts)
        document = self._read()
        state_accounts = document["accounts"]
        names = sorted(state_accounts)
        size = len(names)
        leaves = [_leaf(n, int(state_accounts[n])) for n in names]
        results: list[dict] = []
        needed: set[int] = set()
        for account in sorted(normalized):
            position = bisect.bisect_left(names, account)
            if position < size and names[position] == account:
                results.append({"account": account, "index": position,
                                "prev": None, "next": None})
                needed.add(position)
            else:
                prev_index = position - 1 if position > 0 else None
                next_index = position if position < size else None
                results.append({"account": account, "index": None,
                                "prev": prev_index, "next": next_index})
                if prev_index is not None:
                    needed.add(prev_index)
                if next_index is not None:
                    needed.add(next_index)
        chosen = sorted(needed)
        items = [{"account": names[index], "balance": int(state_accounts[names[index]]),
                  "index": index} for index in chosen]
        nodes = [{"level": level, "index": index, "hash": hash_value}
                 for level, index, hash_value in merkle_multiproof(leaves, chosen)]
        return {"root": _root_for(state_accounts), "size": size,
                "results": results, "items": items, "nodes": nodes}

    def verify_lookup(self, accounts: object, expected_root: object, proof: object) -> bool:
        """Verify a compact existence/absence lookup proof using the proof alone.

        Only a proof isomorphic to one :meth:`prove_lookup` emits is accepted: a JSON
        object with exactly ``root``, ``size``, ``results``, ``items`` and ``nodes``.
        The query ``accounts`` must be a non-empty array of unique non-empty strings
        and ``results`` must answer them in strictly ascending name order. An
        existing result carries a non-null in-range index with null neighbours and a
        same-name, same-index inclusion item; an absent result carries a null index
        and adjacent predecessor/successor indices (null past the ends, with the
        same strict-bracketing and adjacency rules as :meth:`verify_absence`), each
        backed by an inclusion item. ``items`` must equal exactly the de-duplicated
        union of existing accounts and referenced boundaries -- no missing or
        unrelated entries -- and ``nodes`` must be the minimal shared multi-proof
        that recomputes a root equal to both ``proof.root`` and ``expected_root``.
        Size 0 is anchored solely by the empty-tree root with every result null.
        Type confusion (including booleans posing as integers), missing or extra
        fields, or any other inconsistency return False; the state directory is
        never read.
        """
        try:
            normalized = _validate_account_set(accounts)
            if not _is_hex64(expected_root):
                return False
            if not isinstance(proof, dict) or set(proof) != {
                "root", "size", "results", "items", "nodes"
            }:
                return False
            root = proof["root"]
            if not _is_hex64(root) or root != expected_root:
                return False
            size = proof["size"]
            if not _is_int(size) or size < 0:
                return False
            raw_results = proof["results"]
            raw_items = proof["items"]
            raw_nodes = proof["nodes"]
            if (not isinstance(raw_results, list) or not isinstance(raw_items, list)
                    or not isinstance(raw_nodes, list)):
                return False
            if len(raw_results) != len(normalized):
                return False

            if size == 0:
                if raw_items or raw_nodes or root != merkle_root([]).hex():
                    return False
                for result, account in zip(raw_results, sorted(normalized)):
                    if (not isinstance(result, dict)
                            or set(result) != {"account", "index", "prev", "next"}
                            or result["account"] != account
                            or result["index"] is not None
                            or result["prev"] is not None
                            or result["next"] is not None):
                        return False
                return True

            # Validate results and collect the item indices each result requires.
            required: set[int] = set()
            specs: list[tuple[str, int, int]] = []
            for result, account in zip(raw_results, sorted(normalized)):
                if (not isinstance(result, dict)
                        or set(result) != {"account", "index", "prev", "next"}
                        or result["account"] != account):
                    return False
                index, previous, following = result["index"], result["prev"], result["next"]
                if index is not None:
                    if (not _is_int(index) or not 0 <= index < size
                            or previous is not None or following is not None):
                        return False
                    required.add(index)
                    specs.append((account, index, index))
                    continue
                if previous is not None and (not _is_int(previous) or not 0 <= previous < size):
                    return False
                if following is not None and (not _is_int(following) or not 0 <= following < size):
                    return False
                prev_index = -1 if previous is None else previous
                next_index = size if following is None else following
                if next_index != prev_index + 1:
                    return False
                if previous is not None:
                    required.add(previous)
                if following is not None:
                    required.add(following)
                specs.append((account, prev_index, next_index))

            # Validate inclusion items and index them by leaf position.
            leaves: dict[int, bytes] = {}
            item_names: dict[int, str] = {}
            previous_name: str | None = None
            previous_index = -1
            for item in raw_items:
                if not isinstance(item, dict) or set(item) != {"account", "balance", "index"}:
                    return False
                name = item["account"]
                index = item["index"]
                if not isinstance(name, str) or not name:
                    return False
                if previous_name is not None and not previous_name < name:
                    return False
                if not _is_int(item["balance"]) or item["balance"] < 0:
                    return False
                if not _is_int(index) or not previous_index < index < size:
                    return False
                leaves[index] = _leaf(name, item["balance"])
                item_names[index] = name
                previous_name, previous_index = name, index
            if set(item_names) != required:
                return False

            # Existing results need a same-name item; absent ones need strict bracketing.
            for account, prev_index, next_index in specs:
                if prev_index == next_index:
                    if item_names[prev_index] != account:
                        return False
                else:
                    if prev_index >= 0 and not item_names[prev_index] < account:
                        return False
                    if next_index < size and not item_names[next_index] > account:
                        return False

            nodes: dict[tuple[int, int], bytes] = {}
            previous_position: tuple[int, int] | None = None
            for node in raw_nodes:
                if not isinstance(node, dict) or set(node) != {"level", "index", "hash"}:
                    return False
                level, index = node["level"], node["index"]
                if not _is_int(level) or not _is_int(index) or level < 0 or index < 0:
                    return False
                position = (level, index)
                if previous_position is not None and not previous_position < position:
                    return False
                if not _is_hex64(node["hash"]):
                    return False
                nodes[position] = bytes.fromhex(node["hash"])
                previous_position = position

            recomputed = merkle_verify_multiproof(leaves, nodes, size)
            return recomputed is not None and recomputed.hex() == root
        except (KeyError, TypeError, ValueError):
            return False

    def prove_page(self, start: str, limit: int) -> dict:
        """Paged inclusion proof for up to ``limit`` accounts at or after ``start``.

        The page lists the first ``limit`` accounts whose names are not less than
        ``start`` in ascending name order, using the same compact ``items``/``nodes``
        layout as :meth:`prove_many`. ``prev`` anchors the page start: the immediate
        predecessor of the first matching account (or of ``start`` when no account
        matches), null when none exists; ``next`` anchors the page end: the immediate
        successor strictly after the last item, null on a partial page or at the tail.
        ``start`` must be a string (the empty string starts at the very first account)
        and ``limit`` a positive JSON integer (booleans are not integers); anything
        else raises ``ValueError``. Generation never mutates accounts, versions, the
        root or snapshots, and an empty state uses the empty-tree root.
        """
        if not isinstance(start, str):
            raise ValueError("start must be a string")
        if not _is_int(limit) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        document = self._read()
        state_accounts = document["accounts"]
        names = sorted(state_accounts)
        size = len(names)
        root = _root_for(state_accounts)
        leaves = [_leaf(n, int(state_accounts[n])) for n in names]
        first = bisect.bisect_left(names, start)

        def entry(index: int) -> dict | None:
            if not 0 <= index < size:
                return None
            return {"account": names[index], "balance": int(state_accounts[names[index]]),
                    "index": index}

        last = min(first + limit, size)
        page_indices = list(range(first, last))
        prev_index = first - 1
        next_index = last if len(page_indices) == limit and last < size else None
        items = [{"account": names[index], "balance": int(state_accounts[names[index]]),
                  "index": index} for index in page_indices]
        needed = set(page_indices)
        if prev_index >= 0:
            needed.add(prev_index)
        if next_index is not None:
            needed.add(next_index)
        nodes = [{"level": level, "index": index, "hash": hash_value}
                 for level, index, hash_value in merkle_multiproof(leaves, sorted(needed))]
        return {"start": start, "limit": limit, "root": root, "size": size,
                "prev": entry(prev_index),
                "next": entry(next_index) if next_index is not None else None,
                "items": items, "nodes": nodes}

    def verify_page(self, start: object, limit: object, expected_root: object, proof: object) -> bool:
        """Verify a name-paginated proof using the proof alone; no state is read.

        Only a proof isomorphic to one :meth:`prove_page` emits is accepted: a JSON
        object with exactly ``start``, ``limit``, ``root``, ``size``, ``prev``,
        ``next``, ``items`` and ``nodes``, with the query fields equal to the
        arguments. ``items`` must be strictly ascending by name and by continuous
        full-list index beginning at the first account at or past ``start``, each
        name at or above ``start`` with a non-negative integer balance; ``prev``
        (null before the first slot) must be an included account strictly below
        ``start`` at the index immediately before the page, and ``next`` (null when
        the page is partial or at the tail) an included account strictly after the
        last item at the immediately following index. The page may hold at most
        ``limit`` items and a short page forces ``next`` to be null. The items plus
        the non-null boundaries must be exactly the proven leaves, and the minimal
        shared multi-proof must consume every node and recompute a root equal to
        both ``proof.root`` and ``expected_root``. Size 0 is anchored solely by the
        empty-tree root with both boundaries null and empty arrays. Type confusion
        (including booleans posing as integers), missing or extra fields, gaps,
        out-of-order names, surplus nodes or any other inconsistency return False.
        """
        try:
            if not isinstance(start, str):
                return False
            if not _is_int(limit) or limit <= 0:
                return False
            if not _is_hex64(expected_root):
                return False
            if not isinstance(proof, dict) or set(proof) != {
                "start", "limit", "root", "size", "prev", "next", "items", "nodes"
            }:
                return False
            if proof["start"] != start:
                return False
            proven_limit = proof["limit"]
            if not _is_int(proven_limit) or proven_limit != limit:
                return False
            root = proof["root"]
            if not _is_hex64(root) or root != expected_root:
                return False
            size = proof["size"]
            if not _is_int(size) or size < 0:
                return False
            previous, following, raw_items, raw_nodes = (
                proof["prev"], proof["next"], proof["items"], proof["nodes"])
            if not isinstance(raw_items, list) or not isinstance(raw_nodes, list):
                return False
            if len(raw_items) > limit:
                return False

            if size == 0:
                return (previous is None and following is None and not raw_items
                        and not raw_nodes and root == merkle_root([]).hex())

            def check_entry(boundary: object) -> dict | None:
                """Validate one compact inclusion entry, returning normalized fields."""
                if not isinstance(boundary, dict) or set(boundary) != {
                    "account", "balance", "index"
                }:
                    return None
                name = boundary["account"]
                index = boundary["index"]
                balance = boundary["balance"]
                if (not isinstance(name, str) or not name or not _is_int(index)
                        or not 0 <= index < size or not _is_int(balance) or balance < 0):
                    return None
                return {"account": name, "balance": balance, "index": index}

            prev_entry = check_entry(previous) if previous is not None else None
            if previous is not None and prev_entry is None:
                return False
            next_entry = check_entry(following) if following is not None else None
            if following is not None and next_entry is None:
                return False

            page_start = 0 if prev_entry is None else prev_entry["index"] + 1
            page_end = size - 1 if next_entry is None else next_entry["index"] - 1
            expected_count = max(0, page_end - page_start + 1)
            if expected_count != len(raw_items) or expected_count > limit:
                return False
            # A short (partial) page is the unique end signal: next must then be null.
            if expected_count < limit and next_entry is not None:
                return False
            # page_start/page_end are pinned by the boundaries; the count equality and
            # continuous item indices below force prev/next to sit adjacent to the page.
            if prev_entry is not None and not prev_entry["account"] < start:
                return False

            leaves: dict[int, bytes] = {}
            item_names: dict[int, str] = {}
            last_name: str | None = None
            for position, item in enumerate(raw_items):
                checked = check_entry(item)
                if checked is None:
                    return False
                name, balance, index = (checked["account"], checked["balance"],
                                        checked["index"])
                if index != page_start + position:
                    return False
                if not name >= start:
                    return False
                if last_name is not None and not last_name < name:
                    return False
                leaves[index] = _leaf(name, balance)
                item_names[index] = name
                last_name = name
            if next_entry is not None:
                anchor_name = item_names[page_end] if raw_items else start
                if not next_entry["account"] > anchor_name:
                    return False

            if prev_entry is not None:
                index = prev_entry["index"]
                if index in leaves:
                    return False
                leaves[index] = _leaf(prev_entry["account"], prev_entry["balance"])
            if next_entry is not None:
                index = next_entry["index"]
                if index in leaves:
                    return False
                leaves[index] = _leaf(next_entry["account"], next_entry["balance"])

            nodes: dict[tuple[int, int], bytes] = {}
            previous_position: tuple[int, int] | None = None
            for node in raw_nodes:
                if not isinstance(node, dict) or set(node) != {"level", "index", "hash"}:
                    return False
                level, node_index = node["level"], node["index"]
                if not _is_int(level) or not _is_int(node_index) or level < 0 or node_index < 0:
                    return False
                position = (level, node_index)
                if previous_position is not None and not previous_position < position:
                    return False
                if not _is_hex64(node["hash"]):
                    return False
                nodes[position] = bytes.fromhex(node["hash"])
                previous_position = position

            recomputed = merkle_verify_multiproof(leaves, nodes, size)
            return recomputed is not None and recomputed.hex() == root
        except (KeyError, TypeError, ValueError):
            return False

    def prove_update(self, updates: object) -> dict:
        """Read-only preview proof for replacing balances without writing.

        ``updates`` is a non-empty JSON object mapping non-empty account names to
        non-negative JSON integers (booleans are not integers). Every named account
        must already exist -- a zero-balance account counts -- or ``KeyError`` is
        raised; malformed structure or types raise ``ValueError`` before the state is
        read, and an uninitialised state raises ``FileNotFoundError``. The proof
        carries the current ``root``, ``new_root`` (the root after replacing only the
        named balances), the total ``size``, one ``items`` entry per updated account
        holding its *old* balance in the same compact layout as :meth:`prove_many`,
        and the minimal ``nodes`` shared by both trees. Updating every account yields
        empty ``nodes``; when every new balance equals the old one the two roots are
        equal. Nothing is persisted and the input object is never modified.
        """
        normalized = _validate_updates(updates)
        document = self._read()
        state_accounts = document["accounts"]
        for account in normalized:
            if account not in state_accounts:
                raise KeyError(f"unknown account {account!r}")
        names = sorted(state_accounts)
        chosen = sorted(names.index(account) for account in normalized)
        leaves = [_leaf(n, int(state_accounts[n])) for n in names]
        items = [{"account": names[index], "balance": int(state_accounts[names[index]]),
                  "index": index} for index in chosen]
        root = merkle_root(leaves).hex()
        new_leaves = list(leaves)
        for account, balance in normalized.items():
            new_leaves[names.index(account)] = _leaf(account, balance)
        new_root = merkle_root(new_leaves).hex()
        nodes = [{"level": level, "index": index, "hash": hash_value}
                 for level, index, hash_value in merkle_multiproof(leaves, chosen)]
        return {"root": root, "new_root": new_root, "size": len(names),
                "items": items, "nodes": nodes}

    def verify_update(self, updates: object, expected_root: object, proof: object) -> bool:
        """Verify a balance-update preview proof using the proof alone; no state is read.

        Only a proof isomorphic to one :meth:`prove_update` emits is accepted: a JSON
        object with exactly ``root``, ``new_root``, ``size``, ``items`` and
        ``nodes``. The ``updates`` object must be valid and equal as a set to the
        proven accounts, and ``root`` must equal the trusted ``expected_root``.
        Items carry the strictly ascending old-balance entries in the same compact
        layout as :meth:`verify_many`; the minimal nodes must recompute ``root`` from
        the old leaves and ``new_root`` from the same leaves with the named balances
        replaced, consuming every node exactly once in each recomputation. The
        supplied nodes anchor the new tree because each needed sibling subtree
        contains none of the updated accounts, so its hash is unchanged. Invalid
        arguments, missing or extra fields, a set mismatch, type confusion
        (including booleans), out-of-order entries, out-of-range indices, missing,
        duplicate or surplus nodes, or either root being wrong returns False.
        """
        try:
            normalized = _validate_updates(updates)
            if not _is_hex64(expected_root):
                return False
            if not isinstance(proof, dict) or set(proof) != {
                "root", "new_root", "size", "items", "nodes"
            }:
                return False
            root = proof["root"]
            new_root = proof["new_root"]
            if not _is_hex64(root) or root != expected_root or not _is_hex64(new_root):
                return False
            size = proof["size"]
            raw_items = proof["items"]
            raw_nodes = proof["nodes"]
            if (not _is_int(size) or size <= 0 or not isinstance(raw_items, list)
                    or not isinstance(raw_nodes, list)):
                return False
            if len(raw_items) != len(normalized):
                return False

            old_leaves: dict[int, bytes] = {}
            previous_name: str | None = None
            previous_index = -1
            for item in raw_items:
                if not isinstance(item, dict) or set(item) != {"account", "balance", "index"}:
                    return False
                name = item["account"]
                index = item["index"]
                if not isinstance(name, str) or not name:
                    return False
                if previous_name is not None and not previous_name < name:
                    return False
                if not _is_int(item["balance"]) or item["balance"] < 0:
                    return False
                if not _is_int(index) or not previous_index < index < size:
                    return False
                old_leaves[index] = _leaf(name, item["balance"])
                previous_name, previous_index = name, index
            if {item["account"] for item in raw_items} != set(normalized):
                return False

            nodes: dict[tuple[int, int], bytes] = {}
            previous_position: tuple[int, int] | None = None
            for node in raw_nodes:
                if not isinstance(node, dict) or set(node) != {"level", "index", "hash"}:
                    return False
                level, index = node["level"], node["index"]
                if not _is_int(level) or not _is_int(index) or level < 0 or index < 0:
                    return False
                position = (level, index)
                if previous_position is not None and not previous_position < position:
                    return False
                if not _is_hex64(node["hash"]):
                    return False
                nodes[position] = bytes.fromhex(node["hash"])
                previous_position = position

            old_root = merkle_verify_multiproof(old_leaves, nodes, size)
            if old_root is None or old_root.hex() != root:
                return False
            new_leaves = dict(old_leaves)
            for item in raw_items:
                new_leaves[item["index"]] = _leaf(item["account"],
                                                  normalized[item["account"]])
            rebuilt = merkle_verify_multiproof(new_leaves, nodes, size)
            return rebuilt is not None and rebuilt.hex() == new_root
        except (KeyError, TypeError, ValueError):
            return False
