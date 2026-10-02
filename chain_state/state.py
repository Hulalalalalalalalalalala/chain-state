"""The account state machine.

State is a mapping of account name to non-negative balance, persisted as one JSON file inside
the state directory. The state root is computed over accounts sorted by name, so it depends on
the contents and not on the order in which accounts were written.
"""

from __future__ import annotations

import bisect
import contextlib
import json
import os
import re
import tempfile
from pathlib import Path

from .merkle import (leaf_hash, merkle_multiproof, merkle_proof, merkle_root,
                     merkle_verify_multiproof, node_hash)

__all__ = ["State"]

STATE_FILE = "state.json"
SNAPSHOTS_KEY = "snapshots"
REQUESTS_KEY = "requests"
RECEIPTS_KEY = "receipts"

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


def _level_widths(size: int) -> list[int]:
    """Width of every level (leaf level first) in the duplicated-last-node tree."""
    widths = [size]
    while widths[-1] > 1:
        widths.append((widths[-1] + 1) // 2)
    return widths


def _check_merkle_path(leaf: bytes, index: int, size: int, path: object, root: str) -> bool:
    """Validate a sibling path and recompute the root for the tree ``size`` implies.

    Beyond the shape checks of :func:`_proof_path`, every step that lands on the
    last real node of an odd-width level must carry a sibling equal to the current
    node itself: that node is duplicated to even out the level, so nothing else
    may appear on the right. This holds at the leaf level and every higher level,
    however many times one path meets a duplicated tail. Any violation of the
    rule -- a foreign hash at a duplicated position -- fails even when the depth,
    sides and recomputed root all match.
    """
    steps = _proof_path(index, size, path)
    if steps is None:
        return False
    widths = _level_widths(size)
    current = leaf
    position = index
    for level, step in enumerate(steps):
        if widths[level] % 2 and position == widths[level] - 1:
            if step["hash"] != current.hex():
                return False
        sibling = bytes.fromhex(step["hash"])
        current = node_hash(current, sibling) if step["side"] == "right" else node_hash(sibling, current)
        position //= 2
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


def _validate_transfers(batch: object) -> list[dict]:
    """Validate a batch of transfers: a non-empty array of exact transfer objects.

    Each item must be a JSON object carrying exactly ``source``, ``target`` and
    ``amount``: distinct non-empty names and a positive JSON integer (booleans are
    not integers). Repeated transfers and repeated accounts are allowed. Returns
    independent normalized copies; malformed structure or types raise ``ValueError``.
    """
    if not isinstance(batch, list) or not batch:
        raise ValueError("transfers must be a non-empty array")
    normalized: list[dict] = []
    for transfer in batch:
        if not isinstance(transfer, dict) or set(transfer) != {"source", "target", "amount"}:
            raise ValueError("each transfer must be an object with exactly source, target and amount")
        source = transfer["source"]
        target = transfer["target"]
        amount = transfer["amount"]
        if not isinstance(source, str) or not source:
            raise ValueError("source must be a non-empty string")
        if not isinstance(target, str) or not target:
            raise ValueError("target must be a non-empty string")
        if source == target:
            raise ValueError("source and target must be different accounts")
        if not _is_int(amount) or amount <= 0:
            raise ValueError("amount must be a positive integer")
        normalized.append({"source": source, "target": target, "amount": amount})
    return normalized


def _validate_request_record(record: object) -> dict:
    """Validate one persisted once-request record and return an independent copy.

    A record carries exactly ``version`` (a non-negative JSON integer), ``root``
    (64 lowercase hex characters) and ``transfers`` (a non-empty array shaped like a
    :meth:`State.transfer_many` batch). Missing fields, extra fields or type
    confusion raise ``ValueError``.
    """
    if not isinstance(record, dict) or set(record) != {"version", "root", "transfers"}:
        raise ValueError("corrupt request record: expected exactly version, root and transfers")
    version = record["version"]
    if not _is_int(version) or version < 0:
        raise ValueError("corrupt request record: version must be a non-negative integer")
    root = record["root"]
    if not _is_hex64(root):
        raise ValueError("corrupt request record: root must be 64 lowercase hexadecimal characters")
    transfers = _validate_transfers(record["transfers"])
    return {"version": version, "root": root, "transfers": transfers}


def _validate_transfer_proof(proof: object) -> dict:
    """Validate the shape of a persisted transfer preview proof and return a deep copy.

    Mirrors the structure :meth:`State.prove_transfers` emits: exactly ``root`` and
    ``new_root`` (64 lowercase hex characters), ``size`` (a positive JSON integer),
    ``items`` (strictly ascending non-empty names with non-negative JSON integer
    balances and in-range, strictly ascending indices) and ``nodes`` (strictly
    ascending ``(level, index)`` positions, levels and indices non-negative, each
    hash 64 lowercase hex characters). Anything malformed raises ``ValueError``;
    the cryptographic root checks live in :meth:`State.verify_transfers`.
    """
    if not isinstance(proof, dict) or set(proof) != {
        "root", "new_root", "size", "items", "nodes"
    }:
        raise ValueError("corrupt receipt proof: expected exactly root, new_root, size, items and nodes")
    root = proof["root"]
    new_root = proof["new_root"]
    if not _is_hex64(root) or not _is_hex64(new_root):
        raise ValueError("corrupt receipt proof: roots must be 64 lowercase hexadecimal characters")
    size = proof["size"]
    if not _is_int(size) or size <= 0:
        raise ValueError("corrupt receipt proof: size must be a positive integer")
    raw_items = proof["items"]
    raw_nodes = proof["nodes"]
    if not isinstance(raw_items, list) or not isinstance(raw_nodes, list):
        raise ValueError("corrupt receipt proof: items and nodes must be arrays")
    items: list[dict] = []
    previous_name: str | None = None
    previous_index = -1
    for item in raw_items:
        if not isinstance(item, dict) or set(item) != {"account", "balance", "index"}:
            raise ValueError("corrupt receipt proof: each item must hold exactly account, balance and index")
        name = item["account"]
        index = item["index"]
        if not isinstance(name, str) or not name:
            raise ValueError("corrupt receipt proof: item accounts must be non-empty strings")
        if previous_name is not None and not previous_name < name:
            raise ValueError("corrupt receipt proof: items must be strictly ascending by name")
        if not _is_int(item["balance"]) or item["balance"] < 0:
            raise ValueError("corrupt receipt proof: item balances must be non-negative integers")
        if not _is_int(index) or not previous_index < index < size:
            raise ValueError("corrupt receipt proof: item indices must be strictly ascending and in range")
        items.append({"account": name, "balance": item["balance"], "index": index})
        previous_name, previous_index = name, index
    nodes: list[dict] = []
    previous_position: tuple[int, int] | None = None
    for node in raw_nodes:
        if not isinstance(node, dict) or set(node) != {"level", "index", "hash"}:
            raise ValueError("corrupt receipt proof: each node must hold exactly level, index and hash")
        level, index = node["level"], node["index"]
        if not _is_int(level) or not _is_int(index) or level < 0 or index < 0:
            raise ValueError("corrupt receipt proof: node level and index must be non-negative integers")
        position = (level, index)
        if previous_position is not None and not previous_position < position:
            raise ValueError("corrupt receipt proof: nodes must be strictly ascending by level then index")
        if not _is_hex64(node["hash"]):
            raise ValueError("corrupt receipt proof: node hashes must be 64 lowercase hexadecimal characters")
        nodes.append({"level": level, "index": index, "hash": node["hash"]})
        previous_position = position
    return {"root": root, "new_root": new_root, "size": size,
            "items": items, "nodes": nodes}


def _validate_receipt(receipt: object) -> dict:
    """Validate one persisted settlement receipt and return an independent copy.

    A receipt carries exactly ``version`` (a non-negative JSON integer),
    ``transfers`` (a non-empty batch shaped like a :meth:`State.transfer_many`
    batch) and ``proof`` (a transfer preview proof). Consistency with the
    matching success record and cryptographic verification of the proof against
    the record's old root are checked by :meth:`State.transfer_receipt`.
    Missing fields, extra fields or type confusion raise ``ValueError``.
    """
    if not isinstance(receipt, dict) or set(receipt) != {"version", "transfers", "proof"}:
        raise ValueError("corrupt receipt: expected exactly version, transfers and proof")
    version = receipt["version"]
    if not _is_int(version) or version < 0:
        raise ValueError("corrupt receipt: version must be a non-negative integer")
    transfers = _validate_transfers(receipt["transfers"])
    proof = _validate_transfer_proof(receipt["proof"])
    return {"version": version, "transfers": transfers, "proof": proof}


def _source_item_names(proof: object) -> list[str] | None:
    """Pull the item-name list out of a candidate compose source; None when the shape is off."""
    if not isinstance(proof, dict) or set(proof) != {"root", "size", "items", "nodes"}:
        return None
    raw_items = proof["items"]
    if not isinstance(raw_items, list):
        return None
    names: list[str] = []
    for item in raw_items:
        if not isinstance(item, dict):
            return None
        name = item.get("account")
        if not isinstance(name, str) or not name:
            return None
        names.append(name)
    return names


def _source_result_names(proof: object) -> list[str] | None:
    """Pull the result-name list out of a candidate compose-lookup source; None when the shape is off."""
    if not isinstance(proof, dict) or set(proof) != {
        "root", "size", "results", "items", "nodes"
    }:
        return None
    raw_results = proof["results"]
    if not isinstance(raw_results, list):
        return None
    names: list[str] = []
    for result in raw_results:
        if not isinstance(result, dict):
            return None
        name = result.get("account")
        if not isinstance(name, str) or not name:
            return None
        names.append(name)
    return names


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
    path = boundary["path"]
    return _check_merkle_path(_leaf(name, balance), index, size, path, root)


class State:
    """A single-process account state machine rooted at ``root``."""

    def __init__(self, root: str | Path) -> None:
        self.directory = Path(root)
        self.path = self.directory / STATE_FILE

    # -- persistence ------------------------------------------------------------------

    def init(self) -> None:
        """Create an empty state, replacing any existing one.

        Snapshots, successful once-request records and their settlement receipts
        are reset along with the accounts and version.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write({"version": 0, "accounts": {}, SNAPSHOTS_KEY: {},
                     REQUESTS_KEY: {}, RECEIPTS_KEY: {}})

    def _read(self) -> dict:
        if not self.path.is_file():
            raise FileNotFoundError(f"no state at {self.path}; run init first")
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, document: dict) -> None:
        """Atomically replace the state file, leaving the old one intact on failure.

        The new document is fully written and flushed to a temporary file in the
        state directory, then renamed onto the state path. A failure anywhere in
        that sequence raises ``OSError`` without clobbering the existing state
        file.
        """
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(document, sort_keys=True, indent=2)
        # Match the permissions plain ``write_text`` would have used: keep an
        # existing file's mode, else apply the process umask to 0o666.
        try:
            mode = self.path.stat().st_mode & 0o777
        except FileNotFoundError:
            umask = os.umask(0)
            os.umask(umask)
            mode = 0o666 & ~umask
        temporary = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.directory, delete=False)
        try:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary.close()
            os.chmod(temporary.name, mode)
            os.replace(temporary.name, self.path)
        except BaseException:
            temporary.close()
            with contextlib.suppress(OSError):
                os.unlink(temporary.name)
            raise

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

    @staticmethod
    def _requests(document: dict) -> dict:
        """The successful once-request records, treating a state file without them as empty.

        A missing key is added to ``document`` so callers can persist new records;
        a present-but-wrong-typed value is treated as corruption. Records never
        participate in the state root and are not part of snapshots.
        """
        if REQUESTS_KEY not in document:
            document[REQUESTS_KEY] = {}
        requests = document[REQUESTS_KEY]
        if not isinstance(requests, dict):
            raise ValueError("corrupt request records: expected a JSON object")
        return requests

    @staticmethod
    def _receipts(document: dict) -> dict:
        """The settlement receipts, treating a state file without them as empty.

        A missing key is added to ``document`` so callers can persist new receipts;
        a present-but-wrong-typed value is treated as corruption. Receipts never
        participate in the state root, are not part of snapshots and are kept keyed
        by the same request id as the success records.
        """
        if RECEIPTS_KEY not in document:
            document[RECEIPTS_KEY] = {}
        receipts = document[RECEIPTS_KEY]
        if not isinstance(receipts, dict):
            raise ValueError("corrupt receipts: expected a JSON object")
        return receipts

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

    def transfer_many(self, batch: object) -> int:
        """Atomically settle a non-empty batch of transfers in order and return the new version.

        ``batch`` is a non-empty JSON array; every item is an object carrying exactly
        ``source``, ``target`` and ``amount``, with distinct non-empty names and a
        positive JSON integer (booleans are not integers). Repeated transfers and
        accounts are allowed. Every endpoint must already exist -- a zero-balance
        account counts -- or ``KeyError`` is raised. Transfers settle in order, so a
        credit from one transfer is available to a later debit; each source must hold
        enough at its turn or ``ValueError`` is raised. Structure is validated before
        the state is read, so malformed input raises ``ValueError`` while an
        uninitialised state raises ``FileNotFoundError``. The batch adds exactly one
        version (even when every final balance equals its starting value), drained
        accounts keep their records, and a rejected batch changes neither the
        accounts, version, root nor snapshots.
        """
        normalized = _validate_transfers(batch)
        document = self._read()
        accounts = document["accounts"]
        for transfer in normalized:
            if transfer["source"] not in accounts:
                raise KeyError(f"unknown account {transfer['source']!r}")
            if transfer["target"] not in accounts:
                raise KeyError(f"unknown account {transfer['target']!r}")
        balances = {name: int(balance) for name, balance in accounts.items()}
        for transfer in normalized:
            source, target, amount = (transfer["source"], transfer["target"],
                                      transfer["amount"])
            if balances[source] < amount:
                raise ValueError(
                    f"insufficient funds: {source!r} has {balances[source]}, needs {amount}"
                )
            balances[source] -= amount
            balances[target] += amount
        for name, balance in balances.items():
            accounts[name] = balance
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def transfer_many_once(self, request_id: object, expected_root: object, batch: object) -> int:
        """Idempotently settle a transfer batch under an old-root constraint.

        ``request_id`` is a non-empty string identifying the request, ``expected_root``
        is the 64-lowercase-hex state root the state must currently carry, and
        ``batch`` follows the same rules and in-order settlement semantics as
        :meth:`transfer_many`. All three arguments are validated before the state is
        read, so malformed structure, types or root formatting raise ``ValueError``
        while a legal-but-uninitialised state raises ``FileNotFoundError``.

        A first success requires the current root to equal ``expected_root``; it
        settles the whole batch in order, advances the version exactly once (even
        when every final balance is unchanged), records the request and saves a
        settlement receipt holding the same preview proof
        :meth:`prove_transfers` would return immediately before the commit. The
        return value is still just the new version; the receipt is read back via
        :meth:`transfer_receipt`. A repeat carrying the same id, old root and
        batch returns the first success's version without settling or writing,
        even if the accounts changed or a snapshot was restored in between; a
        repeat never (re)writes a receipt. Batch equality preserves array order
        and duplicates and ignores object key order. The same id with another
        old root or batch raises ``RuntimeError``; a new id against a mismatched
        current root raises ``RuntimeError`` as well. After the repeat check the
        old root is compared, then every endpoint is checked -- an unknown
        endpoint raises ``KeyError`` -- and only then does the batch settle,
        with an insufficient balance raising ``ValueError``. A failed attempt
        neither consumes the id nor mutates the input; accounts, root, version,
        snapshots, records and receipts all stay unchanged. The settled root
        equals the receipt proof's ``new_root`` (and the ``new_root``
        :meth:`prove_transfers` returns from the same old state); the root
        constraint is independent of the version. Accounts, the record and the
        receipt commit in one atomic write, so a write failure raises
        ``OSError`` and changes nothing.
        """
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request id must be a non-empty string")
        if not _is_hex64(expected_root):
            raise ValueError("expected root must be 64 lowercase hexadecimal characters")
        normalized = _validate_transfers(batch)

        document = self._read()
        accounts = document["accounts"]
        requests = self._requests(document)
        current_root = _root_for(accounts)

        # Repeat requests win over every state-level check: a recorded success
        # replays its version regardless of later account changes or restores,
        # and never writes or backfills a receipt.
        if request_id in requests:
            saved = _validate_request_record(requests[request_id])
            if saved["root"] != expected_root or saved["transfers"] != normalized:
                raise RuntimeError(
                    f"request {request_id!r} already succeeded under a different root or batch"
                )
            return saved["version"]

        if current_root != expected_root:
            raise RuntimeError(
                f"current root {current_root} does not match expected root {expected_root}"
            )
        # The preview performs the endpoint and in-order funds checks and yields
        # exactly the proof prove_transfers would emit from this old state.
        proof, balances = self._transfer_preview(document, normalized)
        for name, balance in balances.items():
            accounts[name] = balance
        document["version"] = int(document["version"]) + 1
        version = document["version"]
        requests[request_id] = {
            "version": version, "root": expected_root,
            "transfers": normalized}
        receipts = self._receipts(document)
        receipts[request_id] = {
            "version": version, "transfers": normalized, "proof": proof}
        self._write(document)
        return version

    def _transfer_preview(self, document: dict, normalized: list[dict]) -> tuple[dict, dict]:
        """Build the transfer preview proof for ``normalized`` over an unmutated document.

        Returns the same proof object :meth:`prove_transfers` returns -- so a proof
        saved at commit time and one previewed beforehand compare equal as JSON --
        together with the settled name-to-balance mapping. Callers run their own
        root constraint before this; an unknown endpoint raises ``KeyError`` and an
        insufficient balance during in-order settlement raises ``ValueError``.
        """
        state_accounts = document["accounts"]
        for transfer in normalized:
            if transfer["source"] not in state_accounts:
                raise KeyError(f"unknown account {transfer['source']!r}")
            if transfer["target"] not in state_accounts:
                raise KeyError(f"unknown account {transfer['target']!r}")
        names = sorted(state_accounts)
        endpoint_names = {endpoint for transfer in normalized
                          for endpoint in (transfer["source"], transfer["target"])}
        chosen = sorted(names.index(name) for name in endpoint_names)
        leaves = [_leaf(n, int(state_accounts[n])) for n in names]
        items = [{"account": names[index], "balance": int(state_accounts[names[index]]),
                  "index": index} for index in chosen]
        root = merkle_root(leaves).hex()
        balances = {name: int(balance) for name, balance in state_accounts.items()}
        for transfer in normalized:
            source, target, amount = (transfer["source"], transfer["target"],
                                      transfer["amount"])
            if balances[source] < amount:
                raise ValueError(
                    f"insufficient funds: {source!r} has {balances[source]}, needs {amount}"
                )
            balances[source] -= amount
            balances[target] += amount
        new_leaves = list(leaves)
        for index in chosen:
            name = names[index]
            new_leaves[index] = _leaf(name, balances[name])
        new_root = merkle_root(new_leaves).hex()
        nodes = [{"level": level, "index": index, "hash": hash_value}
                 for level, index, hash_value in merkle_multiproof(leaves, chosen)]
        proof = {"root": root, "new_root": new_root, "size": len(names),
                 "items": items, "nodes": nodes}
        return proof, balances

    def prove_transfers(self, batch: object) -> dict:
        """Read-only preview proof for an atomic transfer batch without writing.

        ``batch`` follows the same rules as :meth:`transfer_many`; structure and types
        are validated before the state is read (``ValueError``), an uninitialised state
        raises ``FileNotFoundError``, an unknown endpoint raises ``KeyError`` and an
        insufficient balance raises ``ValueError``. The proof carries the current
        ``root``, the ``new_root`` after settling the whole batch in order, the total
        ``size``, one ``items`` entry per de-duplicated endpoint holding its *old*
        balance in the same compact layout as :meth:`prove_many`, and the minimal
        ``nodes`` shared by both trees. Proving a batch whose endpoints cover every
        account yields empty ``nodes``; when every final balance equals the old one the
        two roots are equal. Nothing is persisted and the input array is never modified.
        """
        normalized = _validate_transfers(batch)
        document = self._read()
        proof, _ = self._transfer_preview(document, normalized)
        return proof

    def verify_transfers(self, batch: object, expected_root: object, proof: object) -> bool:
        """Verify a transfer-batch preview proof using the proof alone; no state is read.

        Only a proof isomorphic to one :meth:`prove_transfers` emits is accepted: a JSON
        object with exactly ``root``, ``new_root``, ``size``, ``items`` and ``nodes``.
        The ``batch`` must be a valid non-empty transfer array, the endpoint de-dup set
        must equal the proven accounts, and ``root`` must equal the trusted 64-lowercase
        hex ``expected_root``. Items carry the strictly ascending old-balance entries in
        the same compact layout as :meth:`verify_many`; the minimal nodes must recompute
        ``root`` from the old leaves and ``new_root`` from the same leaves after the
        whole batch settles in order with every per-transfer debit covered, consuming
        every node exactly once in each recomputation. Invalid arguments, missing or
        extra fields, a set mismatch, type confusion (including booleans), out-of-order
        entries, out-of-range indices, insufficient balances, missing, duplicate or
        surplus nodes, or either root being wrong returns False.
        """
        try:
            normalized = _validate_transfers(batch)
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
            endpoints = {endpoint for transfer in normalized
                         for endpoint in (transfer["source"], transfer["target"])}
            if len(raw_items) != len(endpoints):
                return False

            old_leaves: dict[int, bytes] = {}
            old_balances: dict[str, int] = {}
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
                old_balances[name] = item["balance"]
                previous_name, previous_index = name, index
            if {item["account"] for item in raw_items} != endpoints:
                return False

            balances = dict(old_balances)
            for transfer in normalized:
                source, target, amount = (transfer["source"], transfer["target"],
                                          transfer["amount"])
                if balances[source] < amount:
                    return False
                balances[source] -= amount
                balances[target] += amount

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
                name = item["account"]
                new_leaves[item["index"]] = _leaf(name, balances[name])
            rebuilt = merkle_verify_multiproof(new_leaves, nodes, size)
            return rebuilt is not None and rebuilt.hex() == new_root
        except (KeyError, TypeError, ValueError):
            return False

    def transfer_receipt(self, request_id: object) -> dict | None:
        """Return the historical settlement receipt for a once-request, or None.

        A receipt exists only for requests whose *first* success was recorded by
        a build that saved receipts; an older success record without a receipt
        yields ``None`` and is never backfilled, neither here nor on a repeat
        commit. The returned object carries exactly ``request_id``, ``version``,
        ``transfers`` and ``proof``: the identifier, version and batch of the
        first successful settlement (the batch preserves order and duplicates),
        and the preview proof saved at commit time. The proof equals the one
        :meth:`prove_transfers` returned before the commit as JSON content, and
        its ``new_root`` is the state root right after that settlement, so it
        verifies through :meth:`verify_transfers` together with the batch and
        the record's trusted old root long after later account changes or
        snapshot restores.

        ``request_id`` must be a non-empty string (``ValueError``); a legal id
        against an uninitialised state raises ``FileNotFoundError`` and an
        unknown identifier raises ``KeyError``. A persisted receipt with illegal
        fields or types, one whose id/version/batch do not match the success
        record, or one whose proof cannot be verified against the record's old
        root raises ``ValueError`` -- corruption is never reported as a missing
        receipt. The result is an independent deep copy; the query neither
        writes nor advances the version.
        """
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request id must be a non-empty string")
        document = self._read()
        requests = self._requests(document)
        if request_id not in requests:
            raise KeyError(f"unknown request {request_id!r}")
        record = _validate_request_record(requests[request_id])
        receipts = self._receipts(document)
        if request_id not in receipts:
            # An older success record never gets a backfilled receipt.
            return None
        receipt = _validate_receipt(receipts[request_id])
        if receipt["version"] != record["version"] or receipt["transfers"] != record["transfers"]:
            raise ValueError("corrupt receipt: version or transfers do not match the success record")
        proof = receipt["proof"]
        if not self.verify_transfers(receipt["transfers"], record["root"], proof):
            raise ValueError("corrupt receipt: proof does not verify against the recorded old root")
        return {"request_id": request_id, "version": receipt["version"],
                "transfers": receipt["transfers"], "proof": proof}

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
        sides match the tree shape ``size`` implies. Where the path meets the last real
        node of an odd-width level, the sibling must equal that node itself (the
        duplicated tail), at the leaf level and every higher level. Any mismatch, type
        confusion, encoding oddity, out-of-range index, wrong duplicated-tail sibling or
        non-closing path returns False.
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
            return _check_merkle_path(_leaf(account, balance), index, size, proof["path"], root)
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
        ``size`` leaves and obey the odd-level duplicated-tail rule (a path landing on
        the last real node of an odd-width level must carry that very node as its
        sibling). A zero count is anchored solely by the empty-tree root (size 0
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
                if not _check_merkle_path(_leaf(name, balance), index, size, item["path"], root):
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
        each recompute the one root over a tree of ``size`` leaves and obey the
        odd-level duplicated-tail rule (a path landing on the last real node of an
        odd-width level must carry that very node as its sibling). Any mismatch, type
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
                if not _check_merkle_path(_leaf(name, balance), index, size, item["path"], root):
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
        Every path obeys the odd-level duplicated-tail rule: a step landing on the
        last real node of an odd-width level must carry that very node as its
        sibling. Any mismatch, type confusion, encoding oddity, gap or broken path
        returns False.
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
                if not _check_merkle_path(_leaf(name, balance), index, size, boundary["path"], root):
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
                if not _check_merkle_path(_leaf(name, balance), index, size, item["path"], root):
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
        the first/last slot), and both paths must recompute the one root while
        obeying the odd-level duplicated-tail rule (a step landing on the last
        real node of an odd-width level must carry that very node as its sibling).
        Every inconsistency, tampering, type confusion or encoding oddity returns False.
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

    def compose_many(self, accounts: object, trusted_root: object, sources: object) -> dict:
        """Recompose a compact inclusion proof offline from existing proofs alone.

        ``accounts`` follows the same rules as :meth:`prove_many`: a non-empty array
        of unique non-empty strings in any order. ``trusted_root`` must be 64
        lowercase hexadecimal characters. ``sources`` must be a non-empty array;
        every entry must be a proof shaped like one :meth:`prove_many` emits that
        passes :meth:`verify_many` under its own item-name set and ``trusted_root``,
        and all sources must agree on the root and total account count. Sources may
        overlap or repeat in any order.

        Validation order is: the target names and root format first, then every
        source, then target coverage. Invalid arguments, an invalid source,
        mismatched totals, conflicting same-name balances or indices, one index
        bound to different names, or different hashes at one node position raise
        ``ValueError``; when every source is legal but a target name appears in no
        source's items the result is ``KeyError`` (node hashes are not account
        coverage). The returned proof has the exact shape :meth:`prove_many` would
        emit over the same real state -- only target items and the minimal real
        siblings connecting them to the root, with the usual ordering and
        odd-level duplication rule, empty ``nodes`` when the targets cover the
        whole tree -- so it verifies through :meth:`verify_many`. Only the inputs
        are used: the state directory is neither read nor written and need not
        exist, and neither the inputs nor any persisted state is mutated.
        """
        normalized = _validate_account_set(accounts)
        if not _is_hex64(trusted_root):
            raise ValueError("trusted root must be 64 lowercase hexadecimal characters")
        if not isinstance(sources, list) or not sources:
            raise ValueError("sources must be a non-empty array")

        shared_size: int | None = None
        # Indexed account facts merged from the sources; these maps never share
        # structure with the inputs (ints are immutable, dicts rebuilt on output).
        balances: dict[str, int] = {}
        index_of: dict[str, int] = {}
        name_at: dict[int, str] = {}
        known: dict[tuple[int, int], str] = {}
        for position, source in enumerate(sources):
            names = _source_item_names(source)
            # verify_many never raises on malformed structure, but feeding it a
            # non-array query would; an unparseable source is simply invalid.
            if names is None or len(names) != len(set(names)) or not self.verify_many(
                    names, trusted_root, source):
                raise ValueError(f"source {position} is not a valid multi-account proof for the trusted root")
            size = source["size"]
            if shared_size is None:
                shared_size = size
            elif size != shared_size:
                raise ValueError(
                    f"source {position} reports size {size}, expected {shared_size}")
            for item in source["items"]:
                name, balance, index = item["account"], item["balance"], item["index"]
                if name in balances:
                    if balances[name] != balance or index_of[name] != index:
                        raise ValueError(
                            f"conflicting source entries for account {name!r}")
                else:
                    if index in name_at:
                        raise ValueError(
                            f"index {index} bound to both {name_at[index]!r} and {name!r}")
                    balances[name] = balance
                    index_of[name] = index
                    name_at[index] = name
            for node in source["nodes"]:
                key = (node["level"], node["index"])
                if key in known:
                    if known[key] != node["hash"]:
                        raise ValueError(
                            f"conflicting node hash at level {key[0]} index {key[1]}")
                else:
                    known[key] = node["hash"]

        assert shared_size is not None
        targets = set(normalized)
        missing = targets - balances.keys()
        if missing:
            raise KeyError(f"no source proves account {sorted(missing)[0]!r}")

        widths = _level_widths(shared_size)
        # Every real node position learnable from the sources, keyed by
        # (level, index): proven leaves and supplied siblings alike (a level-0
        # node is merely a non-item neighbour leaf, never account coverage).
        values: dict[tuple[int, int], bytes] = {
            (0, index_of[name]): _leaf(name, balances[name]) for name in balances}

        def observe(position: tuple[int, int], digest: bytes) -> None:
            """Record a real node hash, rejecting a different hash at one position."""
            previous = values.get(position)
            if previous is not None and previous != digest:
                raise ValueError(
                    f"conflicting node hash at level {position[0]} index {position[1]}")
            values[position] = digest

        for (level, index), hash_value in known.items():
            observe((level, index), bytes.fromhex(hash_value))
        # Bottom-up closure: a parent is known when both children are known; on an
        # odd level the last real node is its own duplicated sibling. A parent
        # supplied by one source and reconstructed from another source's interior
        # must be the same real subtree hash.
        for level in range(len(widths) - 1):
            width = widths[level]
            for parent in range((width + 1) // 2):
                left_position, right_position = parent * 2, parent * 2 + 1
                left_key = (level, left_position)
                duplicated_tail = width % 2 and left_position == width - 1
                if left_key not in values:
                    continue
                if not duplicated_tail and (level, right_position) not in values:
                    continue
                left = values[left_key]
                right = left if duplicated_tail else values[(level, right_position)]
                observe((level + 1, parent), node_hash(left, right))

        chosen = sorted(index_of[name] for name in targets)
        wanted: set[tuple[int, int]] = set()
        current = set(chosen)
        for level in range(len(widths) - 1):
            width = widths[level]
            next_level: set[int] = set()
            for position in current:
                sibling = position ^ 1
                if sibling in current:
                    pass  # both children belong to targets, reconstructed together
                elif width % 2 and sibling == width:
                    pass  # duplicated tail, never a real supplied sibling
                else:
                    wanted.add((level, sibling))
                next_level.add(position // 2)
            current = next_level

        ordered = sorted(wanted)
        for position in ordered:
            if position not in values:
                # Defensive: coverage plus individually valid proofs always closes
                # the tree, so this marks mutually inconsistent source material.
                raise ValueError(f"sources do not connect account set to the root: missing {position}")
        items = [{"account": name_at[index], "balance": balances[name_at[index]],
                  "index": index}
                 for index in chosen]
        nodes = [{"level": level, "index": index, "hash": values[(level, index)].hex()}
                 for level, index in ordered]
        return {"root": trusted_root, "size": shared_size,
                "items": items, "nodes": nodes}

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

    def compose_lookup(self, accounts: object, trusted_root: object, sources: object) -> dict:
        """Recompose an existence/absence lookup proof offline from existing lookup proofs.

        ``accounts`` follows the same rules as :meth:`prove_lookup`: a non-empty
        array of unique non-empty strings in any order. ``trusted_root`` must be 64
        lowercase hexadecimal characters. ``sources`` must be a non-empty array;
        every entry must be a proof shaped like one :meth:`prove_lookup` emits that
        passes :meth:`verify_lookup` under its own result-name set and
        ``trusted_root``, and all sources must agree on the root and total account
        count. Sources may overlap or repeat in any order.

        Validation order is: the target names and root format first, then every
        source, then target coverage. Invalid arguments, an invalid source,
        mismatched totals, conflicting same-name balances or indices, one index
        bound to different names, a name/index ordering contradiction, or
        different hashes at one node position raise ``ValueError``. A target need
        not appear in any source's ``results``: a same-name entry in the union of
        the sources' plaintext items proves existence (boundary entries and
        zero-balance accounts included), while two plaintext entries strictly
        bracketing the target with adjacent full-list indices prove absence (the
        boundaries may come from different sources); a name before the index-0
        entry, after the last-index entry, or in an empty tree is provably absent
        as well. Hash-only or non-adjacent bracketing does not cover a target;
        when every source is legal but a target cannot be decided the result is
        ``KeyError``. The returned proof has the exact shape
        :meth:`prove_lookup` would emit over the same real state -- one result
        per target, the de-duplicated union of the needed existence entries and
        boundaries, and the minimal real siblings connecting them to the root,
        with the usual ordering and odd-level duplication rule -- so it verifies
        through :meth:`verify_lookup`. Only the inputs are used: the state
        directory is neither read nor written and need not exist, and neither
        the inputs nor any persisted state is mutated.
        """
        normalized = _validate_account_set(accounts)
        if not _is_hex64(trusted_root):
            raise ValueError("trusted root must be 64 lowercase hexadecimal characters")
        if not isinstance(sources, list) or not sources:
            raise ValueError("sources must be a non-empty array")

        shared_size: int | None = None
        # Plaintext account facts merged from the sources' items; these maps
        # never share structure with the inputs (ints are immutable, dicts and
        # lists rebuilt on output).
        balances: dict[str, int] = {}
        index_of: dict[str, int] = {}
        name_at: dict[int, str] = {}
        known: dict[tuple[int, int], str] = {}
        for position, source in enumerate(sources):
            names = _source_result_names(source)
            # verify_lookup never raises on malformed structure, but feeding it a
            # non-array query would; an unparseable source is simply invalid.
            if names is None or len(names) != len(set(names)) or not self.verify_lookup(
                    names, trusted_root, source):
                raise ValueError(f"source {position} is not a valid lookup proof for the trusted root")
            size = source["size"]
            if shared_size is None:
                shared_size = size
            elif size != shared_size:
                raise ValueError(
                    f"source {position} reports size {size}, expected {shared_size}")
            for item in source["items"]:
                name, balance, index = item["account"], item["balance"], item["index"]
                if name in balances:
                    if balances[name] != balance or index_of[name] != index:
                        raise ValueError(
                            f"conflicting source entries for account {name!r}")
                else:
                    if index in name_at:
                        raise ValueError(
                            f"index {index} bound to both {name_at[index]!r} and {name!r}")
                    balances[name] = balance
                    index_of[name] = index
                    name_at[index] = name
            for node in source["nodes"]:
                key = (node["level"], node["index"])
                if key in known:
                    if known[key] != node["hash"]:
                        raise ValueError(
                            f"conflicting node hash at level {key[0]} index {key[1]}")
                else:
                    known[key] = node["hash"]

        assert shared_size is not None
        # A global name/index ordering contradiction across sources: the merged
        # plaintext names sorted by name must carry strictly ascending indices.
        # Each source is internally consistent, so this can only disagree across
        # two individually valid sources.
        ordered_plaintext = sorted(balances)
        for earlier, later in zip(ordered_plaintext, ordered_plaintext[1:]):
            if index_of[earlier] >= index_of[later]:
                raise ValueError(
                    f"name and index ordering contradiction between {earlier!r} and {later!r}")

        # Every source is individually legal and mutually consistent; only now,
        # after all validation, decide each target from the plaintext union.
        # Hash-only neighbour leaves carry no name and never take part.
        results: list[dict] = []
        needed: set[int] = set()
        if shared_size == 0:
            # An empty tree proves every target absent with no boundaries.
            for account in sorted(normalized):
                results.append({"account": account, "index": None,
                                "prev": None, "next": None})
            return {"root": trusted_root, "size": 0,
                    "results": results, "items": [], "nodes": []}
        item_names = ordered_plaintext
        undecided: list[str] = []
        for account in sorted(normalized):
            if account in balances:
                # A same-name plaintext item (even one that only ever served as
                # another query's boundary) anchors existence directly.
                index = index_of[account]
                results.append({"account": account, "index": index,
                                "prev": None, "next": None})
                needed.add(index)
                continue
            slot = bisect.bisect_left(item_names, account)
            prev_name = item_names[slot - 1] if slot > 0 else None
            next_name = item_names[slot] if slot < len(item_names) else None
            prev_index = index_of[prev_name] if prev_name is not None else None
            next_index = index_of[next_name] if next_name is not None else None
            adjacent = (
                (prev_index is None and next_index == 0)
                or (next_index is None and prev_index == shared_size - 1)
                or (prev_index is not None and next_index is not None
                    and next_index == prev_index + 1))
            if not adjacent:
                # Hash-only or non-adjacent bracketing, or no bracket at all.
                undecided.append(account)
                continue
            results.append({"account": account, "index": None,
                            "prev": prev_index, "next": next_index})
            if prev_index is not None:
                needed.add(prev_index)
            if next_index is not None:
                needed.add(next_index)
        if undecided:
            raise KeyError(f"no source determines account {undecided[0]!r}")

        widths = _level_widths(shared_size)
        # Every real node position learnable from the sources, keyed by
        # (level, index): proven leaves and supplied siblings alike (a level-0
        # node is merely a non-item neighbour leaf, never account coverage).
        values: dict[tuple[int, int], bytes] = {
            (0, index_of[name]): _leaf(name, balances[name]) for name in balances}

        def observe(position: tuple[int, int], digest: bytes) -> None:
            """Record a real node hash, rejecting a different hash at one position."""
            previous = values.get(position)
            if previous is not None and previous != digest:
                raise ValueError(
                    f"conflicting node hash at level {position[0]} index {position[1]}")
            values[position] = digest

        for (level, index), hash_value in known.items():
            observe((level, index), bytes.fromhex(hash_value))
        # Bottom-up closure: a parent is known when both children are known; on an
        # odd level the last real node is its own duplicated sibling. A parent
        # supplied by one source and reconstructed from another source's interior
        # must be the same real subtree hash.
        for level in range(len(widths) - 1):
            width = widths[level]
            for parent in range((width + 1) // 2):
                left_position, right_position = parent * 2, parent * 2 + 1
                left_key = (level, left_position)
                duplicated_tail = width % 2 and left_position == width - 1
                if left_key not in values:
                    continue
                if not duplicated_tail and (level, right_position) not in values:
                    continue
                left = values[left_key]
                right = left if duplicated_tail else values[(level, right_position)]
                observe((level + 1, parent), node_hash(left, right))

        chosen = sorted(needed)
        wanted: set[tuple[int, int]] = set()
        current = set(chosen)
        for level in range(len(widths) - 1):
            width = widths[level]
            next_level: set[int] = set()
            for position in current:
                sibling = position ^ 1
                if sibling in current:
                    pass  # both children belong to items, reconstructed together
                elif width % 2 and sibling == width:
                    pass  # duplicated tail, never a real supplied sibling
                else:
                    wanted.add((level, sibling))
                next_level.add(position // 2)
            current = next_level

        ordered = sorted(wanted)
        for position in ordered:
            if position not in values:
                # Defensive: coverage plus individually valid proofs always
                # closes the tree, so this marks mutually inconsistent source
                # material.
                raise ValueError(f"sources do not connect account set to the root: missing {position}")
        items = [{"account": name_at[index], "balance": balances[name_at[index]],
                  "index": index}
                 for index in chosen]
        nodes = [{"level": level, "index": index, "hash": values[(level, index)].hex()}
                 for level, index in ordered]
        return {"root": trusted_root, "size": shared_size,
                "results": results, "items": items, "nodes": nodes}

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
