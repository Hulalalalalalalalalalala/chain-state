"""The account state machine.

State is a mapping of account name to non-negative balance, persisted as one JSON file inside
the state directory. The state root is computed over accounts sorted by name, so it depends on
the contents and not on the order in which accounts were written.
"""

from __future__ import annotations

import bisect
import json
from pathlib import Path

from .merkle import leaf_hash, merkle_proof, merkle_root, verify_proof

__all__ = ["State"]

STATE_FILE = "state.json"


def _leaf(account: str, balance: int) -> bytes:
    return leaf_hash(f"{account}:{balance}".encode("utf-8"))


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

    def verify(self, account: str, balance: int, proof: dict) -> bool:
        """Verify ``account``/``balance`` against ``proof`` alone, without reading the state."""
        try:
            if proof["account"] != account or int(proof["balance"]) != int(balance):
                return False
            if int(proof["index"]) >= int(proof["size"]):
                return False
            return verify_proof(_leaf(account, int(balance)), int(proof["index"]), proof["path"], str(proof["root"]))
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

    def verify_absence(self, account: str, proof: dict) -> bool:
        """Verify an absence proof using the proof alone; no state directory is read.

        Returns False (never raises) when the proof was tampered with, the root does not
        match, or the boundary indices do not close tightly around ``account``.
        """
        try:
            if proof["account"] != account or not isinstance(account, str) or not account:
                return False
            size = int(proof["size"])
            if size < 0:
                return False
            root = str(proof["root"])
            bytes.fromhex(root)

            previous, following = proof.get("prev"), proof.get("next")

            if size == 0:
                return previous is None and following is None and root == merkle_root([]).hex()
            if previous is None and following is None:
                return False

            def check_boundary(boundary: object, expected_index: int, relation: str) -> None:
                if not isinstance(boundary, dict):
                    raise ValueError("missing boundary")
                name = boundary["account"]
                balance = int(boundary["balance"])
                index = int(boundary["index"])
                path = boundary["path"]
                if not isinstance(name, str) or index != expected_index or not 0 <= index < size:
                    raise ValueError("bad boundary")
                # The duplicated-last-node tree pins the path depth to the tree size.
                if not isinstance(path, list) or len(path) != (size - 1).bit_length():
                    raise ValueError("path depth does not match size")
                ordered = name < account if relation == "prev" else name > account
                if not ordered:
                    raise ValueError("boundary does not close")
                if not verify_proof(_leaf(name, balance), index, path, root):
                    raise ValueError("bad boundary path")

            prev_index = int(previous["index"]) if previous is not None else -1
            next_index = int(following["index"]) if following is not None else size
            if next_index != prev_index + 1:
                return False
            if previous is not None:
                check_boundary(previous, prev_index, "prev")
            if following is not None:
                check_boundary(following, next_index, "next")
            return True
        except (KeyError, TypeError, ValueError, IndexError):
            return False
