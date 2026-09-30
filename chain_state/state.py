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

    def delete(self, account: str) -> int:
        """Remove an existing ``account`` and return the new version number."""
        document = self._read()
        if account not in document["accounts"]:
            raise KeyError(f"unknown account {account!r}")
        del document["accounts"][account]
        document["version"] = int(document["version"]) + 1
        self._write(document)
        return document["version"]

    def get(self, account: str) -> int:
        """Balance of ``account``, or 0 when the account is unknown or deleted."""
        return int(self._read()["accounts"].get(account, 0))

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

        Absence follows from the accounts being sorted by name: the proof binds the hash gap
        in which ``account`` would have to sit. ``before`` is the predecessor account (with its
        inclusion proof), ``after`` the successor; each side is ``None`` at a list boundary.
        With zero accounts both sides are ``None`` and the empty-tree root alone is the proof.
        """
        if not isinstance(account, str) or not account:
            raise ValueError("account must be a non-empty string")
        document = self._read()
        accounts = document["accounts"]
        if account in accounts:
            raise KeyError(f"account exists {account!r}")
        names = sorted(accounts)
        leaves = [_leaf(n, int(accounts[n])) for n in names]
        root = merkle_root(leaves).hex()
        position = bisect.bisect_left(names, account)

        def bound(index: int | None) -> dict | None:
            if index is None:
                return None
            name = names[index]
            return {"account": name, "balance": int(accounts[name]), "index": index,
                    "path": merkle_proof(leaves, index)}

        before = bound(position - 1 if position > 0 else None)
        after = bound(position if position < len(names) else None)
        return {"account": account, "root": root, "size": len(names), "before": before, "after": after}

    def verify_absence(self, account: str, proof: dict) -> bool:
        """Verify an absence proof using only the proof, never the state directory."""
        try:
            if not isinstance(proof, dict) or str(proof["account"]) != account:
                return False
            root, size = str(proof["root"]), int(proof["size"])
            if size < 0:
                return False
            before, after = proof["before"], proof["after"]
            if size == 0:
                return before is None and after is None and root == merkle_root([]).hex()

            def check_bound(bound, relation: str) -> tuple[str, int] | None:
                if bound is None:
                    return None
                name = str(bound["account"])
                balance, index = int(bound["balance"]), int(bound["index"])
                if not 0 <= index < size:
                    raise ValueError("boundary index out of range")
                if not (name < account if relation == "before" else account < name):
                    raise ValueError("boundary does not bracket the account")
                if not verify_proof(_leaf(name, balance), index, bound["path"], root):
                    raise ValueError("boundary proof does not match the root")
                return name, index

            left = check_bound(before, "before")
            right = check_bound(after, "after")
            # The two bounds must be adjacent leaves (or the single end leaf at a boundary),
            # otherwise an existing account could occupy a position inside the gap.
            if left is not None and right is not None:
                return left[0] < right[0] and right[1] == left[1] + 1
            if left is not None:
                return right is None and left[1] == size - 1
            if right is not None:
                return left is None and right[1] == 0
            return False
        except (KeyError, TypeError, ValueError, AttributeError):
            return False
