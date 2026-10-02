"""Command line entry point: ``python3 -m chain_state --root <dir> <subcommand>``.

Exit codes: 0 success, 1 a state or verification error, 2 a usage error.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import DOMAIN, SOURCE_CATEGORIES, __version__
from .state import State

USAGE_ERROR = 2


def _non_negative_int(text: str) -> int:
    """argparse type: exactly a non-negative JSON integer (booleans rejected)."""
    try:
        value = json.loads(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a non-negative JSON integer, got {text!r}")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise argparse.ArgumentTypeError(f"expected a non-negative JSON integer, got {text!r}")
    return value


def _positive_int(text: str) -> int:
    """argparse type: exactly a positive JSON integer (booleans rejected)."""
    try:
        value = json.loads(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a positive JSON integer, got {text!r}")
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise argparse.ArgumentTypeError(f"expected a positive JSON integer, got {text!r}")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chain_state", description="Account state machine with a verifiable state root")
    parser.add_argument("--root", required=True, help="state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an empty state")
    write = sub.add_parser("set", help="write an account balance")
    write.add_argument("account")
    write.add_argument("balance", type=int)
    delete = sub.add_parser("delete", help="remove an existing account")
    delete.add_argument("account")
    apply = sub.add_parser("apply", help="apply one set/delete transaction from inline JSON")
    apply.add_argument("transaction", help="transaction JSON, or - to read it from stdin")
    transfer = sub.add_parser("transfer", help="atomically move funds from one account to another")
    transfer.add_argument("source")
    transfer.add_argument("target")
    transfer.add_argument("amount", type=_positive_int)
    read = sub.add_parser("get", help="read an account balance")
    read.add_argument("account")
    sub.add_parser("root", help="print the state root")
    snapshot = sub.add_parser("snapshot", help="save the current accounts under a label")
    snapshot.add_argument("label")
    restore = sub.add_parser("restore", help="replace the current accounts with a saved snapshot")
    restore.add_argument("label")
    sub.add_parser("snapshots", help="print every saved snapshot as JSON")
    prove = sub.add_parser("prove", help="print an inclusion proof as JSON")
    prove.add_argument("account")
    prove_absence = sub.add_parser("prove-absence", help="print an absence proof as JSON")
    prove_absence.add_argument("account")
    prove_prefix = sub.add_parser("prove-prefix", help="print an ascending name-prefix proof as JSON")
    prove_prefix.add_argument("count", type=_non_negative_int)
    prove_range = sub.add_parser("prove-range", help="print an ascending index-range proof as JSON")
    prove_range.add_argument("start", type=_non_negative_int)
    prove_range.add_argument("end", type=_non_negative_int)
    prove_name_range = sub.add_parser("prove-name-range", help="print a name half-range proof as JSON")
    prove_name_range.add_argument("start")
    prove_name_range.add_argument("end")
    prove_many = sub.add_parser("prove-many", help="print a compact inclusion proof for many accounts as JSON")
    prove_many.add_argument("accounts", help="accounts JSON array, or - to read it from stdin")
    prove_update = sub.add_parser("prove-update", help="preview a balance update and print its read-only proof as JSON")
    prove_update.add_argument("updates", help="updates JSON object, or - to read it from stdin")
    prove_lookup = sub.add_parser("prove-lookup", help="print a compact existence/absence lookup proof for many accounts as JSON")
    prove_lookup.add_argument("accounts", help="accounts JSON array, or - to read it from stdin")
    prove_page = sub.add_parser("prove-page", help="print a name-paginated proof as JSON")
    prove_page.add_argument("start", help="name to start at (the empty string starts at the first account)")
    prove_page.add_argument("limit", type=_positive_int)
    verify = sub.add_parser("verify", help="verify an inclusion proof")
    verify.add_argument("account")
    verify.add_argument("balance", type=int)
    verify.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_absence = sub.add_parser("verify-absence", help="verify an absence proof")
    verify_absence.add_argument("account")
    verify_absence.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_prefix = sub.add_parser("verify-prefix", help="verify an ascending name-prefix proof")
    verify_prefix.add_argument("count", type=_non_negative_int)
    verify_prefix.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_range = sub.add_parser("verify-range", help="verify an ascending index-range proof")
    verify_range.add_argument("start", type=_non_negative_int)
    verify_range.add_argument("end", type=_non_negative_int)
    verify_range.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_name_range = sub.add_parser("verify-name-range", help="verify a name half-range proof")
    verify_name_range.add_argument("start")
    verify_name_range.add_argument("end")
    verify_name_range.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_many = sub.add_parser("verify-many", help="verify a compact inclusion proof for many accounts")
    verify_many.add_argument("accounts", help="accounts JSON array (inline only)")
    verify_many.add_argument("expected_root")
    verify_many.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_update = sub.add_parser("verify-update", help="verify an update preview proof")
    verify_update.add_argument("updates", help="updates JSON object (inline only)")
    verify_update.add_argument("expected_root")
    verify_update.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_lookup = sub.add_parser("verify-lookup", help="verify a compact existence/absence lookup proof for many accounts")
    verify_lookup.add_argument("accounts", help="accounts JSON array (inline only)")
    verify_lookup.add_argument("expected_root")
    verify_lookup.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_page = sub.add_parser("verify-page", help="verify a name-paginated proof")
    verify_page.add_argument("start")
    verify_page.add_argument("limit", type=_positive_int)
    verify_page.add_argument("expected_root")
    verify_page.add_argument("proof", help="proof JSON, or - to read it from stdin")
    sub.add_parser("report", help="print this domain's report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    state = State(args.root)
    try:
        if args.command == "init":
            state.init()
            print(f"initialised {state.path}")
        elif args.command == "set":
            print(state.set(args.account, args.balance))
        elif args.command == "delete":
            print(state.delete(args.account))
        elif args.command == "apply":
            raw = sys.stdin.read() if args.transaction == "-" else args.transaction
            print(state.apply(json.loads(raw)))
        elif args.command == "transfer":
            print(state.transfer(args.source, args.target, args.amount))
        elif args.command == "get":
            print(state.get(args.account))
        elif args.command == "root":
            print(state.state_root())
        elif args.command == "snapshot":
            print(state.create_snapshot(args.label))
        elif args.command == "restore":
            print(state.restore_snapshot(args.label))
        elif args.command == "snapshots":
            print(json.dumps(state.list_snapshots(), sort_keys=True))
        elif args.command == "prove":
            print(json.dumps(state.prove(args.account), sort_keys=True))
        elif args.command == "prove-absence":
            print(json.dumps(state.prove_absence(args.account), sort_keys=True))
        elif args.command == "prove-prefix":
            print(json.dumps(state.prove_prefix(args.count), sort_keys=True))
        elif args.command == "prove-range":
            print(json.dumps(state.prove_range(args.start, args.end), sort_keys=True))
        elif args.command == "prove-name-range":
            print(json.dumps(state.prove_name_range(args.start, args.end), sort_keys=True))
        elif args.command == "prove-many":
            raw = sys.stdin.read() if args.accounts == "-" else args.accounts
            print(json.dumps(state.prove_many(json.loads(raw)), sort_keys=True))
        elif args.command == "prove-update":
            raw = sys.stdin.read() if args.updates == "-" else args.updates
            print(json.dumps(state.prove_update(json.loads(raw)), sort_keys=True))
        elif args.command == "prove-lookup":
            raw = sys.stdin.read() if args.accounts == "-" else args.accounts
            print(json.dumps(state.prove_lookup(json.loads(raw)), sort_keys=True))
        elif args.command == "prove-page":
            print(json.dumps(state.prove_page(args.start, args.limit), sort_keys=True))
        elif args.command == "verify":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            ok = state.verify(args.account, args.balance, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-absence":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            ok = state.verify_absence(args.account, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-prefix":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            ok = state.verify_prefix(args.count, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-range":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            ok = state.verify_range(args.start, args.end, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-name-range":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            ok = state.verify_name_range(args.start, args.end, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-many":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            accounts = json.loads(args.accounts)
            ok = state.verify_many(accounts, args.expected_root, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-update":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            updates = json.loads(args.updates)
            ok = state.verify_update(updates, args.expected_root, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-lookup":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            accounts = json.loads(args.accounts)
            ok = state.verify_lookup(accounts, args.expected_root, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "verify-page":
            raw = sys.stdin.read() if args.proof == "-" else args.proof
            ok = state.verify_page(args.start, args.limit, args.expected_root, json.loads(raw))
            print("valid" if ok else "invalid")
            return 0 if ok else 1
        elif args.command == "report":
            print(json.dumps({"domain": DOMAIN, "version": __version__, "sourceCategories": list(SOURCE_CATEGORIES),
                              "tags": _tags(), "components": ["state", "merkle"],
                              "readiness": {"stateRoot": True, "inclusionProof": True, "reorg": False}}, ensure_ascii=False, sort_keys=True))
        return 0
    except FileNotFoundError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (KeyError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return USAGE_ERROR


def _tags() -> list[str]:
    """Tags this domain claims: the comma-separated line that follows each named category heading."""
    import pathlib
    corpus = pathlib.Path(__file__).resolve().parent.parent / "corpus.md"
    if not corpus.is_file():
        return []
    wanted, tags, collect = set(SOURCE_CATEGORIES), [], False
    for line in corpus.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped in wanted:
            collect = True
            continue
        if not collect or not stripped:
            continue
        for token in stripped.split(","):
            token = token.strip().replace("\\", "")
            if token and token not in tags:
                tags.append(token)
        collect = False
    return tags


if __name__ == "__main__":
    raise SystemExit(main())
