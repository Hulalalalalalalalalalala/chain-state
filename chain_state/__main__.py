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
    apply = sub.add_parser("apply", help="apply one set/delete transaction from inline JSON (- for stdin)")
    apply.add_argument("transaction", help="transaction JSON, or - to read it from stdin")
    read = sub.add_parser("get", help="read an account balance")
    read.add_argument("account")
    sub.add_parser("root", help="print the state root")
    prove = sub.add_parser("prove", help="print an inclusion proof as JSON")
    prove.add_argument("account")
    prove_absence = sub.add_parser("prove-absence", help="print an absence proof as JSON")
    prove_absence.add_argument("account")
    verify = sub.add_parser("verify", help="verify an inclusion proof")
    verify.add_argument("account")
    verify.add_argument("balance", type=int)
    verify.add_argument("proof", help="proof JSON, or - to read it from stdin")
    verify_absence = sub.add_parser("verify-absence", help="verify an absence proof")
    verify_absence.add_argument("account")
    verify_absence.add_argument("proof", help="proof JSON, or - to read it from stdin")
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
        elif args.command == "get":
            print(state.get(args.account))
        elif args.command == "root":
            print(state.state_root())
        elif args.command == "prove":
            print(json.dumps(state.prove(args.account), sort_keys=True))
        elif args.command == "prove-absence":
            print(json.dumps(state.prove_absence(args.account), sort_keys=True))
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
