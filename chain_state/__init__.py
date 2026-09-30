"""chain-state: an account state machine with a verifiable state root."""

__version__ = "0.2.0"

#: The technical domain this package belongs to.
DOMAIN = "blockchain-state"

#: Category headings in corpus.md whose tags this domain claims.
SOURCE_CATEGORIES = ("🧱 Layer1 / Layer2 / 公链核心", "🧾 智能合约 / Solidity / Move / WASM", "🌉 跨链 / 桥接 / 互操作")

from .state import State  # noqa: E402  (re-exported after the constants above)

__all__ = ["State", "DOMAIN", "SOURCE_CATEGORIES", "__version__"]
