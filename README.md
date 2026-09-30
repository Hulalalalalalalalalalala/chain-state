# chain-state

最小的账户状态机，以及可对外的**状态根**与**包含证明**。用于演示"链上状态 + 轻客户端验证"这一族问题。

## 依赖

仅标准库（Python 3.10+）。不需要第三方包、不需要网络。

## 安装与运行

无需安装，直接以模块方式运行：

```bash
python3 -m chain_state --root ./state init
python3 -m chain_state --root ./state set alice 100
python3 -m chain_state --root ./state get alice
python3 -m chain_state --root ./state root
python3 -m chain_state --root ./state prove alice
python3 -m chain_state --root ./state verify alice 100 <proof>
python3 -m chain_state --root ./state delete alice
python3 -m chain_state --root ./state prove-absence alice
python3 -m chain_state --root ./state verify-absence alice <proof>
```

`--root` 指向状态目录，不存在时由 `init` 创建。

子命令：`init`、`set <account> <balance>`、`get <account>`、`root`、`prove <account>`、`verify <account> <balance> <proof>`、`delete <account>`、`prove-absence <account>`、`verify-absence <account> <proof>`、`report`。

## 公开接口

`chain_state.State(root)`：

- `init() -> None` 建立空状态。
- `set(account, balance) -> int` 写入余额并返回新版本号。
- `get(account) -> int` 读取余额；账户不存在或已删除返回 0。
- `delete(account) -> int` 删除存在的账户并返回新版本号；账户不存在抛出 `KeyError`。
- `version() -> int` 当前版本号。
- `state_root() -> str` 当前全部账户的状态根（十六进制）。
- `prove(account) -> dict` 该账户的包含证明。
- `verify(account, balance, proof) -> bool` 仅用证明与状态根验证。
- `prove_absence(account) -> dict` 不存在账户的不存在证明；账户存在时抛出 `KeyError`。
- `verify_absence(account, proof) -> bool` 仅用证明验证账户不存在，不读取状态目录。

不存在证明是可序列化 JSON，包含 `account`、`root`、`size` 以及排序哈希边界 `before`/`after`（各自带包含证明，列表端头为 `null`）。账户或证明被改动、root 不符、索引或边界不闭合时返回 `False`，不抛异常。

## 约定

- 状态根必须只由账户与余额决定，与写入顺序无关。
- 证明必须能被**不知道全量状态**的一方验证通过。
- 余额为非负整数；非法输入抛出 `ValueError`。
- `set` 写入 0 仍是余额为 0 的账户（账户存在），不等于删除。

## 限制

- 单进程、单文件状态，无并发写保护。
- 未实现分叉与重组；版本号只增不减。

## 语料

`corpus.md` 是本项目对应的技术标签语料（GitHub 热门技术标签，含 Layer1/Layer2、智能合约、跨链等分类）。
