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
python3 -m chain_state --root ./state apply '{"set": {"bob": 5}, "delete": ["alice"]}'
echo '{"set": {"bob": 5}}' | python3 -m chain_state --root ./state apply -
python3 -m chain_state --root ./state prove-absence alice
python3 -m chain_state --root ./state verify-absence alice <proof>
python3 -m chain_state --root ./state prove-prefix 2
python3 -m chain_state --root ./state verify-prefix 2 <proof>
```

`--root` 指向状态目录，不存在时由 `init` 创建。

子命令：`init`、`set <account> <balance>`、`get <account>`、`root`、`prove <account>`、`verify <account> <balance> <proof>`、`delete <account>`、`apply <transaction>`、`prove-absence <account>`、`verify-absence <account> <proof>`、`prove-prefix <count>`、`verify-prefix <count> <proof>`、`report`。

`apply` 的位置参数为内联交易 JSON，值为 `-` 时从 stdin 读取。交易只许含 `set` 对象与 `delete` 数组（两字段省略或为空即空批次），成功只输出版本号；非法交易以 2 退出，未 init 以 1 退出。

## 公开接口

`chain_state.State(root)`：

- `init() -> None` 建立空状态。
- `set(account, balance) -> int` 写入余额并返回新版本号。
- `get(account) -> int` 读取余额；账户不存在或已删除返回 0。
- `delete(account) -> int` 删除存在的账户并返回新版本号；账户不存在抛出 `KeyError`。写入 0 不是删除。
- `apply(transaction) -> int` 原子提交一笔交易：`set` 对象写入账户新余额、`delete` 数组删除账户，整批只增加一个版本；两字段省略或为空即空批次，返回当前版本且不写入。校验全部先于写入：结构或类型错误抛出 `ValueError`，删除不存在账户抛出 `KeyError`，失败后无可见变化。
- `version() -> int` 当前版本号。
- `state_root() -> str` 当前全部账户的状态根（十六进制）。
- `prove(account) -> dict` 该账户的包含证明。
- `verify(account, balance, proof) -> bool` 仅用证明与状态根验证。
- `prove_absence(account) -> dict` 账户不存在证明；账户当前存在（含余额为 0）时抛出 `KeyError`。
- `verify_absence(account, proof) -> bool` 仅凭证明验证账户不存在，不读取状态目录；任何不一致均返回 `False`。
- `prove_prefix(count) -> dict` 名称升序前缀证明：给出从最小名称开始的连续 `count` 个账户与余额；`count` 为非法类型、负数或超过账户数时抛出 `ValueError`，非空状态下 `count` 为 0 无法锚定 root 同样抛出 `ValueError`。
- `verify_prefix(count, proof) -> bool` 仅凭证明验证前缀，不读取状态目录；非法 `count` 或任何不一致均返回 `False`。

### 前缀证明

证明为可序列化 JSON，只含 `count`、`root`、`size`、`items`：

- `items` 按名称严格升序，每项只含 `account`、`balance`、`index`、`path`，索引从 0 连续到 `count-1`，`path` 沿用包含证明的兄弟路径格式。
- 验证方逐项重算同一 `root`，并核对名称升序、余额为非负整数、索引连续、`size >= count`。
- 空状态的 `count` 0 生成并验证空 `items`，`root` 为空树根；非空状态的 `count` 0 无法锚定 root，生成抛 `ValueError`、验证返回 `False`。

### 不存在证明

证明为可序列化 JSON，包含 `account`、`root`、`size`，以及按名称排序后夹住目标账户的边界：

- 空状态：`size` 为 0，无边框，`root` 必须等于空树的状态根。
- 目标位于所有账户之前/之后：仅给出后继（索引 0）或前驱（索引 size-1）。
- 目标位于两个账户之间：同时给出前驱与后继，且二者索引相邻。

每条边界自带该账户的包含路径，验证方据此在不知晓全量状态的情况下确认边界真实、名称严格夹逼目标。

## 约定

- 状态根必须只由账户与余额决定，与写入顺序无关。
- 证明必须能被**不知道全量状态**的一方验证通过。
- 余额为非负整数；非法输入抛出 `ValueError`。
- 验证命令成功输出 `valid` 并以 0 退出，失败输出 `invalid` 并以 1 退出；证明 JSON 语法错误属于用法错误（退出码 2）。

## 限制

- 单进程、单文件状态，无并发写保护。
- 未实现分叉与重组；版本号只增不减。

## 语料

`corpus.md` 是本项目对应的技术标签语料（GitHub 热门技术标签，含 Layer1/Layer2、智能合约、跨链等分类）。
