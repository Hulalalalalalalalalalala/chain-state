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
python3 -m chain_state --root ./state transfer alice bob 10
python3 -m chain_state --root ./state prove-absence alice
python3 -m chain_state --root ./state verify-absence alice <proof>
python3 -m chain_state --root ./state prove-prefix 3
python3 -m chain_state --root ./state verify-prefix 3 <proof>
python3 -m chain_state --root ./state prove-range 1 3
python3 -m chain_state --root ./state verify-range 1 3 <proof>
python3 -m chain_state --root ./state prove-name-range c e
python3 -m chain_state --root ./state verify-name-range c e <proof>
python3 -m chain_state --root ./state prove-many '["alice","bob"]'
echo '["alice","bob"]' | python3 -m chain_state --root ./state prove-many -
python3 -m chain_state --root ./state verify-many '["alice","bob"]' <root> <proof>
python3 -m chain_state --root ./state snapshot checkpoint
python3 -m chain_state --root ./state restore checkpoint
python3 -m chain_state --root ./state snapshots
```

`--root` 指向状态目录，不存在时由 `init` 创建。

子命令：`init`、`set <account> <balance>`、`get <account>`、`root`、`prove <account>`、`verify <account> <balance> <proof>`、`delete <account>`、`apply <transaction>`、`transfer <source> <target> <amount>`、`prove-absence <account>`、`verify-absence <account> <proof>`、`prove-prefix <count>`、`verify-prefix <count> <proof>`、`prove-range <start> <end>`、`verify-range <start> <end> <proof>`、`prove-name-range <start> <end>`、`verify-name-range <start> <end> <proof>`、`prove-many <accounts>`、`verify-many <accounts> <expected-root> <proof>`、`snapshot <label>`、`restore <label>`、`snapshots`、`report`。

`apply` 的位置参数为内联交易 JSON，值为 `-` 时从 stdin 读取。交易只许含 `set` 对象与 `delete` 数组（两字段省略或为空即空批次），成功只输出版本号；非法交易以 2 退出，未 init 以 1 退出。

`prove-many` 的位置参数为内联账户 JSON 数组，值为 `-` 时改从 stdin 读取；`verify-many` 依次接收账户 JSON 数组（仅内联，不支持 `-`）、可信状态根与证明 JSON（证明参数支持 `-` 读 stdin）。生成成功以 0 退出，非法输入或未知账户以 2 退出，未 init 以 1 退出；验证成功输出 `valid` 并以 0 退出，失败输出 `invalid` 并以 1 退出，JSON 语法错误或缺少参数以 2 退出。

## 公开接口

`chain_state.State(root)`：

- `init() -> None` 建立空状态。
- `set(account, balance) -> int` 写入余额并返回新版本号。
- `get(account) -> int` 读取余额；账户不存在或已删除返回 0。
- `delete(account) -> int` 删除存在的账户并返回新版本号；账户不存在抛出 `KeyError`。写入 0 不是删除。
- `apply(transaction) -> int` 原子提交一笔交易：`set` 对象写入账户新余额、`delete` 数组删除账户，整批只增加一个版本；两字段省略或为空即空批次，返回当前版本且不写入。校验全部先于写入：结构或类型错误抛出 `ValueError`，删除不存在账户抛出 `KeyError`，失败后无可见变化。
- `transfer(source, target, amount) -> int` 原子转账：`source`、`target` 为不同的非空字符串，`amount` 为正的 JSON 整数（布尔不算整数）；source 已存在且余额充足，target 不存在则创建、已存在则在原余额上增加。成功时源账户减少 amount（变为 0 也保留账户记录），目标账户增加 amount，整次操作只增加一个版本并返回。所有校验与余额检查先于写入：参数或类型错误抛出 `ValueError`，source 不存在抛出 `KeyError`，余额不足抛出 `ValueError`，失败后账户、版本与状态根均不变。
- `version() -> int` 当前版本号。
- `state_root() -> str` 当前全部账户的状态根（十六进制）。
- `prove(account) -> dict` 该账户的包含证明。
- `verify(account, balance, proof) -> bool` 仅用证明与状态根验证。
- `prove_absence(account) -> dict` 账户不存在证明；账户当前存在（含余额为 0）时抛出 `KeyError`。
- `verify_absence(account, proof) -> bool` 仅凭证明验证账户不存在，不读取状态目录；任何不一致均返回 `False`。
- `prove_prefix(count) -> dict` 从最小名称起前 `count` 个账户的连续前缀证明；`count` 须为非负 JSON 整数，大于账户数抛 `ValueError`。非空状态的 count 0 无法锚定 root，抛 `ValueError`；空状态的 count 0 以空树根生成空 items。
- `verify_prefix(count, proof) -> bool` 仅凭证明验证名称升序连续前缀，不读取状态目录；`count` 非法或任何不一致均返回 `False`。
- `prove_range(start, end) -> dict` 名称升序索引半开区间 `[start, end)` 的连续区间证明；`start`、`end` 须为非负 JSON 整数且满足 `start < end <= 账户数`，否则抛 `ValueError`。
- `verify_range(start, end, proof) -> bool` 仅凭证明验证名称升序的连续索引区间，不读取状态目录；参数非法或任何不一致均返回 `False`。
- `prove_name_range(start, end) -> dict` 账户名称半开区间 `start <= account < end` 的区间证明，区间允许为空；`start`、`end` 须为非空字符串且 `start < end`，否则抛 `ValueError`。证明只含 `start`、`end`、`root`、`size`、`prev`、`next`、`items`：items 升序覆盖区间内全部账户（完整列表序号），prev/next 为 `start` 前一账户与 `end` 后一账户（端点外为 `null`），items 填满二者之间的序号空档；空状态无边界、无 items。
- `verify_name_range(start, end, proof) -> bool` 仅凭证明验证名称半开区间，不读取状态目录；参数非法、字段缺失或多余、名称或边界错误、items 断裂、路径不能重算 root 等任何不一致均返回 `False`。
- `prove_many(accounts) -> dict` 任意账户集合的紧凑包含证明；`accounts` 为非空数组，元素是互不重复的非空字符串，允许乱序。结构、类型非法或名称重复抛 `ValueError`，未知账户抛 `KeyError`，合法参数但状态未初始化抛 `FileNotFoundError`。零余额账户也可证明，生成不改变账户、版本或快照。
- `verify_many(accounts, expected_root, proof) -> bool` 仅凭证明与可信状态根验证，不读取状态目录；参数非法、字段缺失或多余、查询集合与 items 不符、名称或索引未严格递增、节点位置越界、节点重复或冗余、节点不能全部用完或重算根不等于 `proof.root`/可信根等任何不一致均返回 `False`，合法证明返回 `True`。
- `create_snapshot(label) -> int` 在不改变当前账户、版本与状态根的前提下，把当前 accounts 的独立副本连同调用前版本、状态根保存为名为 `label` 的快照，返回调用前版本；`label` 须为非空字符串，同名快照已存在抛 `ValueError`。
- `restore_snapshot(label) -> int` 用快照 accounts 完整替换当前账户映射，使状态根严格等于快照 root，版本只增加一次并返回新版本；即使内容相同也增加版本，原快照保持不变、可重复恢复。`label` 非法抛 `ValueError`，未知 label 抛 `KeyError`；快照缺字段、类型错误或 root 不能由 accounts 重算时抛 `ValueError`，且任何失败都不改变账户、版本、状态根或快照集合。
- `list_snapshots() -> dict` 只读返回独立副本，按 label 排序；每个值只含 `accounts`（账户名到非负整数余额）、`version`（创建时版本）与 `root`（64 个小写十六进制字符）。

### 快照

快照随 `state.json` 持久化在 `snapshots` 字段中；没有该字段的旧状态文件按空集合兼容读取，状态根仍只由账户与余额决定。

- `snapshot <label>` 成功输出版本号（快照前版本）；`restore <label>` 成功输出新版本号；`snapshots` 以稳定键顺序输出快照映射的 JSON。
- 未 init 以 1 退出；label 非法、重复创建、未知恢复与损坏快照以 2 退出；合法命令以 0 退出。`verify*` 仍只凭证明验证，不读取状态目录或快照。

### 前缀证明

证明为可序列化 JSON，只含 `count`、`root`、`size`、`items`：

- `items` 按名称严格升序，索引从 0 连续到 count-1，每项只含 `account`、`balance`、`index`、`path`，路径沿用包含证明格式，每项都须重算同一 `root`。
- 验证方拒绝 `count` 不符、`size < count`、负数或非整数余额、索引断裂、非严格升序及路径错误。
- 空状态的 count 0：`items` 为空，`root` 必须等于空树状态根。

### 区间证明

证明为可序列化 JSON，只含 `start`、`end`、`root`、`size`、`items`，其中 `start`、`end` 是账户名称升序列表上的半开区间 `[start, end)`：

- `items` 恰好覆盖索引 `start` 到 `end-1`，按名称严格升序，每项只含 `account`、`balance`、`index`、`path`，路径沿用包含证明格式，每项都须重算同一 `root`。
- 验证方拒绝顶层字段缺失或多余、参数与证明内 `start`/`end` 不一致、`size < end`、`root` 不是 64 个小写十六进制字符、items 数量不符、索引断裂、名称非严格升序、负数或非整数余额及路径错误。
- 区间不能为空（`start < end`）；空状态没有可证明的区间。
- 证明位置参数可直接传 JSON 文本，也可传 `-` 从 stdin 读取（与其它 verify 命令一致）。

### 不存在证明

证明为可序列化 JSON，包含 `account`、`root`、`size`，以及按名称排序后夹住目标账户的边界：

- 空状态：`size` 为 0，无边框，`root` 必须等于空树的状态根。
- 目标位于所有账户之前/之后：仅给出后继（索引 0）或前驱（索引 size-1）。
- 目标位于两个账户之间：同时给出前驱与后继，且二者索引相邻。

每条边界自带该账户的包含路径，验证方据此在不知晓全量状态的情况下确认边界真实、名称严格夹逼目标。

### 多账户紧凑包含证明

证明为可序列化 JSON，只含 `root`、`size`、`items`、`nodes`：

- `root` 为现有状态根（64 个小写十六进制字符），`size` 为正整数账户总数。
- `items` 为数组，按账户名严格升序，每项只含 `account`、`balance`（非负整数）、`index`（该账户在全量名称排序中的位置，`0 <= index < size`）；账户名与索引都严格递增。
- `nodes` 为数组，每项只含 `level`、`index`、`hash`：`level` 从叶层 0 起，`index` 为该层从 0 起的位置，数组按 `(level, index)` 严格升序，`hash` 为 64 个小写十六进制字符。
- `nodes` 恰好包含把 `items` 连接到根所缺的**真实兄弟节点**：能由所选账户或较低层节点重建的节点一律不含，奇数层末节点的复制项不单独给出（验证方按现有树规则自行复制末节点），同一位置只出现一次。选中全部账户时 `nodes` 为空。
- 验证方不读状态目录：检查查询集合与 `items` 完全一致、名称与索引严格递增、节点位置在 `size` 决定的树形范围内，随后逐层重算，所有节点必须恰好被用完一次，重算出的根同时等于 `proof.root` 与传入的可信根。查询集合不符、字段缺失或多余、重复或冗余节点、越界位置、布尔冒充整数或根不符均判定为 `invalid`。
- `prove-many` 的账户参数与 `verify-many` 的证明参数都可传 `-` 从 stdin 读取；`verify-many` 的账户数组与可信根只接受内联参数。

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
