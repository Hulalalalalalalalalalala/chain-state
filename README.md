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
python3 -m chain_state --root ./state prove-lookup '["alice","bob","carol"]'
echo '["alice","bob","carol"]' | python3 -m chain_state --root ./state prove-lookup -
python3 -m chain_state --root ./state verify-lookup '["alice","bob","carol"]' <root> <proof>
python3 -m chain_state --root ./state prove-page '' 10
python3 -m chain_state --root ./state verify-page '' 10 <root> <proof>
python3 -m chain_state --root ./state prove-update '{"alice": 50, "bob": 0}'
echo '{"alice": 50}' | python3 -m chain_state --root ./state prove-update -
python3 -m chain_state --root ./state verify-update '{"alice": 50}' <root> <proof>
python3 -m chain_state --root ./state snapshot checkpoint
python3 -m chain_state --root ./state restore checkpoint
python3 -m chain_state --root ./state snapshots
```

`--root` 指向状态目录，不存在时由 `init` 创建。

子命令：`init`、`set <account> <balance>`、`get <account>`、`root`、`prove <account>`、`verify <account> <balance> <proof>`、`delete <account>`、`apply <transaction>`、`transfer <source> <target> <amount>`、`prove-absence <account>`、`verify-absence <account> <proof>`、`prove-prefix <count>`、`verify-prefix <count> <proof>`、`prove-range <start> <end>`、`verify-range <start> <end> <proof>`、`prove-name-range <start> <end>`、`verify-name-range <start> <end> <proof>`、`prove-many <accounts>`、`verify-many <accounts> <expected-root> <proof>`、`prove-lookup <accounts>`、`verify-lookup <accounts> <expected-root> <proof>`、`prove-page <start> <limit>`、`verify-page <start> <limit> <expected-root> <proof>`、`prove-update <updates>`、`verify-update <updates> <expected-root> <proof>`、`snapshot <label>`、`restore <label>`、`snapshots`、`report`。

`apply` 的位置参数为内联交易 JSON，值为 `-` 时从 stdin 读取。交易只许含 `set` 对象与 `delete` 数组（两字段省略或为空即空批次），成功只输出版本号；非法交易以 2 退出，未 init 以 1 退出。

`prove-many` 的位置参数为内联账户 JSON 数组，值为 `-` 时改从 stdin 读取；`verify-many` 依次接收账户 JSON 数组（仅内联，不支持 `-`）、可信状态根与证明 JSON（证明参数支持 `-` 读 stdin）。生成成功以 0 退出，非法输入或未知账户以 2 退出，未 init 以 1 退出；验证成功输出 `valid` 并以 0 退出，失败输出 `invalid` 并以 1 退出，JSON 语法错误或缺少参数以 2 退出。

`prove-lookup` 的参数与 stdin 支持对齐 `prove-many`（账户 JSON 数组，`-` 从 stdin 读取），但未知账户是正常结果而非错误；`verify-lookup` 的参数对齐 `verify-many`（账户 JSON 数组仅内联、可信状态根、证明 JSON 支持 `-`）。生成成功以 0 退出，非法输入以 2 退出，未 init 以 1 退出；验证输出 `valid`/`invalid` 并分别以 0/1 退出，JSON 语法错误或缺少参数以 2 退出。

`prove-page` 依次接收名称起点 `start`（字符串，允许空串表示从首个账户开始）与正整数 `limit`（布尔不算整数）；`verify-page` 依次接收 `start`、`limit`、可信状态根与证明 JSON（证明参数支持 `-` 读 stdin）。生成成功输出证明 JSON 并以 0 退出，非法参数以 2 退出，未 init 以 1 退出；验证对参数非法、字段缺失或多余、类型错误、漏项、乱序、违规节点或根不符统一输出 `invalid` 并以 1 退出，成功输出 `valid` 并以 0 退出，JSON 语法错误或缺参数以 2 退出。

`prove-update` 的位置参数为内联更新 JSON 对象（账户名到新余额），值为 `-` 时改从 stdin 读取；`verify-update` 依次接收仅内联的更新 JSON 对象、可信旧根与证明 JSON（证明参数支持 `-` 读 stdin）。生成成功输出证明并以 0 退出，非法输入或未知账户以 2 退出，未 init 以 1 退出；验证输出 `valid`/`invalid` 并分别以 0/1 退出，JSON 语法错误或缺参数以 2 退出。生成与验证都不改变账户、版本、快照与持久化内容。

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
- `prove_lookup(accounts) -> dict` 一次查询同时证明账户存在或不存在的紧凑证明；`accounts` 为非空数组，元素是互不重复的非空字符串，允许乱序，按名称排序处理。未知账户是正常结果，零余额账户仍算存在；结构、类型非法或名称重复抛 `ValueError`，合法参数但状态未初始化抛 `FileNotFoundError`。生成不改变账户、版本、状态根或快照。
- `verify_lookup(accounts, expected_root, proof) -> bool` 仅凭证明与可信状态根验证存在/不存在查询，不读取状态目录；参数非法、查询集合与 results 不符、存在结果与同名条目不符、不满足既有不存在证明的名称夹逼及相邻边界规则、无关或缺失条目、违规节点、字段缺失或多余、非法类型与布尔冒充整数均返回 `False`；全部约束满足且重算根同时等于 `proof.root` 与可信根时返回 `True`。
- `prove_page(start, limit) -> dict` 名称分页证明：返回名称升序中不小于 `start` 的前 `limit` 个账户。`start` 为字符串（允许空串，从首个账户起），`limit` 为正的 JSON 整数（布尔不算整数），否则抛 `ValueError`；合法参数但状态未初始化抛 `FileNotFoundError`。零余额账户仍参与分页；生成不改变账户、版本、状态根或快照。
- `verify_page(start, limit, expected_root, proof) -> bool` 仅凭参数、可信状态根与证明验证名称分页，不读取状态目录；`expected_root` 须为 64 个小写十六进制字符。检查名称关系、连续全量索引、页长不超过 `limit`、不满页时 `next` 为 `null`、边界与条目共用的最小节点全部用完且重算根同时等于 `proof.root` 与可信根；参数非法、字段缺失或多余、类型错误、漏项、乱序、违规节点或根不符均返回 `False`，合法证明返回 `True`。
- `prove_update(updates) -> dict` 只读的余额更新预览证明：`updates` 为非空 JSON 对象，账户名是非空字符串、新余额是非负 JSON 整数（布尔不算整数）。结构与类型校验先于读取状态：非法输入抛 `ValueError`，合法但未初始化抛 `FileNotFoundError`，任一账户不存在抛 `KeyError`；零余额账户仍算存在。证明只含 `root`、`new_root`、`size`、`items`、`nodes`：`root` 为当前根，`new_root` 为仅替换指定余额后的完整状态根，`items` 恰好含更新集合的旧余额（条目格式、排序、索引与节点最小规则沿用多账户证明）。更新全部账户时 `nodes` 为空；全部余额不变时两根相等。生成不改变账户、版本、快照与持久化内容，也不修改输入。
- `verify_update(updates, expected_root, proof) -> bool` 仅凭更新对象、可信旧根与证明验证，不读取状态目录；仅当旧根等于可信根、新根对应指定余额替换且其余账户不变时返回 `True`。参数非法、字段缺失或多余、集合不符、类型错误（含布尔冒充整数）、乱序、索引越界、节点缺失重复或冗余、任一根不符均返回 `False`。
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

### 存在/不存在混合查询证明

证明为可序列化 JSON，只含 `root`、`size`、`results`、`items`、`nodes`：

- `root` 沿用当前状态根（64 个小写十六进制字符），`size` 为非负整数账户总数。
- `results` 按查询名称严格升序，每项只含 `account`、`index`、`prev`、`next`。存在账户（含零余额）的 `index` 为同名账户的全量排序位置，`prev`、`next` 均为 `null`；不存在账户的 `index` 为 `null`，`prev`、`next` 为立即前驱、后继的全量索引（越过首/尾用 `null`），夹逼与相邻规则与不存在证明一致。
- `items` 沿用多账户证明的条目格式（每项只含 `account`、`balance`、`index`），恰好覆盖存在查询账户与全部所需边界的去重并集，名称与索引严格递增；`nodes` 沿用其节点格式、排序与最小兄弟节点规则，全部条目共用一份证明。
- 验证方不读状态目录：检查查询集合与 `results` 完全一致且按名升序、存在结果与同名同索引条目一致、不存在结果的边界名称严格夹逼且索引相邻、`items` 不多不少恰好覆盖所需条目、节点规则与多账户证明相同，重算出的根同时等于 `proof.root` 与可信根。查询集合不符、无关或缺失条目、违规节点、字段缺失或多余、布尔冒充整数或根不符均判定为 `invalid`。
- 空状态使用既有空树根，`size` 为 0，`items` 与 `nodes` 为空，各结果的 `index`、`prev`、`next` 均为 `null`。
- `prove-lookup` 的账户参数与 `verify-lookup` 的证明参数都可传 `-` 从 stdin 读取；`verify-lookup` 的账户数组与可信根只接受内联参数。

### 名称分页证明

证明为可序列化 JSON，只含 `start`、`limit`、`root`、`size`、`prev`、`next`、`items`、`nodes`：

- `start`、`limit` 与生成参数一致；`root` 为当前状态根（64 个小写十六进制字符），`size` 为账户总数。
- `items` 为本页账户：名称升序中不小于 `start` 的前 `limit` 个账户，按名称严格升序、全量索引连续递增，条目格式沿用多账户证明（每项只含 `account`、`balance`、`index`，余额为非负整数，零余额账户仍在页内）。
- `prev` 为首个符合起点账户的立即前驱（即 `start` 之前紧邻的账户），越过首端为 `null`；`next` 为本页之后的立即后继（最后一个条目索引的紧邻后一账户），越过尾端或本页不满 `limit` 时为 `null`。`prev`/`next` 采用与 `items` 相同的紧凑条目格式，不携带独立路径。
- `nodes` 沿用多账户证明的节点格式、排序与最小兄弟节点规则，由本页条目与非空边界去重后共用一份多证明，不含独立路径或其他账户。
- 验证方不读状态目录：核对查询字段与参数一致、可信根为 64 个小写十六进制字符且等于 `proof.root`，检查 `items` 名称均不小于 `start` 且严格升序、索引连续、页长不超过 `limit`，`prev` 名称严格小于 `start` 且紧贴本页起点，`next` 名称严格大于本页末账户且紧贴下一索引，不满页时 `next` 必须为 `null`；随后逐层重算，所有节点必须恰好用完一次，重算出的根同时等于 `proof.root` 与可信根。参数非法、字段缺失或多余、类型错误（含布尔冒充整数）、漏项、乱序、违规节点或根不符均判定为 `invalid`。
- 空状态使用既有空树根，`size` 为 0，`prev`、`next` 为 `null`，`items`、`nodes` 为空；起点超过尾账户时返回空页，`prev` 为尾账户、`next` 为 `null`。
- 翻页：`next` 非空时以其 `account` 作为下一页的 `start`（下一页的 `prev` 即上一页末账户）；`next` 为 `null` 表示已到末尾。
- `verify-page` 的证明参数可传 `-` 从 stdin 读取；`start`、`limit` 与可信根只接受内联位置参数。

### 余额更新预览证明

只读证明，凭可信旧根确认一次尚未写入的余额更新所对应的新状态根。证明为可序列化 JSON，只含 `root`、`new_root`、`size`、`items`、`nodes`：

- `root` 为当前状态根（64 个小写十六进制字符），`new_root` 为仅把指定账户余额替换为新值、其余账户保持不变后的完整状态根，`size` 为账户总数（正整数）。
- `items` 恰好覆盖更新集合，按账户名严格升序，每项只含 `account`、`balance`（**旧**余额，非负整数）、`index`（全量名称排序位置，`0 <= index < size`），不附带其他账户的明文余额或独立路径。
- `nodes` 沿用多账户证明的节点格式、排序与最小兄弟节点规则，新旧两棵树共用同一份节点：每个所需兄弟子树都不含被更新账户，故其哈希在两树间不变，验证方据此分别重算两根。更新全部账户时 `nodes` 为空；全部新余额等于旧余额时 `new_root == root`。
- 验证方不读状态目录：核对更新对象非空且名称/余额合法、查询集合与 `items` 完全一致、名称与索引严格递增、节点规则与多账户证明相同，先用旧余额叶子重算 `root`（须同时等于 `proof.root` 与可信根），再仅替换命名叶子的余额重算 `new_root`；两次重算都必须把所有节点恰好用完一次。更新对象与证明集合不符、字段缺失或多余、类型错误（含布尔冒充整数）、乱序、索引越界、节点缺失、重复或冗余、任一根不符均判定为 `invalid`。
- `prove-update` 的更新对象与 `verify-update` 的证明参数都可传 `-` 从 stdin 读取；`verify-update` 的更新对象与可信根只接受内联参数。预览不写入：账户、版本、快照与持久化内容均不变。

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
