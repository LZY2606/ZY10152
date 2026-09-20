# bgp-lab — 简化 BGP 策略沙箱

在**不连接真实路由器**的前提下试验简化的 BGP import/export 策略。系统对一个场景计算：

- 每个节点对每个前缀的**最优路径**（Adj-RIB-In → Loc-RIB 的完整选路过程）；
- 每条会话上的**对外发布结果**（UPDATE / WITHDRAW / 被过滤及原因）；
- 从初始注入到稳定（或已证明振荡）的**确定性收敛轨迹**；
- 某条路由被**接受、改写或拒绝的逐条规则理由**。

页面用**拓扑图**、**稳定时间线**和**单前缀决策树**展示同一场景；可以修改一条策略、撤回一条通告或注入邻居重启，在提交前查看影响的节点、前缀与发布差异。新场景是基于快照的**分支**，原场景与中间收敛步骤不被覆盖。

---

## 安装与演示

```bash
# 仅拉取锁定依赖（离线/可复现安装）
cargo fetch --locked

# 运行全部测试，然后在本机启动服务
cargo test --locked && cargo run --locked -- --listen 127.0.0.1:5352
```

打开浏览器：<http://127.0.0.1:5352>

可选参数：`--db <sqlite 路径>`（默认 `bgp-lab.sqlite`）。
离线导出某个内置场景的完整轨迹 JSON：`cargo run --bin dump -- dispute-wheel`。

---

## 策略子集（Policy subset）

策略挂在节点上，分为按顺序求值的 `import` 与 `export` 两个规则列表。

**匹配条件 `when`（多个条件之间为 AND）**

| 条件 | 说明 |
| --- | --- |
| `peer` | 对端节点 id（import 为发送方，export 为接收方） |
| `prefix` + `prefix_cmp` | 前缀，比较符 `eq/ne/in/not-in/matches`（`*`/`?` glob） |
| `as_path_len` + `as_path_len_cmp` | AS_PATH 长度，`eq/ne/gte/lte` |
| `as_path_contains` | 路径中必须包含的 AS 号 |
| `local_pref` / `med` + 比较符 | 属性比较 |
| `community_any` + `community_any_cmp` | community 存在性 `in/not-in` |

**动作 `do`**

- `set_local_pref`、`set_med`
- `add_community`、`remove_communities`
- `as_path_prepend`：在发送边界额外预挂本端 AS（eBGP 出口总会先自动追加一次本端 AS）

**三种命中语义（核心需求）**

1. **没有命中继续** — 条件不匹配，进入下一条规则，轨迹记为 `miss`；
2. **命中并继续** — `on_match: continue`，动作立即生效，求值继续，**后续条件看到的是改写后的新值**；
3. **终止接受 / 终止拒绝** — `on_match: accept | reject`，立即结束该策略求值。

全部规则都未终止时，使用策略默认（本实现默认 **accept**，逐条轨迹标记 `default-accept/default-reject`）。

### 协议级硬约束（独立于策略，始终带证据）

- **AS_PATH 环**：eBGP 收到的路由若 AS_PATH 已含本端 AS，按 RFC 4271 §9.1.2 **在入向拒绝**，并把该 UPDATE 视为该会话该 NLRI 的替换（旧 Adj-RIB-In 条目一并删除）。这与“策略拒绝”不同——策略拒绝会**保留**旧条目。两种拒绝都在轨迹中明确区分。
- **iBGP split-horizon**：从 iBGP 学到的路由不再向另一个 iBGP 对等体发布，以 `ibgp-split-horizon` 证据显示。

---

## 选路顺序（Best-path order）

`src/bestpath.rs` 严格按以下顺序比较，每一阶段都产出可展示的证据：

1. 最高 **LOCAL_PREF**
2. 最短 **AS_PATH**
3. 最低 **来源类型**（本地起源 `<` eBGP `<` iBGP）
4. 最低 **MED** —— **仅当左邻 AS（AS_PATH 最左 AS）相同才比较**；不同则跳过并在证据中标注 skipped
5. **eBGP 优于 iBGP**
6. 最低 **ingress 邻居 id**（router-id）
7. **最终确定性 tie-break**：对 `(BGP 属性, ingress 会话, 邻居 id)` 的稳定字典序键

第 6–7 阶段只可能分开“BGP 属性完全相同、仅入口不同”的路由。对这类**两个等价最优路径**，系统仍然选出唯一胜者，但会把另一条记录为 `equal_peer` 并展示最终 tie-break 键，因此：

- 结果**不依赖**哈希表迭代或并行消息处理顺序（同输入永远同胜者、同指纹）；
- tie-break 稳定且**可解释**。

---

## 收敛证据（Convergence evidence）

### 确定性虚拟事件队列

每个虚拟消息的比较键为
`(tick, seq, kind, session, prefix)`，同一会话同一前缀的排队消息会被更新的一条**取代**（UPDATE/WITHDRAW 替换语义）。`seq` 只用于入队顺序、**不进入状态签名**。因此重放同一场景输入会生成**逐字节相同的收敛轨迹指纹**（测试 `deterministic_trace_fingerprint_replays_identically`）。

### 三种结果

| 结果 | 含义 |
| --- | --- |
| `stable` | 事件队列清空，全局状态静止 |
| `oscillation` | 检测到**重复出现的全局状态签名**（含每个节点的 best / 等值对端 / Adj-RIB-In / 发布标记，以及用相对 tick 规范化后的待发队列） |
| `inconclusive` | 达到消息数安全上限但**没有**循环证据 |

**振荡不会**因为“超过迭代次数”被简单宣布失败：`inconclusive` 明确表示“没有证明”，而 `oscillation` 必须附带可核验证明：

- 重复的状态签名 `state_signature`
- 第一次 / 再次出现的步骤号与 tick
- 涉及的节点与前缀
- 构成循环的步骤区间

内置 fixture **`dispute-wheel`** 是 Griffin–Wilkie–Rexford BAD_GADGET 式环：A/B/C 三家客户对“经对端的间接路由”的偏好高于直连提供商，形成无稳定解的循环偏好。确定性引擎在第 10 步与第 26 步观察到同一全局状态并给出证明（不是撞上限）。把 `max_iterations` 调到 3 会得到 `inconclusive` 而不是被误报为振荡。

### 发布门槛

只有结果为 **stable** 或 **带可核验证明的 oscillation** 时，分支才允许提交（`POST /commit`）；`inconclusive` 返回 `409`。

---

## 场景与分支（快照模型）

- 场景 id = 输入（节点、会话、通告、事件、规则、延迟、引擎版本）规范化 JSON 的 SHA-256 前 16 位；同输入同规则指纹在 `computations` 表中**去重**，复用收敛轨迹指纹。
- `POST /api/scenarios/{id}/preview` 只计算**影响**（规则级差异、受影响节点/前缀、最优路径差异、对外发布差异），**不写场景**。
- `POST /api/scenarios/{id}/commit` 生成一个带 `parent_id` 的新不可变场景；原场景与其中间收敛步骤保持不变。
- `POST /api/drafts/diff` 对同一基场景的两个分支给出**规则级并发差异**，双方都改了同一规则但值不同时标记 `conflict`。

### HTTP API 摘要

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/scenarios` | 列出场景 |
| POST | `/api/scenarios` | 上传场景（按指纹去重）并计算 |
| GET | `/api/scenarios/{id}` | 输入 + 最新结果 |
| POST | `/api/scenarios/{id}/preview` | 编辑影响预览（不提交） |
| POST | `/api/scenarios/{id}/commit` | 提交为快照分支 |
| POST | `/api/drafts/diff` | 两分支的规则级差异 |
| GET | `/api/health` | 健康检查 |

编辑载荷示例：

```json
{
  "edits": {
    "rules": [{ "node": "R2", "direction": "import", "upsert": true,
      "rule": { "id": "block-r1", "when": {"peer": "R1"},
                "do": {}, "on_match": "reject" } }],
    "removed_rule_ids": [],
    "withdraw": ["ann-prefix-a"],
    "restart": ["R3"],
    "restart_tick": 25
  },
  "branch_name": "trial"
}
```

---

## 内置 fixture

| 名称 | 演示点 |
| --- | --- |
| `basic-preferences` | local-pref / community 改写、miss-continue、撤回级联 |
| `med-community-rewrite` | 命中并继续设置 MED，后续条件见新值，community 删除，terminate-reject |
| `as-path-loop` | **入向 AS_PATH 环拒绝**与 iBGP/环相关证据 |
| `equal-paths` | 两条属性相同的 eBGP 路由：唯一稳定胜者 + `equal_peer` 解释 |
| `dispute-wheel` | BAD_GADGET 循环偏好，可核验的重复全局状态证明 |

---

## 存储与实现

- Rust 后端（`tiny_http` + `rusqlite/bundled`），前端为嵌入二进制的原生 HTML/CSS/JS（无构建步骤）；
- SQLite 表：`scenarios`（含 `parent_id`）、`computations`（输入指纹去重）、`runs`（完整结果 JSON）、`drafts`（编辑草稿与基版本号）；
- 模块：`model`（数据模型）、`policy`（规则求值与逐条证据）、`bestpath`（选路）、`engine`（确定性事件队列与循环证明）、`scenario`（分支与并发差异）、`store`、`api`、`fixtures`。

## 测试

```bash
cargo test --locked
```

覆盖：偏好/撤回收敛、轨迹指纹重放一致、AS 环证据、等值路径稳定 tie-break、dispute-wheel 循环证明、安全上限返回 inconclusive、邻居重启确定性重收敛、快照分支不覆盖基场景。
