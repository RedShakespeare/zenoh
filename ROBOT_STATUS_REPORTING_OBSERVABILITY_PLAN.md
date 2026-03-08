# Robot Status Reporting: Admin / Metrics 输出字段方案（MVP）

> 目标：在“最小可测试”前提下，为机器人状态上报能力提供稳定可观测性，支持联调、排障与后续平滑演进。

## 1. 已确认输入（来自需求拍板）

- `robot_id` 优先来源于证书；证书字段映射后续补充。
- `inactivity` 用于生产，默认超时 `10s`。
- HTTP 上报成功判定当前仅 `200`。
- 测试环境默认 `dry_run = false`。

## 2. 本方案定位

- 本方案先提供 **MVP 字段集**，优先保证可观测、可联调、可告警。
- 字段名后续允许按业务语义优化，但应遵守“向后兼容迁移策略”（见第 7 节）。

## 3. Admin 输出字段（面向人和排障）

建议在 admin 状态端点中新增或挂载以下字段：

| 字段名 | 类型 | 示例值 | 说明 |
|---|---|---|---|
| `enabled` | bool | `true` | feature `robot-status-reporting` 是否启用 |
| `report_mode` | string | `"http"` / `"dry_run"` | 上报模式 |
| `keepalive_mode` | string | `"transport_closed_only"` | keepalive 策略 |
| `inactivity_timeout_sec` | u64 | `10` | `keepalive_mode=inactivity` 时超时阈值（秒） |
| `tracked_sessions` | u64 | `3` | 当前会话跟踪表大小 |
| `last_report` | object\|null | 见下 | 最近一次上报摘要（可空） |

`last_report` 子字段建议：

| 子字段名 | 类型 | 示例值 | 说明 |
|---|---|---|---|
| `robot_id` | string | `"rb-001"` | 本次上报 robot 标识 |
| `status` | string | `"ONLINE"` / `"OFFLINE"` | 上报状态 |
| `trigger` | string | `"session_open"` / `"transport_closed"` / `"inactivity_timeout"` | 触发来源 |
| `http_code` | u16\|null | `200` | `dry_run` 或尚未发 HTTP 时可空 |
| `result` | string | `"success"` / `"failure"` | 上报结果 |
| `timestamp_ms` | u64 | `1734000000000` | 事件发生时间（epoch ms） |

## 4. Metrics 输出字段（面向监控/告警）

建议最小集合如下（Prometheus 风格示例）：

1. `robot_status_report_total{status, result}` (counter)
   - 例：`robot_status_report_total{status="ONLINE",result="success"}`
2. `robot_status_report_http_total{code}` (counter)
   - 仅 `report_mode=http` 递增
   - 例：`robot_status_report_http_total{code="200"}`
3. `robot_status_offline_trigger_total{trigger}` (counter)
   - 用于区分 OFFLINE 根因
   - 例：`trigger="transport_closed"` 或 `"inactivity_timeout"`
4. `robot_status_tracked_sessions` (gauge)
   - 当前跟踪中的会话数量

> 当前成功判定仅 `HTTP 200`。因此建议 `result=success` 与 `code=200` 强一致；其他码统一 `result=failure`。

## 5. 默认值与行为建议（MVP）

- 默认 `keepalive_mode = transport_closed_only`（更稳妥，降低误 OFFLINE 风险）。
- 如切到 `inactivity`：默认 `inactivity_timeout_sec = 10`（已拍板）。
- 默认 `report_mode = http`，测试环境也默认真实请求（`dry_run=false`）。

## 6. 告警与排障建议

可先配 2 条基础告警：

1. **连续上报失败告警**
   - 条件：`robot_status_report_total{result="failure"}` 在窗口内持续增长。
2. **OFFLINE 根因异常偏高告警**
   - 条件：`robot_status_offline_trigger_total{trigger="inactivity_timeout"}` 增速异常。

排障最短路径：

1. 看 admin `enabled/report_mode/keepalive_mode` 配置是否符合预期。
2. 看 `last_report` 的 `trigger/result/http_code`。
3. 对照 metrics 中 `*_total` 的最近增量，确认是单点故障还是系统性故障。

## 7. 字段改名兼容策略（你关心的“后续可能改名”）

为避免后续业务命名调整影响监控，建议按以下步骤演进：

1. **先加新字段，不立刻删旧字段**（双写至少 1 个发布周期）。
2. 在发布说明中声明旧字段弃用（deprecated）。
3. 监控面板与告警规则迁移完成后，再移除旧字段。
4. 指标改名时保留兼容映射（如 exporter 侧 relabel 或并行输出）。

## 8. 里程碑（建议）

- **M1**：实现第 3、4 节最小字段，不做复杂证书映射。
- **M2**：接入证书字段最终定义，稳定 `robot_id` 来源说明。
- **M3**：按业务需要优化字段命名，并按第 7 节执行兼容迁移。

### 8.1 PR 拆分硬性标准（新增）

为确保每次变更都可评审、可回滚、可验证，新增以下硬性约束：

1. **每个 PR 的总改动行数必须 `< 500` 行**（以 Git diff 行数为准）。
2. 统计范围包含：
   - 功能代码改动；
   - 单元测试/集成测试改动；
   - 必需的最小文档或配置改动。
3. 若单个目标超出 500 行，必须继续拆分为多个独立 PR（按可运行闭环切分）。
4. 每个 PR 必须自带可验证项（至少 1 条可执行测试或检查命令）。

## 9. 建议补充：业务命名可变时的“稳定语义层”

考虑到你已确认“字段名后续可能按业务实际调整”，建议从一开始把字段拆成两层：

1. **稳定语义键（内部/指标层）**
   - 尽量不改名，用于代码、告警规则、仪表盘数据源。
   - 例如：`robot_status_report_total{status,result}`、`offline_trigger`。
2. **业务展示名（外部/文档层）**
   - 可按业务术语演进。
   - 例如 `robot_id` 未来可展示为 `device_id`，但底层语义键先保持兼容。

这样做的收益：

- 业务名称可演进，不会频繁破坏告警规则。
- 评审时可以先对齐“语义正确”，再迭代“命名美观”。

## 10. 字段改名模板（可直接用于 PR/发布说明）

当你未来决定把某字段改成更贴近业务的名字时，建议按如下模板执行：

1. **发布 N（双写）**
   - 新增字段：`new_name`
   - 保留字段：`old_name`
   - 两者值保持一致。
2. **发布 N+1（迁移）**
   - 仪表盘、告警、运维脚本全部切到 `new_name`。
   - 在文档中标注 `old_name` 计划删除时间。
3. **发布 N+2（清理）**
   - 删除 `old_name`。
   - 保留一次升级指引，说明替换关系。

示例（仅示意）：

- `last_report.robot_id` -> `last_report.device_id`
- `robot_status_tracked_sessions` -> `device_status_tracked_sessions`

在上述迁移期内，推荐继续输出原指标以保持 Prometheus 告警平稳。

---

该方案优先服务“可测试、可观测、可运维”，并为后续业务命名调整预留低风险演进路径。
