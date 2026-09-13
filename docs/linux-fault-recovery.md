# Linux 故障诊断与恢复验证

本文对应 v1.0.0。控制端、内置插件和目标端必须使用同一版本；旧版本不识别新增探针配置。部署流程见 [安装指南](install.md)，服务与 HTTP 检查见 [服务恢复说明](deployment/service-http-recovery.md)。

## 能力范围

本阶段沿用已有的文件、服务操作及其准备、执行、验证和回滚流程。受授权的文件操作包括 `set_mode`、`replace_managed_file`；业务服务可使用已有的受授权服务操作。新增探针为诊断提供证据，并在操作后重新读取目标状态，判断管理员设定的恢复条件是否全部满足。

容量、内存、负载、包状态、TCP 和 DNS 探针只提供诊断与验证能力。登记这些探针不授予删除文件、清理磁盘、杀进程、安装软件包或修改主机网络配置的权限。当前加固安装器仍拒绝包写入授权。遇到没有受支持修复操作的问题，应输出诊断结果并交由管理员处理。

## 两端分别登记相同探针

控制端目标配置（或 `init --input` 请求的 `targets` 项）与目标端 `target-install.json` 都支持 `diagnostic_probes`。管理员必须在两端登记相同的 `id`、`kind`、`resource`、`max_bytes`。目标安装器将目标端登记写入策略；控制端登记不会自动向目标端授权。

目标 RPC 请求只传 `probe_id`，不传探针定义，目标端按自己的策略解析 ID。响应使用 `probe_digest` 和 `result` 封装观测值；摘要是包含默认值的完整探针定义的规范 JSON（键排序、紧凑分隔符、ASCII 转义）的 SHA-256。控制端在接收证据和验证恢复时核对摘要，缺失摘要或两端任一字段不一致均视为探针不可用，不能报告恢复成功。修改定义时应同步两端，并重新采集确认。省略 `diagnostic_probes` 等价于空列表，不存在隐式默认探针。

每个目标最多 8 个探针，ID 必须唯一，格式为 1–64 个 ASCII 字母、数字、`_`、`-`，首字符须为字母或数字。每项包含：

| 字段 | 含义 |
| --- | --- |
| `id` | 管理员定义的精确 ID，供证据及恢复检查引用 |
| `kind` | 下表列出的探针类型 |
| `resource` | 按类型指定的精确对象，最长 1024 字符 |
| `max_bytes` | 目标采集读取预算，整数 1–1048576，默认 1048576；文件超过预算时不返回内容摘要 |

| 类型 | `resource` 示例 | 输出字段 |
| --- | --- | --- |
| `filesystem` | `/srv/app`，或 `/` | `total_bytes`、`available_bytes`、`used_percent`、`free_inodes`，均为整数 |
| `memory` | `host` | `total_bytes`、`available_bytes`、`used_percent`、`swap_total_bytes`、`swap_free_bytes`，均为整数 |
| `load` | `host` | `load_1_milli`、`load_5_milli`、`load_15_milli`、`cpu_count`，均为整数；负载值放大 1000 倍 |
| `file` | `/srv/app/app.conf` | `exists` 布尔值；`mode`、`size_bytes` 整数；`sha256` 字符串，无法计算时为空 |
| `package` | `myapp` | `installed` 布尔值；`version` 字符串，未安装时为空 |
| `tcp` | `tcp://127.0.0.1:8080` | `reachable` 布尔值 |
| `dns` | `app.example.com` | `resolved` 布尔值；`addresses` 为最多 16 个规范 IP 字符串组成的列表 |

文件系统探针读取指定目录所在文件系统的容量，不统计目录内文件总量。文件路径必须为规范绝对路径；文件探针还必须通过目标端已有受管目录读取授权，不允许通过符号链接绕过授权，也不能访问已有受保护路径。TCP 地址必须包含端口，不得包含路径、凭据、查询或片段。TCP/DNS 从**目标端**探测；已有 HTTP 恢复检查仍从**控制端**请求。

目标安装器只在目标管理员登记 TCP/DNS 探针时，为 executor 的 `RestrictAddressFamilies` 配置 `AF_UNIX AF_INET AF_INET6`；其他配置保持 `AF_UNIX`。这不会开放网络配置写入权限，也不会更改防火墙或系统服务保护。

## 示例：文件权限与文件系统容量

以下均为要合入现有配置的片段，不能替代包含目标身份、公钥、来源网段和连接信息的完整配置。

先将下面字段合入目标端的 `target-install.json`。`/srv/app` 必须预先存在并满足安装指南中的受管目录限制。`ENABLE` 是安装器对非空受管资源的明确确认；控制端是否允许写入仍由其独立策略决定。

```json
{
  "managed_resources": [
    {"capability": "files", "resource": "/srv/app"}
  ],
  "confirm_managed_resources": "ENABLE",
  "diagnostic_probes": [
    {"id": "app-config", "kind": "file", "resource": "/srv/app/app.conf", "max_bytes": 1048576},
    {"id": "app-capacity", "kind": "filesystem", "resource": "/srv/app", "max_bytes": 1048576}
  ]
}
```

将下面字段合入控制端同一目标的初始化配置。示例保持只读；登记能力不等于启用写入。需要受控文件修复时，按安装指南配置全局写入模式、明确写入确认及目标写入开关，保留原有风险审批和操作授权流程。

```json
{
  "write_enabled": false,
  "auto_execute_low": false,
  "capabilities": [
    {"name": "files", "actions": ["set_mode", "replace_managed_file"], "resources": ["/srv/app/app.conf"]}
  ],
  "diagnostic_probes": [
    {"id": "app-config", "kind": "file", "resource": "/srv/app/app.conf", "max_bytes": 1048576},
    {"id": "app-capacity", "kind": "filesystem", "resource": "/srv/app", "max_bytes": 1048576}
  ],
  "evidence_sources": [
    {"id": "config-state", "kind": "probe", "resource": "app-config", "initial": true, "max_bytes": 8192},
    {"id": "capacity-state", "kind": "probe", "resource": "app-capacity", "initial": true, "max_bytes": 8192}
  ],
  "recovery_checks": [
    {
      "id": "config-permissions", "kind": "probe", "resource": "app-config",
      "conditions": [
        {"field": "exists", "operator": "eq", "value": true},
        {"field": "mode", "operator": "eq", "value": 420}
      ]
    },
    {
      "id": "capacity-headroom", "kind": "probe", "resource": "app-capacity",
      "conditions": [
        {"field": "available_bytes", "operator": "ge", "value": 1073741824},
        {"field": "used_percent", "operator": "le", "value": 90}
      ]
    }
  ]
}
```

`420` 是十进制权限值，对应八进制 `0644`；JSON 不支持八进制数值。示例要求文件存在且权限为 `0644`，并要求文件系统可用空间至少 1 GiB、使用率不超过 90%。两项恢复检查都必须通过。权限修复本身不会释放磁盘空间：若容量条件仍失败，系统不能报告整体恢复成功。

文件探针返回属性和摘要，不返回文件正文。若诊断需要读取受管配置正文，可另行使用已有 `kind: file` 证据源。若要验证配置内容，增加 `sha256` 的 `eq` 条件，值为预期内容的 64 位小写十六进制 SHA-256，同时保留 `exists=true`；文件超过该探针读取预算而无法计算摘要时，此条件不会通过。

## 条件、预算与结果

证据源和恢复检查中的 `resource` 都是探针 ID，证据源自身的 `id` 是供补采引用的证据 ID，不能混用。`initial: false` 的证据仅在模型请求已登记证据 ID 时补采。证据输出预算与探针读取预算独立：证据源 `max_bytes` 为 256–16384，所有证据源合计不超过 65536 字节；每个目标最多 8 个证据源和 8 项恢复检查。

探针恢复检查必须包含 1–16 个条件。同一检查的所有条件、同一目标的所有恢复检查均须通过。字段及值类型必须与探针输出匹配：

- 整数字段支持 `eq`、`ge`、`le`；数值必须为非负整数，不能用字符串、浮点数或布尔值代替。
- 布尔值和字符串字段仅支持 `eq`。
- DNS 的 `addresses` 支持 `contains`，值为单个规范 IP 字符串。
- 检查文件属性或摘要时必须同时要求 `exists=true`；检查包版本时必须同时要求 `installed=true`。
- 已有 `http`、`service_active` 检查不能配置 `conditions`，继续使用原有字段。

未知探针 ID、未知输出字段、类型不匹配、缺少条件会在配置阶段拒绝。执行后重新采集探针结果，并核对目标身份；原始诊断证据不会被重复当作恢复证明。读取失败、输出截断或校验失败不能证明恢复成功。

恢复条件只证明管理员选择的状态成立。例如端口可连接不等于应用业务正常、DNS 解析成功不等于依赖可访问、文件权限正确不等于配置内容正确。应结合业务服务状态、HTTP 健康检查或内容摘要选择本次故障的恢复标准。结果解释及回滚状态见 [服务恢复说明](deployment/service-http-recovery.md#如何判断结果)。
