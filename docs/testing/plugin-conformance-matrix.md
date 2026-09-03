# 内置插件一致性矩阵

所有内置插件统一通过共享 harness `tests/contract/test_all_manifests.py`、共享 host contract（`tests/contract/test_plugin_protocol.py`、`test_plugin_crash_matrix.py`），以及各插件族测试（`test_transport_plugins.py`、`test_capability_plugins.py`、`test_model_plugin.py`、`test_notification_plugins.py`）验证。AF_UNIX、symlink、权限和 owner capability 门禁是强制 Linux 发布检查。

## Manifest

| Manifest | 类型 | 操作或接口 | 风险下限 | 网络 | Secret reference |
|---|---|---|---|---|---|
| `transport-local` | transport | `verify_identity`、`read`、`execute_typed` | 读 low / 写 high | 无 | — |
| `transport-ssh` | transport | `verify_identity`、`read`、`execute_typed` | 读 low / 写 high | target-ssh | `target:ssh-key`、`target:known-hosts` |
| `capability-files` | capability | `files.replace_managed_file`（low）、`files.set_mode`（low） | 读 low / 写 high | 无 | — |
| `capability-services` | capability | `services.restart/start/stop/enable/disable`（low） | 读 low / 写 high | 无 | — |
| `capability-packages` | capability | `packages.install_exact`（high）、`packages.remove_exact`（high） | 读 low / 写 high | 无 | — |
| `model-openai-compatible` | model | `diagnose`、`plan`、`critic` | 读 low / 写 high | model-provider | `model:api-key` |
| `notification-cli` | notification | `send` | 读 low / 写 high | 无 | — |
| `notification-flashduty` | notification | `send` | 读 low / 写 high | notification-endpoint | `notification:flashduty-integration-key` |
| `notification-smtp` | notification | `send` | 读 low / 写 high | smtp-server | `notification:smtp-user`、`notification:smtp-password` |
| `notification-webhook` | notification | `send` | 读 low / 写 high | notification-endpoint | `notification:webhook-hmac-key` |

## Harness 检查项（`test_all_manifests.py`）

- 严格 manifest schema：`PluginManifest`、`extra="forbid"`、frozen。
- API 协商：`api_min <= 1.0 <= api_max`，主版本为 1。
- 使用不含路径穿越的绝对 Unix socket 路径。
- `executable` 必须解析为内置包中可导入的 `module:function`，并且预期插件类存在。
- 操作参数 schema 使用严格且自包含的 JSON Schema：根类型为 `object`、`additionalProperties: false`，并使用与注册表相同的校验器。
- 风险下限：manifest 的 `write_risk_floor >= read_risk_floor`，每项 capability 操作的风险下限都必须被 manifest 写入风险下限覆盖。
- 声明接口：capability 操作只能声明已注册 RPC 接口提供的 prepare、apply、undo、verify 和 reconcile；每种 manifest 类型的预期 RPC 方法名固定。
- 声明要求：transport 必须声明权限；model 必须声明 `model-provider` 和 `model:` secret reference；notification 必须声明权限。
- Wheel 一致性：`dist/` 中存在 wheel 时，只能有一个 wheel 且不能存在 sdist；所有 manifest 和插件模块必须包含在 wheel 中；entry point 必须精确为 `a4diag-plugin = a4diag_builtin_plugins.host:main`；不得打包测试 fixture、`.pyc`、secret 或固定目标 IP。

## 崩溃与恢复矩阵（`test_plugin_crash_matrix.py`）

- Effect handler 在 dispatch 后崩溃：返回 `execution_unknown`，details 完成脱敏，内部 secret 不会到达 client，并隔离 host。
- 使用同一 replay store 的新 host 重启后恢复 `health` 和 `read`；已崩溃 ticket 永不重放；重新签发的 ticket 可在重启后正常执行。
- 无效 ticket：返回 `malformed_token`，dispatch 为零。
- 重复请求：返回 `replay`，第二次 dispatch 为零。
- 超大或畸形 frame：稳定返回 `payload_too_large`、`multiple_frames`、`invalid_json`、`invalid_utf8` 或 `duplicate_key`。
- Handler 输出超限：返回 `invalid_handler_result`，确保 RPC response 有界。
- Effect 超时：返回 `execution_unknown`；同一个已隔离实例上的 reconcile 继续被阻止，新实例可以提供 health。

## 测试套件强制执行的安全不变量

- 不存在通用 LOW shell 方法；所有执行都使用固定 argv 模板或类型化 helper action；包中不存在 `shell=True`。
- 身份漂移、host key 变化或 ticket 不匹配会在 dispatch 前阻止写操作，操作 spawn 为零。
- HIGH 操作必须携带已审批 ticket；未知执行永远不会自动重试。
- 严格类型化 schema 拒绝模型输出中的原始 `command`、`shell`、`script` 和 `argv` 字段。
- Secret 通过 reference 在每次调用时解析；不得出现在代码、日志、URL、错误消息或通知 payload 中。
- 通知只对连接错误、429 和 5xx 执行重试。

## Phase 4 Linux 门禁

六项真实 AF_UNIX host/client/path 场景和两项 symlink 权限场景是强制 Phase 4 Linux 门禁；任何权限、无效路径或宽泛 `OSError` skip 都不能作为发布证据。
