# 核心安全验收矩阵

在仓库根目录运行以下发布门禁：

```text
python -m pytest tests/test_core_security_acceptance.py -q
```

该测试模块使用临时 SQLite 审批库、事务库、LangGraph checkpoint store、内存 ticket replay store 和类型化 fake port。测试不会访问网络、启动子进程或操作真实目标。“零 effect”表示 `prepare == apply == undo == 0`。

| 安全不变量 | 精确 pytest node ID | 预期状态或错误 | effect 与锁不变量 |
|---|---|---|---|
| 空配置必须安全 | `tests/test_core_security_acceptance.py::test_safe_empty_defaults_expose_no_target_and_no_write` | `policy_denied`；默认为 `read_only`、无目标、不自动执行 LOW | 零 effect；零事务记录、零目标锁 |
| 拒绝未知目标 | `tests/test_core_security_acceptance.py::test_unknown_target_denial_has_zero_effects` | `policy_denied`、`target_resolution_failed:*` | 零 effect |
| 计划身份必须匹配观测身份 | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[identity-mismatch]` | `policy_denied`、`target_fingerprint_mismatch` | 零 effect |
| 缺少 capability 授权时 fail-closed | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[missing-capability]` | `policy_denied`、`capability_not_allowed` | 零 effect |
| 缺少 action 授权时 fail-closed | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[missing-action]` | `policy_denied`、`action_not_allowed` | 零 effect |
| 允许列表外资源必须 fail-closed | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[resource-escape]` | `policy_denied`、`resource_not_allowed` | 零 effect |
| 目标写禁用具有最高约束力 | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[target-read-only]` | `policy_denied`、`target_read_only` | 零 effect |
| 全局只读模式具有最高约束力 | `tests/test_core_security_acceptance.py::test_policy_denials_never_reach_state_changing_executor[global-read-only]` | `policy_denied`、`global_read_only` | 零 effect |
| 词法路径穿越不能进入计划 | `tests/test_core_security_acceptance.py::test_lexical_resource_traversal_is_rejected_before_workflow` | Pydantic `ValidationError` | 零 effect |
| HIGH 必须经过本地审批 | `tests/test_core_security_acceptance.py::test_high_without_approval_has_no_ticket_and_no_effects` | `pending_approval` | 零 effect、签发 ticket 为零 |
| 审批必须绑定冻结摘要 | `tests/test_core_security_acceptance.py::test_changed_frozen_digest_is_denied_on_full_high_resume` | `policy_denied`、`approval_mismatch` | 零 effect |
| resume 时重新检查审批有效期 | `tests/test_core_security_acceptance.py::test_expired_approval_is_rejected_on_full_resume` | `approval_expired` | 零 effect |
| 拒绝过期操作 ticket | `tests/test_core_security_acceptance.py::test_operation_ticket_boundary_rejects_invalid_use[expired]` | `TicketError(expired)` | executor effect 为零 |
| 操作 ticket 只能使用一次 | `tests/test_core_security_acceptance.py::test_operation_ticket_boundary_rejects_invalid_use[replayed]` | `TicketError(replay)` | executor effect 为零 |
| 操作 ticket 与阶段绑定 | `tests/test_core_security_acceptance.py::test_operation_ticket_boundary_rejects_invalid_use[wrong-phase]` | `TicketError(phase_mismatch)` | executor effect 为零 |
| 同目标互斥并受全局上限约束 | `tests/test_core_security_acceptance.py::test_transaction_locks_enforce_same_target_and_cross_target_cap` | 同一目标的第二项写操作抛出 `TargetBusyError`；达到上限 2 后，第三个目标抛出 `GlobalWriteLimitError` | 只允许两个不同目标锁；同一目标永远不会同时存在两个锁 |
| 未知 apply 只 reconcile，绝不重放 | `tests/test_core_security_acceptance.py::test_unknown_apply_restart_reconciles_without_second_apply` | 首次为 `execution_unknown`；resume 后在恰好一次 `reconcile:apply:0` 和一次 `verify:0` 后变为 `succeeded` | `apply:0` 只发生一次；恢复后的 `verify:0` 内，另一个同目标事务得到 `TargetBusyError`；只在 verify/close 后释放锁 |
| checkpoint 崩溃窗口后已完成 effect 仍可恢复 | `tests/test_core_security_acceptance.py::test_completed_apply_crash_reconstructs_without_replay` | 重建图后，通过恰好一次 `reconcile:apply:0` 和一次 `verify:0` 恢复为 `succeeded` | `apply:0` 总计一次；verify 内的同目标探测看到 busy；只在 verify/close 后释放锁 |
| 回滚顺序必须与 apply 顺序严格相反 | `tests/test_core_security_acceptance.py::test_rollback_is_exact_reverse_order` | `rollback_succeeded` | apply 顺序严格为 `0,1,2`；undo/restore 严格逐项交错为 `2,1,0` |
| 明确回滚失败必须如实报告 | `tests/test_core_security_acceptance.py::test_rollback_failure_is_truthful_and_lock_safe[partial]` | 持久化 `rollback_partial`；undo 第 `0` 步持久化为 `failed` | apply 为 `0,1`；undo/restore 为 `1,0`；不执行 reconcile；终态释放锁 |
| 不确定回滚必须如实报告 | `tests/test_core_security_acceptance.py::test_rollback_failure_is_truthful_and_lock_safe[unknown]` | 持久化 `rollback_unknown`；undo 第 `0` 步持久化为 `unknown` | apply 为 `0,1`；undo 为 `1,0`；仅恢复第 `1` 步；恰好一次 `reconcile:undo:0`，undo 重放为零，并保留锁 |
| 模型中断不能产生写操作 | `tests/test_core_security_acceptance.py::test_model_failure_is_read_only_and_has_zero_effects` | `read_only_no_model` | 零 effect |
| 可选通知失败不能取代 CLI 审批 | `tests/test_core_security_acceptance.py::test_optional_notification_failure_is_audited_and_locally_approvable` | 首次为带 `notification_failed` 的 `pending_approval`；本地审批后 resume 为 `succeeded` | 本地审批前零 effect |
| 必需通知返回 false acknowledgement 时阻止审批 | `tests/test_core_security_acceptance.py::test_required_notification_failure_is_blocked_and_non_approvable[false]` | `notification_blocked`；审批存储拒绝本地审批 | 零 effect |
| 必需通知返回畸形 truthy acknowledgement 时拒绝 | `tests/test_core_security_acceptance.py::test_required_notification_failure_is_blocked_and_non_approvable[malformed-truthy]` | `notification_blocked`；审批存储拒绝本地审批 | 零 effect |
| HIGH resume 时重新检查当前配置 | `tests/test_core_security_acceptance.py::test_current_boundary_revocation_on_high_resume_has_zero_effects[configuration]` | 撤销为只读后返回 `policy_denied` | 零新增 effect |
| HIGH resume 时重新检查当前身份 | `tests/test_core_security_acceptance.py::test_current_boundary_revocation_on_high_resume_has_zero_effects[identity]` | `policy_denied`、`target_identity_changed` | 零新增 effect |

任何 node ID 发生变化时，都必须重新运行 `pytest --collect-only`，并在同一次变更中更新本表。
