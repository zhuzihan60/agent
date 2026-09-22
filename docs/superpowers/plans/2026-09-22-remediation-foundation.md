# Remediation Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立新增修复共同使用的授权、任务持久化与真实效果报告。

**Architecture:** 新增严格 profile，控制端冻结 binding，目标端独立复核。长任务与效果日志持久化，重放只返回既有任务。

**Tech Stack:** Python 3.11、Pydantic、SQLite、Ed25519、systemd socket activation。

**Spec:** [设计 3、10](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划 Global Constraints](2026-09-22-linux-remediation-jev.md#global-constraints)。不更改 v1.0 的签名规范；新能力走协议 1.1，旧功能继续使用 1.0。

## Review Focus

prepare 后撤销授权（F2）、并发重复请求和未知 job（F3）、不可逆副作用被误报回滚（F4）、helper 绕过入口（F5）、旧配置静默开权限（F1/F5）。

## Task F1: Profile、配置与规范摘要

**Files:** Create `src/a4diag/repair_profiles.py`, `tests/test_repair_profiles.py`; modify `src/a4diag/domain.py`, `src/a4diag/init_config.py`, `src/a4diag/config.py`, `packages/a4diag-target-runtime/src/a4diag_target/policy.py`。

**Interfaces:** `RepairProfile` 字段为 `id, target_id, capability, resource, actions, constraints, recovery_check_ids, cooldown_seconds, hourly_limit, expires_at, standing_authorization`。所有模型 `extra='forbid', frozen=True`；整数 strict，时间为 UTC epoch 秒。`profile_digest(profile: RepairProfile) -> str` 使用现有 canonical_json_bytes；constraints 按 capability 验证，不接受未知键。`RepairBinding` 字段为 `profile_id, profile_digest, preconditions_digest`，后者在 prepare 前为 null，apply 必填。

- [ ] 写失败测试与具体 fixture：

```python
from a4diag.repair_profiles import RepairProfile, profile_digest

def test_default_profile_is_not_standing_authorization():
    p = RepairProfile(id='web', target_id='demo', capability='services',
        resource='demo.service', actions=('restart',), constraints={},
        recovery_check_ids=('health',), expires_at=2000000000)
    assert p.standing_authorization is False
    assert p.cooldown_seconds == 600
    assert p.hourly_limit == 2
    assert len(profile_digest(p)) == 64
```

- [ ] 运行 `python -m pytest -q tests/test_repair_profiles.py`，确认导入失败；补默认值、严格字段与摘要。另测布尔冒充整数、Unicode 等价键冲突、无恢复检查、重复 ID、无限有效期、未知 capability、任意 shell 参数以及控制端／目标端摘要漂移。
- [ ] 配置默认 `repair_profiles=()`；部署时验证精确资源和适配器约束，不允许现有 `/**` 通配授权自动升级成新 profile。再次运行测试与 `tests/test_init_config.py tests/test_config_policy.py`，通过后提交 `feat: define explicit repair profiles`。

## Task F2: 持续授权与协议 1.1

**Files:** Modify `src/a4diag/policy_engine.py`, `src/a4diag/plugin_api/ticket.py`, `src/a4diag/plugin_api/target_protocol.py`, `src/a4diag/plugin_ports.py`, `packages/a4diag-target-runtime/src/a4diag_target/executor.py`, `packages/a4diag-target-runtime/src/a4diag_target/policy.py`; create `tests/test_repair_authorization.py`, `tests/target_runtime/test_repair_protocol.py`。

**Interfaces:** `authorize_profile(profile, operation, *, now: int, presented_digest: str) -> RepairBinding` 放在 repair_profiles；不满足条件抛 `RepairAuthorizationError(code)`。新增独立的 `TargetRequestV11`（不以可选新字段改变旧规范），包含 binding、`authorization_kind='one_shot'|'standing'`、`authorization_id`，以及 `query_job`、`confirm_job` 生命周期。两种授权都保持 HIGH 风险标记；standing 必须匹配目标本地仍有效的 profile，不能仅检查字符串 ID。

- [ ] 写 prepare 后撤销负例（profile／operation fixture 使用 F1 的 demo service）：

```python
def test_revoked_profile_cannot_apply(prepared_repair):
    prepared_repair.target.revoke('web')
    result = prepared_repair.apply_signed()
    assert result.code == 'profile_revoked'
    assert prepared_repair.effect_calls == []
```

`prepared_repair` 通过真实签名与 TargetExecutor 建立 prepared 状态，效果适配器仅记录调用；不得直接测试一个返回常量的策略 stub。

- [ ] 运行两个新增测试文件，验证缺少新协议／授权时报错。实现 1.0／1.1 按明确版本分发、完整签名与摘要绑定、每阶段 profile 重查。修改后重放旧请求必须仍按 1.0 校验；旧目标收到 1.1 必须拒绝。
- [ ] 测试伪造 standing ID、风险降级、跨目标／跨 profile、prepare marker 替换、有效期边界、撤销后的 apply/confirm、签名票据复用；运行 `tests/test_operation_ticket.py tests/test_target_protocol.py tests/test_policy_engine_v3.py`。通过后提交 `feat: bind repair authorization across controller and target`。

## Task F3: 资源锁与持久 job

**Files:** Create `src/a4diag/repair_store.py`, `src/a4diag/repair_jobs.py`, `packages/a4diag-target-runtime/src/a4diag_target/repair_jobs.py`, `tests/test_repair_jobs.py`, `tests/target_runtime/test_repair_jobs.py`; modify `src/a4diag/transaction_store.py`, `src/a4diag/runtime.py`, `packages/a4diag-target-runtime/src/a4diag_target/replay.py`。

**Interfaces:** `RepairStore(path: Path)`：`reserve(target_id: str, resource: str, transaction_id: str, now: int, cooldown_seconds: int, hourly_limit: int) -> str` 返回持久 reservation ID，违反约束抛 `RepairLimitError(code)`；`mark_started(reservation_id: str, now: int)`、`finish(reservation_id: str, outcome: str)`。`RepairJob` 字段 `id, transaction_id, step_id, profile_digest, operation_digest, state, changed, result, started_at, finished_at`。目标 `JobStore.ensure(transaction_id, step_id, operation_digest) -> RepairJob` 与 `get(job_id)` 返回模型；唯一约束绑定 transaction/step。

- [ ] 写重启后冷却与相同任务重入：

```python
def test_duplicate_job_reuses_identity(tmp_path):
    from a4diag_target.repair_jobs import JobStore
    path = tmp_path / 'jobs.db'
    first = JobStore(path).ensure('tx1', '0', 'a' * 64)
    second = JobStore(path).ensure('tx1', '0', 'a' * 64)
    assert first.id == second.id
```

- [ ] 运行新增 tests 确认缺失实现。用 SQLite `BEGIN IMMEDIATE` 与唯一约束构建 reserve/start；job 状态为 prepared/running/succeeded/failed/partial/unknown，不把进程消失解释成未执行。资源锁无自动超时释放；先验证关联 job 已终止才释放。
- [ ] 目标接受 apply 后持久写入 running，再启动独立 worker；断线仅断 RPC。崩溃发生在写入 running 与启动之间时，由 boot ID、pid/starttime、worker 记录及真实目标状态 reconcile，无法确定则 unknown，禁止自动再次执行。
- [ ] 测试两进程同时 reserve、错误摘要复用、数据库满、时钟回拨、重启后额度、job 查询越权、撤销后只读查询、返回包超限。运行新增测试和事务／重放回归，通过后提交 `feat: persist bounded repair attempts and long running jobs`。

## Task F4: 效果语义和工作流

**Files:** Create `src/a4diag/repair_effects.py`, `tests/test_repair_effects.py`; modify `src/a4diag/workflow.py`, `src/a4diag/transaction_store.py`, `src/a4diag/report.py`, `src/a4diag/audit.py`, `src/a4diag/plugin_api/manifest.py`。

**Interfaces:** `EffectKind = Literal['restorable','compensatable','irreversible']`；由清单声明，模型无权填写。`RepairEffect` 字段 `kind, changed, restoration_verified`；`rollback_outcome(effects: Sequence[RepairEffect]) -> str` 返回既有 rollback_succeeded/rollback_partial/rollback_unknown。job pending 返回 execution_unknown 并保持 reconciliation 路径，不在超时后直接 undo。

- [ ] 固定不可逆效果行为：

```python
def test_irreversible_change_never_reports_full_rollback():
    from a4diag.repair_effects import RepairEffect, rollback_outcome
    effects = [RepairEffect(kind='irreversible', changed=True,
                            restoration_verified=False)]
    assert rollback_outcome(effects) == 'rollback_partial'
```

- [ ] 运行新增测试确认失败。实现只在所有已改变步骤均可恢复且已独立验证时报告 rollback_succeeded；未知改变优先 unknown；不可逆已改变为 partial。对旧插件清单兼容现有 reversible 字段，不把历史操作错误重新分类为新动作。
- [ ] 覆盖混合计划、部分 apply、取消、unknown job、无变化步骤、审计失败、应用后恢复检查失败。运行 `tests/test_workflow_v3.py tests/test_restoration_verification.py tests/test_report_retention.py` 与新测试；提交 `fix: report irreversible repair effects accurately`。

## Task F5: 隔离 helper、生产配置与升级

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_helper.py`, `deploy/a4diag-repair-helper@.service`, `deploy/a4diag-repair-helper@.socket`, `tests/integration/test_repair_helpers.py`; modify `packages/a4diag-target-runtime/pyproject.toml`, `tools/install_target_lib.sh`, `src/a4diag/builtin_catalog.py`, `tools/build_release.py`。

**Interfaces:** helper 接受有长度上限的 SignedTargetRequest；只运行配置中精确登记的 adapter，与普通 executor 共用签名校验、授权和 job store。安装器输出 `new_write_helpers_enabled` 自检列表，空 profiles 时为空。

- [ ] 写集成负例：

```python
def test_unsigned_local_helper_call_is_denied(installed_helper):
    response = installed_helper.send({'action': 'restart'})
    assert response['error'] == 'signature_required'
    assert installed_helper.effects() == []
```

- [ ] 在 systemd 测试机运行 `A4DIAG_TEST_SYSTEMD=1 python -m pytest -q tests/integration/test_repair_helpers.py`，确认安装入口未实现导致失败。
- [ ] 新 helper 按能力拆 systemd drop-in：磁盘仅写授权缓存及状态目录；容器仅访问登记 socket；APT 只在独立启用时放开包管理所需系统写入且使用单独授权；网络仅写登记配置和 watchdog 状态。保留主 executor 的 ProtectSystem 和受保护路径拒绝。
- [ ] 验证直接 socket 请求、错误 peer UID、未知 adapter、安装中断、旧配置升级、跨 helper 请求、重复状态目录等不会扩大权限；打包清单校验通过后提交 `feat: deploy isolated repair helpers`。
