# Service Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复登记服务的卡死或崩溃，并限制重复干预。

**Architecture:** 扩展 systemd 证据与受控 reset-failed；共享持久限次模块。新增独立观察器，至少观察 60 秒后才能报告恢复。

**Tech Stack:** Python、systemd D-Bus／现有固定 systemctl argv、HTTP、SQLite。

**Spec:** [设计 5](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划](2026-09-22-linux-remediation-jev.md#global-constraints)；依赖 F。无任意 kill；恢复 runtime 状态不等于恢复旧进程内存。

## Review Focus

active 但 HTTP 卡死、启动限流、真正慢启动、重启计数归零／InvocationID 变化、控制端重启后绕过冷却，分别归 S1/S2。

## Task S1: 服务证据与 reset-failed

**Files:** Modify `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_services.py`, `packages/a4diag-builtin-plugins/manifests/capability-services.json`, `packages/a4diag-target-runtime/src/a4diag_target/diagnostics.py`, `packages/a4diag-target-runtime/src/a4diag_target/helper.py`; create `tests/test_service_fault_evidence.py`。

**Interfaces:** 新 `ServiceFaultSnapshot` 字段 `active_state, sub_state, invocation_id, main_pid, exec_main_status, result, n_restarts, observed_at`。`parse_service_fault_snapshot(output: str, observed_at: int) -> ServiceFaultSnapshot` 放在 capability_services。增加 reset-failed 精确 unit 动作，profile 明确登记后才可执行，效果声明 compensatable（计数不可恢复）。

- [ ] 写故障属性解析测试：

```python
def test_active_is_not_equivalent_to_business_healthy():
    from a4diag_builtin_plugins.capability_services import parse_service_fault_snapshot
    raw = ('ActiveState=active\nSubState=running\nInvocationID=abc\n'
           'MainPID=42\nExecMainStatus=0\nResult=success\nNRestarts=3\n')
    state = parse_service_fault_snapshot(raw, observed_at=100)
    assert state.n_restarts == 3
    assert not hasattr(state, 'business_recovered')
```

- [ ] 运行 `python -m pytest -q tests/test_service_fault_evidence.py` 确认失败。实现固定属性列表采集，未知、缺失、截断和非整数属性视为证据不可用；不把默认 0 填入缺失字段。
- [ ] 将 reset-failed 纳入签名 action／marker 和目标授权；无写权限、受保护 unit、错误 marker 拒绝。补计数归零和 InvocationID 变化测试，运行 capability 契约及诊断读取回归，通过后提交 `feat: collect crash evidence and authorize service reset`。

## Task S2: 持续观察、持久限次与真实故障

**Files:** Create `src/a4diag/repair_verification.py`, `tests/test_repair_observation.py`, `tests/integration/test_service_fault_repair.py`, `tests/e2e/fixtures/flapping_service.py`; modify `src/a4diag/workflow.py`, `src/a4diag/plugin_ports.py`, `src/a4diag/recovery.py`。

**Interfaces:** `HealthSample` 字段 `elapsed_seconds: int, resource_identity: str, healthy: bool, restart_count: int`；`observation_passed(samples: Sequence[HealthSample], *, min_duration_seconds: int = 60, max_gap_seconds: int = 5) -> bool`，要求同一资源、全部健康、重启计数不再增长、首尾跨度足够且无采样空档。通过 F3 job 定时调度采样，不用一次 60 秒阻塞 RPC。

- [ ] 写最小持续观察测试：

```python
def test_single_healthy_sample_cannot_prove_recovery():
    from a4diag.repair_verification import HealthSample, observation_passed
    samples = [HealthSample(elapsed_seconds=0, resource_identity='web',
                            healthy=True, restart_count=0)]
    assert observation_passed(samples) is False
```

- [ ] 运行 `python -m pytest -q tests/test_repair_observation.py`，确认失败。实现单调时间和重启后观察重新开始逻辑；不把进程重启前的样本拼接成连续健康。HTTP 超时计入总预算，空白样本是失败。
- [ ] 接入 F3 reserve／mark_started，在 prepare/apply 之前检查每资源 600 秒与每小时两次限制；同一事务查询不能消耗新额度，重复告警不能触发更多重启。
- [ ] 使用真实 systemd 演示服务：HTTP 卡住但 PID 存活、启动立即退出、StartLimitHit、合法慢启动、恢复后再崩溃。证明只在连续观察通过时 succeeded；持续崩溃停止自动尝试。
- [ ] 运行 `A4DIAG_TEST_SYSTEMD=1 python -m pytest -q tests/integration/test_service_fault_repair.py`、观察测试及既有服务／HTTP 验收，通过后提交 `feat: verify sustained service recovery and enforce retry budgets`。
