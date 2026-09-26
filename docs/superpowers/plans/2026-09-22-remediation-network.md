# DNS and Network Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 恢复管理员登记的 DNS／Netplan 基线，断开控制链路时可在目标本地恢复原配置。

**Architecture:** 先持久备份并启动独立 watchdog，再应用配置；控制端重新连接、目标及业务检查全部通过后以签名 nonce 确认。期限内未确认的事务由本地 watchdog 恢复。

**Tech Stack:** systemd timers／boot recovery、systemd-resolved、Netplan、Python、Ed25519。

**Spec:** [设计 8](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划](2026-09-22-linux-remediation-jev.md#global-constraints)；依赖 F。确认期限默认 120 秒；不能放开通用文件插件对网络保护路径的写权限；只恢复登记基线。

## Review Focus

SSH 失联（N2）、目标重启（N2）、过期／跨事务确认（N1）、错误管理器／WSL 自动 DNS（N3）、回滚配置被并发修改（N2/N3）。

## Task N1: 持久 watchdog 与一次性确认

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_network_watchdog.py`, `deploy/a4diag-network-recovery.service`, `deploy/a4diag-network-recovery.timer`, `tests/target_runtime/test_network_watchdog.py`; modify `packages/a4diag-target-runtime/pyproject.toml`、F2 的 1.1 confirm_job 和 F3 job store。

**Interfaces:** `NetworkLease` 字段 `transaction_id, profile_digest, applied_config_digest, target_fingerprint, nonce, deadline_epoch, boot_id, state`；`confirm_network(lease, *, transaction_id: str, config_digest: str, nonce: str, now_epoch: int, current_boot_id: str) -> NetworkLease` 只在 active／同 boot／未到期／全部绑定相符时返回 confirmed，否则抛 `NetworkConfirmationError(code)`。签名、授权由 helper 在调用前验证。

- [ ] 写期限边界负例：

```python
def test_confirmation_at_deadline_is_too_late(network_lease):
    import pytest
    from a4diag_target.repair_network_watchdog import confirm_network, NetworkConfirmationError
    with pytest.raises(NetworkConfirmationError, match='expired'):
        confirm_network(network_lease, transaction_id=network_lease.transaction_id,
            config_digest=network_lease.applied_config_digest,
            nonce=network_lease.nonce, now_epoch=network_lease.deadline_epoch,
            current_boot_id=network_lease.boot_id)
```

`network_lease` 构造 deadline=1120、boot_id='boot1'、state='active' 的严格模型，使用合法摘要与 nonce。

- [ ] 运行 `python -m pytest -q tests/target_runtime/test_network_watchdog.py` 确认失败。实现原子状态变更与 nonce 消费，确认和超时恢复共享同一目标锁；一方进入 restoring 后另一方不可确认。
- [ ] 使用单调时钟限制同 boot 的实际期限；epoch 持久化只用于记录与重启判断，墙钟后退不能延期。boot ID 改变则先恢复所有未确认状态，不延长租约。
- [ ] 测试跨事务／摘要／目标、重复确认、确认和恢复并发、时钟跳变、状态文件损坏和 timer 未启动；这些情况都不能开始网络改动。单元通过后提交 `feat: persist network repair confirmation leases`。

## Task N2: Netplan 基线恢复与断连保护

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_netplan.py`, `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_network.py`, `packages/a4diag-builtin-plugins/manifests/capability-network.json`, `tests/integration/test_network_recovery_watchdog.py`; modify installer、helper registry、profile constraints、plugin ports。

**Interfaces:** `prepare_netplan(profile_id: str) -> dict[str, JsonValue]` 返回备份摘要、期望配置摘要、实际管理器及关联 lease；`apply_netplan(job_id: str) -> None` 从受保护 job 读取配置，不采纳模型任意 YAML。`restore_network(transaction_id: str) -> str` 返回 restored/failed/unknown，并实际核对文件和运行态。

- [ ] 写控制链路丢失测试：

```python
def test_target_restores_without_controller(network_lab):
    before = network_lab.active_config_digest()
    network_lab.apply_baseline_that_breaks_control_route()
    network_lab.stop_controller()
    network_lab.wait_for_watchdog()
    assert network_lab.active_config_digest() == before
    assert network_lab.ssh_identity_matches()
```

fixture 在 D 盘独立 Linux 测试机建立专用接口与 SSH 链路，通过第二条只供测试观察的通道读取事实；不能用控制端修复网络制造成功。

- [ ] 运行 `A4DIAG_TEST_NETWORK=1 python -m pytest -q tests/integration/test_network_recovery_watchdog.py` 确认缺失实现失败。备份所有会受影响的精确配置文件、权限和运行态，固定白名单字段；拒绝 hooks、任意脚本、未知 renderer 和超范围路由。原子写入前必须确认备份、lease、timer 和 boot recovery 已持久就绪。
- [ ] 校验 Netplan 基线后 apply；失败、超时或控制端未签名确认均触发目标本地恢复。清晰区分 timer 创建成功和恢复成功。恢复失败保持 failed，保留数据供人工处理。
- [ ] 确认前重新连 SSH 验证原指纹，执行 DNS／目标连通性／业务检查；只在全部成功后发送 F2 confirm_job，不能绕过失败检查。并发管理员修改则不盲目覆盖新文件，报告 conflict/unknown，并保留可人工恢复的原备份。
- [ ] 测试 SSH 中断、控制端退出、目标重启、确认竞态、恢复命令失败、错误基线和其他接口不受影响；通过后提交 `feat: restore Netplan baselines with local rollback watchdog`。

## Task N3: systemd-resolved 与完整网络业务验收

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_resolved.py`, `tests/target_runtime/test_resolved_profile.py`, `tests/integration/test_dns_remediation.py`; modify network capability、installer、profile constraints。

**Interfaces:** `ResolvedBaseline` 字段 `link_id, servers, routing_domains, expected_records`；`validate_dns_result(addresses: Sequence[str], expected_addresses: Sequence[str]) -> bool` 对规范 IP 集合执行 profile 中的精确预期比较，不将任意可解析结果视为成功。profile 的运行态与持久配置来源同时登记。

- [ ] 写错误解析结果测试：

```python
def test_wrong_address_is_not_dns_recovery():
    from a4diag_target.repair_resolved import validate_dns_result
    assert not validate_dns_result(['192.0.2.9'], ['192.0.2.10'])
```

- [ ] 运行新增单元确认失败。检测 resolver 与 renderer 归属，WSL 自动生成 resolv.conf、NetworkManager 或未知链路返回 unsupported；不覆盖 /etc/resolv.conf。恢复登记 link DNS、路由域及持久来源；必要重载在专用 profile 下执行。
- [ ] DNS 改动也使用 N1/N2 watchdog，保存先前配置并验证恢复。无法完整重建原设置时拒绝 apply，不能用 revert-to-default 代替原配置。
- [ ] 真实隔离 DNS 服务注入错误地址、NXDOMAIN、服务器不可达、链路替换；核对正确记录、目标出站业务和控制端业务三项。`A4DIAG_TEST_NETWORK=1 python -m pytest -q tests/integration/test_dns_remediation.py` 与网络回滚测试通过后提交 `feat: recover managed DNS baselines with verification`。
