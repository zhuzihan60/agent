# Missing Package Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 从明确可信的制品中安装登记的缺失包与依赖，不升级或移除既有包。

**Architecture:** APT prepare 求解并冻结完整事务及制品；目标端独立授权后在持久 worker 安装，返回 job ID。失败核对实际 dpkg 状态，报告部分改变。

**Tech Stack:** APT／dpkg、仓库签名元数据、Python、systemd worker、SQLite。

**Spec:** [设计 7](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划](2026-09-22-linux-remediation-jev.md#global-constraints)；依赖 F。HIGH 不降级，旧 hardened executor 包写入仍禁用，只有独立 APT profile/helper 开放 install_exact。

## Review Focus

隐式依赖升级、仓库求解漂移、maintainer script 失败、锁冲突、断线后重复安装，归 A1/A2。

## Task A1: 冻结完整依赖和制品

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_apt.py`, `tests/target_runtime/test_repair_apt.py`; modify `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_packages.py`, packages manifest、repair profile constraints。

**Interfaces:** `PackageChange` 字段 `name, architecture, prior_version: str|None, desired_version: str|None, sha256: str|None`；`FrozenAptPlan` 字段 `changes, package_db_digest, repository_metadata_digests, artifact_paths, plan_digest`。`validate_missing_only(changes: Sequence[PackageChange], allowed: set[tuple[str,str,str]]) -> None`；违反抛 `AptPlanError(code)`。

- [ ] 写隐式依赖升级测试：

```python
def test_dependency_upgrade_is_not_a_missing_package_install():
    import pytest
    from a4diag_target.repair_apt import PackageChange, AptPlanError, validate_missing_only
    change = PackageChange(name='libdemo', architecture='amd64', prior_version='1',
                           desired_version='2', sha256='a'*64)
    with pytest.raises(AptPlanError, match='existing_package_change'):
        validate_missing_only([change], {('libdemo', '2', 'amd64')})
```

- [ ] 运行 APT unit tests 确认失败。使用机器可核验的事务集合读取工具输出，固定 locale，拒绝不认识的记录；模拟求解不可写系统，不自动运行 update 或修复 dpkg。核验目标 OS/architecture、包名版本、每一依赖授权和状态。
- [ ] 下载阶段要求可信元数据签名与哈希链，禁止 allow-unauthenticated／不可信仓库。将文件存于私有事务目录并记录摘要；prepare 后重新下载同名包不许替换已冻结制品。并发 dpkg 数据库变化使准备失效。
- [ ] 测试未知依赖、包移除、架构不符、虚拟包解析、损坏元数据、哈希不符、被禁止系统包和 malformed version；运行 package contract 回归，通过后提交 `feat: freeze exact missing-package repair transactions`。

## Task A2: 有锁安装 job、失败核验与生产入口

**Files:** Modify A1 modules、目标 repair_jobs、helper registry、`tools/install_target_lib.sh`; create `deploy/a4diag-apt-worker@.service`, `tests/integration/test_apt_remediation.py`, `tests/e2e/fixtures/build_demo_debs.py`。

**Interfaces:** `start_install(plan: FrozenAptPlan, job_id: str) -> None` 只消费 job store 中已授权摘要对应的制品；`inspect_install(job_id: str) -> RepairJob` 核对全部包的 configured 状态和版本，不以 worker 退出码作为唯一成功证据。

- [ ] 写断线重试测试：

```python
def test_disconnect_does_not_start_second_package_worker(apt_lab):
    job_id = apt_lab.start_then_disconnect()
    apt_lab.reconnect_and_reconcile(job_id)
    assert apt_lab.worker_start_count(job_id) == 1
    assert apt_lab.package_version('a4diag-demo') == '1.0'
```

fixture 构建无害 deb、本地签名仓库和真实 helper，断开的是 SSH 客户端，不替换 APT 为 mock。

- [ ] 运行 `A4DIAG_TEST_APT=1 python -m pytest -q tests/integration/test_apt_remediation.py` 确认缺少生产入口失败。worker 启动前持久记录，使用包管理器支持的原生锁；不删除锁文件、不额外持有与 dpkg 子进程死锁的锁。数据库复核与调用间仍有变更则通过实际求解／执行约束拒绝未冻结内容。
- [ ] 安装只使用冻结的本地制品并关闭网络获取，不允自动求解升级／移除；限时的是控制端等待，worker 持续受查询与审计。撤销授权阻止未开始任务，不能强杀进行中的 dpkg。管理员脚本副作用不可自动卸载抵消。
- [ ] 失败后收集实际包集合与状态，将 changed/partial/unknown 准确持久化。系统日志和业务验证失败不能被包版本达标掩盖。环境不支持可靠冻结执行时该 adapter 返回 unsupported，不能开放无约束 apt-get。
- [ ] 测试锁占用、脚本失败、解包后重启、准入后仓库改包、撤销、断线和依赖额外变化。安装器旧配置仍不启用 APT helper；上述测试、helper 安装回归通过后提交 `feat: execute and reconcile authorized package repair jobs`。
