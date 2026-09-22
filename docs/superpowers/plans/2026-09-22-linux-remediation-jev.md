# Linux Remediation and Jev Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为五类 Linux 故障提供有授权、有真实恢复验证的自动修复，并接入可选 Jev 辅助。

**Architecture:** 在现有控制端签名事务之上增加 repair profile、持续授权、持久化 job 和准确的不可逆效果报告。修复由隔离的目标 helper 执行；Jev 仅提供分类、补采和候选建议。拆为七份子计划，各自有独立测试和交付边界。

**Tech Stack:** Python 3.11、Pydantic、SQLite、现有 httpx／SSH／systemd，Docker、Podman、Kubernetes apps/v1，APT、systemd-resolved、Netplan、TypeSafe System One HTTP API。

**Spec:** [已确认设计](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

- 默认仍只读。
- 保留现有 SSH 身份校验、两端独立授权、签名操作票据、审计和重放保护。
- 模型只选择已登记的 profile，不能新增授权资源。
- 逐次审批之外增加明确的持续授权；不能下调动作固有风险。
- 不可逆动作失败时可报告部分改变或需人工处理，不能报告 rollback_succeeded。
- 沿用现有执行预算作为短动作上限；APT 等长事务使用持久化 job。
- 默认每个资源十分钟最多一次、每小时最多两次。
- 验证窗口默认至少 60 秒、每 5 秒采样。
- 网络默认确认期限 120 秒；恢复任务独立于 SSH 与控制端进程。
- WSL 继续使用 D 盘，不填满 C 盘。
- Jev 独立 API Key 引用，禁止复用 DeepSeek Key。
- 不向新服务发送日志，直到用户配置凭据并明确授权发送测试证据。
- 本任务不自动合并 main、改版本号或发布 Release。

容器计划覆盖 Docker、Podman rootful／rootless，以及无状态 Kubernetes Deployment；主机平台限定 Ubuntu／Debian 的上述管理器。测试用版本需在执行时记录并锁定，不从 latest 浮动镜像推断兼容性。保持 Python >=3.11,<3.12 的现有约束，不为 HTTP 接入引入新 SDK 依赖。

## Review Focus

1. 授权在 prepare 后撤销：apply 必须拒绝；已经开始的不可逆 job 只观察，不因撤销杀死包管理器（基础 F2、软件包 A2）。
2. 对象同名替换或并发管理员变更：操作失败且不覆盖新对象（磁盘 D1、容器 C1/C3、网络 N2）。
3. 控制端断线／重启、相同告警并发到达：动作最多开始一次，未知结果先 reconcile（基础 F3、服务 S2）。
4. 空间或 inode 耗尽影响审计：变更前审计不可持久化就不执行，不能误报清理成功（磁盘 D2）。
5. 混合故障或外部模型高置信误判：系统指标改善而业务失败仍不算恢复，Jev 不能放宽授权（Jev J2、总验收 V1）。

## 子计划与顺序

| 阶段 | 文档 | 交付结果 | 依赖 |
|---|---|---|---|
| F | [共享基础](2026-09-22-remediation-foundation.md) | 两端授权、持久任务、效果语义与 helper 通道 | 无 |
| D | [磁盘／inode](2026-09-22-remediation-disk.md) | 有界缓存清理与真实文件系统验收 | F |
| S | [服务恢复](2026-09-22-remediation-services.md) | 卡死／崩溃证据、限次恢复、观察窗口 | F |
| C | [容器恢复](2026-09-22-remediation-containers.md) | Docker、Podman、Deployment 独立适配器 | F、S 的观察器 |
| A | [缺失软件包](2026-09-22-remediation-apt.md) | 冻结依赖安装与断线后的状态核验 | F |
| N | [DNS／网络](2026-09-22-remediation-network.md) | 登记基线恢复与本地 watchdog | F |
| J | [Jev 辅助](2026-09-22-remediation-jev.md) | off／observe／assist，独立凭据与用量 | F；在各能力完成后扩充候选集 |
| V | 本文件 V1/V2 | 全流程验收、部署和文档闭合 | F/D/S/C/A/N/J |

默认执行顺序 F→D→S→C→A→N→J→V。不并行改共享协议、workflow、安装器；即使采用子代理，也要按依赖顺序集成。

## 文件与接口约定

新领域模块位于 `src/a4diag/repair_profiles.py`、`repair_store.py`、`repair_jobs.py`、`repair_verification.py`、`advisor.py`；现有 `workflow.py` 只接入委托调用，不继续堆叠每种修复的业务代码。

目标模块放在 `packages/a4diag-target-runtime/src/a4diag_target/repair_*.py`；内置插件放在 `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_*.py` 和 `advisor_jev.py`。安装器、插件清单、配置和打包清单须随功能任务一起修改；不能只完成类而漏掉生产入口。

所有新 tests 文件均在相应子计划中明确命名。示例测试展示必须固定的行为，实施时补全该任务所列参数化负例；导入名及签名按各子计划执行，不创造第二套兼容函数。

## 开始执行前

- [ ] 确认当前 linked worktree 的 git/common-dir；从设计分支创建 `feat/linux-remediation-jev`，保留用户更改。提交身份为 `zhuzihan60`，邮箱沿用仓库配置。
- [ ] 获取并记录远端 main；如有新代码先评估差异，禁止覆盖或重写新提交。
- [ ] 记录 Python、OS、systemd、APT、Docker、Podman、Kubernetes、Netplan 版本与测试机磁盘位置。运行 `python -m pytest -q` 获取本轮基线，失败需定位后再判断归属。
- [ ] 验证旧版只读配置与现有服务／HTTP 验收仍可运行。旧报告只能作历史参考，不替代这轮测试。

Linux 命令在隔离测试环境执行；Windows 工作区只做编辑和支持跨平台的测试。配置文件与密钥正文不进入命令输出。D 盘实验日志统一放 `D:/A4Diag-WSL-Test/evidence/linux-remediation-jev/`。

## Task V1: 真实故障闭环与 Jev 对照

**Files:** Create `tests/e2e/run_linux_remediation.py`, `tests/e2e/test_linux_remediation.py`, `tests/e2e/fixtures/remediation_cases.json`; update `.github/workflows/test.yml`, `docs/testing/linux-remediation-jev.md`。

**Interfaces:** runner 输出 JSON：`case_id, environment, injected_fault, transaction_id, independent_checks, side_effects, rollback_state, provider_usage, outcome`。`provider_usage` 缺失必须为 null，不能填零伪装真实调用。敏感原日志另存有权限的目标文件，仅归档脱敏证据。

- [ ] 写失败用例，固定混合故障的终态：

```python
def test_space_recovered_but_http_failed_is_not_success(case_result):
    assert case_result['independent_checks']['space_ok'] is True
    assert case_result['independent_checks']['http_ok'] is False
    assert case_result['outcome'] != 'succeeded'
    assert case_result['rollback_state'] != 'rollback_succeeded'
```

`case_result` fixture 从 runner 生成的证据文件读上述场景，文件缺失是失败，不回退虚假结果。

- [ ] 首次运行 `A4DIAG_REMEDIATION_E2E=1 python -m pytest -q tests/e2e/test_linux_remediation.py`，确认未接通时失败。
- [ ] 实现 runner：为 D/S/C/A/N 中每个适配器分别执行成功、无效修复、越权和中断场景。先用固定方案隔离执行器问题，再让真实 DeepSeek 走 diagnose→plan→critic→授权→执行→独立验证；模型不能提前获知故障注入脚本的正确答案。
- [ ] Jev 凭据和数据授权具备后执行 observe 与 assist 两组同分布故障，固定模型版本／故障种子；保存实际 request 数、usage 和恢复结果。无凭据时只完成协议与回退测试，真实联调保持未完成。
- [ ] 验收网络链路使用 D 盘独立 systemd Linux 环境，不能在测试机所在的宿主网卡上注入断网。Docker／Podman／Kubernetes 各自真实运行；不具备环境不能把相应测试跳过当作支持。
- [ ] 运行全量测试、真实 SSH 生产链路、各 helper 集成与安装矩阵；仅在所有要求通过时标记总验收通过。
- [ ] 提交：`test: verify Linux remediation against real injected faults`。

## Task V2: 两端打包、迁移、自检与操作文档

**Files:** Modify `tools/build_release.py`, `tools/install_target_lib.sh`, `install-a4diag-target.sh`, `src/a4diag/init_config.py`, `src/a4diag/init_transaction.py`, `src/a4diag/builtin_catalog.py`, `docs/install.md`, `docs/linux-fault-recovery.md`; create `tests/integration/test_remediation_upgrade.py`, `docs/jev-integration.md`。

**Interfaces:** 延续现有初始化请求，新增 `repair_profiles` 和 `advisor` 可选配置；所有默认空／off。自检列出 adapter 可用性及原因，但不触发任何修复。

- [ ] 写安装回归：

```python
def test_upgrade_does_not_enable_new_writes(upgraded_target):
    assert upgraded_target.config['repair_profiles'] == []
    assert upgraded_target.config['advisor']['mode'] == 'off'
    assert upgraded_target.selfcheck()['new_write_helpers_enabled'] == []
```

fixture 用旧版空授权配置进行真实新包安装，读取安装后的实际配置。

- [ ] 运行 `python -m pytest -q tests/integration/test_remediation_upgrade.py`，确认新字段与自检未实现时失败。
- [ ] 接通内置清单、入口、schemas、helper 单元和安装包校验和；仅按目标端 profile 安装必要权限。旧配置升级和失败恢复均需保留原授权及 secret reference。
- [ ] 文档给出每类最小配置、持续授权与逐次批准区别、不可逆动作说明、真实支持环境和 Jev 独立凭据设置。安装步骤必须从新构建的包实际运行后记录；发布前不提供不存在的 Release 下载链接。
- [ ] 运行构建／verify-source、两端离线自检及发行版安装矩阵。保留审计，恢复实验服务和只读设置。
- [ ] 提交：`docs: document verified Linux remediation deployment`。

## 完成与交付

- [ ] 审查整条分支与授权边界；确认测试没有以 stub 替代标称真实场景。
- [ ] 汇总实际测试数、环境、失败／跳过原因、真实模型 usage、支持范围以及残余限制。
- [ ] 向用户报告分支与证据；不自动合并 main 或发布新版本。

## 计划自审记录

设计 3 对应 F；设计 4 对应 D；设计 5 对应 S；设计 6 对应 C；设计 7 对应 A；设计 8 对应 N；设计 9 对应 J；设计 10 对应 V。Review Focus 五项已分别分配到相应测试任务。执行中遇到新平台或 API 差异，先给最小复现并修订对应接口，不能删除验收条件以赶进度。
