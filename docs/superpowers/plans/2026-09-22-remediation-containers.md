# Container Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 分别恢复登记的 Docker、Podman 容器和无状态 Kubernetes Deployment。

**Architecture:** 三个适配器共享业务验证和 profile 协议，但分别处理运行时身份、用户归属和集群控制器。签名入口不暴露通用容器 API。

**Tech Stack:** Python httpx、Unix sockets、Podman REST／固定 CLI、Kubernetes apps/v1 JSON Patch、systemd。

**Spec:** [设计 6](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划](2026-09-22-linux-remediation-jev.md#global-constraints)；依赖 F 与 S2。首版不操作卷、不 exec、不任意创建容器；Kubernetes 仅无状态 Deployment。

## Review Focus

同名不同 ID（C1）、rootless UID／socket 混淆（C2）、RBAC／命名空间越界（C3）、并发 rollout（C3）、Running 但 readiness／业务不健康（C1/C3）。

## Task C1: Docker adapter 与精确容器授权

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_containers.py`, `packages/a4diag-target-runtime/src/a4diag_target/repair_docker.py`, `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_containers.py`, `packages/a4diag-builtin-plugins/manifests/capability-containers.json`, `tests/target_runtime/test_repair_docker.py`, `tests/integration/test_docker_repair.py`; modify helper registry、profile constraints、builtin catalog、installer。

**Interfaces:** `ContainerIdentity` 字段 `runtime, container_id, image_digest, owner_uid`；`ContainerSnapshot` 字段 `identity, running, health, exit_code, oom_killed, restart_count`。`DockerAdapter.inspect(container_id: str) -> ContainerSnapshot`，`start(container_id: str)`，`restart(container_id: str, timeout_seconds: int)`；`require_same_container(expected, observed) -> None` 比较全部身份字段，不一致抛 `ContainerIdentityError`。

- [ ] 写替换身份负例：

```python
def test_same_name_different_id_is_rejected():
    import pytest
    from a4diag_target.repair_containers import ContainerIdentity, ContainerIdentityError, require_same_container
    a = ContainerIdentity(runtime='docker', container_id='a'*64,
                          image_digest='sha256:'+'c'*64, owner_uid=0)
    b = a.model_copy(update={'container_id': 'b'*64})
    with pytest.raises(ContainerIdentityError):
        require_same_container(a, b)
```

- [ ] 运行新增 unit tests 确认失败。实现有限 Unix socket 请求、TLS／远程 daemon 默认拒绝、完整 ID／image 核对；API 路径仅允许 inspect/start/restart。未知或无 Docker Health 字段不等于健康，须由业务检查补足。
- [ ] 生命周期 prepare 保存身份及先前 running 状态，apply 重查后执行；reconcile 查实际状态及操作记录，不能单凭 running 就推断特定 restart 已完成。S2 观察器使用同一 ID，重启计数变化立即判失败。
- [ ] 真实 Docker 测试退出、unhealthy、OOM、同名替换、未授权容器、超时和重复告警；`A4DIAG_TEST_DOCKER=1 python -m pytest -q tests/integration/test_docker_repair.py` 通过后提交 `feat: repair explicitly managed Docker containers`。

## Task C2: Podman rootful／rootless 与 systemd 归属

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_podman.py`, `tests/target_runtime/test_repair_podman.py`, `tests/integration/test_podman_repair.py`; modify C1 capability、profile constraints、`tools/install_target_lib.sh`。

**Interfaces:** `PodmanAdapter(owner_uid: int, socket_path: Path)` 提供 C1 相同 inspect/start/restart；`validate_runtime_owner(*, expected_uid: int, peer_uid: int, path_owner_uid: int) -> None` 不匹配抛 `ContainerIdentityError`。socket 路径由安装器依据管理员配置生成，不采纳模型参数。

- [ ] 写 UID 混淆测试：

```python
def test_rootless_socket_cannot_be_used_as_another_user():
    import pytest
    from a4diag_target.repair_podman import validate_runtime_owner
    from a4diag_target.repair_containers import ContainerIdentityError
    with pytest.raises(ContainerIdentityError):
        validate_runtime_owner(expected_uid=1001, peer_uid=1002, path_owner_uid=1002)
```

- [ ] 运行 Podman unit tests 验证失败。安装用户 helper 绑定 UID、受控 runtime 目录、peer credentials；不存在用户会话/socket 时返回 unavailable，不 fallback 到 root 容器。
- [ ] 对 Quadlet／systemd 管理容器，profile 必须指向登记 unit，并转入 S 服务事务；不同时调用 Podman restart 与 systemd restart。包含所有者身份的 canonical resource 例如 `podman/1001/<完整ID>`，不能混用 docker resource。
- [ ] 使用独立普通用户测试 rootless、rootful、同名跨用户、socket symlink、伪造 owner、unit 接管。`A4DIAG_TEST_PODMAN=1 python -m pytest -q tests/integration/test_podman_repair.py` 通过后提交 `feat: add owner-bound Podman recovery`。

## Task C3: Kubernetes Deployment 的受限 patch 与恢复

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_kubernetes.py`, `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_kubernetes.py`, `packages/a4diag-builtin-plugins/manifests/capability-kubernetes.json`, `deploy/kubernetes/repair-agent.yaml`, `tests/target_runtime/test_repair_kubernetes.py`, `tests/integration/test_kubernetes_repair.py`; modify helper registry、profile constraints、installer／catalog。

**Interfaces:** `DeploymentIdentity(cluster_id: str, namespace: str, name: str, uid: str)`；`deployment_patch(*, uid: str, resource_version: str, container_index: int, prior_image: str, desired_image: str) -> list[dict[str, JsonValue]]` 返回只包含身份/版本/原 image 测试与 image 替换的 JSON Patch；重启动作另用固定注解键 `a4diag.io/restart-transaction`。允许 image digest 来自 profile，不能用 latest。

- [ ] 写具体 CAS patch 测试：

```python
def test_image_repair_checks_concurrent_rollout():
    from a4diag_target.repair_kubernetes import deployment_patch
    patch = deployment_patch(uid='u1', resource_version='42', container_index=0,
        prior_image='demo@sha256:'+'a'*64, desired_image='demo@sha256:'+'b'*64)
    assert {'op': 'test', 'path': '/metadata/uid', 'value': 'u1'} in patch
    assert {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '42'} in patch
    assert patch[-1]['path'] == '/spec/template/spec/containers/0/image'
    assert patch[-1]['op'] == 'replace'
```

- [ ] 运行 Kubernetes unit tests，确认失败。实现精确 patch、UID 及原字段 CAS、受限 namespace RBAC 和 resourceNames；不能提供 wildcard patch 方法给模型。ServiceAccount 不读取 Secrets、不 exec，API client 禁用 kubeconfig 任意 exec credential 插件，仅从管理员受保护凭据引用读取证书／token。
- [ ] namespace 内 read/list 权限与 Secret 数据分离，只取 Pod／事件白名单字段，限制日志长度并脱敏；不把 imagePullSecret 内容或完整环境变量发往模型。TLS 验证必须开启。
- [ ] prepare 检查副本数、暂停、GitOps 标记、并发 generation、RollingUpdate maxUnavailable／maxSurge 与 profile 最低可用副本；不能把 PDB 当作 rolling update 的保护。apply 返回 F3 job，轮询 observedGeneration、updated/available replicas、旧副本退出与业务检查；deadline 后停止干预。
- [ ] 回退 patch 仍需原值 CAS；若其他控制器改过 image 则报告 conflict，不能强制恢复整份旧 spec。restart 补偿不声称恢复旧 Pod。
- [ ] D 盘 kind/k3s 隔离集群真实验证坏镜像恢复、卡死滚动重启、持续 CrashLoop、错误 namespace、UID 替换、RBAC403、HTTP409、同名对象和容量不足。`A4DIAG_TEST_KUBERNETES=1 python -m pytest -q tests/integration/test_kubernetes_repair.py` 通过后提交 `feat: recover authorized Kubernetes Deployments`。
