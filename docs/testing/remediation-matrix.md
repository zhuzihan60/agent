# 修复能力与验收边界

本页描述 v1.1.0 的支持范围和必过检查，不把跳过的测试计为通过。每次运行的实际通过数、环境和日志以对应提交的 GitHub Actions 为准。

| 能力 | 实现和授权范围 | 真实验收入口 |
| --- | --- | --- |
| 只读采集与七类 Linux 探针 | 管理员登记的目标、source/probe ID，有限输出 | 普通回归、SSH production-e2e |
| 独立 helper / 持久化作业 | 签名、peer 身份、profile、目标和有效期绑定；断线不重放 | `test_repair_helpers.py`、`test_repair_job_systemd.py` |
| 磁盘 | 指定缓存目录、年龄/数量/字节上限、写入者控制；不可逆删除 | `test_disk_remediation.py`，仅临时 64 MiB ext4 镜像制造空间/inode 故障 |
| systemd 服务 | 精确登记服务、独立业务检查、持续恢复观察 | `test_service_fault_repair.py` |
| Docker / Podman | 精确容器 ID；Podman 固定 owner UID 与受保护 socket；不回退到其他 owner | `test_docker_repair.py`、`test_podman_repair.py` |
| Kubernetes | 固定集群入口、namespace、Deployment 名称和 UID；重启/已登记镜像恢复，条件更新 | `test_kubernetes_repair.py`，独立 k3s + 最小 ServiceAccount |
| APT / 网络改写 / Jev | 尚未交付，计划文档不是已实现功能 | 无，不宣称支持 |

## CI 门槛

`test.yml` 与 `release.yml` 复用 `remediation.yml`，在四台独立、一次性的 Ubuntu 24.04 GitHub-hosted runner 上执行真实修复。它会在测试主机建立临时服务、用户、容器、集群和安装目录，不能在生产机或持久 self-hosted runner 上运行。脚本会拒绝不符合条件的环境及已有目标安装。

- 普通回归和 root 特权回归分别运行；后者使用私有挂载命名空间及受保护源码路径。
- 四组真实验收显式开启对应环境开关，检查 JUnit 中确有执行且没有 skipped/failure/error。
- 容器镜像仅用于测试，运行时记录解析到的镜像摘要；Kubernetes 使用导入后的不可变 digest，不把 Docker 源 registry digest 误当成 containerd 导入后 manifest digest。
- k3s 二进制固定版本并校验官方 release SHA-256；实验室 ServiceAccount 不获得读取 Secrets、执行 Pod 命令或读取 Nodes 的权限。
- 这些测试使用可控模型夹具和故障注入，不能等同于真实商业模型准确率评测，也不证明所有 Linux 发行版、CNI、容器版本或集群发行版都受支持。

发行版安装检查沿用 [安装矩阵](distro-matrix.md)。其他环境应先只读验证，再在隔离演示资源进行验收，不直接开启自动修复。

## 已知限制

告警诊断目前串行处理，独立修复心跳持续运行；`max_concurrency=2` 是上限，并非承诺两个模型诊断同时执行。租约约 60 秒、每 15 秒续租；处理异常最多尝试 5 次，退避 5/20/80/300 秒。已完成的诊断结果（包括失败或证据不足）不因此重新执行整个流程。超限或无法安全恢复的记录明确抑制，人工检查后应发起新的诊断请求，不清空历史事务。

Kubernetes 分页和关联证据有总预算，超大或频繁变化的工作负载可能只得到部分证据。日志和事件是非原子的观测，不能推导绝对一致快照。确定性证据评分仅检查引用和采集质量，不是统计概率或因果证明；不能用该指标声称诊断准确率或 MTTR 已提升某一百分比。
