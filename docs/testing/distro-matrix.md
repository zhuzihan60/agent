# 发行版验证矩阵

A4Diag 0.5.0 通过 `.github/workflows/test.yml` 和 `release.yml` 验证以下环境。控制端要求 systemd 247+；矩阵绿色既可能表示安装成功，也可能表示旧环境被按预期拒绝，不能一概视为支持。

| 发行版 | 版本 | 容器镜像 |
| --- | --- | --- |
| Alibaba Cloud Linux | 3 | `langfarm/alinux3@sha256:c5c67ed6e33dc967e9a05ec3cec680abaf24bc2ea0fb23ee0d1470750882c6b1` |
| Rocky Linux | 8、9 | `rockylinux:8`、`rockylinux:9` |
| AlmaLinux | 8、9 | `almalinux:8`、`almalinux:9` |
| Ubuntu | 22.04、24.04 | `ubuntu:22.04`、`ubuntu:24.04` |
| Debian | 12 | `debian:12` |

RHEL 由 AlmaLinux/Rocky 的等效证据以及单独配置的许可 runner 覆盖；workflow 文件中不保存任何凭据。

控制端在 Rocky/AlmaLinux 9、Ubuntu 22.04/24.04、Debian 12 验证安装；Alibaba Cloud Linux 3 和 Rocky/AlmaLinux 8 的旧版 systemd 验证明确拒绝安装。目标端另设 `target-distro`，验证 Alibaba Cloud Linux 3、Rocky Linux 9、Ubuntu 24.04、Debian 12。

Alibaba Cloud Linux CI 容器是通过 digest 固定的 Alibaba Linux 3 测试镜像，已经包含 GitHub Actions 所需的归档工具，避免 checkout 前依赖网络安装软件包。生产支持依据官方操作系统身份 `ID=alinux` 和主版本 3 判断，而不是依据 CI 镜像名称。

## 每个矩阵作业的门禁

- **unit**：在 Linux Python 3.11 上运行完整 `pytest -q -rs`，覆盖 unit、contract、integration 和 acceptance。Windows 不是受支持的运行时，也不是发布门禁。
- **build**：构建同为 0.5.0 的控制端、内置插件和目标端 wheel；运行 `verify-source` 检查固定目标字面量，并验证两类发布包的清单和哈希。
- **distro**：在每个特权容器镜像中运行 `distro_smoke.sh`，离线安装组装后的发布包；验证只读默认值 `global_mode: read_only`、`targets: []`、离线 `self-check`，并确认 systemd 单元绝不允许写入 `/etc/a4diag/config.yaml`。
- **release**：只由 `v*` 标签触发；从 lockfile 重新构建，使用仓库 secret 对 manifest 签名，重新验证签名，在已签名发布包上运行发行版 smoke，并且只有全部必需作业成功后才发布。

## 仅限 Linux 的门禁

- AF_UNIX socket 测试（contract harness）
- symlink 创建测试
- POSIX 文件权限 0600 和 owner 检查
- init-config POSIX 权限门禁
- bash 安装器 harness 和 systemd 隔离检查

## 明确不执行的操作

CI 不访问用户生产服务器、发送真实邮件或调用外部模型/FlashDuty 服务。独立 `production-e2e` 在一次性 GitHub runner 上运行真实 systemd、SSH、目标执行器和插件进程；模型插件连接本地协议响应服务，验证补采、独立 HTTP 恢复检查和失败回滚。
