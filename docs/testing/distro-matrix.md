# 支持的发行版矩阵

A4Diag 0.4.2 通过 `.github/workflows/test.yml` 和 `release.yml` 在所有受支持发行版上执行 CI 验证：

| 发行版 | 版本 | 容器镜像 |
| --- | --- | --- |
| Alibaba Cloud Linux | 3 | `langfarm/alinux3@sha256:c5c67ed6e33dc967e9a05ec3cec680abaf24bc2ea0fb23ee0d1470750882c6b1` |
| Rocky Linux | 8、9 | `rockylinux:8`、`rockylinux:9` |
| AlmaLinux | 8、9 | `almalinux:8`、`almalinux:9` |
| Ubuntu | 22.04、24.04 | `ubuntu:22.04`、`ubuntu:24.04` |
| Debian | 12 | `debian:12` |

RHEL 由 AlmaLinux/Rocky 的等效证据以及单独配置的许可 runner 覆盖；workflow 文件中不保存任何凭据。

Alibaba Cloud Linux CI 容器是通过 digest 固定的 Alibaba Linux 3 测试镜像，已经包含 GitHub Actions 所需的归档工具，避免 checkout 前依赖网络安装软件包。生产支持依据官方操作系统身份 `ID=alinux` 和主版本 3 判断，而不是依据 CI 镜像名称。

## 每个矩阵作业的门禁

- **unit**：在 Linux Python 3.11 上运行完整 `pytest -q -rs`，覆盖 unit、contract、integration 和 acceptance。Windows 不是受支持的运行时，也不是发布门禁。
- **build**：构建精确的 `a4diag-0.4.2-py3-none-any.whl` 和 `a4diag_builtin_plugins-0.4.2-py3-none-any.whl`；运行 `verify-source` 检查固定目标字面量，并运行 `verify-release`。
- **distro**：在每个特权容器镜像中运行 `distro_smoke.sh`，离线安装组装后的发布包；验证只读默认值 `global_mode: read_only`、`targets: []`、离线 `self-check`，并确认 systemd 单元绝不允许写入 `/etc/a4diag/config.yaml`。
- **release**：只由 `v*` 标签触发；从 lockfile 重新构建，使用仓库 secret 对 manifest 签名，重新验证签名，在已签名发布包上运行发行版 smoke，并且只有全部必需作业成功后才发布。

## 仅限 Linux 的门禁

- AF_UNIX socket 测试（contract harness）
- symlink 创建测试
- POSIX 文件权限 0600 和 owner 检查
- init-config POSIX 权限门禁
- bash 安装器 harness 和 systemd 隔离检查

## 明确不执行的操作

CI 矩阵永远不会访问真实外部服务器、发送邮件、调用模型 API 或请求 FlashDuty；transport 测试全部使用注入的 fake。
