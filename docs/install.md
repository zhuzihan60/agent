# A4Diag v0.5.0 安装与升级指南

v0.5.0 正在本分支准备发布。正式发布前，`releases/latest` 仍指向已发布的旧版本。升级前请阅读 [v0.5.0 发布说明](release/v0.5.0.md)，先升级目标端，再升级控制端并重新初始化插件配置。

A4Diag 由两个独立部分组成：

- **控制端**：运行 LangGraph 编排、模型、审批、审计和报告服务。
- **目标端**：只安装受限执行器，通过固定能力接口接受控制端请求。

目标端安装始终由管理员手动完成，Agent 不具备安装目标端、创建虚拟机或扩展自身管理范围的权限。新安装默认保持只读，不会自动注册目标或开启写能力。

## 1. 系统要求

- x86_64 Linux 和 systemd
- Python 3.11
- `curl`、`openssl`、`sha256sum`、`tar`
- root 权限

服务/HTTP 恢复闭环要求控制端使用 **systemd 247+**，以支持插件独立凭据。Alibaba Cloud Linux 3、Rocky/AlmaLinux 8 的旧版 systemd 不满足要求，控制端安装器会明确拒绝，CI 只验证拒绝行为。目标端单独验证 Alibaba Cloud Linux 3、Rocky Linux 9、Ubuntu 24.04 和 Debian 12。闭环配置与模型接入见 [服务与 HTTP 恢复闭环](deployment/service-http-recovery.md)。

控制端安装验证范围：

| 发行版 | 版本 |
| --- | --- |
| Rocky Linux | 9 |
| AlmaLinux | 9 |
| Ubuntu | 22.04、24.04 |
| Debian | 12 |

## 2. 安装或升级控制端

### 2.1 一键安装

建议先保存并审查脚本：

```bash
curl -fsSLo /tmp/install-a4diag.sh \
  https://github.com/zhuzihan60/agent/releases/latest/download/install-a4diag.sh
less /tmp/install-a4diag.sh
sudo bash /tmp/install-a4diag.sh
```

也可以使用简化命令：

```bash
curl -fsSL \
  https://github.com/zhuzihan60/agent/releases/latest/download/install-a4diag.sh \
  | sudo bash
```

首次下载信任 GitHub HTTPS 和本仓库控制权。安装脚本内置发布公钥，会在解压前验证 `a4diag.tar.gz` 的 RSA/SHA-256 分离签名；解压后还会再次验证 `MANIFEST.json`、`MANIFEST.sig` 和 `SHA256SUMS`。

### 2.2 离线或中转安装

在可访问 GitHub 的中转机下载以下四个文件：

- `a4diag.tar.gz`
- `a4diag.tar.gz.sig`
- `a4diag-release-public.pem`
- `install-a4diag.sh`

将文件复制到控制端同一目录后执行：

```bash
cd /path/to/a4diag-release

openssl dgst -sha256 \
  -verify a4diag-release-public.pem \
  -signature a4diag.tar.gz.sig \
  a4diag.tar.gz

sudo A4DIAG_RELEASE_URL="file://$PWD/a4diag.tar.gz" \
  A4DIAG_RELEASE_SIGNATURE_URL="file://$PWD/a4diag.tar.gz.sig" \
  bash ./install-a4diag.sh
```

如果公钥也是从同一网络位置下载的，应通过可信渠道核对其指纹。安装程序默认拒绝未签名或摘要不匹配的归档，不应在生产环境设置 `A4DIAG_ALLOW_UNSIGNED=1`。

### 2.3 安装程序执行内容

1. 检查 root、发行版、Python 3.11 和系统命令。
2. 验证版本锁、签名和全部文件摘要。
3. 暂存到 `/opt/a4diag/releases/<version>`。
4. 从锁定 wheelhouse 创建独立虚拟环境，全程使用 `--no-index`。
5. 在暂存版本中运行 `a4diag self-check --offline`。
6. 安装加固后的 systemd 单元。
7. 原子切换 `/opt/a4diag/current`。
8. 启动 `a4diag-core.service`；启动失败时自动恢复上一版本。

升级使用相同安装命令。以下数据不会被覆盖：

- `/etc/a4diag/config.yaml`
- Secret 和插件 pin
- 审批及事务数据库
- 审计日志和报告

配置不存在时才会创建默认配置，初始状态为：

```yaml
global_mode: read_only
auto_execute_low: false
targets: []
plugins: []
```

### 2.4 控制端安装验收

```bash
sudo a4diag self-check --offline
sudo systemctl is-enabled a4diag-core.service
sudo systemctl is-active a4diag-core.service
sudo systemctl show a4diag-core.service \
  -p ActiveState -p SubState -p Result -p NRestarts
readlink -f /opt/a4diag/current
sudo journalctl -u a4diag-core.service -n 50 --no-pager
```

预期 `self-check` 返回 `"ok": true`，服务为 `active/running`，且新安装仍显示 `global_mode: read_only` 和空目标列表。

## 3. 安装目标端

### 3.1 在控制端生成目标安装材料

下面使用文档保留地址作为示例，请替换目标 ID 和控制端来源网段：

```bash
sudo a4diag target bootstrap target-1 \
  --output /root/a4diag-target-1 \
  --source-cidr 192.0.2.20/32
```

输出目录必须事先不存在。命令会：

- 在输出目录生成不含私钥的 `target-install.json`。
- 将 SSH 私钥和操作签名私钥保存到控制端 `/etc/a4diag/secrets/targets/target-1/`。
- 默认生成空的 `managed_resources`，因此没有任何可写资源。

管理员必须审查 `target-install.json`。只有确实需要写入时，才添加精确资源，并把 `confirm_managed_resources` 从 `DISABLED` 改为字面量 `ENABLE`。文件能力的 `resource` 是目录根，例如 `/srv/app` 或 `/etc/example`；目录必须在安装前存在，且路径本身及其父目录不能是符号链接。安装器只接受由 ASCII 字母、数字、`._+@:-` 和路径分隔符组成的绝对路径，以免 systemd 对空白、`%` 等字符进行二次解释。

文件根不能等于、位于或包含受保护路径。受保护范围包括 SSH、网络、防火墙、用户与认证、密钥、内核、systemd、定时任务、SELinux、libvirt、QEMU 以及 A4Diag 自身路径；`/`、`/etc`、`/usr`、`/var` 等包含这些路径的宽泛根也会被拒绝。安装器会从已验证的文件根生成 `a4diag-target-executor.service.d/managed-roots.conf`，重建精确的 `ReadWritePaths`，同时保留 `ProtectSystem=strict`、`ProtectHome=yes` 和执行器状态目录。

当前加固后的目标执行器拒绝 `packages` 授权。RPM/DEB 包管理需要同时修改多个系统目录，在线仓库还需要 AF_INET/AF_INET6；把这些权限直接加入 root 执行器会破坏现有隔离边界。不要通过自定义 drop-in 关闭 `ProtectSystem` 或扩大 `RestrictAddressFamilies`。需要包变更时，应由管理员在执行器之外完成；将来如提供包能力，必须使用独立的最小权限 helper，并单独限制仓库和网络出口。

### 3.2 在目标服务器执行安装

将以下文件复制到目标服务器：

- `a4diag-target.tar.gz`
- `a4diag-target.tar.gz.sig`
- `install-a4diag-target.sh`
- 已审查的 `target-install.json`

在目标服务器执行：

```bash
cd /path/to/a4diag-target-release

sudo A4DIAG_TARGET_RELEASE_URL="file://$PWD/a4diag-target.tar.gz" \
  A4DIAG_TARGET_RELEASE_SIGNATURE_URL="file://$PWD/a4diag-target.tar.gz.sig" \
  A4DIAG_TARGET_INSTALL_CONFIG="$PWD/target-install.json" \
  bash ./install-a4diag-target.sh
```

如果目标服务器可以稳定访问 GitHub，也可以只准备 `target-install.json` 后执行：

```bash
sudo A4DIAG_TARGET_INSTALL_CONFIG="$PWD/target-install.json" \
  bash ./install-a4diag-target.sh
```

这里的脚本仍需事先从正式 Release 下载并审查。目标端安装器会验证签名、创建受限账号与 forced-command SSH 配置，并启动 socket-activated executor。

### 3.3 目标端安装验收

```bash
sudo systemctl is-enabled a4diag-target-executor.socket
sudo systemctl is-active a4diag-target-executor.socket
sudo systemctl status a4diag-target-executor.socket --no-pager -l
sudo test -x /usr/libexec/a4diag/a4diag-transport-helper
sudo test -f /etc/a4diag-target/policy.json
sudo test -f /etc/a4diag-target/operation-public.pem
sudo systemctl cat a4diag-target-executor.service
sudo systemctl show a4diag-target-executor.service \
  -p ProtectSystem -p ProtectHome -p ReadWritePaths -p RestrictAddressFamilies
sudo journalctl -u a4diag-target-executor.socket -n 50 --no-pager
```

如果配置了文件根，`systemctl cat` 应显示安装器生成的 `managed-roots.conf`；`systemctl show` 应继续显示 `ProtectSystem=strict`、`ProtectHome=yes` 和 `RestrictAddressFamilies=AF_UNIX`，并只在 `ReadWritePaths` 中增加已审查的文件根。升级或策略变更会同步重启正在运行的执行器，使新策略和挂载命名空间立即生效；被中断的事务必须通过持久化状态进行核对后才能继续。安装目标端不等于授权控制端写入。还必须在控制端 settings v3 中注册目标并完成 machine-id、OS、systemd 和 SSH host key 身份绑定。

## 4. 启用受控处理能力

建议按以下顺序启用：

1. 注册目标，但保持 `global_mode: read_only`。
2. 完成只读诊断、身份绑定、报告持久化和通知通道验收。
3. 管理员审查目标端 `managed_resources` 和控制端 capability 范围。
4. 如确有需要，再显式启用 `read_write` 和 LOW 自动执行。
5. HIGH 操作始终等待摘要绑定的人工审批。

HIGH 操作审批后还需明确恢复事务：

```bash
sudo a4diag approvals list --json
sudo a4diag approvals show <transaction-id>
sudo a4diag approvals approve <transaction-id> --digest <full-plan-digest>
sudo a4diag resume <transaction-id>
```

审批前执行器调用必须为零。目标身份、配置、计划摘要或有效期变化都会使审批失效。

## 5. 回滚

服务启动失败时，安装程序会自动恢复上一版本。手动回滚前先确认目标版本目录存在：

```bash
sudo test -d /opt/a4diag/releases/<previous-version>
sudo ln -s /opt/a4diag/releases/<previous-version> /opt/a4diag/current.new
sudo mv -T /opt/a4diag/current.new /opt/a4diag/current
sudo systemctl daemon-reload
sudo systemctl restart a4diag-core.service
sudo a4diag self-check --offline
```

旧版本不会自动删除，应在新版本稳定并完成审计备份后再单独清理。

## 6. 卸载

只卸载程序、保留配置和审计数据：

```bash
sudo systemctl disable --now a4diag-core.service
sudo rm -rf /opt/a4diag/releases /opt/a4diag/current
```

`/etc/a4diag` 和 `/var/lib/a4diag` 包含配置、密钥引用、审批、事务、报告和审计记录，默认不要删除。如需彻底清理，应先备份并单独确认准确路径。

## 7. 延伸文档

- [控制端与目标端部署](deployment/builtin-controller-target.md)
- [v0.3 到 v0.4 迁移指南](migration/v0.3-to-v0.4.md)
- [验收运行手册](testing/acceptance-runbook.md)
- [发行版兼容矩阵](testing/distro-matrix.md)
- [v0.5.0 发布说明](release/v0.5.0.md)
