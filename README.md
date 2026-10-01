# A4Diag 1.1.0

v1.1.0 增加有独立授权边界的磁盘、服务、Docker/Podman 与 Kubernetes Deployment 修复，并加固告警持久化重试、日志脱敏及证据引用校验。控制端、内置插件和目标端必须使用同一版本。默认只读，升级不会自动启用写权限。兼容性变化和升级顺序见 [v1.1.0 发布说明](docs/release/v1.1.0.md)，能力与验收边界见 [支持矩阵](docs/testing/remediation-matrix.md)。

[![CI](https://github.com/zhuzihan60/agent/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/zhuzihan60/agent/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/zhuzihan60/agent)](https://github.com/zhuzihan60/agent/releases/latest)

A4Diag 是一个基于 LangGraph 的通用 Linux 故障诊断与受控修复 Agent。
它采用插件化运行时、固定能力接口、目标身份绑定、摘要绑定审批、可回滚事务和追加式审计日志。

项目默认 **只读**。Agent 只能访问管理员显式注册并授权的目标，不会根据 IP、告警中的
`instance` 字段或“第一个目标”进行回退匹配。

## 三步上手（单机）

在一台 Linux 服务器上同时装好控制端和被控端，诊断这台机器自己：

```bash
# 1. 安装控制端（自带 Python，不需要事先安装任何运行环境）
curl -fsSL https://github.com/zhuzihan60/agent/releases/latest/download/install-a4diag.sh | sudo bash

# 2. 设置：选择大模型、输入 API key、选择要监控的服务（例如 nginx）
sudo a4diag setup

# 3. 出问题时，用一句话描述现象
sudo a4diag diagnose "网站打不开"
```

`a4diag setup` 会自动下载并安装同版本的被控端组件，把本机登记为只读目标 `local`。
支持 DeepSeek、通义千问（阿里云百炼）、OpenAI、本机 Ollama 和其他 OpenAI 兼容服务；
API key 以 0600 权限保存在 `/etc/a4diag/secrets/`，不会写进配置文件。之后想更换模型或
监控的服务，再运行一次 `sudo a4diag setup` 即可。

`a4diag diagnose` 会收集已登记服务的状态和日志，交给模型分析，在终端输出原因和建议，
完整报告保存在 `/var/lib/a4diag/reports/`。默认 **只诊断不修改**。

### 状态网页

安装后自动启动只读状态网页 `http://127.0.0.1:8765`，显示控制端服务、模型、被控端在线与
身份状态，以及最近的诊断结果。网页没有任何修改操作。

| 控制端在哪里 | 在 Windows 上怎么打开 |
| --- | --- |
| WSL | 直接在浏览器打开 `http://localhost:8765` |
| 远程 Linux 服务器 | `ssh -L 8765:127.0.0.1:8765 用户@服务器`，再打开 `http://localhost:8765` |
| 局域网内直接访问 | `sudo a4diag setup --dashboard-lan`，按提示用带令牌的地址打开 |

默认只监听本机回环地址；开放到局域网时必须使用 setup 生成的访问令牌。

## 两个安装包

| 安装包 | 装在哪里 | 安装命令 |
| --- | --- | --- |
| 控制端 `a4diag.tar.gz` | 运行 Agent 的机器 | `install-a4diag.sh` |
| 被控端 `a4diag-target.tar.gz` | 每台要诊断的机器 | `install-a4diag-target.sh` |

两个包都经过签名，并各自附带 Python 3.11 运行环境：系统已有 `python3.11` 时使用系统的，
没有时自动使用包内的。单机使用时，被控端由 `a4diag setup` 自动安装，无需手动下载。
管理远程服务器见下文 [添加远程被控端](#添加远程被控端)。

## 安装说明

### 系统要求

- x86_64 Linux；控制端要求 systemd 247+
- `curl`、`openssl`、`sha256sum`、`tar`
- root 权限

控制端安装验证范围：

| 发行版 | 已验证版本 |
| --- | --- |
| Rocky Linux | 9 |
| AlmaLinux | 9 |
| Ubuntu | 22.04、24.04 |
| Debian | 12 |

Alibaba Cloud Linux 3、Rocky/AlmaLinux 8 的旧版 systemd 不满足控制端要求，CI 验证安装器明确拒绝。目标端单独验证 Alibaba Cloud Linux 3、Rocky Linux 9、Ubuntu 24.04 和 Debian 12。

### 安装过程

安装脚本会下载最新的 GitHub Release，先使用脚本内置的 RSA 公钥验证
`a4diag.tar.gz` 的 SHA-256 签名，再解压归档。归档内部的 `MANIFEST.json`、
`MANIFEST.sig` 和 `SHA256SUMS` 会被再次验证，任何校验失败都会中止安装。

> `curl | sudo bash` 的首次信任边界是 GitHub HTTPS 和本仓库的控制权。
> 如果需要更严格的首次安装，可先下载并审查 `install-a4diag.sh`，再执行本地文件。

安装过程不会自动注册目标、开启写权限或覆盖已有配置。新安装的默认配置为：

```yaml
global_mode: read_only
targets: []
plugins: []
```

当前版本：[v1.1.0](https://github.com/zhuzihan60/agent/releases/tag/v1.1.0)

## 安全模型

- **默认只读**：未显式开启写能力时只诊断、生成报告和建议排查命令。
- **目标隔离**：仅接受配置中注册的 `target_id`；目标 machine-id 或 SSH host key
  发生变化时，在执行前拒绝操作。
- **固定能力接口**：模型只能选择经过校验的 capability/action/resource，不能直接生成
  `shell`、`script`、`argv` 或任意命令交给执行器。
- **LOW 风险**：只有管理员显式启用写权限和 LOW 自动执行策略后，才允许自动 apply、
  verify，并在失败时进入 undo/reconcile。
- **HIGH 风险**：执行前必须由管理员在 CLI 中审批完整 plan digest；审批前 executor
  调用次数必须为零。
- **未知执行不重放**：超时或进程崩溃会进入 `execution_unknown`，恢复时先 reconcile，
  不会盲目重复 apply。
- **审计失败即只读**：审计哈希链损坏或插件 pin 校验失败会强制锁定为只读模式。

## 添加远程被控端

下面以被控端 `web-1`（地址 `192.0.2.10`，RFC 5737 文档示例地址）为例。被控端只接受
来自控制端地址的、受限于固定命令的 SSH 连接。

**1. 在控制端生成被控端安装材料**（私钥只留在控制端）：

```bash
sudo a4diag target bootstrap web-1 --output /root/a4diag-web-1 --source-cidr <控制端IP>/32
```

**2. 在 `/root/a4diag-web-1/target-install.json` 中登记要诊断的服务**，并把
`confirm_managed_resources` 改为 `ENABLE`：

```json
"managed_resources": [{"capability": "services", "resource": "nginx.service"}],
"confirm_managed_resources": "ENABLE"
```

**3. 把 `target-install.json` 复制到被控端，在被控端安装被控端包：**

```bash
curl -fsSLO https://github.com/zhuzihan60/agent/releases/latest/download/install-a4diag-target.sh
sudo A4DIAG_TARGET_INSTALL_CONFIG="$PWD/target-install.json" bash install-a4diag-target.sh
```

**4. 回到控制端，固定被控端的 SSH 主机密钥：**

```bash
ssh-keyscan -t ed25519 192.0.2.10 | sudo tee /etc/a4diag/secrets/targets/web-1/known_hosts
sudo chown a4diag:a4diag /etc/a4diag/secrets/targets/web-1/known_hosts
sudo chmod 0600 /etc/a4diag/secrets/targets/web-1/known_hosts
```

请通过可信渠道核对指纹（例如在被控端运行 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`）。

**5. 在控制端登记。** `a4diag init` 写入完整配置，请同时保留已有的模型和目标：

```json
{
  "global_mode": "read_only",
  "model": {"base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat",
            "api_key_ref": "file:model-api-key"},
  "targets": [{
    "id": "web-1", "mode": "ssh", "host": "192.0.2.10", "port": 22, "user": "a4diag-target",
    "transport": "transport-ssh-web-1",
    "identity_file_ref": "file:targets/web-1/ssh-ed25519",
    "known_hosts_ref": "file:targets/web-1/known_hosts",
    "operation_signing_key_ref": "file:targets/web-1/operation-ed25519.pem",
    "evidence_sources": [
      {"id": "nginx-state", "kind": "service_state", "resource": "nginx.service"},
      {"id": "nginx-logs", "kind": "service_logs", "resource": "nginx.service"}
    ],
    "recovery_checks": [{"id": "nginx-active", "kind": "service_active", "resource": "nginx.service"}]
  }]
}
```

```bash
sudo a4diag init --input web-1.json
sudo a4diag diagnose --target web-1 "网站打不开"
```

登记时会实时核对被控端的 machine-id、系统版本、systemd 和 SSH 主机密钥，之后任何一项变化
都会在执行前被拒绝。登记后仍保持只读；写能力必须由管理员按照部署策略另行显式开启。

## HIGH 风险人工审批

HIGH 风险计划会停在 `pending_approval`，不会提前执行：

```bash
sudo a4diag approvals list --json
sudo a4diag approvals show <transaction-id>
sudo a4diag approvals approve <transaction-id> --digest <full-plan-digest>
```

审批会重新检查计划摘要、有效期、当前目标身份和必要通知状态。摘要、身份或配置发生变化时，
原审批自动失效。

## 插件与通知

查看、安装或停用经过签名与摘要校验的插件：

```bash
sudo a4diag plugin list
sudo a4diag plugin verify <plugin-package>
sudo a4diag plugin install <plugin-package>
sudo a4diag plugin disable <plugin-name>
```

内置通知插件包括：

- CLI 审批事件文件
- FlashDuty
- SMTP Email
- 通用 Webhook（可选 HMAC）

Secret 通过引用解析，不应写入配置、URL、通知正文或日志。

## 离线安装

在可联网机器下载 Release 的四个资产，并将其复制到离线主机：

- `a4diag.tar.gz`
- `a4diag.tar.gz.sig`
- `a4diag-release-public.pem`
- `install-a4diag.sh`

解压已验证的归档后执行：

```bash
sudo A4DIAG_TRUSTED_KEY=/path/to/a4diag-release-public.pem \
  ./install.sh --offline /path/to/release-dir
```

离线安装只使用归档中的锁定 wheelhouse，不会访问 PyPI。完整安装、回滚和卸载说明见
[安装指南](docs/install.md)。

## 安装后检查

```bash
sudo a4diag self-check --offline
sudo systemctl status a4diag-dashboard.service
sudo systemctl status a4diag-core.service
sudo a4diag plugin list --json
sudo a4diag approvals list --json
```

在启用任何写能力前，先完成只读诊断、目标身份绑定、报告持久化和通知通道验收。

## 开发与验证

生产运行时仅支持 Linux。完整测试应在 Linux 或 GitHub Actions 中执行：

```bash
python -m compileall -q src packages tests tools
python -m pytest -q
python tools/build_release.py verify-source --project-root .
```

当前发布门禁包括完整 pytest、签名构建、篡改归档拒绝，以及 8 个 Linux 发行版的
离线安装和公开 bootstrap smoke。

更多文档：

- [发行版测试矩阵](docs/testing/distro-matrix.md)
- [验收运行手册](docs/testing/acceptance-runbook.md)
- [安装指南](docs/install.md)

## 卸载

```bash
sudo systemctl disable --now a4diag-core.service a4diag-dashboard.service
sudo rm -rf /opt/a4diag/releases /opt/a4diag/current /opt/a4diag/runtime
```

单机设置还安装了被控端组件，可用其安装脚本卸载（保留审计状态）：

```bash
sudo A4DIAG_TARGET_CONFIRM_UNINSTALL=REMOVE bash /opt/a4diag-target/current/tools/install_target_lib.sh uninstall
```

`/etc/a4diag` 和 `/var/lib/a4diag` 包含配置、审批、事务与审计数据，默认不会删除。
如需清理，请先备份审计记录并明确确认删除范围。
