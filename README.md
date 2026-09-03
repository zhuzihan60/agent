# A4Diag 0.4.2

[![CI](https://github.com/zhuzihan60/agent/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/zhuzihan60/agent/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/zhuzihan60/agent)](https://github.com/zhuzihan60/agent/releases/latest)

A4Diag 是一个基于 LangGraph 的通用 Linux 故障诊断与受控修复 Agent。
它采用插件化运行时、固定能力接口、目标身份绑定、摘要绑定审批、可回滚事务和追加式审计日志。

项目默认 **只读**。Agent 只能访问管理员显式注册并授权的目标，不会根据 IP、告警中的
`instance` 字段或“第一个目标”进行回退匹配。

## 快速安装

### 系统要求

- x86_64 Linux 与 systemd
- Python 3.11
- `curl`、`openssl`、`sha256sum`、`tar`
- root 权限

GitHub Actions 已验证以下发行版：

| 发行版 | 已验证版本 |
| --- | --- |
| Alibaba Cloud Linux | 3 |
| Rocky Linux | 8、9 |
| AlmaLinux | 8、9 |
| Ubuntu | 22.04、24.04 |
| Debian | 12 |

### 一键安装

```bash
curl -fsSL https://github.com/zhuzihan60/agent/releases/latest/download/install-a4diag.sh | sudo bash
sudo a4diag self-check --offline
```

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

当前正式版本：[v0.4.2](https://github.com/zhuzihan60/agent/releases/tag/v0.4.2)

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

## 注册目标

使用严格 JSON 输入注册本机或 SSH 目标。下面的地址属于 RFC 5737 文档保留网段，
仅用于示例：

```json
{
  "targets": [
    {
      "id": "target-1",
      "mode": "ssh",
      "host": "192.0.2.10",
      "port": 22,
      "user": "a4diag",
      "capabilities": [
        {
          "name": "files",
          "actions": ["replace"],
          "resources": ["/etc/example/**"]
        }
      ]
    }
  ]
}
```

```bash
sudo a4diag init --input target-request.json --output /etc/a4diag/config.yaml
sudo a4diag self-check --offline
```

`identity_ref` 由初始化流程根据目标 ID 生成，不能由输入文件指定。首次注册后仍保持只读；
写能力必须由管理员按照部署策略另行显式开启。

详细迁移步骤见
[v0.3 → v0.4 迁移指南](docs/migration/v0.3-to-v0.4.md)。

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
sudo systemctl disable --now a4diag-core.service
sudo rm -rf /opt/a4diag/releases /opt/a4diag/current
```

`/etc/a4diag` 和 `/var/lib/a4diag` 包含配置、审批、事务与审计数据，默认不会删除。
如需清理，请先备份审计记录并明确确认删除范围。
