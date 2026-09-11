# 内置控制端与目标端部署说明

服务证据采集、模型约束和业务健康验证的配置见 [服务与 HTTP 恢复闭环](service-http-recovery.md)。本分支控制端要求 systemd 247+；旧配置缺少恢复检查时会拒绝自动写入。

在控制服务器上安装已签名的控制端归档，并验证其签名和 `SHA256SUMS`。使用 `a4diag target bootstrap` 生成经过管理员审查的 `target-install.json`，然后把已签名的目标端归档传输到目标服务器并安装。目标端安装必须由管理员执行，Agent 永远不会自行安装目标端。

文件授权只支持预先存在、无符号链接且名称可由 systemd 安全解析的绝对目录根，例如 `/srv/app` 和 `/etc/example`。安装器拒绝与 SSH、网络、用户、内核、systemd、虚拟化及 A4Diag 自身资源重叠的路径，也拒绝 `/etc` 这类包含受保护资源的宽泛根。通过验证后，安装器会生成 `a4diag-target-executor.service.d/managed-roots.conf`，在保持 `ProtectSystem=strict` 和 `ProtectHome=yes` 的同时，把这些精确目录加入 `ReadWritePaths`。

当前目标执行器不接受包授权，因为 RPM/DEB 包管理需要宽泛的系统目录写权限，在线仓库还需要网络地址族。管理员不应通过 drop-in 放宽执行器沙箱；包变更应在执行器之外执行，直到项目提供独立且限制仓库与网络出口的最小权限 helper。

首先在 settings v3 中以只读模式注册目标。确认绑定的 machine-id、操作系统、systemd 和 SSH host key 身份均正确。只有在审查目标策略与受管资源根目录后，才能启用 LOW 风险执行。HIGH 风险操作保持 `pending_approval`，直到管理员依次执行 `a4diag approvals show`、`approve`，并明确运行 `a4diag resume TRANSACTION`（或使用等效的服务触发方式）。

每项操作都有类型化验证和 undo。审计与报告存储采用追加写方式，并能在服务重启后保留。即使已经人工审批，SSH、网络、防火墙、密钥、用户、内核、libvirt 和虚拟机生命周期资源仍然永久禁止修改。
