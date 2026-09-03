# 内置控制端与目标端部署说明

在控制服务器上安装已签名的控制端归档，并验证其签名和 `SHA256SUMS`。使用 `a4diag target bootstrap` 生成经过管理员审查的 `target-install.json`，然后把已签名的目标端归档传输到目标服务器并安装。目标端安装必须由管理员执行，Agent 永远不会自行安装目标端。

首先在 settings v3 中以只读模式注册目标。确认绑定的 machine-id、操作系统、systemd 和 SSH host key 身份均正确。只有在审查目标策略与受管资源根目录后，才能启用 LOW 风险执行。HIGH 风险操作保持 `pending_approval`，直到管理员依次执行 `a4diag approvals show`、`approve`，并明确运行 `a4diag resume TRANSACTION`（或使用等效的服务触发方式）。

每项操作都有类型化验证和 undo。审计与报告存储采用追加写方式，并能在服务重启后保留。即使已经人工审批，SSH、网络、防火墙、密钥、用户、内核、libvirt 和虚拟机生命周期资源仍然永久禁止修改。
