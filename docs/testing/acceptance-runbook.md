# 本地与 SSH 安全及混沌验收手册

验收套件 `tests/acceptance/` 用于证明 Agent 的操作边界和恢复行为，**不会连接任何真实服务器、SSH daemon、邮件服务器、模型 API 或 FlashDuty endpoint**。每台“机器”都是注入的 fake，所有连接尝试都会记录到连接账本；被测试的运行时是实际的 Phase 3 `Runtime`。

## 运行方法

```bash
python -m pytest tests/acceptance -q
```

默认场景全部使用 fake。实时 `t_11` 沙箱场景使用 `@pytest.mark.live_t11` 标记，只有提供真实一次性环境后才会运行：

```bash
sudo A4DIAG_ACCEPTANCE=1 python -m pytest tests/acceptance -q
```

## 覆盖范围

| 文件 | 场景 |
| --- | --- |
| `test_local_remediation.py` | 修复并验证 LOW 故障；外部或未注册目标从未被连接（账本条目为零）；身份漂移阻止写入重新验证；未知执行不重放；模型超时和网络中断以零 executor 调用的方式 fail-closed；已消费 ticket 不可重用；预留实时 t_11 场景。 |
| `test_ssh_remediation.py` | host key 变化阻止全部操作（apply/undo 为零）；SSH 用户名来自配置而非硬编码；未注册 SSH 目的地（IP、主机名或其他 ID）从未被连接；只按注册名称授权，即使已注册目标自身的 IP 也不能作为授权标识。 |
| `test_plugin_chaos.py` | dispatch 前、apply 后和 prepare 期间崩溃；所有场景都从持久化 dispatch intent 执行 reconcile，且 `apply_count <= 1`；verify 失败触发严格逆序回滚；undo 崩溃如实报告 `rollback_unknown` 或 `execution_unknown`；apply 期间网络中断时 fail-closed 且不重试。 |
| `test_high_risk_gate.py` | HIGH 未审批时 executor dispatch 为零；错误摘要持续被阻止；正确的本地 CLI 审批只 dispatch 一次；审批后目标身份变化会使审批失效；即使模型声称 LOW，具有高风险下限的操作仍保持 HIGH。 |

## 证据纪律

- 每项测试都通过连接账本断言外部 canary（未注册目的地）从未被连接。
- 报告中只使用 transaction ID 和 event ID，不断言或打印 secret。
- 本手册不能替代真实环境验收。正式发布前，特权发行版矩阵和实时 `t_11` 沙箱仍是必需的 Linux 门禁。
