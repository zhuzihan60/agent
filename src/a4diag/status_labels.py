"""Plain-language labels for workflow statuses shown by the CLI and dashboard."""

from __future__ import annotations

STATUS_LABELS = {
    "diagnosed": "已完成诊断",
    "read_only": "已完成诊断（只读模式，未执行任何修改）",
    "read_only_no_model": "未配置模型，只收集了证据",
    "insufficient_evidence": "证据不足，无法确认原因",
    "policy_denied": "建议的操作被安全策略拒绝",
    "pending_approval": "等待管理员审批",
    "approval_expired": "审批已过期",
    "notification_blocked": "必需的通知未送达，已暂停",
    "succeeded": "已修复并验证通过",
    "failed": "处理失败",
    "execution_unknown": "执行结果未知，需要核对",
    "rollback_succeeded": "修复未通过验证，已回滚",
    "rollback_partial": "回滚未完全成功",
    "rollback_unknown": "回滚结果未知，需要核对",
}

# Statuses where the agent did its job; anything else needs a human to look.
SETTLED_STATUSES = frozenset(
    {"diagnosed", "read_only", "succeeded", "pending_approval", "rollback_succeeded"}
)


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)
