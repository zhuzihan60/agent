# Disk and Inode Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在明确授权的可丢弃缓存中释放容量和 inode，并证明业务恢复。

**Architecture:** prepare 冻结有限候选清单和写入者停止状态；apply 逐项复核并删除，每批重新读取文件系统状态。不可逆删除使用基础模块的 partial／unknown 报告。

**Tech Stack:** Python dir_fd/open flags、statvfs、SQLite、systemd、ext4 loopback 测试。

**Spec:** [设计 4](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划](2026-09-22-linux-remediation-jev.md#global-constraints)；依赖 F1–F5。首版只清理普通缓存文件，不截断活动日志，不使用全盘 find／prune。

## Review Focus

目录／inode 替换、仍打开的已删文件、硬链接／跨挂载、审计空间耗尽、写入者未真正停止，分别纳入 D1/D2。

## Task D1: 准备有界候选清单

**Files:** Create `packages/a4diag-target-runtime/src/a4diag_target/repair_disk.py`, `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/capability_disk.py`, `packages/a4diag-builtin-plugins/manifests/capability-disk.json`, `tests/target_runtime/test_repair_disk.py`; modify repair profile constraints、helper 注册表和 builtin catalog。

**Interfaces:** `DiskLimits` 字段 `root, min_age_seconds, max_files, max_bytes, min_free_bytes, min_free_inodes, writer_unit`；`DiskEntry` 字段 `relative_path, dev, ino, size, mtime_ns, ctime_ns`；`DiskMarker` 字段 `root_dev, root_ino, entries, writer_stop_marker, initial_free_bytes, initial_free_inodes`。`prepare_cleanup(limits: DiskLimits, *, now_ns: int) -> DiskMarker`；`entry_unchanged(entry: DiskEntry, current: os.stat_result) -> bool`，拒绝非普通、nlink≠1 或任意绑定字段变化。

- [ ] 写具体 inode 替换测试：

```python
def test_replaced_candidate_is_not_accepted(tmp_path):
    from a4diag_target.repair_disk import DiskEntry, entry_unchanged
    p = tmp_path / 'cache'
    p.write_bytes(b'old')
    st = p.stat()
    saved = DiskEntry(relative_path='cache', dev=st.st_dev, ino=st.st_ino,
        size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns)
    p.rename(tmp_path / 'kept-old')
    p.write_bytes(b'new')
    assert not entry_unchanged(saved, p.stat())
```

- [ ] 运行 `python -m pytest -q tests/target_runtime/test_repair_disk.py`，确认缺失实现。实现逐级 O_NOFOLLOW 目录打开和 FD 绑定、扫描深度／数量／输出限制；超过清单预算报 preparation_budget_exceeded，不无界扫描。
- [ ] 首版只接受 administrator-owned 缓存目录和登记的已停止写入者 unit。目标外部并发写入不能仅靠 advisory flock 假装阻止；检测到文件变化或无法证明写入者边界时拒绝清理。writer_unit 停止步骤走已有授权事务并记录先前状态。
- [ ] 测试根替换、父目录符号链接、FIFO、硬链接、mount 边界、过新文件、root 路径拒绝、超预算和危险 unit；运行新增测试及既有文件恢复回归，通过后提交 `feat: prepare bounded cache cleanup candidates`。

## Task D2: 不可逆清理、资源验证与实机验收

**Files:** Modify D1 模块、`src/a4diag/repair_effects.py`, `src/a4diag/plugin_ports.py`, `tools/install_target_lib.sh`; create `tests/integration/test_disk_remediation.py`, `tests/e2e/fixtures/disk_fault.py`。

**Interfaces:** `apply_cleanup(marker: DiskMarker, limits: DiskLimits) -> dict[str, JsonValue]` 返回 `removed_files, removed_logical_bytes, available_bytes, free_inodes, target_met, skipped_changed`；capability lifecycle 使用已有 prepare/apply/verify/reconcile 结构，undo 明确返回 irreversible，不伪造撤销。

- [ ] 写真实打开文件测试：

```python
def test_unlinked_open_file_is_not_proof_of_recovery(full_test_fs):
    with full_test_fs.open_filler() as held:
        result = full_test_fs.repair()
        assert result['removed_files'] > 0
        assert result['target_met'] is False
        assert held.readable()
```

fixture 在专用 ext4 loop image 创建 filler，实际清理后读取 statvfs；不能 stub `target_met`。

- [ ] 运行 `A4DIAG_TEST_DISK=1 python -m pytest -q tests/integration/test_disk_remediation.py` 验证失败。实现每批删除前元数据复核、预算计数及 fsync 审计；效果意图先持久化再删除，崩溃后逐项 reconcile，不重复计入已删除字节。
- [ ] 创建预分配状态空间并在测试中耗尽其外部文件系统；即使写入应急日志仍失败也必须停在变更前。预留空间只服务本事务，不能拿来执行用户缓存扫描。业务检查失败保留 partial 状态；写入者原先运行时按事务补偿启动并验证，不能遗漏恢复应用。
- [ ] 在 D 盘独立镜像分别耗尽 block 和 inode，注入容量达标但 HTTP 失败、控制端断线、扫描后替换、删除中进程退出。验证有限扫描／删除、审计和业务结果。
- [ ] 运行磁盘测试、既有 filesystem 探针回归和 helper 安装测试，通过后提交 `feat: repair cache capacity with independent recovery checks`。
