# Jev Advisory Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 接入可选 Jev 分类、补采与候选方案建议，并保留真实用量和确定性权限边界。

**Architecture:** 独立 advisor 插件调用 TypeSafe System One，严格解析 typed response。off 完全不调用，observe 只记录，assist 将合法建议交给现有模型流程；最终执行和恢复验证不由 Jev 决定。

**Tech Stack:** Python、Pydantic、现有 httpx／secrets 插件设施、TypeSafe HTTP API。

**Spec:** [设计 9](../specs/2026-09-22-linux-remediation-jev-design.md)

## Global Constraints

继承[总计划](2026-09-22-linux-remediation-jev.md#global-constraints)；依赖 F。TypeSafe 使用独立 secret reference；模型列表和请求 schema 在编码时复核官方文档，不自动安装第三方 Jev Router。

## Review Focus

高置信未知选项、NaN／Infinity／重复 JSON 键、日志注入、网络故障回退、Jev 概率浮点数误入只支持整数的签名规范，分别归 J1/J2。

## Task J1: Advisor 契约和 TypeSafe 客户端

**Files:** Create `src/a4diag/advisor.py`, `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/advisor_jev.py`, `packages/a4diag-builtin-plugins/manifests/advisor-jev.json`, `tests/test_jev_advisor.py`; modify `src/a4diag/plugin_api/manifest.py`, `packages/a4diag-builtin-plugins/src/a4diag_builtin_plugins/host.py`, `src/a4diag/builtin_catalog.py`。

**Interfaces:** `AdvisorConfig(mode: Literal['off','observe','assist']='off', model: str, base_url: str, api_key_ref: str, timeout_seconds: int=5, minimum_confidence: float=0.9)`，timeout 1..30；默认 URL `https://api.typesafe.ai/v1`。`Advice` 字段 `fault_class, evidence_ids, profile_ids, uncertain, model, confidence, probabilities, usage, elapsed_ms, fallback_reason`；`AdvisorPort.advise(state: dict[str, JsonValue], candidates: dict[str, JsonValue]) -> Advice`。HTTP 响应解析函数 `parse_jev_response(payload: str, expected_questions: dict[str, dict[str, JsonValue]]) -> dict[str, JsonValue]` 严格检验字段。

- [ ] 写未知候选拒绝测试：

```python
def test_high_confidence_unknown_choice_is_rejected():
    import pytest
    from a4diag_builtin_plugins.advisor_jev import parse_jev_response, AdvisorProtocolError
    raw = ('{"model":"test","answers":{"route":{"type":"choice",'
           '"choice":"shell","probabilities":{"shell":1.0},"confidence":1.0}},'
           '"usage":{"input_tokens":10,"output_tokens":1}}')
    expected = {'route': {'type': 'choice', 'criteria': {'services': None, 'unknown': None}}}
    with pytest.raises(AdvisorProtocolError):
        parse_jev_response(raw, expected)
```

- [ ] 运行 `python -m pytest -q tests/test_jev_advisor.py` 确认失败。使用 httpx 的受控 transport、5 秒默认超时和有限响应体，POST `/systemone`，body 为 `model/state/questions`；key 仅在 Authorization header，禁用跨 host 重定向。
- [ ] 核验问题集合、Choice candidates、Score levels、Noul 范围、所有数字有限、usage 非负 strict integer；Choice probabilities 总和与范围容差明确，禁止 bool 充数和重复键。模型可报告 actual version，未返回版本视为协议错误。
- [ ] 现有 canonical_json_bytes 不支持 float：概率只在 advisor 响应模型保留 float，审计保存无损十进制字符串；不将 Advice 整体塞入 Operation／签名参数。加入 round-trip 测试，不能通过放宽整个签名 JSON 来适配 Jev。
- [ ] HTTP401/403、429、5xx、DNS、超时、证书错误、超限均返回稳定 fallback_reason，日志不含 secret 或完整请求正文。运行插件 host、registry、secret 回归，通过后提交 `feat: add typed Jev advisory plugin`。

## Task J2: off／observe／assist 工作流与约束

**Files:** Modify `src/a4diag/workflow.py`, `src/a4diag/plugin_ports.py`, `src/a4diag/settings.py`, `src/a4diag/init_config.py`, `src/a4diag/init_transaction.py`, `src/a4diag/report.py`; create `tests/test_jev_workflow.py`, `tests/test_jev_privacy.py`。

**Interfaces:** `advisory_evidence(state, candidates) -> dict[str, JsonValue]` 位于 advisor.py，仅提取已授权且已脱敏的证据、程序计算阈值和候选；`apply_advice(advice: Advice, *, mode: str, allowed_evidence_ids: set[str], allowed_profile_ids: set[str]) -> dict[str, JsonValue]` 返回建议 ID 和说明标签，不返回 Operation。

- [ ] 写 observe 不改变执行的集成测试：

```python
def test_observe_cannot_turn_denied_plan_into_execution(workflow_with_jev):
    run = workflow_with_jev(mode='observe', advice='high_confidence_repair', write_enabled=False)
    assert run.executed_operations == []
    assert run.original_policy_denial_preserved
    assert run.advisor_usage['input_tokens'] > 0
```

该 fixture 使用实际 workflow、policy 与插件协议，只有 HTTP 服务商响应为 fixture；不能把它统计成真实 Token 消耗。

- [ ] 运行新增 tests 确认失败。off 不构建客户端／不解析密钥；observe 除审计和延时外结果与原流程一致；assist 仅提供候选及有限补采建议，不能略过 DeepSeek critic。所有补采仍受原有两轮、8 个证据及字节预算约束。
- [ ] 高风险提示可要求复核但不能自行批准；低置信或错误回退原路径。清理日志中的注入指令作为数据处理，恶意“忽略授权”“已恢复”不能变成执行指令。profile 和资源候选由配置生成，不从 Jev 文本生成。
- [ ] 在正常、证据不足、混合故障、中文日志、矛盾建议、服务商故障下检查最终权限与恢复结果；原风险 HIGH 不因建议变 LOW。审计包含 actual model、耗时、usage 和 fallback，不含凭据；通过后提交 `feat: integrate optional Jev advice without weakening policy`。

## Task J3: 真实 API 联调与受控对照

**Files:** Create `tests/e2e/run_jev_comparison.py`, `tests/e2e/test_jev_live_evidence.py`, `docs/testing/jev-comparison.md`; update `docs/jev-integration.md`。

**Interfaces:** runner 输入已有脱敏故障集和独立 secret reference，输出 `mode, provider, actual_model, requests, usage, routing_decisions, recovery_outcomes, fallback_count`；对照只使用同一故障集，不把 observe 与 assist 的重复试验当独立样本夸大准确率。

- [ ] 写证据完整性测试：

```python
def test_live_usage_is_attached_to_actual_provider_records(live_evidence):
    assert live_evidence['requests'] > 0
    assert live_evidence['provider'] == 'typesafe'
    assert live_evidence['actual_model']
    assert live_evidence['usage']['input_tokens'] > 0
```

fixture 只读取 runner 真实输出；未启用 live test 默认跳过并说明缺少外部条件，不能生成伪造 evidence 让测试通过。

- [ ] 先完成 dry-run 请求展示（脱敏）、配置与预算检查。只有新 Jev 凭据与发送测试证据授权齐备才运行 `A4DIAG_JEV_LIVE=1 python -m pytest -q tests/e2e/test_jev_live_evidence.py`。
- [ ] 固定调用预算，先小样本 observe，核对服务商 usage；再运行 assist 对照并同时执行至少一条真实修复及一条拒绝／失败保护链。记录准确率分母、异常案例、耗时和费用口径，不承诺统计显著收益。
- [ ] 无凭据／授权则记录外部条件未满足，其他模块继续开发，整项 Jev 实测保持未验收。成功后提交 `test: record real Jev advisory comparison evidence`。
