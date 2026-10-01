"use strict";
// Read-only status page. Everything is rendered with textContent, never as HTML.

const REFRESH_MS = 10000;
const MODE_LABELS = { read_only: "只读（只诊断，不修改）", read_write: "读写（允许受控修复）" };
const IDENTITY = {
  ok: ["在线，身份一致", "ok"],
  changed: ["身份已变化，已拒绝操作", "bad"],
  unreachable: ["无法连接", "bad"],
};

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function unitDot(state) {
  if (state.active === "active") return "ok";
  if (state.active === "inactive" || state.active === "activating") return "warn";
  return state.active === "unknown" ? "" : "bad";
}

function when(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  return isNaN(date) ? iso : date.toLocaleString();
}

function facts(target, rows) {
  target.replaceChildren();
  for (const [label, value] of rows) {
    target.append(el("dt", null, label), el("dd", null, value));
  }
}

function renderController(controller) {
  const model = controller.model;
  facts(document.getElementById("controller-facts"), [
    ["版本", controller.version],
    ["模式", MODE_LABELS[controller.global_mode] || controller.global_mode],
    ["模型", model ? `${model.model}（${model.base_url}）` : "未配置"],
    ["待审批", controller.pending_approvals === null ? "无法读取" : String(controller.pending_approvals)],
  ]);
  const units = document.getElementById("controller-units");
  units.replaceChildren(...controller.units.map((unit) =>
    el("li", null, el("span", { class: `dot ${unitDot(unit)}`, "aria-hidden": "true" }),
      `${unit.unit}：${unit.active}${unit.sub && unit.sub !== unit.active ? ` / ${unit.sub}` : ""}`)));
}

function renderTargets(targets) {
  const container = document.getElementById("targets");
  if (!targets.length) {
    container.replaceChildren(el("p", { class: "muted" }, "还没有登记被控端。"));
    return;
  }
  container.replaceChildren(...targets.map((target) => {
    const [label, tone] = IDENTITY[target.identity.state] || [target.identity.state, "warn"];
    const where = target.mode === "local" ? "本机" : `${target.host}:${target.port}`;
    const card = el("article", { class: "target" },
      el("div", { class: "target-head" }, el("strong", null, target.id),
        el("span", { class: `badge ${tone}` }, label)),
      el("p", { class: "muted" }, `${where} · ${target.write_enabled ? "允许修复" : "只读"}`));
    if (target.identity.detail) card.append(el("p", { class: "muted" }, `原因：${target.identity.detail}`));
    if (target.executor) {
      card.append(el("p", null, el("span", { class: `dot ${unitDot(target.executor)}`, "aria-hidden": "true" }),
        ` 执行器：${target.executor.active}`));
    }
    card.append(el("div", { class: "chips" }, ...(target.watched.length
      ? target.watched.map((name) => el("span", { class: "chip" }, name))
      : [el("span", { class: "muted" }, "未登记监控的服务")])));
    const latest = target.latest_report;
    card.append(el("p", { class: "muted" }, latest
      ? `最近诊断：${when(latest.finished_at)} · ${latest.status_label}`
      : "还没有诊断记录"));
    return card;
  }));
}

function renderReports(reports) {
  const table = document.getElementById("reports");
  document.getElementById("reports-empty").hidden = reports.length > 0;
  table.hidden = reports.length === 0;
  table.tBodies[0].replaceChildren(...reports.map((report) => {
    const row = el("tr", { tabindex: "0" },
      el("td", { class: "when" }, when(report.finished_at)),
      el("td", null, report.target_id),
      el("td", null, el("span", { class: `badge ${report.settled ? "ok" : "warn"}` }, report.status_label)),
      el("td", null, report.cause));
    const open = () => showReport(report.task_id);
    row.addEventListener("click", open);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter") open(); });
    return row;
  }));
}

async function showReport(taskId) {
  const panel = document.getElementById("detail");
  const body = document.getElementById("detail-body");
  body.replaceChildren(el("p", { class: "muted" }, "正在读取…"));
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
  try {
    const response = await fetch(`/api/report/${encodeURIComponent(taskId)}`, { credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const report = await response.json();
    const diagnosis = report.diagnosis || {};
    const parts = [el("p", null, `${taskId} · ${report.target_id || ""} · ${report.status || ""}`)];
    if (diagnosis.cause) parts.push(el("h3", null, "原因"), el("p", null, diagnosis.cause));
    if ((diagnosis.recommended_actions || []).length) {
      parts.push(el("h3", null, "建议"), el("ol", null, ...diagnosis.recommended_actions.map((a) => el("li", null, a))));
    }
    if ((report.operations || []).length) {
      parts.push(el("h3", null, "计划的操作"), el("ul", null, ...report.operations.map((op) =>
        el("li", null, `${op.capability}.${op.action} ${op.resource}`))));
    }
    if (report.error) parts.push(el("h3", null, "说明"), el("p", null, report.error));
    parts.push(el("h3", null, "收集到的证据"), el("pre", null, (report.evidence || []).map((item) =>
      `[${item.kind}${item.resource ? " " + item.resource : ""}]\n${item.content ?? ""}`).join("\n\n") || "（无）"));
    body.replaceChildren(...parts);
  } catch (error) {
    body.replaceChildren(el("p", null, `读取失败：${error.message}`));
  }
}

async function refresh() {
  const errorBox = document.getElementById("error");
  try {
    const response = await fetch("/api/status", { credentials: "same-origin" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const status = await response.json();
    errorBox.hidden = true;
    document.getElementById("updated").textContent = `更新于 ${when(status.generated_at)}`;
    if (status.error) {
      errorBox.textContent = `配置无法读取：${status.error}`;
      errorBox.hidden = false;
      document.getElementById("setup-hint").hidden = false;
      return;
    }
    document.getElementById("subtitle").textContent =
      `${status.targets.length} 个被控端 · 每 ${REFRESH_MS / 1000} 秒自动刷新`;
    document.getElementById("setup-hint").hidden = status.configured;
    renderController(status.controller);
    renderTargets(status.targets);
    renderReports(status.reports);
  } catch (error) {
    errorBox.textContent = `无法连接到控制端：${error.message}`;
    errorBox.hidden = false;
  }
}

document.getElementById("detail-close").addEventListener("click", () => {
  document.getElementById("detail").hidden = true;
});
refresh();
setInterval(refresh, REFRESH_MS);
