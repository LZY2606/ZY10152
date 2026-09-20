// BGP Lab browser UI: topology, stable timeline, per-prefix decision tree and
// rule-by-rule accept/rewrite/reject traces with snapshot-branch edit preview.
"use strict";

const state = {
  scenarios: [],
  current: null,      // full scenario payload {id,input,result}
  selectedNode: null,
  selectedPrefix: null,
  selectedStep: null, // step seq for trace view
  preview: null,
  tab: "decision",
  edit: { rules: [], removed_rule_ids: [], withdraw: [], restart: [], restart_tick: null },
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 3200);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error || `${res.status}`);
  return data;
}

const kindLabel = {
  "origin-inject": "起源",
  "origin-withdraw": "撤回",
  receive: "接收",
  withdraw: "撤销",
  restart: "重启",
  refresh: "刷新",
};

function statusBadge(result) {
  if (!result) return "";
  const map = { stable: ["stable", "已稳定"], oscillation: ["oscillation", "振荡（已证明）"], inconclusive: ["inconclusive", "未收敛（无证明）"] };
  const [cls, label] = map[result.status] || ["", result.status];
  return `<span class="badge ${cls}">${label} · ${result.messages_processed} 消息 · t=${result.ticks}</span>`;
}

// ---------------- scenario loading ----------------

async function loadList(selectId) {
  const data = await api("/api/scenarios");
  state.scenarios = data.scenarios;
  renderScenarioList();
  const sel = $("scenarioSelect");
  sel.innerHTML = state.scenarios
    .map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("");
}

async function openScenario(id, keepNode) {
  state.current = await api(`/api/scenarios/${id}`);
  state.preview = null;
  state.edit = { rules: [], removed_rule_ids: [], withdraw: [], restart: [], restart_tick: null };
  state.selectedStep = null;
  if (!keepNode) state.selectedNode = Object.keys(state.current.input.nodes)[0];
  const prefixes = collectPrefixes();
  state.selectedPrefix = prefixes[0] || null;
  $("scenarioSelect").value = id;
  $("fp").textContent = "fp " + (state.current.input_fingerprint || "").slice(0, 12);
  renderAll();
}

function collectPrefixes() {
  const set = new Set();
  (state.current?.result?.best || []).forEach((b) => set.add(b.prefix));
  (state.current?.input?.announcements || []).forEach((a) => set.add(a.prefix));
  return [...set].sort();
}

function renderScenarioList() {
  const el = $("scenarioList");
  el.innerHTML = state.scenarios
    .map((s) => `<div class="scenario-item ${state.current?.id === s.id ? "active" : ""}" data-id="${esc(s.id)}">
        <div class="n">${esc(s.name)} ${s.parent_id ? '<span class="muted">⎇ 分支</span>' : ""}</div>
        <div class="meta mono">${esc(s.id)} · ${esc(s.input_fingerprint.slice(0, 10))}</div>
      </div>`)
    .join("");
  el.querySelectorAll(".scenario-item").forEach((d) =>
    d.onclick = () => openScenario(d.dataset.id));
}

// ---------------- topology ----------------

function bestMap() {
  const m = new Map();
  const src = state.preview?.result || state.current?.result;
  if (!src) return m;
  for (const b of src.best) m.set(`${b.node}|${b.prefix}`, b);
  return m;
}

function renderTopology() {
  const svg = $("topo");
  const input = state.current.input;
  const result = state.preview?.result || state.current.result;
  const pfx = state.selectedPrefix;
  const affected = new Set(state.preview?.affected_nodes || []);
  const best = bestMap();

  const NS = "http://www.w3.org/2000/svg";
  svg.innerHTML = "";
  const edges = [];

  // Determine which sessions carry the best path for the selected prefix.
  const bestIngress = new Map(); // node -> session id that won
  for (const b of result.best) {
    if (b.prefix !== pfx) continue;
    const sess = b.route.ingress_session;
    if (sess) bestIngress.set(b.node, sess);
  }

  for (const s of input.sessions) {
    const a = input.nodes[s.local], b = input.nodes[s.remote];
    if (!a || !b) continue;
    const isBest = bestIngress.get(s.remote) === s.id;
    const isAffected = affected.has(s.local) || affected.has(s.remote);
    const cls = `edge ${isBest ? "best" : ""} ${isAffected ? "affected" : ""}`;
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
    line.setAttribute("class", cls);
    line.setAttribute("marker-end", "url(#arrow)");
    svg.appendChild(line);
    if (s.delay > 1 || s.kind === "ibgp") {
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", (a.x + b.x) / 2); t.setAttribute("y", (a.y + b.y) / 2 - 3);
      t.setAttribute("class", "edge-label");
      t.textContent = `d=${s.delay}${s.kind === "ibgp" ? " iBGP" : ""}`;
      svg.appendChild(t);
    }
  }

  // arrow marker
  const defs = document.createElementNS(NS, "defs");
  defs.innerHTML = `<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
    <path d="M0,0 L10,5 L0,10 z" fill="#3a4a5e"/></marker>`;
  svg.appendChild(defs);

  for (const [id, n] of Object.entries(input.nodes)) {
    const g = document.createElementNS(NS, "g");
    g.setAttribute("transform", `translate(${n.x - 38},${n.y - 24})`);
    g.style.cursor = "pointer";
    const cls = `node-rect ${state.selectedNode === id ? "selected" : ""} ${affected.has(id) ? "affected" : ""}`;
    g.innerHTML = `<rect width="76" height="48" rx="8" class="${cls}"/>
      <text x="38" y="20" class="node-label">${esc(id)}</text>
      <text x="38" y="36" class="node-asn">AS ${n.asn}</text>`;
    g.onclick = () => { state.selectedNode = id; state.selectedStep = null; renderAll(); };
    svg.appendChild(g);

    const b = best.get(`${id}|${pfx}`);
    if (b) {
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", n.x); t.setAttribute("y", n.y + 42);
      t.setAttribute("class", "node-asn good");
      t.textContent = "lp=" + b.route.local_pref + " [" + (b.route.as_path.join(" ") || "∅") + "]";
      svg.appendChild(t);
    } else if (pfx) {
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", n.x); t.setAttribute("y", n.y + 42);
      t.setAttribute("class", "node-asn bad");
      t.textContent = "无路由";
      svg.appendChild(t);
    }
  }

  if (result.cycle) {
    const note = document.createElementNS(NS, "text");
    note.setAttribute("x", 12); note.setAttribute("y", 20);
    note.setAttribute("class", "node-label");
    note.setAttribute("fill", "#e8b34a");
    note.setAttribute("text-anchor", "start");
    note.textContent = `⚠ 振荡循环证明: 步骤 ${result.cycle.first_seen_at_step}↔${result.cycle.recurred_at_step} · sig ${result.cycle.state_signature.slice(0,10)}`;
    svg.appendChild(note);
  }
}

// ---------------- timeline ----------------

function renderTimeline() {
  const result = state.preview?.result || state.current.result;
  const el = $("timeline");
  $("statusBadge").innerHTML = statusBadge(result);
  $("stepPos").textContent = state.selectedStep
    ? `步骤 ${state.selectedStep}/${result.steps.length}`
    : `共 ${result.steps.length} 个事件`;

  el.innerHTML = result.steps.map((s) => {
    let detail = esc(s.summary);
    if (s.receive) {
      const r = s.receive;
      const cls = r.accepted ? "accept" : "reject";
      detail += ` <span class="pill ${cls}">${r.accepted ? "接受" : "拒绝"}</span>`;
      if (r.loop_evidence) detail += ` <span class="bad">AS环</span>`;
    }
    return `<div class="timeline-row ${state.selectedStep === s.seq ? "on" : ""}" data-seq="${s.seq}">
      <span class="tk mono">t${s.tick}</span>
      <span class="kind">${kindLabel[s.kind] || s.kind}</span>
      <span>${detail}</span>
    </div>`;
  }).join("");
  el.querySelectorAll(".timeline-row").forEach((r) => {
    r.onclick = () => {
      state.selectedStep = Number(r.dataset.seq);
      state.tab = "trace";
      switchTab("trace");
      renderAll();
    };
  });
}

// ---------------- decision tree ----------------

function renderDecision() {
  const el = $("tab-decision");
  const input = state.current.input;
  const result = state.preview?.result || state.current.result;
  const node = state.selectedNode;
  const pfx = state.selectedPrefix;

  // latest step with a selection for node+prefix
  let selection = null;
  for (let i = result.steps.length - 1; i >= 0; i--) {
    const s = result.steps[i];
    if (s.node === node && (s.prefix === pfx) && s.selection) { selection = s.selection; break; }
  }
  const bestEntry = result.best.find((b) => b.node === node && b.prefix === pfx);

  // candidate tree: walk ingress sessions to their advertising nodes (one level deep
  // for the fixture policy subset), rooted logically at the prefix's originators.
  const rib = (result.states.find((x) => x.node === node) || { advertised: {} });
  const receives = [];
  for (const s of result.steps) {
    if (s.node !== node || s.prefix !== pfx || !s.receive) continue;
    receives.push(s);
  }
  const lastBySession = new Map();
  receives.forEach((s) => lastBySession.set(s.receive.session, s));

  let html = `<h2 style="margin:0 0 8px">${esc(node)} 对 ${esc(pfx)} 的决策</h2>`;
  if (bestEntry) {
    const r = bestEntry.route;
    html += `<div class="kv">
      <b>最优来源</b><span>${esc(r.ingress_session ? sessionPeer(r.ingress_session) : "本地起源")} (${r.provenance})</span>
      <b>Local Pref</b><span>${r.local_pref}</span>
      <b>AS Path</b><span class="mono">[${r.as_path.join(" ") || "∅"}]</span>
      <b>MED</b><span>${r.med ?? "—"}</span>
      <b>Community</b><span class="mono">${r.communities.join(", ") || "—"}</span>
      <b>等值对端</b><span>${bestEntry.equal_peer ? `<span class="warn">${esc(bestEntry.equal_peer)} （属性相同，稳定 tie-break 选定本路径）</span>` : "无"}</span>
    </div>`;
  } else {
    html += `<p class="bad">当前 RIB 中没有该前缀的可用路由。</p>`;
  }

  html += `<div class="tree" style="margin-top:10px"><ul>`;
  const origins = input.announcements.filter((a) => a.prefix === pfx);
  for (const a of origins) {
    html += `<li>🟢 <b>${esc(a.node)}</b> 起源 <span class="muted">lp=${a.local_pref} med=${a.med ?? 0}</span>
      <ul><li>沿 eBGP/iBGP 会话传播（见时间线接收事件）</li></ul></li>`;
  }
  html += `</ul></div>`;

  if (selection) {
    html += `<h2 style="margin:14px 0 6px">选路阶段（${selection.stages.length}）</h2>`;
    for (const stg of selection.stages) {
      html += `<div class="stage"><b>${stg.stage}. ${esc(stg.name)}</b>
        <div class="muted">${esc(stg.detail)}</div>
        <div class="muted">保留: ${stg.retained.map(esc).join(" → ")}</div></div>`;
    }
    html += `<pre class="json mono">tie_key = ${esc(selection.tie_key_winner || "")}</pre>`;
  } else {
    html += `<p class="muted" style="margin-top:10px">该节点在此前缀没有重新选路的记录（无候选或未变化）。</p>`;
  }
  el.innerHTML = html;
}

function sessionPeer(sessionId) {
  const s = state.current.input.sessions.find((x) => x.id === sessionId);
  return s ? `${s.local} → ${s.remote}` : sessionId;
}

// ---------------- rule trace ----------------

function renderTrace() {
  const el = $("tab-trace");
  const result = state.preview?.result || state.current.result;
  const node = state.selectedNode;
  const pfx = state.selectedPrefix;

  const matching = result.steps.filter((s) =>
    s.node === node && (!pfx || s.prefix === pfx) && (s.receive || s.exports.length));

  if (!state.selectedStep) {
    el.innerHTML = `<h2 style="margin:0 0 8px">${esc(node)} 的规则证据</h2>
      <p class="muted">点击时间线中的任意事件查看逐条规则求值；或选择下面一条最新事件：</p>` +
      matching.slice(-8).reverse().map((s) =>
        `<button class="ghost" style="margin:3px" data-jump="${s.seq}">#${s.seq} t${s.tick} ${esc(s.summary)}</button>`
      ).join("");
    el.querySelectorAll("[data-jump]").forEach((b) => {
      b.onclick = () => { state.selectedStep = Number(b.dataset.jump); renderAll(); };
    });
    return;
  }

  const step = result.steps.find((s) => s.seq === state.selectedStep);
  if (!step) { el.innerHTML = "<p>未找到步骤</p>"; return; }

  let html = `<div class="row"><h2 style="margin:0">步骤 #${step.seq} · t${step.tick} · ${esc(step.node)}</h2>
    <span class="spacer"></span><button class="ghost" id="clearStep">清除选择</button></div>
    <p>${esc(step.summary)}</p>`;

  if (step.selection) {
    html += `<h2 style="margin:8px 0 4px">选路</h2>`;
    for (const stg of step.selection.stages) {
      html += `<div class="stage"><b>${stg.stage}. ${esc(stg.name)}</b>
        <span class="muted">— ${esc(stg.detail)}</span>
        <div class="muted">保留: ${stg.retained.map(esc).join(" → ")}</div></div>`;
    }
  }

  if (step.receive) {
    const r = step.receive;
    html += `<h2 style="margin:10px 0 4px">入向策略：来自 ${esc(r.from)} 的 ${esc(r.prefix)}
      <span class="pill ${r.accepted ? "accept" : "reject"}">${r.accepted ? "终止/默认接受" : "拒绝"}</span></h2>
      <div class="muted">reason: ${esc(r.reason)}</div>`;
    if (r.loop_evidence) html += `<div class="evidence">⛔ ${esc(r.loop_evidence.detail)}</div>`;
    html += renderPolicyRules(r.policy.trace);
    if (r.route_after) html += `<pre class="json mono">${esc(JSON.stringify(r.route_after, null, 2))}</pre>`;
  }

  if (step.exports.length) {
    html += `<h2 style="margin:10px 0 4px">出向发布（${step.exports.length} 个邻居）</h2>`;
    for (const e of step.exports) {
      html += `<div class="rule"><div class="head">
        <span class="pill ${e.published ? "accept" : "reject"}">${e.published ? "发布" : "过滤"}</span>
        <b>→ ${esc(e.to)}</b><span class="muted">${esc(e.reason)}</span></div><div class="body">`;
      if (e.loop_evidence) html += `<div class="evidence">⛔ ${esc(e.loop_evidence.detail)}</div>`;
      for (const sup of e.suppressed) {
        html += `<div class="muted">• ${esc(sup.reason)} — ${esc(sup.detail)}</div>`;
      }
      if (e.policy) html += renderPolicyRules(e.policy.trace);
      if (e.route) html += `<pre class="json mono">${esc(JSON.stringify(e.route, null, 2))}</pre>`;
      html += `</div></div>`;
    }
  }
  el.innerHTML = html;
  $("clearStep").onclick = () => { state.selectedStep = null; renderAll(); };
}

function renderPolicyRules(trace) {
  if (!trace || !trace.length) return `<p class="muted">（无规则）</p>`;
  return trace.map((t) => {
    const map = {
      miss: ["miss", "未命中继续"],
      "hit-continue": ["continue", "命中并继续"],
      "hit-accept": ["accept", "终止接受"],
      "hit-reject": ["reject", "终止拒绝"],
    };
    const [cls, label] = map[t.outcome] || ["miss", t.outcome];
    return `<div class="rule"><div class="head">
      <span class="pill ${cls}">${label}</span>
      <b>[${t.index}] ${esc(t.rule)}</b></div>
      <div class="body">${esc(t.detail || "条件不匹配")}
      ${t.after ? `<pre class="json mono">${esc(JSON.stringify(t.after, null, 2))}</pre>` : ""}
      </div></div>`;
  }).join("");
}

// ---------------- policy editor ----------------

function renderEditor() {
  const el = $("tab-editor");
  const input = state.current.input;
  const node = state.selectedNode;
  const spec = input.nodes[node];

  let html = `<h2 style="margin:0 0 8px">编辑 ${esc(node)} (AS ${spec.asn}) 的策略</h2>
  <p class="muted">修改不会覆盖原场景；预览/提交都会生成快照分支。当前未提交变更：
    <b>${state.edit.rules.length}</b> 条规则改动，<b>${state.edit.removed_rule_ids.length}</b> 条删除，
    <b>${state.edit.restart.length}</b> 重启，<b>${state.edit.withdraw.length}</b> 撤回。</p>`;

  for (const dir of ["import", "export"]) {
    const rules = spec.policy[dir] || [];
    html += `<h2 style="margin:10px 0 4px">${dir.toUpperCase()} 规则（${rules.length}）</h2>`;
    rules.forEach((r, i) => {
      const removed = state.edit.removed_rule_ids.some((x) => x.node === node && x.direction === dir && x.rule === r.id);
      const edited = state.edit.rules.find((x) => x.node === node && x.direction === dir && x.rule.id === r.id);
      const lp = edited ? edited.rule.do_.set_local_pref : r.do_.set_local_pref;
      const med = edited ? edited.rule.do_.set_med : r.do_.set_med;
      const on = edited ? edited.rule.on_match : r.on_match;
      html += `<div class="rule" ${removed ? 'style="opacity:.45"' : ""}><div class="head">
        <b>[${i}] ${esc(r.id)}</b><span class="muted">${esc(r.description || "")}</span></div>
        <div class="body">
          <div class="muted">when: ${esc(summarizeMatch(r.when))}</div>
          <div class="row" style="margin-top:4px">
            <label>set local-pref <input type="number" style="width:70px" value="${lp ?? ""}"
              data-dir="${dir}" data-rule="${esc(r.id)}" data-f="lp"></label>
            <label>set med <input type="number" style="width:64px" value="${med ?? ""}"
              data-dir="${dir}" data-rule="${esc(r.id)}" data-f="med"></label>
            <label>on_match
              <select data-dir="${dir}" data-rule="${esc(r.id)}" data-f="on">
                ${["continue", "accept", "reject"].map((o) =>
                  `<option ${on === o ? "selected" : ""}>${o}</option>`).join("")}
              </select></label>
            <button class="ghost" data-dir="${dir}" data-remove="${esc(r.id)}">
              ${removed ? "↩ 撤销删除" : "✕ 删除"}</button>
          </div>
        </div></div>`;
    });
    html += `<button class="ghost" data-add="${dir}" style="margin:2px 0 8px">+ 添加 ${dir} 规则</button>`;
  }

  el.innerHTML = html;

  el.querySelectorAll("input[data-rule], select[data-rule]").forEach((inp) => {
    inp.onchange = () => stageRuleEdit(inp.dataset.dir, inp.dataset.rule, inp.dataset.f, inp.value);
  });
  el.querySelectorAll("[data-remove]").forEach((b) => {
    b.onclick = () => toggleRemove(node, b.dataset.dir, b.dataset.remove);
  });
  el.querySelectorAll("[data-add]").forEach((b) => {
    b.onclick = () => addRule(node, b.dataset.add);
  });
}

function summarizeMatch(m) {
  const parts = [];
  if (m.peer) parts.push(`peer=${m.peer}`);
  if (m.prefix) parts.push(`prefix ${m.prefix_cmp || "eq"} ${m.prefix}`);
  if (m.as_path_len != null) parts.push(`as_path_len ${m.as_path_len_cmp || "eq"} ${m.as_path_len}`);
  if (m.local_pref != null) parts.push(`local_pref ${m.local_pref_cmp || "eq"} ${m.local_pref}`);
  if (m.med != null) parts.push(`med ${m.med_cmp || "eq"} ${m.med}`);
  if (m.community_any?.length) parts.push(`community ${m.community_any_cmp || "in"} ${m.community_any.join(",")}`);
  return parts.join(" 且 ") || "匹配所有";
}

function baseRule(node, dir, id) {
  const rules = state.current.input.nodes[node].policy[dir] || [];
  const found = rules.find((r) => r.id === id);
  return found ? JSON.parse(JSON.stringify(found)) : null;
}

function stageRuleEdit(dir, id, field, value) {
  const node = state.selectedNode;
  let edit = state.edit.rules.find((x) => x.node === node && x.direction === dir && x.rule.id === id);
  const rule = edit ? edit.rule : baseRule(node, dir, id);
  if (!rule) return;
  if (field === "lp") rule.do_.set_local_pref = value === "" ? null : Number(value);
  if (field === "med") rule.do_.set_med = value === "" ? null : Number(value);
  if (field === "on") rule.on_match = value;
  if (!edit) {
    state.edit.rules.push({ node, direction: dir, rule, upsert: false });
  } else {
    edit.rule = rule;
  }
  renderEditor();
  toast(`已暂存对 ${id} 的修改（尚未提交）`);
}

function toggleRemove(node, dir, id) {
  const idx = state.edit.removed_rule_ids.findIndex((x) => x.node === node && x.direction === dir && x.rule === id);
  if (idx >= 0) state.edit.removed_rule_ids.splice(idx, 1);
  else state.edit.removed_rule_ids.push({ node, direction: dir, rule: id });
  renderEditor();
}

function addRule(node, dir) {
  const id = prompt("新规则 id", "new-rule-" + (state.edit.rules.length + 1));
  if (!id) return;
  const rule = {
    id, description: "user-added",
    when: {}, do_: {}, on_match: "accept",
  };
  state.edit.rules.push({ node, direction: dir, rule, upsert: true });
  renderEditor();
}

// ---------------- preview / commit ----------------

async function runPreview() {
  try {
    const data = await api(`/api/scenarios/${state.current.id}/preview`, {
      method: "POST",
      body: { edits: state.edit, branch_name: state.current.input.name + "-trial", save_draft: "ui-draft" },
    });
    state.preview = data;
    toast(`预览完成：影响 ${data.affected_nodes.length} 节点 / ${data.affected_prefixes.length} 前缀`);
    renderAll();
  } catch (e) { toast("预览失败: " + e.message); }
}

function renderPreview() {
  const el = $("tab-preview");
  const pv = state.preview;
  let html = `<h2 style="margin:0 0 8px">变更预览（基于快照的分支）</h2>
    <div class="row"><button class="primary" id="doPreview">计算影响（不提交）</button>
    <button id="doCommit" ${pv ? "" : "disabled"}>提交为新场景分支</button>
    <button class="ghost" id="clearEdit">清空变更</button></div>`;

  if (!pv) {
    html += `<p class="muted" style="margin-top:8px">暂存编辑、撤回或重启后点击“计算影响”，可在提交前看到受影响节点、前缀与发布差异。原场景与中间收敛步骤不会被覆盖。</p>`;
    el.innerHTML = html;
    $("doPreview").onclick = runPreview;
    $("doCommit").onclick = commitBranch;
    $("clearEdit").onclick = clearEdits;
    return;
  }

  html += `<div style="margin:8px 0">${statusBadge(pv.result)}</div>`;
  if (pv.result.cycle) {
    const c = pv.result.cycle;
    html += `<div class="evidence" style="background:#2b2416;border-color:#6a5426;color:#f0d49a">
      可核验未收敛证明：全局状态签名 <span class="mono">${esc(c.state_signature.slice(0,16))}</span>
      在步骤 ${c.first_seen_at_step} 与 ${c.recurred_at_step} 重复；节点 ${c.involved_nodes.map(esc).join(", ")}；
      前缀 ${c.involved_prefixes.map(esc).join(", ")}</div>`;
  }
  if (pv.result.inconclusive_reason) {
    html += `<div class="evidence">${esc(pv.result.inconclusive_reason)}</div>`;
  }

  html += `<h2 style="margin:10px 0 4px">规则级差异（${pv.diffs.length}）</h2>`;
  for (const d of pv.diffs) {
    const icon = d.op.includes("added") ? "➕" : d.op.includes("removed") ? "➖" : "✏️";
    html += `<div class="rule"><div class="head"><span>${icon}</span>
      <b>${esc(d.node)} · ${esc(d.direction)} · ${esc(d.rule)}</b>
      <span class="muted">${esc(d.op)}</span></div>
      <div class="body">${esc(d.detail)}</div></div>`;
  }

  html += `<h2 style="margin:10px 0 4px">受影响节点 / 前缀</h2>
    <div class="muted">节点: ${pv.affected_nodes.map(esc).join(", ") || "（无）"}</div>
    <div class="muted">前缀: ${pv.affected_prefixes.map(esc).join(", ") || "（无）"}</div>`;

  if ((pv.intermediate_diffs || []).length) {
    html += `<h2 style="margin:10px 0 4px">中间收敛差异（最终状态相同，但收敛过程不同）</h2>
      <table><tr><th>节点</th><th>前缀</th><th>前</th><th>后</th></tr>
      ${pv.intermediate_diffs.map((d) => `<tr><td>${esc(d.node)}</td><td>${esc(d.prefix)}</td>
        <td class="mono">${esc(d.before || "")}</td><td class="mono">${esc(d.after || "")}</td></tr>`).join("")}</table>
      <p class="muted">轨迹指纹${pv.trace_changed ? "已改变" : "未改变"}。</p>`;
  }
  html += `<h2 style="margin:10px 0 4px">最优路径差异</h2>
    <table><tr><th>节点</th><th>前缀</th><th>变更前</th><th>变更后</th></tr>
    ${pv.best_path_diffs.map((d) => `<tr><td>${esc(d.node)}</td><td>${esc(d.prefix)}</td>
      <td class="mono diff-del">${esc(d.before || "∅")}</td>
      <td class="mono diff-add">${esc(d.after || "∅")}</td></tr>`).join("") ||
      '<tr><td colspan="4" class="muted">无差异</td></tr>'}</table>`;

  html += `<h2 style="margin:10px 0 4px">对外发布差异</h2>
    <table><tr><th>会话</th><th>前缀</th><th>变化</th><th>前</th><th>后</th></tr>
    ${pv.publication_diffs.map((d) => `<tr><td class="mono">${esc(d.from)}→${esc(d.to)}</td>
      <td>${esc(d.prefix)}</td><td>${esc(d.change)}</td>
      <td class="mono diff-del">${esc(d.before || "∅")}</td>
      <td class="mono diff-add">${esc(d.after || "∅")}</td></tr>`).join("") ||
      '<tr><td colspan="5" class="muted">无差异</td></tr>'}</table>`;

  el.innerHTML = html;
  $("doPreview").onclick = runPreview;
  $("doCommit").onclick = commitBranch;
  $("clearEdit").onclick = clearEdits;
}

async function commitBranch() {
  try {
    const data = await api(`/api/scenarios/${state.current.id}/commit`, {
      method: "POST",
      body: { edits: state.edit, branch_name: state.current.input.name + "-branch-" + Date.now() % 100000 },
    });
    toast(`已提交快照分支 ${data.scenario_id.slice(0, 8)}（原场景保留）`);
    await loadList();
    await openScenario(data.scenario_id);
  } catch (e) { toast("提交被拒绝: " + e.message); }
}

function clearEdits() {
  state.edit = { rules: [], removed_rule_ids: [], withdraw: [], restart: [], restart_tick: null };
  state.preview = null;
  renderAll();
}

// ---------------- wiring ----------------

function switchTab(name) {
  state.tab = name;
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === name));
  ["decision", "trace", "editor", "preview"].forEach((t) => {
    $("tab-" + t).style.display = t === name ? "" : "none";
  });
}

function populateNodePicker() {
  $("nodePick").innerHTML = Object.keys(state.current.input.nodes)
    .map((n) => `<option ${n === state.selectedNode ? "selected" : ""}>${esc(n)}</option>`).join("");
}

function populatePrefixPicker() {
  const all = collectPrefixes();
  $("prefixPick").innerHTML = all.map((p) =>
    `<option ${p === state.selectedPrefix ? "selected" : ""}>${esc(p)}</option>`).join("");
}

function renderAll() {
  if (!state.current) return;
  renderScenarioList();
  populateNodePicker();
  populatePrefixPicker();
  renderTopology();
  renderTimeline();
  renderDecision();
  renderTrace();
  renderEditor();
  renderPreview();
}

document.querySelectorAll(".tabs button").forEach((b) => {
  b.onclick = () => switchTab(b.dataset.tab);
});
$("scenarioSelect").onchange = (e) => openScenario(e.target.value);
$("replayBtn").onclick = async () => {
  await openScenario(state.current.id, true);
  toast("已按相同输入与规则指纹重放，收敛轨迹指纹保持一致");
};
$("prefixPick").onchange = (e) => { state.selectedPrefix = e.target.value; renderAll(); };
$("nodePick").onchange = (e) => { state.selectedNode = e.target.value; renderAll(); };
$("restartBtn").onclick = () => {
  const n = $("nodePick").value;
  if (!state.edit.restart.includes(n)) state.edit.restart.push(n);
  switchTab("preview"); renderPreview();
  toast(`已暂存邻居 ${n} 重启`);
};
$("withdrawBtn").onclick = () => {
  const first = state.current.input.announcements[0];
  if (first && !state.edit.withdraw.includes(first.id)) {
    state.edit.withdraw.push(first.id);
    switchTab("preview"); renderPreview();
    toast(`已暂存撤回 ${first.id}`);
  }
};

(async function init() {
  await loadList();
  if (state.scenarios.length) await openScenario(state.scenarios[0].id);
})();
