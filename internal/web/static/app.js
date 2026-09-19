let state = {nodes: [], edges: [], batches: [], verifications: [], exports: []};
let selectedNode = null;

const $ = (selector) => document.querySelector(selector);
const resultBox = $("#result");

function showResult(value, isError = false) {
  resultBox.style.color = isError ? "#ffd7d7" : "#d9f2df";
  resultBox.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const text = await response.text();
  let body = text ? JSON.parse(text) : {};
  if (!response.ok) throw Object.assign(new Error(body.error || response.statusText), {status: response.status, body});
  return body;
}

async function loadState() {
  state = await api("/api/state");
  render();
}

function short(value, length = 8) {
  return value ? String(value).slice(0, length) : "—";
}

function render() {
  const counts = state.counts || {};
  $("#pending-count").textContent = (counts.batch_pending || 0) + " / " + (counts.node_pending || 0);
  $("#accepted-count").textContent = counts.node_accepted || 0;
  $("#rejected-count").textContent = (counts.node_rejected || 0) + " / " + (counts.batch_rejected || 0);
  $("#recovering-count").textContent = (counts.node_recovering || 0) + " / " + (counts.batch_recovering || 0);
  $("#clock-info").textContent = `当前校正偏移：${state.clock_offset_nanos || 0} 纳秒；校验成功 ${counts.verification_success || 0}，失败 ${counts.verification_failure || 0}`;
  renderGraph();
  renderBatches();
  renderExports();
}

function nodeDepth(node, cache = new Map()) {
  if (cache.has(node.id)) return cache.get(node.id);
  if (!node.parent_id) return 0;
  const parent = state.nodes.find((item) => item.id === node.parent_id);
  const depth = parent ? nodeDepth(parent, cache) + 1 : 0;
  cache.set(node.id, depth);
  return depth;
}

function renderGraph() {
  const width = Math.max(900, state.nodes.length * 170);
  const height = Math.max(360, (Math.max(...state.nodes.map(nodeDepth), 0) + 1) * 150);
  const positions = new Map();
  const columns = new Map();
  for (const node of state.nodes) {
    const depth = nodeDepth(node);
    if (!columns.has(depth)) columns.set(depth, 0);
    positions.set(node.id, {
      x: 90 + columns.get(depth) * 210,
      y: 60 + depth * 120,
    });
    columns.set(depth, columns.get(depth) + 1);
  }
  const edges = state.edges.map((edge) => {
    const a = positions.get(edge.from);
    const b = positions.get(edge.to);
    if (!a || !b) return "";
    return `<line class="edge" x1="${a.x + 78}" y1="${a.y + 34}" x2="${b.x}" y2="${b.y + 34}" />`;
  }).join("");
  const nodes = state.nodes.map((node) => {
    const p = positions.get(node.id);
    const label = `${node.kind} · ${node.status}\n${node.name}\n${short(node.id, 10)}`;
    const lines = label.split("\n").map((text, i) => `<text x="${p.x + 10}" y="${p.y + 20 + i * 15}">${escapeXml(text)}</text>`).join("");
    return `<g class="node ${node.status}" data-id="${node.id}" transform="translate(${p.x},${p.y})">
      <rect width="170" height="68" rx="8"></rect>${lines}</g>`;
  }).join("");
  $("#graph").innerHTML = `<svg width="${width}" height="${height}">
    <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
      <path d="M0,0 L0,6 L8,3 z" fill="#52606d"></path>
    </marker></defs>${edges}${nodes}</svg>`;
  document.querySelectorAll(".node").forEach((element) => {
    element.addEventListener("click", () => showNode(element.dataset.id));
  });
}

function escapeXml(value) {
  return String(value).replace(/[<>&'"]/g, (char) => ({"<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;"}[char]));
}

async function showNode(id) {
  selectedNode = id;
  const node = state.nodes.find((item) => item.id === id);
  const verifications = await api(`/api/nodes/${encodeURIComponent(id)}/verifications`);
  const lastSuccess = [...verifications.verifications].reverse().find((item) => item.ok);
  $("#node-detail").innerHTML = `<button id="verify-chain">验证从根证据到此节点的完整链</button><pre>${escapeXml(JSON.stringify({node, last_success: lastSuccess || null, verification_history: verifications.verifications}, null, 2))}</pre>`;
  $("#verify-chain").addEventListener("click", async () => {
    try {
      showResult(await api(`/api/verify/${encodeURIComponent(id)}`, {method: "POST"}));
      await showNode(id);
    } catch (error) {
      showResult(error.body || error.message, true);
    }
  });
}

function renderBatches() {
  $("#batches").innerHTML = state.batches.map((batch) => `
    <div class="batch ${batch.status}">
      <strong>${escapeXml(batch.filename)}</strong>
      <div>批次：${batch.id}</div>
      <div>状态：${batch.status}；块：${batch.blocks.length}/${batch.total_blocks}</div>
      <div>来源：${escapeXml(batch.source)}</div>
      ${batch.error ? `<div>失败原因：${escapeXml(batch.error)}</div>` : ""}
      ${batch.quarantine_path ? `<div>隔离路径：${escapeXml(batch.quarantine_path)}</div>` : ""}
      <button data-seal="${batch.id}" data-hash="${batch.final_hashes.sha256 || ""}">填入封存表单</button>
      ${batch.status === "pending" || batch.status === "recovering" ? `<button data-recover="${batch.id}" data-action="continue">标记恢复中</button><button data-recover="${batch.id}" data-action="quarantine">隔离暂存</button>` : ""}
    </div>`).join("") || '<p class="muted">尚无批次。</p>';
  document.querySelectorAll("[data-seal]").forEach((button) => {
    button.addEventListener("click", () => {
      $('[name="batch_id"][form="form-seal"], #form-seal [name="batch_id"]').value = button.dataset.seal;
      showTab("batch");
    });
  });
  document.querySelectorAll("[data-recover]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        showResult(await api(`/api/batches/${encodeURIComponent(button.dataset.recover)}/recover`, {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify({action: button.dataset.action}),
        }));
        await loadState();
      } catch (error) {
        showResult(error.body || error.message, true);
      }
    });
  });
}

function renderExports() {
  $("#exports").innerHTML = state.exports.map((record) => `
    <div class="export-record">
      <div><strong>${record.id}</strong> · ${record.size} 字节</div>
      <div>SHA-256: ${record.sha256}</div>
      <a href="/api/exports/${record.id}/download">下载 ZIP</a>
    </div>`).join("");
}

function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((button) => button.classList.toggle("active", button.dataset.tab === name));
  document.querySelectorAll(".tab-body").forEach((body) => body.classList.remove("active"));
  const target = $(`#form-${name}, #tab-${name}`);
  if (target) target.classList.add("active");
}

document.querySelectorAll(".tabs button").forEach((button) => {
  button.addEventListener("click", () => showTab(button.dataset.tab));
});

function formData(element) {
  return new FormData(element);
}

function bindJSONForm(selector, path, method = "POST") {
  $(selector).addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = Object.fromEntries(formData(form).entries());
    if (data.include_derived) data.include_derived = true;
    for (const key of ["offset_nanos"]) if (data[key] !== undefined) data[key] = Number(data[key]);
    const idem = data.idempotency_key;
    delete data.idempotency_key;
    try {
      const output = await api(path, {
        method,
        headers: {"Content-Type": "application/json", ...(idem ? {"Idempotency-Key": idem} : {})},
        body: JSON.stringify(data),
      });
      showResult(output);
      form.reset();
      await loadState();
    } catch (error) {
      showResult(error.body || error.message, true);
    }
  });
}

function bindMultipart(selector, path) {
  $(selector).addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const idem = data.get("idempotency_key");
    data.delete("idempotency_key");
    try {
      const output = await api(path, {method: "POST", headers: idem ? {"Idempotency-Key": idem} : {}, body: data});
      showResult(output);
      form.reset();
      await loadState();
      if (output.batch?.id) $("#form-block [name='batch_id'], #form-seal [name='batch_id']").forEach?.((input) => input.value = output.batch.id);
    } catch (error) {
      showResult(error.body || error.message, true);
    }
  });
}

bindMultipart("#form-direct", "/api/evidence");
bindJSONForm("#form-batch-create", "/api/batches");
bindMultipart("#form-derive", "/api/derive");
bindJSONForm("#form-transfer", "/api/transfers");
bindJSONForm("#form-clock", "/api/clock-adjustments");
bindJSONForm("#form-export", "/api/exports");
bindMultipart("#form-import", "/api/imports");

$("#form-block").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const idem = data.get("idempotency_key");
  const batchID = encodeURIComponent(data.get("batch_id"));
  data.delete("idempotency_key");
  try {
    showResult(await api(`/api/batches/${batchID}/blocks`, {method: "POST", headers: idem ? {"Idempotency-Key": idem} : {}, body: data}));
    event.currentTarget.reset();
    await loadState();
  } catch (error) { showResult(error.body || error.message, true); }
});

$("#form-seal").addEventListener("submit", async (event) => {
  event.preventDefault();
  const raw = Object.fromEntries(new FormData(event.currentTarget).entries());
  const batchID = encodeURIComponent(raw.batch_id);
  const idem = raw.idempotency_key;
  try {
    showResult(await api(`/api/batches/${batchID}/seal`, {
      method: "POST",
      headers: {"Content-Type": "application/json", ...(idem ? {"Idempotency-Key": idem} : {})},
      body: JSON.stringify({expected_sha256: raw.expected_sha256}),
    }));
    event.currentTarget.reset();
    await loadState();
  } catch (error) { showResult(error.body || error.message, true); }
});

$("#refresh").addEventListener("click", loadState);
loadState().catch((error) => showResult(error.message, true));
