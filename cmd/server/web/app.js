'use strict';
const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const shortHash = h => h ? h.slice(0, 12) : '';

let state = null;
let selectedNode = null;

function toast(msg, ok) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + (ok === false ? 'err' : 'ok');
  setTimeout(() => t.classList.add('hidden'), 3500);
}

async function api(path, opts) {
  opts = opts || {};
  const key = opts.idemKey;
  delete opts.idemKey;
  const hdr = opts.headers || {};
  if (key) hdr['Idempotency-Key'] = key;
  opts.headers = hdr;
  const res = await fetch(path, opts);
  const ct = res.headers.get('content-type') || '';
  const body = ct.includes('json') ? await res.json() : await res.text();
  if (!res.ok) throw new Error((body && body.error) || res.statusText);
  return { body, res };
}

async function refresh() {
  const { body } = await api('/api/state');
  state = body;
  $('#clock').textContent = '服务器时间 ' + new Date(body.now).toLocaleString() + ' · 事件 ' + body.events.length;
  renderSessions(body);
  renderArtifacts(body);
  renderChecks(body);
  renderSelects(body);
  renderPackages(body);
  renderClockFacts(body);
  renderEvents(body);
  drawGraph(await (await fetch('/api/graph')).json());
}

function renderSessions(st) {
  const boxes = { pending: [], accepted: [], rejected: [], recovering: [] };
  st.sessions.forEach(s => { (boxes[s.status] || boxes.pending).push(s); });
  for (const k of Object.keys(boxes)) {
    $('#list-' + k).innerHTML = boxes[k].map(sessCard).join('') || '<div class="muted">—</div>';
  }
  $$('#list-pending .act-seal, #list-recovering .act-seal').forEach(b => b.onclick = () => seal(b.dataset.id));
  $$('#list-pending .act-quar, #list-recovering .act-quar').forEach(b => b.onclick = () => quarantine(b.dataset.id));
}

function progress(s) {
  const have = Object.keys(s.blocks || {}).length;
  const pct = s.block_count ? Math.round(100 * have / s.block_count) : 0;
  return `<div class="bar"><div style="width:${pct}%"></div></div>
    <div>${have}/${s.block_count} 块 · ${pct}%</div>`;
}

function sessCard(s) {
  let actions = '';
  if (s.status === 'pending' || s.status === 'recovering') {
    actions = `<button class="ghost act-seal" data-id="${s.id}">封存</button>
      <button class="ghost act-quar" data-id="${s.id}">隔离</button>`;
  }
  const fails = (s.failures || []).map(f => `<div class="log err">${esc(f.stage)}: ${esc(f.detail)}</div>`).join('');
  return `<div class="sess"><b>${esc(s.filename)}</b>
    <div class="id">${esc(s.id)}</div>
    <div>${esc(s.source.kind)} · ${esc(s.source.origin)}</div>
    ${progress(s)}
    ${fails}${actions}</div>`;
}

function renderArtifacts(st) {
  $('#artifacts').innerHTML = st.artifacts.map(a => {
    const ctx = st.custodies.filter(c => c.artifact_id === a.id).length;
    const der = a.derived_from
      ? `<div class="muted">派生自 ${esc(a.derived_from.parent_id)} · ${esc(a.derived_from.tool.name)} ${esc(a.derived_from.tool.version)}</div>` : '';
    return `<div class="art">
      <span class="tag ${a.kind}">${a.kind}</span><b>${esc(a.filename)}</b>
      <div class="hash">${esc(a.id)}</div>
      <div>${a.length} 字节 · 移交 ${ctx} 次${a.package_id ? ' · 包 ' + esc(shortHash(a.package_id)) : ''}</div>
      <div class="hash">sha256 ${esc(a.hashes.sha256)}</div>
      ${(a.sparse_ranges && a.sparse_ranges.length) ? `<div class="muted">稀疏区间 ${a.sparse_ranges.length} 段</div>` : ''}
      ${der}
      <a class="ghost" href="/api/artifacts/${encodeURIComponent(a.id)}/blob" target="_blank" style="color:var(--accent)">下载只读字节</a>
    </div>`;
  }).join('') || '<div class="muted">尚无证据。创建一个采集批次开始。</div>';
}

function renderChecks(st) {
  $('#checks').innerHTML = st.checks.slice().reverse().map(c =>
    `<div class="chkrow ${c.ok ? '' : 'bad'}"><b>${c.ok ? '✔ 验证通过' : '✘ 验证失败'}</b>
     <span class="muted"> ${esc(c.target_id)} · ${new Date(c.time).toLocaleString()}</span>
     <pre>${c.steps.map(x => '✓ ' + esc(x)).join('\n')}${c.errors.length ? '\n' + c.errors.map(x => '✗ ' + esc(x)).join('\n') : ''}</pre></div>`
  ).join('') || '<div class="muted">尚未验证过任何链。</div>';
}

function renderSelects(st) {
  const opts = st.artifacts.map(a => `<option value="${a.id}">${esc(a.filename)} (${a.kind}) ${shortHash(a.hashes.sha256)}</option>`).join('');
  $$('select[name=parent],select[name=target]').forEach(s => { s.innerHTML = opts; });
  $('#export-ids').innerHTML = st.artifacts.filter(a => a.kind !== 'derived')
    .map(a => `<option value="${a.id}">${esc(a.filename)} ${shortHash(a.hashes.sha256)}</option>`).join('');
}

function renderClockFacts(st) {
  $('#clock-facts').innerHTML = st.clock_facts.slice().reverse().map(f =>
    `<div class="sess">${esc(f.old_offset)} → <b>${esc(f.new_offset)}</b> · ${esc(f.reason)}
     <div class="id">${new Date(f.time).toLocaleString()}</div></div>`).join('');
}

function renderEvents(st) {
  $('#event-log').textContent = st.events.map(e =>
    `${e.seq}  ${e.time}  ${e.type.padEnd(18)} ${e.idem_key ? 'idem=' + e.idem_key + ' ' : ''}${JSON.stringify(e.payload)}`
  ).join('\n');
}

async function seal(id) {
  try {
    await api('/api/sessions/' + encodeURIComponent(id) + '/seal',
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', idemKey: 'seal-' + id });
    toast('封存成功'); refresh();
  } catch (e) { toast('封存失败（已保留失败记录）：' + e.message, false); refresh(); }
}

async function quarantine(id) {
  const reason = prompt('隔离原因：', 'operator quarantined');
  if (reason == null) return;
  await api('/api/sessions/' + encodeURIComponent(id) + '/quarantine',
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason }) });
  toast('已隔离'); refresh();
}

$('#create-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  const file = f.file.files[0];
  const blockSize = parseInt(f.blocksize.value, 10);
  const total = parseInt(f.total.value || '0', 10) || file.size;
  const blockCount = Math.ceil(file.size / blockSize) || 1;
  const log = $('#ingest-log');
  log.className = 'log'; log.textContent = '';
  const idem = 'ing-' + crypto.randomUUID();
  try {
    const { body } = await api('/api/sessions', {
      method: 'POST', idemKey: idem,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: file.name, total_length: total, block_size: blockSize, block_count: blockCount,
        source: { kind: f.kind.value, origin: f.origin.value, acquirer: f.acquirer.value, path: file.name },
        note: f.note.value
      })
    });
    const sid = body.session.id;
    for (let i = 0; i < blockCount; i++) {
      const blob = file.slice(i * blockSize, Math.min((i + 1) * blockSize, file.size));
      const headers = {};
      if (f.verifyblocks.checked) {
        const buf = await blob.arrayBuffer();
        headers['X-Block-SHA256'] = await digestHex('SHA-256', buf);
        await putBlock(sid, i, new Blob([buf]), headers);
      } else {
        await putBlock(sid, i, blob, headers);
      }
      log.textContent = `已上传块 ${i + 1}/${blockCount}`;
    }
    await api('/api/sessions/' + sid + '/seal',
      { method: 'POST', idemKey: 'seal-' + sid, headers: { 'Content-Type': 'application/json' }, body: '{}' });
    log.className = 'log ok'; log.textContent = `✔ 批次 ${sid} 全部块写入、清单刷盘、哈希匹配，已可见`;
    toast('采集封存完成'); refresh();
  } catch (e) {
    log.className = 'log err'; log.textContent += '\n✘ ' + e.message + '\n重启后该批次会进入“恢复中”，可继续或隔离。';
    toast(e.message, false); refresh();
  }
});

async function putBlock(sid, i, blob, headers) {
  const res = await fetch('/api/sessions/' + sid + '/blocks/' + i, { method: 'PUT', headers, body: blob });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new Error(j.error || res.statusText);
  }
}

async function digestHex(algo, buf) {
  const h = await crypto.subtle.digest(algo, buf);
  return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
}

$('#derive-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  try {
    const { body } = await api('/api/derive', {
      method: 'POST', idemKey: 'der-' + crypto.randomUUID(),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ parent_id: f.parent.value, tool: f.tool.value, args: f.args.value,
        start: parseInt(f.start.value || '0', 10), end: parseInt(f.end.value || '0', 10) })
    });
    toast('已生成派生节点 ' + body.artifact.id); refresh();
  } catch (e) { toast(e.message, false); }
});

$('#transfer-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  try {
    await api('/api/transfer', {
      method: 'POST', idemKey: 'ctx-' + crypto.randomUUID(),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifact_id: f.target.value, from: f.from.value, to: f.to.value, reason: f.reason.value })
    });
    toast('移交事件已追加'); f.from.value = ''; f.to.value = ''; f.reason.value = ''; refresh();
  } catch (e) { toast(e.message, false); }
});

$('#clock-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  try {
    await api('/api/clock', {
      method: 'POST', idemKey: 'clk-' + crypto.randomUUID(),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_offset: f.oldoff.value, new_offset: f.newoff.value, reason: f.reason.value })
    });
    toast('时钟校正已作为独立事实保存'); refresh();
  } catch (e) { toast(e.message, false); }
});

// ---- Graph --------------------------------------------------------------

function drawGraph(g) {
  const svg = $('#graph');
  const W = svg.clientWidth || 1000, H = 640;
  svg.innerHTML = `<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
    <path d="M0,0 L7,3 L0,6 Z" fill="#445262"/></marker></defs>`;
  const NS = 'http://www.w3.org/2000/svg';
  const byKind = {};
  g.nodes.forEach(n => (byKind[n.kind] = byKind[n.kind] || []).push(n));
  const layerOrder = ['session', 'artifact', 'custody', 'package', 'clock'];
  const pos = {};
  layerOrder.forEach((kind, li) => {
    (byKind[kind] || []).forEach((n, i, arr) => {
      pos[n.id] = { x: 60 + li * (W - 140) / Math.max(layerOrder.length - 1, 1),
                    y: 60 + (i + 0.5) * (H - 120) / Math.max(arr.length, 1) };
    });
  });
  g.edges.forEach(e => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('class', 'link');
    p.setAttribute('d', `M${a.x + 80},${a.y} C${a.x + 120},${a.y} ${b.x - 120},${b.y} ${b.x - 80},${b.y}`);
    svg.appendChild(p);
  });
  g.nodes.forEach(n => {
    const p = pos[n.id]; if (!p) return;
    const gEl = document.createElementNS(NS, 'g');
    gEl.setAttribute('class', 'node ' + n.kind + (selectedNode === n.id ? ' selected' : ''));
    gEl.setAttribute('transform', `translate(${p.x - 80},${p.y - 20})`);
    const r = document.createElementNS(NS, 'rect');
    r.setAttribute('width', '160'); r.setAttribute('height', '40'); r.setAttribute('rx', '7');
    const t = document.createElementNS(NS, 'text');
    t.setAttribute('x', '8'); t.setAttribute('y', '16');
    t.textContent = (n.label || n.id).slice(0, 22);
    const t2 = document.createElementNS(NS, 'text');
    t2.setAttribute('x', '8'); t2.setAttribute('y', '32');
    t2.textContent = (n.status || n.kind + ' ' + (n.detail || '')).slice(0, 24);
    gEl.appendChild(r); gEl.appendChild(t); gEl.appendChild(t2);
    gEl.onclick = () => { selectedNode = n.id; $('#selected-node').textContent = '已选: ' + n.id; drawGraph(g); };
    svg.appendChild(gEl);
  });
}

$('#verify-selected').onclick = async () => {
  if (!selectedNode || !selectedNode.startsWith('artifact:')) {
    toast('请先在图中选择一个证据/派生节点', false); return;
  }
  const id = selectedNode.slice('artifact:'.length);
  const out = $('#verify-out');
  try {
    const { body } = await api('/api/verify', {
      method: 'POST', idemKey: 'chk-' + crypto.randomUUID(),
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target_id: id })
    });
    const c = body.check;
    out.className = 'log ' + (c.ok ? 'ok' : 'err');
    out.textContent = (c.ok ? '✔ 完整链验证通过\n' : '✘ 链验证失败（失败已保存）\n') +
      c.steps.map(x => '✓ ' + x).join('\n') +
      (c.errors.length ? '\n' + c.errors.map(x => '✗ ' + x).join('\n') : '');
    refresh();
  } catch (e) { out.className = 'log err'; out.textContent = e.message; }
};

// ---- Packages ------------------------------------------------------------

function renderPackages(st) {
  $('#package-list').innerHTML = st.packages.slice().reverse().map(p =>
    `<div class="sess">${p.direction === 'export' ? '导出' : '导入'} <b>${esc(shortHash(p.package_id))}</b>
     <div class="hash">sha256 ${esc(p.content_hash)}</div>
     <div>${new Date(p.time).toLocaleString()} · ${p.artifact_ids.length} 个证据${p.with_derived ? '（含派生）' : ''}</div>
     ${p.direction === 'export' ? `<a href="/api/packages/${encodeURIComponent(p.package_id)}/download" style="color:var(--accent)">重新下载（不产生新事件）</a>` : ''}
    </div>`).join('');
}

$('#export-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target;
  const ids = $$('#export-ids option:checked').map(o => o.value);
  const log = $('#export-log');
  try {
    const res = await fetch('/api/export', {
      method: 'POST', idemKey: 'exp-' + crypto.randomUUID(),
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'exp-' + Date.now() },
      body: JSON.stringify({ artifact_ids: ids, with_derived: f.withderived.checked })
    });
    if (!res.ok) throw new Error((await res.json()).error);
    const pkgId = res.headers.get('X-Package-Id');
    const hash = res.headers.get('X-Content-Hash');
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = pkgId + '.fbx.zip';
    a.click();
    log.className = 'log ok';
    log.textContent = `✔ 包 ${pkgId}\n内容哈希 ${hash}`;
    refresh();
  } catch (e) { log.className = 'log err'; log.textContent = e.message; }
});

$('#import-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const file = ev.target.pkg.files[0];
  const log = $('#import-log');
  if (!file) return;
  try {
    const res = await fetch('/api/import', { method: 'POST', headers: { 'Idempotency-Key': 'imp-' + crypto.randomUUID() }, body: file });
    const j = await res.json();
    if (!res.ok) throw new Error(j.error);
    log.className = 'log ' + (j.replayed ? '' : 'ok');
    log.textContent = (j.replayed ? '↺ 该包已登记：返回首次结果，未产生重复移交\n' : '✔ 验证通过并已登记\n') +
      `包 ${j.package_id}\n证据 ${j.artifacts.length} 个 · 移交事件 ${j.transfers} 条\nsha256 ${j.content_hash}`;
    refresh();
  } catch (e) { log.className = 'log err'; log.textContent = '导入被拒绝（未登记任何内容）：' + e.message; }
});

// ---- Tabs ----------------------------------------------------------------

$$('.tabs button').forEach(b => b.onclick = () => {
  $$('.tabs button').forEach(x => x.classList.remove('active'));
  $$('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  $('#tab-' + b.dataset.tab).classList.add('active');
  if (b.dataset.tab === 'graph') refresh();
});

refresh().catch(e => toast('加载状态失败: ' + e.message, false));
setInterval(() => refresh().catch(() => {}), 8000);
