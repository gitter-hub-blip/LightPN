/* LightPN admin panel — no-build vanilla JS SPA.
   REST for snapshots + writes, WebSocket for live updates. */
"use strict";

const $ = (sel, el) => (el || document).querySelector(sel);
const app = $("#app");

// ---- state ----
const state = {
  authed: false,
  nodes: [],        // GET /api/nodes
  links: [],        // GET /api/links
  spark: {},        // nodeId -> [{cpu, rx_rate, tx_rate}] recent heartbeats
  ws: null,
  wsUp: false,
  route: location.hash || "#/nodes",
};

// ---- helpers ----
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) { state.authed = false; render(); throw new Error("未登录"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmtBytes(n) {
  if (!n && n !== 0) return "–";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(n >= 100 || i === 0 ? 0 : 1) + " " + u[i];
}
const fmtRate = n => (n || n === 0 ? fmtBytes(n) + "/s" : "–");

function fmtAgo(ts) {
  if (!ts) return "从未";
  const d = Math.floor(Date.now() / 1000 - ts);
  if (d < 5) return "刚刚";
  if (d < 60) return d + " 秒前";
  if (d < 3600) return Math.floor(d / 60) + " 分钟前";
  if (d < 86400) return Math.floor(d / 3600) + " 小时前";
  return Math.floor(d / 86400) + " 天前";
}

function toast(msg) {
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2200);
}

function nodeName(id) {
  const n = state.nodes.find(n => n.id === id);
  return n ? n.name : id.slice(0, 8);
}

// ---- charts (hand-rolled canvas line chart) ----
function drawChart(canvas, ts, series, opts) {
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth, H = canvas.height / dpr || 160;
  canvas.width = W * dpr; canvas.height = H * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, W, H);
  const padL = 42, padR = 8, padT = 8, padB = 18;
  const iw = W - padL - padR, ih = H - padT - padB;

  let max = opts.max ?? 0;
  if (!opts.max) {
    for (const s of series) for (const v of s.data) if (v > max) max = v;
    max = max > 0 ? max * 1.15 : 1;
  }
  const css = getComputedStyle(document.documentElement);
  const gridColor = css.getPropertyValue("--border").trim();
  const mutedColor = css.getPropertyValue("--muted").trim();

  // grid + y labels
  ctx.strokeStyle = gridColor; ctx.fillStyle = mutedColor;
  ctx.font = "10px " + css.getPropertyValue("--mono");
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = padT + ih * i / 3;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    const val = max * (1 - i / 3);
    ctx.fillText(opts.fmt ? opts.fmt(val) : val.toFixed(0), 2, y + 3);
  }
  // x labels
  if (ts.length > 1) {
    const t0 = new Date(ts[0] * 1000), t1 = new Date(ts[ts.length - 1] * 1000);
    const pad2 = n => String(n).padStart(2, "0");
    const lbl = t => pad2(t.getHours()) + ":" + pad2(t.getMinutes());
    ctx.fillText(lbl(t0), padL, H - 5);
    ctx.fillText(lbl(t1), W - padR - 30, H - 5);
  }
  if (!ts.length) return;

  for (const s of series) {
    ctx.strokeStyle = s.color; ctx.lineWidth = 1.6;
    ctx.beginPath();
    let started = false;
    for (let i = 0; i < ts.length; i++) {
      const x = padL + iw * (ts.length === 1 ? 0.5 : i / (ts.length - 1));
      const y = padT + ih * (1 - Math.min(s.data[i], max) / max);
      if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y);
    }
    ctx.stroke();
  }
}

function drawSpark(canvas, data, color, max) {
  const dpr = window.devicePixelRatio || 1;
  const W = 88, H = 26;
  canvas.width = W * dpr; canvas.height = H * dpr;
  canvas.style.width = W + "px"; canvas.style.height = H + "px";
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  if (!data.length) return;
  let m = max ?? Math.max(...data, 1e-9) * 1.1;
  ctx.strokeStyle = color; ctx.lineWidth = 1.4;
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = W * (data.length === 1 ? 0.5 : i / (data.length - 1));
    const y = H - 2 - (H - 4) * Math.min(v, m) / m;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
}

// ---- websocket ----
function connectWS() {
  if (state.ws) try { state.ws.close(); } catch (e) {}
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(proto + "//" + location.host + "/api/ws");
  state.ws = ws;
  ws.onopen = () => { state.wsUp = true; renderWSDot(); };
  ws.onclose = () => {
    state.wsUp = false; renderWSDot();
    if (state.authed) setTimeout(() => { refreshSnapshots().then(render); connectWS(); }, 3000);
  };
  ws.onmessage = e => {
    let msg; try { msg = JSON.parse(e.data); } catch { return; }
    handleEvent(msg);
  };
}

function handleEvent(msg) {
  const d = msg.data || {};
  switch (msg.ev) {
    case "heartbeat": {
      const n = state.nodes.find(n => n.id === d.node_id);
      if (n) {
        n.status = "online";
        n.last_seen = Math.floor(Date.now() / 1000);
        n.sys_summary = summarize(d.sys);
      }
      const sp = state.spark[d.node_id] = state.spark[d.node_id] || [];
      sp.push(summarize(d.sys));
      if (sp.length > 40) sp.shift();
      if (state.route === "#/nodes") render();
      if (state.route.startsWith("#/node/") && state.route.slice(7) === d.node_id) render();
      break;
    }
    case "node_status":
    case "enrolled":
      refreshSnapshots().then(render);
      break;
    case "link_status": {
      const l = state.links.find(l => l.id === d.link_id);
      if (l && d.status !== "deleted") { l.status = d.status; render(); }
      else refreshSnapshots().then(render);
      break;
    }
  }
}

function summarize(sys) {
  if (!sys) return null;
  return {
    cpu: sys.cpu_pct ?? 0,
    mem: sys.mem_total ? sys.mem_used / sys.mem_total * 100 : 0,
    mem_used: sys.mem_used, mem_total: sys.mem_total,
  };
}

function renderWSDot() {
  const el = $(".wsdot");
  if (el) el.className = "wsdot" + (state.wsUp ? " on" : "");
}

// ---- data ----
async function refreshSnapshots() {
  const [nodes, links] = await Promise.all([api("GET", "/api/nodes"), api("GET", "/api/links")]);
  state.nodes = nodes;
  state.links = links;
}

// ---- views ----
function layout(content) {
  const tabs = [
    ["#/nodes", "节点"],
    ["#/links", "连接"],
  ];
  return `
  <div class="topbar">
    <div class="logo">Light<span>PN</span></div>
    <nav>${tabs.map(([h, t]) =>
      `<a href="${h}" class="${state.route.startsWith(h) || (h === "#/nodes" && state.route.startsWith("#/node/")) ? "active" : ""}">${t}</a>`).join("")}
    </nav>
    <div class="wsdot${state.wsUp ? " on" : ""}" title="实时连接"></div>
    <button id="btn-logout">退出</button>
  </div>
  <main>${content}</main>`;
}

function loginView() {
  return `
  <div class="login-wrap">
    <form class="login-box" id="login-form">
      <h1>Light<span style="color:var(--accent)">PN</span></h1>
      <input name="username" placeholder="用户名" autocomplete="username" required>
      <input name="password" type="password" placeholder="密码" autocomplete="current-password" required>
      <button class="primary" type="submit">登录</button>
      <div class="hint" id="login-err"></div>
    </form>
  </div>`;
}

function nodesView() {
  const cards = state.nodes.map(n => {
    const s = n.sys_summary;
    const sp = state.spark[n.id] || [];
    return `
    <div class="card">
      <div class="head">
        <div class="dot ${n.status}"></div>
        <a class="name" href="#/node/${n.id}">${esc(n.name)}</a>
        <span class="pill ${n.status}" style="margin-left:auto">${n.status}</span>
      </div>
      <div class="kv"><span class="k">Overlay IP</span><span class="v">${esc(n.overlay_ip)}</span></div>
      <div class="kv"><span class="k">Endpoint</span><span class="v">${esc(n.endpoint || "–")}</span></div>
      <div class="kv"><span class="k">最近心跳</span><span class="v">${fmtAgo(n.last_seen)}</span></div>
      <div class="kv"><span class="k">CPU / 内存</span><span class="v">${s ? s.cpu.toFixed(1) + "% / " + s.mem.toFixed(0) + "%" : "–"}</span></div>
      <div class="sparkrow">
        <div><div class="lbl">CPU</div><canvas data-spark="${n.id}:cpu"></canvas></div>
        <div><div class="lbl">内存</div><canvas data-spark="${n.id}:mem"></canvas></div>
      </div>
    </div>`;
  }).join("");
  return layout(`
    <div class="page-head">
      <h1>节点总览</h1>
      <button class="primary" id="btn-add-node">＋ 添加节点</button>
    </div>
    ${state.nodes.length ? `<div class="grid">${cards}</div>` : `<div class="empty">还没有节点。点击「添加节点」生成入网命令。</div>`}
  `);
}

function nodeDetailView(id) {
  const n = state.nodes.find(n => n.id === id);
  if (!n) return layout(`<div class="empty">节点不存在</div>`);
  return layout(`
    <div class="page-head">
      <h1><span class="dot ${n.status}" style="display:inline-block;margin-right:8px"></span>${esc(n.name)}
        <span class="hint mono" style="margin-left:10px">${esc(n.overlay_ip)} · ${esc(n.id)}</span></h1>
      <div style="display:flex;gap:8px">
        <button id="btn-rename">改名</button>
        <button id="btn-rotate" ${n.status === "offline" ? "disabled" : ""}>轮换 WG 密钥</button>
        <button class="danger" id="btn-del-node">删除节点</button>
      </div>
    </div>
    <div class="charts">
      <div class="chartbox"><h3>CPU %</h3><canvas id="c-cpu" height="160"></canvas></div>
      <div class="chartbox"><h3>内存 %</h3><canvas id="c-mem" height="160"></canvas></div>
      <div class="chartbox"><h3>网络速率</h3><canvas id="c-net" height="160"></canvas></div>
      <div class="chartbox"><h3>磁盘 %</h3><canvas id="c-disk" height="160"></canvas></div>
    </div>
    <div class="section-title">当前 Peer</div>
    <div id="peer-table"><div class="empty">加载中…</div></div>
  `);
}

function linksView() {
  const nodes = state.nodes;
  const linkOf = (a, b) => state.links.find(l => (l.a === a && l.b === b) || (l.a === b && l.b === a));
  let matrix = "";
  if (nodes.length > 1) {
    const head = `<tr><th></th>${nodes.map(n => `<th title="${esc(n.name)}">${esc(n.name.slice(0, 10))}</th>`).join("")}</tr>`;
    const rows = nodes.map(a => `<tr><th title="${esc(a.name)}">${esc(a.name.slice(0, 10))}</th>${
      nodes.map(b => {
        if (a.id === b.id) return `<td class="self">·</td>`;
        const l = linkOf(a.id, b.id);
        if (l) return `<td class="cell" data-del-link="${l.id}" title="点击删除 link"><span class="pill ${l.status}">${l.status}</span></td>`;
        return `<td class="cell" data-add-link="${a.id},${b.id}" title="点击创建 link">＋</td>`;
      }).join("")}</tr>`).join("");
    matrix = `<div style="overflow-x:auto"><table class="matrix">${head}${rows}</table></div>`;
  } else {
    matrix = `<div class="empty">至少需要两个节点才能建立连接。</div>`;
  }
  const exitCapable = id => {
    const n = state.nodes.find(n => n.id === id);
    return n && n.exit_capable;
  };
  const exitCell = l => {
    // Options: direct (no exit) / A 经 B 出网 / B 经 A 出网, only offering
    // a direction whose exit node advertises a SOCKS port.
    const opts = [`<option value="">直连(各自出网)</option>`];
    if (exitCapable(l.b)) opts.push(`<option value="${l.b}" ${l.exit_node === l.b ? "selected" : ""}>${esc(nodeName(l.a))} 经 ${esc(nodeName(l.b))} 出网</option>`);
    if (exitCapable(l.a)) opts.push(`<option value="${l.a}" ${l.exit_node === l.a ? "selected" : ""}>${esc(nodeName(l.b))} 经 ${esc(nodeName(l.a))} 出网</option>`);
    if (opts.length === 1) {
      return l.exit_node
        ? `<span class="pill degraded">出口节点已离线</span>`
        : `<span class="hint">无节点开启出口 SOCKS</span>`;
    }
    return `<select data-exit-link="${l.id}">${opts.join("")}</select>`;
  };
  const rows = state.links.map(l => `
    <tr>
      <td>${esc(nodeName(l.a))} ⇄ ${esc(nodeName(l.b))}</td>
      <td><span class="pill ${l.status}">${l.status}</span>${l.status === "degraded" ? `<div class="hint">双方已下发但无握手 —— 检查 WG UDP 端口是否放行</div>` : ""}</td>
      <td>${exitCell(l)}</td>
      <td class="mono">${l.last_handshake ? fmtAgo(l.last_handshake) : "–"}</td>
      <td class="mono">↓${fmtRate(l.rx_rate)} ↑${fmtRate(l.tx_rate)}</td>
      <td><button class="danger" data-del-link="${l.id}">删除</button></td>
    </tr>`).join("");
  return layout(`
    <div class="page-head"><h1>连接矩阵</h1></div>
    ${matrix}
    <div class="section-title">Link 列表</div>
    ${state.links.length ? `<table>
      <tr><th>节点对</th><th>状态</th><th>出口</th><th>最近握手</th><th>速率</th><th></th></tr>${rows}</table>`
      : `<div class="empty">还没有 link。在上方矩阵中点击 ＋ 创建。</div>`}
  `);
}

// ---- modals ----
function showModal(html) {
  const mask = document.createElement("div");
  mask.className = "modal-mask";
  mask.innerHTML = `<div class="modal">${html}</div>`;
  mask.addEventListener("click", e => { if (e.target === mask) mask.remove(); });
  document.body.appendChild(mask);
  return mask;
}

async function addNodeModal() {
  let tok;
  try { tok = await api("POST", "/api/tokens", {}); }
  catch (e) { toast("生成 token 失败: " + e.message); return; }
  const cmd = `lightpn-agent enroll --hub ${location.hostname === "localhost" || location.hostname === "127.0.0.1" ? "<hub公网IP>:7440" : "<hub公网IP>:7440"} --token ${tok.token}`;
  const mask = showModal(`
    <h2>添加节点</h2>
    <p class="hint" style="margin-bottom:10px">在新的边缘机器上执行以下命令(token 15 分钟内有效,使用即焚):</p>
    <div class="cmdbox" id="cmd">${esc(cmd)}</div>
    <div class="hint">点击命令可复制。节点入网后会自动出现在列表中。</div>
    <div class="actions"><button class="primary" id="close">完成</button></div>
  `);
  $("#cmd", mask).onclick = () => { navigator.clipboard.writeText(cmd).then(() => toast("已复制")); };
  $("#close", mask).onclick = () => mask.remove();
}

function confirmModal(text, onOK) {
  const mask = showModal(`
    <h2>确认操作</h2>
    <p>${esc(text)}</p>
    <div class="actions">
      <button id="cancel">取消</button>
      <button class="primary danger" id="ok">确认</button>
    </div>`);
  $("#cancel", mask).onclick = () => mask.remove();
  $("#ok", mask).onclick = async () => { mask.remove(); await onOK(); };
}

// ---- render ----
async function render() {
  if (!state.authed) { app.innerHTML = loginView(); bindLogin(); return; }
  const r = state.route;
  if (r.startsWith("#/node/")) {
    app.innerHTML = nodeDetailView(r.slice(7));
    bindCommon(); bindNodeDetail(r.slice(7));
  } else if (r.startsWith("#/links")) {
    app.innerHTML = linksView();
    bindCommon(); bindLinks();
  } else {
    app.innerHTML = nodesView();
    bindCommon(); bindNodes();
  }
}

function bindLogin() {
  $("#login-form").onsubmit = async e => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api("POST", "/api/login", { username: f.get("username"), password: f.get("password") });
      state.authed = true;
      await refreshSnapshots();
      connectWS();
      render();
    } catch (err) {
      $("#login-err").textContent = "登录失败:" + err.message;
    }
  };
}

function bindCommon() {
  $("#btn-logout").onclick = async () => {
    await api("POST", "/api/logout").catch(() => {});
    state.authed = false;
    if (state.ws) state.ws.close();
    render();
  };
}

function bindNodes() {
  $("#btn-add-node").onclick = addNodeModal;
  document.querySelectorAll("[data-spark]").forEach(c => {
    const [id, kind] = c.dataset.spark.split(":");
    const sp = (state.spark[id] || []).filter(Boolean);
    const css = getComputedStyle(document.documentElement);
    if (kind === "cpu") drawSpark(c, sp.map(s => s.cpu), css.getPropertyValue("--accent").trim(), 100);
    else drawSpark(c, sp.map(s => s.mem), css.getPropertyValue("--ok").trim(), 100);
  });
}

function bindNodeDetail(id) {
  const n = state.nodes.find(n => n.id === id);
  if (!n) return;
  $("#btn-rename").onclick = () => {
    const mask = showModal(`
      <h2>修改备注名</h2>
      <div class="row"><input id="new-name" value="${esc(n.name)}"></div>
      <div class="actions"><button id="cancel">取消</button><button class="primary" id="ok">保存</button></div>`);
    $("#cancel", mask).onclick = () => mask.remove();
    $("#ok", mask).onclick = async () => {
      const name = $("#new-name", mask).value.trim();
      if (!name) return;
      try { await api("PATCH", `/api/nodes/${id}`, { name }); mask.remove(); await refreshSnapshots(); render(); }
      catch (e) { toast(e.message); }
    };
  };
  $("#btn-rotate").onclick = () => confirmModal(
    `轮换 ${n.name} 的 WireGuard 密钥?节点会重新注册,隧道将在数秒内自愈。`,
    async () => { try { await api("POST", `/api/nodes/${id}/rotate-wg`); toast("已下发轮换指令"); } catch (e) { toast(e.message); } });
  $("#btn-del-node").onclick = () => confirmModal(
    `删除节点 ${n.name}?其全部 link 将被清理,节点将被踢下线并吊销证书。此操作不可逆。`,
    async () => {
      try { await api("DELETE", `/api/nodes/${id}`); toast("已删除"); location.hash = "#/nodes"; }
      catch (e) { toast(e.message); }
    });

  loadNodeDetail(id);
}

async function loadNodeDetail(id) {
  try {
    const [metrics, detail] = await Promise.all([
      api("GET", `/api/nodes/${id}/metrics?range=24h`),
      api("GET", `/api/nodes/${id}`),
    ]);
    const css = getComputedStyle(document.documentElement);
    const accent = css.getPropertyValue("--accent").trim();
    const ok = css.getPropertyValue("--ok").trim();
    const warn = css.getPropertyValue("--warn").trim();
    const c = sel => $(sel);
    if (c("#c-cpu")) drawChart(c("#c-cpu"), metrics.ts, [{ data: metrics.cpu, color: accent }], { max: 100, fmt: v => v.toFixed(0) + "%" });
    if (c("#c-mem")) drawChart(c("#c-mem"), metrics.ts, [{ data: metrics.mem, color: ok }], { max: 100, fmt: v => v.toFixed(0) + "%" });
    if (c("#c-net")) drawChart(c("#c-net"), metrics.ts, [
      { data: metrics.rx_rate, color: accent },
      { data: metrics.tx_rate, color: warn },
    ], { fmt: v => fmtBytes(v) });
    if (c("#c-disk")) drawChart(c("#c-disk"), metrics.ts, [{ data: metrics.disk, color: warn }], { max: 100, fmt: v => v.toFixed(0) + "%" });

    const peers = detail.peers || [];
    const el = $("#peer-table");
    if (!el) return;
    el.innerHTML = peers.length ? `<table>
      <tr><th>对端</th><th>最近握手</th><th>累计流量</th><th>Endpoint</th></tr>
      ${peers.map(p => `<tr>
        <td>${esc(nodeName(p.peer_node_id))}</td>
        <td class="mono">${p.last_handshake_ts ? fmtAgo(p.last_handshake_ts) : "无"}</td>
        <td class="mono">↓${fmtBytes(p.rx_bytes)} ↑${fmtBytes(p.tx_bytes)}</td>
        <td class="mono">${esc(p.endpoint || "–")}</td>
      </tr>`).join("")}</table>` : `<div class="empty">该节点当前没有 peer。</div>`;
  } catch (e) { /* node offline / no data */ }
}

function bindLinks() {
  document.querySelectorAll("[data-add-link]").forEach(el => {
    el.onclick = async () => {
      const [a, b] = el.dataset.addLink.split(",");
      try { await api("POST", "/api/links", { a, b }); toast("link 已创建"); await refreshSnapshots(); render(); }
      catch (e) { toast(e.message); }
    };
  });
  document.querySelectorAll("[data-del-link]").forEach(el => {
    el.onclick = () => confirmModal("删除该 link?两端的 WG peer 会立即被移除。", async () => {
      try { await api("DELETE", `/api/links/${el.dataset.delLink}`); toast("已删除"); await refreshSnapshots(); render(); }
      catch (e) { toast(e.message); }
    });
  });
  document.querySelectorAll("[data-exit-link]").forEach(el => {
    el.onchange = async () => {
      try {
        await api("PATCH", `/api/links/${el.dataset.exitLink}`, { exit_node: el.value });
        toast(el.value ? "出口已设置" : "已恢复直连");
        await refreshSnapshots(); render();
      } catch (e) { toast(e.message); render(); }
    };
  });
}

// ---- boot ----
window.addEventListener("hashchange", () => { state.route = location.hash || "#/nodes"; render(); });

(async function boot() {
  try {
    await api("GET", "/api/session");
    state.authed = true;
    await refreshSnapshots();
    connectWS();
  } catch (e) { state.authed = false; }
  render();
  // periodic re-render so "x 分钟前" stays fresh even without events
  setInterval(() => { if (state.authed && state.route === "#/nodes") render(); }, 30000);
})();
