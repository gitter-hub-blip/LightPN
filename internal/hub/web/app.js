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
  toolconf: null,   // { id, data, loading, err } — survives heartbeat re-renders
  exitwg: null,     // { id, data } cached direct-WG state for the open node
  confShown: new Set(), // indices of currently revealed masked values
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
    case "exitwg_status":
      if (state.route.startsWith("#/node/") && state.route.slice(7) === d.node_id) loadExitWG(d.node_id);
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
    <div class="section-title">直连 WG(设备直连出口)</div>
    <div class="hint" style="margin-bottom:8px">独立于组网的第二个 WireGuard 接口(lightpn1):你的手机/电脑直连该节点并以它为全隧道出口。默认关闭。</div>
    <div id="exitwg-box"><div class="empty">加载中…</div></div>
    <div class="section-title">网络工具配置</div>
    <div class="hint" style="margin-bottom:8px">实时从节点读取翻墙软件配置与 WireGuard 运行时状态(不含私钥)。敏感字段默认打码,点击可显示。</div>
    <button id="btn-toolconf" ${n.status === "offline" ? "disabled" : ""}>拉取配置</button>
    <div id="toolconf-out" style="margin-top:10px"></div>
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
  const hubAddr = (tok.control_addr || "").trim() || "<hub公网IP>:7440";
  const needsAddr = hubAddr.startsWith("<");
  // Complete one-liner: real hub addr from the backend, sudo (needs root to
  // write identity + manage the service), and it enables+starts the service
  // so the node comes online without a separate step.
  const cmd = `sudo lightpn-agent enroll --hub ${hubAddr} --token ${tok.token} && sudo systemctl enable --now lightpn-agent`;
  const mask = showModal(`
    <h2>添加节点</h2>
    <p class="hint" style="margin-bottom:10px">在新的边缘机器上以 root 执行以下命令(保留开头的 sudo;入网成功后会自动启动服务;token 15 分钟内有效,使用即焚):</p>
    <div class="cmdbox" id="cmd">${esc(cmd)}</div>
    ${needsAddr ? `<div class="hint" style="color:#c60">hub 未配置 public_addr,命令里的 &lt;hub公网IP&gt;:7440 需手动替换为本机公网地址;或在 hub.json 设 public_addr 并重启 hub 后即自动填入。</div>` : ``}
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

  // Toolconf survives the 15s heartbeat re-render; drop it only when the
  // detail page switches to another node.
  if (state.toolconf && state.toolconf.id !== id) { state.toolconf = null; state.confShown.clear(); }
  $("#btn-toolconf").onclick = () => loadToolConf(id);
  renderToolConf();

  // Direct-connect WG: cached in state like toolconf; re-fetched on actions
  // and on exitwg_status WS events, not on every heartbeat re-render.
  if (state.exitwg && state.exitwg.id !== id) state.exitwg = null;
  if (state.exitwg) renderExitWG(); else loadExitWG(id);

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

// ---- direct-connect WG (exitwg) ----

// wgKeypair generates a WireGuard keypair in the browser via WebCrypto
// X25519. Returns null when unsupported — the UI falls back to pasting a
// pubkey generated on the device.
async function wgKeypair() {
  try {
    const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
    const b64u = jwk.d.replace(/-/g, "+").replace(/_/g, "/");
    const priv = Uint8Array.from(atob(b64u + "=".repeat((4 - b64u.length % 4) % 4)), c => c.charCodeAt(0));
    const b64 = bytes => btoa(String.fromCharCode(...bytes));
    if (priv.length !== 32 || pub.length !== 32) return null;
    return { priv: b64(priv), pub: b64(pub) };
  } catch (e) { return null; }
}

async function loadExitWG(id) {
  try {
    const data = await api("GET", `/api/nodes/${id}/exitwg`);
    state.exitwg = { id, data };
  } catch (e) {
    state.exitwg = { id, err: e.message };
  }
  renderExitWG();
}

function clientConf(ew, ip, privKey) {
  const host = ew.endpoint_host || "<节点公网IP>";
  return `[Interface]
PrivateKey = ${privKey || "<你的设备私钥>"}
Address = ${ip}
DNS = 1.1.1.1

[Peer]
PublicKey = ${ew.pubkey || "<启用后由节点生成,见面板服务端公钥>"}
Endpoint = ${host}:${ew.port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25`;
}

function renderExitWG() {
  const box = $("#exitwg-box");
  const ew = state.exitwg;
  if (!box || !ew) return;
  if (ew.err) { box.innerHTML = `<div class="empty">加载失败:${esc(ew.err)}</div>`; return; }
  const d = ew.data;
  const peers = d.peers || [];
  const rows = peers.map(p => `
    <tr>
      <td>${esc(p.name)}</td>
      <td class="mono">${esc(p.ip)}</td>
      <td class="mono" title="${esc(p.pubkey)}">${esc(p.pubkey.slice(0, 12))}…</td>
      <td style="display:flex;gap:6px">
        <button data-ewconf="${esc(p.ip)}">配置</button>
        <button class="danger" data-ewdel="${esc(p.id)}">移除</button>
      </td>
    </tr>`).join("");
  box.innerHTML = `
    <div class="card" style="margin-bottom:12px">
      <div class="kv"><span class="k">状态</span><span class="v">
        <span class="pill ${d.enabled ? "online" : "offline"}">${d.enabled ? "已启用" : "已停用"}</span></span></div>
      <div class="kv"><span class="k">监听端口(UDP)</span><span class="v">${d.port}</span></div>
      <div class="kv"><span class="k">网段</span><span class="v">${esc(d.cidr)}</span></div>
      <div class="kv"><span class="k">服务端公钥</span><span class="v" title="${esc(d.pubkey)}">${d.pubkey ? esc(d.pubkey.slice(0, 16)) + "…" : "启用后生成"}</span></div>
      ${d.enabled ? `<div class="hint">请在该节点防火墙放行 ${d.port}/udp。</div>` : ""}
      <div style="margin-top:10px;display:flex;gap:8px">
        <button class="${d.enabled ? "danger" : "primary"}" id="ew-toggle">${d.enabled ? "停用" : "启用"}</button>
        <button id="ew-add" ${d.enabled ? "" : "disabled"}>＋ 添加设备</button>
      </div>
    </div>
    ${peers.length ? `<table>
      <tr><th>设备</th><th>隧道 IP</th><th>公钥</th><th></th></tr>${rows}</table>`
      : `<div class="empty">还没有设备。${d.enabled ? "点击「添加设备」生成客户端配置。" : "先启用直连 WG。"}</div>`}
  `;
  const id = ew.id;
  $("#ew-toggle", box).onclick = () => exitwgToggleModal(id, d);
  $("#ew-add", box).onclick = () => exitwgAddDeviceModal(id, d);
  box.querySelectorAll("[data-ewdel]").forEach(el => {
    el.onclick = () => confirmModal("移除该设备?它将立即无法再连接此节点。", async () => {
      try { await api("DELETE", `/api/nodes/${id}/exitwg/peers/${el.dataset.ewdel}`); toast("已移除"); loadExitWG(id); }
      catch (e) { toast(e.message); }
    });
  });
  box.querySelectorAll("[data-ewconf]").forEach(el => {
    el.onclick = () => {
      const conf = clientConf(d, el.dataset.ewconf, null);
      const mask = showModal(`
        <h2>客户端配置</h2>
        <p class="hint" style="margin-bottom:8px">私钥只在添加设备时展示一次,这里以占位符代替 —— 其余字段与当时一致。</p>
        <div class="cmdbox" id="ew-conf" style="white-space:pre">${esc(conf)}</div>
        <div class="hint">点击可复制。</div>
        <div class="actions"><button class="primary" id="close">关闭</button></div>`);
      $("#ew-conf", mask).onclick = () => navigator.clipboard.writeText(conf).then(() => toast("已复制"));
      $("#close", mask).onclick = () => mask.remove();
    };
  });
}

function exitwgToggleModal(id, d) {
  if (d.enabled) {
    confirmModal("停用直连 WG?接口将被移除,所有已配置设备立即断开(设备列表保留,重新启用即恢复)。", async () => {
      try { await api("PUT", `/api/nodes/${id}/exitwg`, { enabled: false, port: d.port }); toast("已下发停用"); setTimeout(() => loadExitWG(id), 500); }
      catch (e) { toast(e.message); }
    });
    return;
  }
  const mask = showModal(`
    <h2>启用直连 WG</h2>
    <div class="row"><label class="hint">监听端口(UDP,需在节点防火墙放行;勿与组网 WG 端口相同)</label>
      <input id="ew-port" type="number" min="1" max="65535" value="${d.port}"></div>
    <p class="hint">启用后 agent 将创建 lightpn1 接口,并自动配置 IP 转发与 NAT(卸载/停用时清理)。</p>
    <div class="actions"><button id="cancel">取消</button><button class="primary" id="ok">启用</button></div>`);
  $("#cancel", mask).onclick = () => mask.remove();
  $("#ok", mask).onclick = async () => {
    const port = parseInt($("#ew-port", mask).value, 10);
    if (!port || port < 1 || port > 65535) { toast("端口无效"); return; }
    try {
      await api("PUT", `/api/nodes/${id}/exitwg`, { enabled: true, port });
      mask.remove(); toast("已下发启用");
      setTimeout(() => loadExitWG(id), 500); // give the agent a beat to report its pubkey
    } catch (e) { toast(e.message); }
  };
}

async function exitwgAddDeviceModal(id, d) {
  const kp = await wgKeypair();
  const mask = showModal(`
    <h2>添加设备</h2>
    <div class="row"><input id="ew-name" placeholder="设备名(如 iphone)"></div>
    ${kp ? `<p class="hint">已在浏览器本地生成密钥对;私钥只出现在下面的配置里,面板不保存。</p>`
         : `<div class="row"><input id="ew-pub" placeholder="设备公钥(在设备上 wg genkey | wg pubkey 生成)"></div>
            <p class="hint">当前浏览器不支持本地生成 X25519 密钥,请粘贴设备公钥。</p>`}
    <div class="actions"><button id="cancel">取消</button><button class="primary" id="ok">添加</button></div>`);
  $("#cancel", mask).onclick = () => mask.remove();
  $("#ok", mask).onclick = async () => {
    const name = $("#ew-name", mask).value.trim();
    if (!name) { toast("请填设备名"); return; }
    const pubkey = kp ? kp.pub : ($("#ew-pub", mask) ? $("#ew-pub", mask).value.trim() : "");
    if (!pubkey) { toast("请填设备公钥"); return; }
    let p;
    try { p = await api("POST", `/api/nodes/${id}/exitwg/peers`, { name, pubkey }); }
    catch (e) { toast(e.message); return; }
    mask.remove();
    loadExitWG(id);
    const conf = clientConf(d, p.ip, kp ? kp.priv : null);
    const m2 = showModal(`
      <h2>${esc(name)} 的客户端配置</h2>
      <p class="hint" style="margin-bottom:8px">${kp ? "含私钥,仅此一次展示 —— 现在就导入设备(WireGuard 客户端「从文件/剪贴板导入」)。" : "把 <你的设备私钥> 换成设备上生成的私钥。"}
      ${d.pubkey ? "" : "⚠ 服务端公钥尚未生成(节点还没应答),稍后在设备列表「配置」里查看完整版。"}</p>
      <div class="cmdbox" id="ew-conf" style="white-space:pre">${esc(conf)}</div>
      <div class="hint">点击可复制。</div>
      <div class="actions"><button class="primary" id="close">完成</button></div>`);
    $("#ew-conf", m2).onclick = () => navigator.clipboard.writeText(conf).then(() => toast("已复制"));
    $("#close", m2).onclick = () => m2.remove();
  };
}

// ---- tool config (conf_get) ----

// Sensitive keys in proxy configs, JSON ("key": "value") and YAML
// (key: value) forms. Matched values are masked; click to reveal.
const MASK_RE = /("(?:privatekey|private_key|password|passwd|secret|secret_key|uuid|psk|token|auth|pass|id)"\s*:\s*")([^"]*)(")|^([ \t-]*(?:private[_-]?key|password|passwd|secret(?:[_-]key)?|uuid|psk|token|auth(?:[_-]str)?|pass)\s*:[ \t]*)([^#\r\n]+)$/gim;

function maskRender(text) {
  MASK_RE.lastIndex = 0;
  let html = "", last = 0, i = 0, m;
  while ((m = MASK_RE.exec(text))) {
    html += esc(text.slice(last, m.index));
    if (m[1] !== undefined) {   // JSON: prefix, value, closing quote
      html += esc(m[1]) + maskSpan(m[2], i++) + esc(m[3]);
    } else {                    // YAML: prefix, value
      html += esc(m[4]) + maskSpan(m[5], i++);
    }
    last = m.index + m[0].length;
  }
  return html + esc(text.slice(last));
}

function maskSpan(v, i) {
  if (!v) return "";
  const shown = state.confShown.has(i);
  return `<span class="mask${shown ? " shown" : ""}" data-v="${esc(v)}" data-i="${i}" title="点击显示/隐藏">${shown ? esc(v) : "••••••••"}</span>`;
}

async function loadToolConf(id) {
  state.toolconf = { id, loading: true };
  state.confShown.clear();
  renderToolConf();
  try {
    const data = await api("GET", `/api/nodes/${id}/toolconf`);
    state.toolconf = { id, data };
  } catch (e) {
    state.toolconf = { id, err: e.message };
  }
  renderToolConf();
}

function renderToolConf() {
  const out = $("#toolconf-out");
  const tc = state.toolconf;
  if (!out || !tc) return;
  if (tc.loading) { out.innerHTML = `<div class="empty">正在从节点拉取…</div>`; return; }
  if (tc.err) { out.innerHTML = `<div class="empty">拉取失败:${esc(tc.err)}</div>`; return; }
  const d = tc.data, wg = d.wg || {};
  let html = `<div class="card" style="margin-bottom:14px">
    <div class="kv"><span class="k">WG 接口</span><span class="v">${esc(wg.iface || "–")}</span></div>
    <div class="kv"><span class="k">监听端口</span><span class="v">${wg.listen_port ?? "–"}</span></div>
    <div class="kv"><span class="k">本机公钥</span><span class="v">${esc(wg.pubkey || "–")}</span></div>
    <div class="kv"><span class="k">内核 Peer 数</span><span class="v">${(wg.peers || []).length}</span></div>
  </div>`;
  const files = d.files || [];
  if (!files.length) {
    html += `<div class="empty">未在常见路径检测到翻墙软件配置(xray / sing-box / v2ray / hysteria / trojan-go / mihomo / clash)。</div>`;
  }
  for (const f of files) {
    html += `<div class="confhead"><span class="pill online">${esc(f.tool)}</span>
      <span class="mono">${esc(f.path)}</span>
      <span class="hint">${fmtBytes(f.size)} · 修改于 ${fmtAgo(f.mtime)}${f.truncated ? " · 已截断" : ""}</span></div>`;
    html += f.err
      ? `<div class="empty">读取失败:${esc(f.err)}</div>`
      : `<pre class="confbox">${maskRender(f.content || "")}</pre>`;
  }
  out.innerHTML = html;
  out.querySelectorAll(".mask").forEach(el => {
    el.onclick = () => {
      const i = Number(el.dataset.i);
      if (state.confShown.has(i)) { state.confShown.delete(i); el.classList.remove("shown"); el.textContent = "••••••••"; }
      else { state.confShown.add(i); el.classList.add("shown"); el.textContent = el.dataset.v; }
    };
  });
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
