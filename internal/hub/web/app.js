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
  confShown: new Set(), // indices of currently revealed masked values
  confKeys: new Map(),  // nodeId -> CryptoKey,查看密码派生密钥的会话内缓存
  svcNames: {},         // alias -> 显示名(hub 侧覆盖,纯装饰)
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
      const cameOnline = n && n.status !== "online"; // 上线属结构性变化(按钮态等)
      if (n) {
        n.status = "online";
        n.last_seen = Math.floor(Date.now() / 1000);
        n.sys_summary = summarize(d.sys);
      }
      const sp = state.spark[d.node_id] = state.spark[d.node_id] || [];
      sp.push(summarize(d.sys));
      if (sp.length > 40) sp.shift();
      // 心跳高频,只做局部 DOM 更新;整页重建会造成周期性闪跳。
      if (state.route === "#/nodes") {
        cameOnline ? render() : patchNodeCard(d.node_id);
      } else if (state.route.startsWith("#/node/") && state.route.slice(7) === d.node_id) {
        cameOnline ? render() : patchNodeDetail(d.node_id);
      }
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
    return `
    <div class="card" data-node-card="${n.id}">
      <div class="head">
        <div class="dot ${n.status}" data-f="dot"></div>
        <a class="name" href="#/node/${n.id}">${esc(n.name)}</a>
        <span class="pill ${n.status}" data-f="pill" style="margin-left:auto">${n.status}</span>
      </div>
      <div class="kv"><span class="k">Overlay IP</span><span class="v">${esc(n.overlay_ip)}</span></div>
      <div class="kv"><span class="k">Endpoint</span><span class="v">${esc(n.endpoint || "–")}</span></div>
      <div class="kv"><span class="k">最近心跳</span><span class="v" data-f="last-seen" ${n.last_seen ? `data-ago="${n.last_seen}"` : ""}>${fmtAgo(n.last_seen)}</span></div>
      <div class="kv"><span class="k">CPU / 内存</span><span class="v" data-f="cpumem">${s ? s.cpu.toFixed(1) + "% / " + s.mem.toFixed(0) + "%" : "–"}</span></div>
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
      <h1><span class="dot ${n.status}" data-f="detail-dot" style="display:inline-block;margin-right:8px"></span>${esc(n.name)}
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
      <td class="mono" ${l.last_handshake ? `data-ago="${l.last_handshake}"` : ""}>${l.last_handshake ? fmtAgo(l.last_handshake) : "–"}</td>
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

function drawSparks(root) {
  const css = getComputedStyle(document.documentElement);
  root.querySelectorAll("[data-spark]").forEach(c => {
    const [id, kind] = c.dataset.spark.split(":");
    const sp = (state.spark[id] || []).filter(Boolean);
    if (kind === "cpu") drawSpark(c, sp.map(s => s.cpu), css.getPropertyValue("--accent").trim(), 100);
    else drawSpark(c, sp.map(s => s.mem), css.getPropertyValue("--ok").trim(), 100);
  });
}

function bindNodes() {
  $("#btn-add-node").onclick = addNodeModal;
  drawSparks(document);
}

// ---- heartbeat patching ----
// 心跳只做局部更新,不整页重建 innerHTML —— 整页重建会让滚动位置、图表
// 画布和 peer 表在每个心跳窗口闪跳一次(此前的问题)。结构性变化(新
// 节点出现、上下线切换)仍走整页 render。

// 列表页:原位刷新一张节点卡片的状态与两条 sparkline。
function patchNodeCard(id) {
  const n = state.nodes.find(n => n.id === id);
  const card = document.querySelector(`[data-node-card="${CSS.escape(id)}"]`);
  if (!n || !card) { render(); return; } // 新节点还没有卡片 → 整页重建
  const f = sel => card.querySelector(`[data-f="${sel}"]`);
  const dot = f("dot"), pill = f("pill"), ls = f("last-seen"), cm = f("cpumem");
  if (dot) dot.className = "dot " + n.status;
  if (pill) { pill.className = "pill " + n.status; pill.textContent = n.status; }
  if (ls) { ls.dataset.ago = n.last_seen; ls.textContent = fmtAgo(n.last_seen); }
  const s = n.sys_summary;
  if (cm) cm.textContent = s ? s.cpu.toFixed(1) + "% / " + s.mem.toFixed(0) + "%" : "–";
  drawSparks(card);
}

// 详情页:心跳只更新标题状态点;图表与 peer 表节流原位刷新(drawChart
// 在既有画布上重画,peer 表拿到数据后才替换内容,不出现「加载中」闪烁)。
function patchNodeDetail(id) {
  const n = state.nodes.find(n => n.id === id);
  const dot = document.querySelector('[data-f="detail-dot"]');
  if (!n || !dot) { render(); return; }
  dot.className = "dot " + n.status;
  const now = Date.now();
  if (now - (state.detailRefreshedAt || 0) >= 12000) {
    state.detailRefreshedAt = now;
    loadNodeDetail(id);
  }
}

// 「x 分钟前」文本刷新:只改带 data-ago 的元素,不动其余 DOM。
function patchAgoTexts() {
  document.querySelectorAll("[data-ago]").forEach(el => {
    el.textContent = fmtAgo(+el.dataset.ago);
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

  state.detailRefreshedAt = Date.now(); // 心跳侧的节流刷新以此为基准
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
        <td class="mono" ${p.last_handshake_ts ? `data-ago="${p.last_handshake_ts}"` : ""}>${p.last_handshake_ts ? fmtAgo(p.last_handshake_ts) : "无"}</td>
        <td class="mono">↓${fmtBytes(p.rx_bytes)} ↑${fmtBytes(p.tx_bytes)}</td>
        <td class="mono">${esc(p.endpoint || "–")}</td>
      </tr>`).join("")}</table>` : `<div class="empty">该节点当前没有 peer。</div>`;
  } catch (e) { /* node offline / no data */ }
}

// ---- tool config (conf_get) ----

// Sensitive values in proxy configs, four forms: JSON ("key": "value"),
// YAML (key: value), Caddyfile forward_proxy (basic_auth user pass) and
// URL userinfo (scheme://user:pass@host)。Matched values are masked; click
// to reveal. 与 internal/agent/viewkey.go 的 maskRE 保持同步 —— 分支相同、
// 顺序相同(agent 端用它生成加密节点的打码预览,两侧匹配行为一致才能保证
// 打码位索引对齐)。
const MASK_RE = new RegExp(
  '("(?:privatekey|private_key|password|passwd|secret|secret_key|uuid|psk|token|auth|pass|id)"\\s*:\\s*")([^"]*)(")'
  + '|^([ \\t-]*(?:private[_-]?key|password|passwd|secret(?:[_-]key)?|uuid|psk|token|auth(?:[_-]str)?|pass)\\s*:[ \\t]*)([^#\\r\\n]+)$'
  + '|^([ \\t]*basic_?auth[ \\t]+\\S+[ \\t]+)(\\S+)'
  + '|(:\\/\\/[^:@\\/\\s"\']+:)([^@\\/\\s"\']+)(@)', "gim");

function maskRender(text) {
  MASK_RE.lastIndex = 0;
  let html = "", last = 0, i = 0, m;
  while ((m = MASK_RE.exec(text))) {
    html += esc(text.slice(last, m.index));
    if (m[1] !== undefined) {          // JSON: prefix, value, closing quote
      html += esc(m[1]) + maskSpan(m[2], i++) + esc(m[3]);
    } else if (m[4] !== undefined) {   // YAML: prefix, value
      html += esc(m[4]) + maskSpan(m[5], i++);
    } else if (m[6] !== undefined) {   // Caddyfile basic_auth: prefix, password
      html += esc(m[6]) + maskSpan(m[7], i++);
    } else {                           // URL userinfo: "://user:", password, "@"
      html += esc(m[8]) + maskSpan(m[9], i++) + esc(m[10]);
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

// ---- end-to-end encrypted conf (agent view password) ----
// data.enc = { kdf, m_kib, t, p, salt, nonce, ct }:agent 用查看密码的
// Argon2id 派生密钥做 AES-256-GCM(密文内层是 gzip(JSON))。hub 只转发
// 密文;这里在浏览器本地重新派生并解密,密码不发往任何服务器。

const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function deriveConfKey(password, enc) {
  const raw = await hashwasm.argon2id({
    password, salt: b64(enc.salt),
    iterations: enc.t, memorySize: enc.m_kib, parallelism: enc.p,
    hashLength: 32, outputType: "binary",
  });
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
}

async function decryptConf(key, enc) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(enc.nonce) }, key, b64(enc.ct));
  const unzipped = await new Response(
    new Blob([pt]).stream().pipeThrough(new DecompressionStream("gzip"))
  ).arrayBuffer();
  return JSON.parse(new TextDecoder().decode(unzipped));
}

// 密码弹框;resolve 为输入串,取消时 resolve null。
function passwordModal(hint) {
  return new Promise(resolve => {
    const mask = showModal(`
      <h2>配置查看密码</h2>
      <p class="hint">该节点的配置已端到端加密(hub 无法解密)。请输入部署时设置的查看密码,解密仅在本浏览器进行。</p>
      ${hint ? `<p class="hint" style="color:#c60">${esc(hint)}</p>` : ""}
      <input type="password" id="vp" placeholder="查看密码" autocomplete="off" style="width:100%">
      <div class="actions">
        <button id="cancel">取消</button>
        <button class="primary" id="ok">解密</button>
      </div>`);
    const input = $("#vp", mask);
    input.focus();
    const done = v => { mask.remove(); resolve(v); };
    $("#cancel", mask).onclick = () => done(null);
    $("#ok", mask).onclick = () => done(input.value);
    input.onkeydown = e => { if (e.key === "Enter") done(input.value); };
    mask.addEventListener("click", e => { if (e.target === mask) resolve(null); });
  });
}

// 解密循环:先试会话内缓存的密钥,失败(或无缓存)则提示输入,密码错误
// (GCM 校验失败)时带提示重试。成功后缓存密钥,本会话内不再询问。
async function unsealConf(id, enc) {
  if (typeof hashwasm === "undefined") throw new Error("argon2 模块未加载,请刷新页面");
  const cached = state.confKeys.get(id);
  if (cached) {
    try { return await decryptConf(cached, enc); }
    catch { state.confKeys.delete(id); } // 密码已在 agent 侧改过
  }
  let hint = "";
  for (;;) {
    const pw = await passwordModal(hint);
    if (pw === null) throw new Error("已取消解密");
    if (!pw) { hint = "密码不能为空。"; continue; }
    const key = await deriveConfKey(pw, enc);
    try {
      const plain = await decryptConf(key, enc);
      state.confKeys.set(id, key);
      return plain;
    } catch { hint = "密码错误(解密校验失败),请重试。"; }
  }
}

// ---- service control (svc_action) ----
// data.services = [{alias, active, enabled}](仅设了查看密码的节点才有)。
// 指令由浏览器用查看密码派生的 key 加密后交 hub 转发,hub 全程只见密文。
// svcNames 是 hub 侧的显示名覆盖(纯装饰),按 alias 索引。

function svcStatePill(active) {
  const on = active === "active";
  const cls = on ? "online" : (active === "failed" ? "offline" : "");
  return `<span class="pill ${cls}">${esc(active || "unknown")}</span>`;
}

function renderSvcCard(d) {
  const svcs = d.services;
  if (!svcs || !svcs.length) return "";
  const names = state.svcNames || {};
  // 孤儿显示名:hub 上还留着、但 agent 当前别名集合里已没有的。agent 端
  // 删别名后 hub 不会被通知,这些残留只能显式清理。
  const live = new Set(svcs.map(s => s.alias));
  const orphans = Object.keys(names).filter(a => !live.has(a));
  let html = `<div class="confhead" style="margin-top:16px"><span class="pill online">远程开关</span>
    <span class="hint">指令在浏览器用查看密码加密,hub 只转发密文</span></div>`;
  if (orphans.length) {
    html += `<div class="hint" style="color:#c60;margin-bottom:8px">
      检测到 ${orphans.length} 个失效显示名(对应别名已在节点上删除):${esc(orphans.join("、"))}
      <a href="#" id="svc-prune"> 清理</a></div>`;
  }
  for (const s of svcs) {
    const label = names[s.alias] || s.alias;
    html += `<div class="card" style="margin-bottom:8px">
      <div class="kv">
        <span class="k">${esc(label)} ${svcStatePill(s.active)}
          <a href="#" class="hint svc-rename" data-alias="${esc(s.alias)}">重命名</a></span>
        <span class="v">
          <button class="svc-act" data-alias="${esc(s.alias)}" data-action="start">启动</button>
          <button class="svc-act" data-alias="${esc(s.alias)}" data-action="restart">重启</button>
          <button class="svc-act danger" data-alias="${esc(s.alias)}" data-action="stop">停止</button>
        </span>
      </div>
    </div>`;
  }
  return html;
}

// 用会话内缓存的 view key 加密 {action, alias, ts};无缓存则弹密码框
// 派生(和解锁配置同一把 key,派生后缓存)。需要 data.enc 提供 KDF 参数。
async function sealSvcCmd(id, enc, action, alias) {
  let key = state.confKeys.get(id);
  if (!key) {
    if (typeof hashwasm === "undefined") throw new Error("argon2 模块未加载,请刷新页面");
    let hint = "";
    for (;;) {
      const pw = await passwordModal(hint);
      if (pw === null) throw new Error("已取消");
      if (!pw) { hint = "密码不能为空。"; continue; }
      key = await deriveConfKey(pw, enc);
      // 用预览里的密文验证密码对不对,避免拿错密码发出去。
      try { await decryptConf(key, enc); state.confKeys.set(id, key); break; }
      catch { hint = "密码错误(校验失败),请重试。"; }
    }
  }
  const plain = new TextEncoder().encode(JSON.stringify({
    action, alias, ts: Math.floor(Date.now() / 1000),
  }));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
  const b64e = u => btoa(String.fromCharCode(...u));
  return { n: b64e(nonce), ct: b64e(ct) };
}

async function doSvcAction(id, action, alias) {
  const tc = state.toolconf;
  if (!tc || !tc.data || !tc.data.enc) { toast("该节点未启用查看密码,无法远程开关"); return; }
  try {
    const sealed = await sealSvcCmd(id, tc.data.enc, action, alias);
    const res = await api("POST", `/api/nodes/${id}/svc`, sealed);
    if (res.ok) toast(`${action} 已执行`);
    else toast("执行失败:" + (res.err || "未知"));
    // 用回执里的最新状态刷新卡片(services 明文,无敏感值)。
    if (res.services) { tc.data.services = res.services; renderToolConf(); }
  } catch (e) { toast(e.message); }
}

function bindSvcCard(id) {
  const prune = $("#svc-prune");
  if (prune) prune.onclick = async e => {
    e.preventDefault();
    const svcs = (state.toolconf && state.toolconf.data.services) || [];
    const aliases = svcs.map(s => s.alias);
    try {
      const res = await api("POST", `/api/nodes/${id}/svcnames/prune`, { aliases });
      toast(`已清理 ${res.removed} 个失效显示名`);
      state.svcNames = await api("GET", `/api/nodes/${id}/svcnames`);
      renderToolConf();
    } catch (err) { toast(err.message); }
  };
  document.querySelectorAll(".svc-act").forEach(btn => {
    btn.onclick = () => {
      const { alias, action } = btn.dataset;
      if (action === "stop") {
        confirmModal("停止该服务?如果你当前的面板流量正经此节点出网,停止后会立即断开。", () => doSvcAction(id, "stop", alias));
      } else {
        doSvcAction(id, action, alias);
      }
    };
  });
  document.querySelectorAll(".svc-rename").forEach(el => {
    el.onclick = async e => {
      e.preventDefault();
      const alias = el.dataset.alias;
      const cur = (state.svcNames || {})[alias] || "";
      const name = prompt(`为「${alias}」设置面板显示名(留空恢复别名):`, cur);
      if (name === null) return;
      try {
        await api("PATCH", `/api/nodes/${id}/svcnames`, { alias, display: name.trim() });
        state.svcNames = await api("GET", `/api/nodes/${id}/svcnames`);
        renderToolConf();
      } catch (err) { toast(err.message); }
    };
  });
}

async function loadToolConf(id) {
  try { state.svcNames = await api("GET", `/api/nodes/${id}/svcnames`); }
  catch { state.svcNames = {}; }
  state.toolconf = { id, loading: true };
  state.confShown.clear();
  renderToolConf();
  try {
    // data.enc 存在时不在此处解密:agent 同时发来了打码预览(files 里
    // 敏感值已替换为 ••),直接展示;点击打码处才走 unsealConf 解锁。
    const data = await api("GET", `/api/nodes/${id}/toolconf`);
    state.toolconf = { id, data };
  } catch (e) {
    state.toolconf = { id, err: e.message };
  }
  renderToolConf();
}

// 解锁加密节点的完整配置:解密成功后用明文替换预览并重新渲染,
// revealIdx(可选)为触发解锁的那个打码位,解锁后直接显示它。
async function unlockToolConf(revealIdx) {
  const tc = state.toolconf;
  if (!tc || !tc.data || !tc.data.enc) return;
  try {
    const plain = await unsealConf(tc.id, tc.data.enc);
    // 保留 enc(供服务命令继续加密下发)并标记已解锁(不再显示打码提示)。
    plain.enc = tc.data.enc;
    plain.unlocked = true;
    state.toolconf = { id: tc.id, data: plain };
    state.confShown.clear();
    if (revealIdx !== undefined) state.confShown.add(revealIdx);
    renderToolConf();
  } catch (e) { toast(e.message); }
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
  const encrypted = d.enc && !d.unlocked; // 仍处于打码预览态
  if (encrypted && files.length) {
    html += `<div class="hint" style="margin-bottom:10px">🔒 该节点已启用配置查看密码:下方为打码预览,敏感值端到端加密 —— 点击任一 •••••••• 输入密码解密。</div>`;
  }
  if (!files.length) {
    // 注意:密文里装的和预览是同一份数据,files 为空时输密码解开也是空 ——
    // 所以这里不提供“解锁”入口,直接说明原因与出路。
    html += `<div class="empty">节点上未检测到配置文件:内置常见路径(xray / sing-box / v2ray / hysteria / trojan-go / shadowsocks / mihomo / clash / caddy / naiveproxy)均未命中。
      配置在其他位置时,可在节点上运行部署脚本菜单「远程开关服务」(或 <span class="mono">lightpn-agent svc-add</span>)登记 unit + 配置文件路径,登记后重新拉取即可显示。</div>`;
  }
  for (const f of files) {
    html += `<div class="confhead"><span class="pill online">${esc(f.tool)}</span>
      <span class="mono">${esc(f.path)}</span>
      <span class="hint">${fmtBytes(f.size)} · 修改于 ${fmtAgo(f.mtime)}${f.truncated ? " · 已截断" : ""}</span></div>`;
    html += f.err
      ? `<div class="empty">读取失败:${esc(f.err)}</div>`
      : `<pre class="confbox">${maskRender(f.content || "")}</pre>`;
  }
  html += renderSvcCard(d);
  out.innerHTML = html;
  bindSvcCard(tc.id);
  out.querySelectorAll(".mask").forEach(el => {
    el.onclick = () => {
      const i = Number(el.dataset.i);
      // 仍处于加密预览:点击打码位即触发密码解锁,而非本地显示。
      if (tc.data && tc.data.enc && !tc.data.unlocked) { unlockToolConf(i); return; }
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
  // 周期性刷新「x 分钟前」文本:只改带 data-ago 的元素,不整页重建
  // (此前这里每 30s render() 一次,同样会造成页面闪跳)。
  setInterval(() => { if (state.authed) patchAgoTexts(); }, 30000);
})();
