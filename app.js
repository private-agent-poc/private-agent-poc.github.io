import * as V from "./verify.js";

const PCCS_URL = "https://pccs.phala.network";
const APPROVED = [
  { app_id: "c3fd4ff7f667603320296795348aa605e214d51b",
    compose_hash: "21b6273ff49f92f6e9be3c9b0ff623ccc87209ff7a51d1cbfb3c65dc0da2dd47",
    note: "pa-attest-mvp · 带 hermes · 2026-11-04" },
];
const COLLATERAL_NOTE = "CVM 转交 · Intel 签名 · 浏览器本地验签";
const GATEWAY_URL = "https://inference.phala.com";

const RELEASES = {
  "dstack-0.6.1": "https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.1",
  "dstack-0.5.12": "https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.12",
  "dstack-0.5.9": "https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.9",
};
const MODEL_PAGES = {
  "z-ai/glm-5.3-flash": "https://huggingface.co/zai-org/GLM-5.3-Flash",
  "Qwen/Qwen3.8-27B-TEE": "https://huggingface.co/Qwen/Qwen3.8-27B",
  "Qwen/Qwen3.8-27B": "https://huggingface.co/Qwen/Qwen3.8-27B",
};
const PROVIDERS = {
  phala: { name: "Phala", relay: ["推理网关", "INTEL TDX"], model: ["上游模型", "TEE · 网关声明"] },
  chutes: { name: "Chutes", relay: ["Chutes 中转", "只见密文"], model: ["模型机", "TDX + GPU"] },
  near: { name: "NEAR", relay: ["NEAR 网关", "见元数据"], model: ["模型机", "TDX + GPU · 运行时部署"] },
};
const ORDER = ["phala", "chutes", "near"];
const LOCAL = /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/;
const REFERENCES = [
  ["ACI 规范", "https://github.com/Dstack-TEE/private-ai-gateway/tree/main/spec"],
  ["dcap-qvl", "https://github.com/Phala-Network/dcap-qvl"],
];

const LABELS = {
  "本次随机 nonce（防重放）": "Nonce",
  "读取 quote": "解析 Quote",
  "硬件证明：Intel TDX quote 签名链": "TDX Quote 签名链",
  "非调试模式（TD_ATTRIBUTES.DEBUG = 0）": "非调试模式",
  "绑定公钥与 nonce（report_data）": "report_data 绑定",
  "绑定公钥与 nonce": "report_data 绑定",
  "公钥集有效期": "公钥集有效期",
  "事件日志重放 = quote 中的 RTMR3": "RTMR3 事件日志重放",
  "系统镜像是官方正式版（固件、内核、rootfs 的度量）": "系统镜像 MRTD · RTMR1 · RTMR2",
  "虚拟硬件配置（RTMR0）与参考值一致": "虚拟硬件 RTMR0",
  "部署配置哈希：sha256(app_compose) = 度量值": "compose-hash",
  "部署配置哈希（compose-hash）": "compose-hash",
  "镜像按 digest 固定": "镜像 digest 固定",
  "无法用 SSH 公钥 / root 密码登录": "无 SSH / root 登录",
  "内嵌源码与本地文件一致": "源码 app.py",
  "镜像 digest 与我们发布的一致": "镜像 digest",
  "compose-hash 与发布记录一致": "compose-hash 记录",
  "app_id": "app_id",
  "compose_hash（和发布记录比对）": "compose_hash",
  "系统镜像 os_image_hash（官方发布包）": "os_image_hash",
  "密钥来源（key-provider）": "key_provider",
  "app-compose 设置": "app-compose",
  "MRTD / RTMR0-2（固件、虚拟硬件、内核、rootfs，已和参考值比对）": "MRTD · RTMR0-2",
  "加密通道：消息用证明里的公钥加密，CVM 解密并加密回复": "端到端加密",
  "加密通道：只有被证明的 CVM 能解开": "端到端加密",
  "加密通道": "端到端加密",
  "回执签名（公钥来自已验证的证明）": "回执签名",
  "CVM 回执：公钥集摘要一致": "回执 · 公钥集摘要",
  "CVM 回执：请求哈希 = 我发出的内容": "回执 · 请求哈希",
  "CVM 回执：回复哈希 = 我收到的内容": "回执 · 响应哈希",
  "源码出处（与度量配置中的 REPO_COMMIT 比对）": "源码出处",
  "推理调用": "推理调用",
  "网关证明": "网关证明",
  "推理请求经网关返回": "推理请求",
  "CVM 发给网关的就是我的消息（未被改写）": "转发内容一致",
  "网关回执": "网关回执",
  "网关回执：公钥集摘要 = 刚验证过的网关": "网关回执 · 公钥集摘要",
  "网关回执：workload_id 一致": "网关回执 · workload_id",
  "网关回执：请求哈希 = CVM 实际发出的字节": "网关回执 · 请求哈希",
  "网关回执：回复哈希 = CVM 实际收到的字节": "网关回执 · 响应哈希",
  "网关回执：上游 TEE 已验证（网关声明，upstream.verified）": "上游 TEE（网关声明）",
  "CVM→网关 TLS 公钥在证明里": "TLS 公钥绑定",
  "沿用本会话的 CVM 验证": "沿用会话验证",
  "加密流：每帧单独加密，序号连续": "加密流",
  "CVM 回执：流式回复哈希 = 我收到的全部帧": "回执 · 流式回复哈希",
  "agent 发给模型的请求": "agent 请求",
  "agent 发给网关的请求里有我这条消息": "agent 请求",
  "沿用本会话的上游验证": "沿用上游验证",
  "本次随机数": "Nonce",
  "模型机验证": "模型机验证",
  "跳过未通过验证的实例": "跳过的实例",
  "证据签名（实例证书）": "证据签名",
  "证据里的随机数是本次的": "证据 Nonce",
  "Intel TDX quote 签名链": "TDX Quote 签名链",
  "非调试模式": "非调试模式",
  "quote 绑定实例证书（report_data[32:64]）": "report_data · 证书",
  "quote 绑定本次随机数和加密公钥（report_data[0:32]）": "report_data · 公钥 + Nonce",
  "度量值命中参考值快照（MRTD、RTMR0-3）": "MRTD · RTMR0-3 参考值",
  "GPU 数量": "GPU 数量",
  "NVIDIA GPU 证明（NRAS）": "NVIDIA GPU 证明",
  "GPU 状态与型号": "GPU 状态 · 型号",
  "CVM 发出的就是我的消息": "转发内容一致",
  "加密发送，只有这台实例能解开": "端到端加密 · 实例",
  "quote 绑定模型公钥（report_data[0:32]）": "report_data · 模型公钥",
  "quote 绑定本次随机数（report_data[32:64]）": "report_data · Nonce",
  "部署日志（compose-manager）": "部署日志",
  "系统镜像与虚拟硬件（MRTD、RTMR0-2）": "系统镜像 · 虚拟硬件",
  "os-image-hash 与参考值一致": "os-image-hash",
  "密钥来自固定的 NEAR KMS（key-provider）": "KMS 身份",
  "app-id 和部署配置是固定的那一份": "app-id · compose 固定",
  "模型公钥由同一应用的多台机器共用": "公钥多机共用",
  "部署日志 · Intel TDX quote 签名链": "部署日志 · TDX Quote",
  "部署日志 · 非调试模式": "部署日志 · 非调试",
  "部署日志和模型在同一台机器（MRTD、RTMR0-3）": "部署日志 · 同一台机器",
  "部署日志哈希绑定在 quote 里": "部署日志哈希",
  "模型代码由 compose-manager 运行时部署，不在硬件度量里": "运行时部署",
  "GPU 证据用的是本次随机数": "GPU Nonce",
  "加密发送": "加密发送",
  "加密发送，只有这台模型机能解开": "端到端加密 · 模型机",
  "回复签名（模型机密钥）": "回复签名",
  "签名覆盖的请求 = CVM 发出的字节": "签名 · 请求哈希",
  "签名覆盖的回复 = CVM 收到的字节": "签名 · 回复哈希",
  "把部署配置改一个字（换镜像）": "篡改 compose",
  "拿旧证明冒充（换一个 nonce 验证）": "重放旧证明",
  "中间人换掉加密公钥": "替换加密公钥",
  "改 quote 里一个比特（伪造硬件证明）": "篡改 Quote",
  "联网开关：已关闭，CVM 出口拒绝外网连接": "联网 · 已关闭",
  "联网开关：已开启": "联网 · 已开启",
  "agent 联网：这些请求离开了 TEE": "联网 · 离开 TEE",
  "联网开关": "联网开关",
  "部署是已批准的那一份（app_id、compose-hash）": "已批准的部署",
  "容器日志不公开（public_logs = false）": "日志不公开",
  "出口隔离": "出口隔离",
};

const label = (name) => {
  const base = name.replace(/^(网关|Chutes|NEAR) · /, "");
  return LABELS[base] || base;
};

const $ = (sel, el = document) => el.querySelector(sel);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

const state = { base: null, token: null, source: null, quoteVerifier: null, cvmVerifier: null, local: false,
                provider: "phala", providers: {}, conversation: [], records: [], selected: null, busy: false, seq: 0,
                session: null, sessionId: null, nonces: new Set(), reverifyNext: false,
                agent: false, models: {}, modelSel: {}, atts: [], chats: {}, chatOrder: [], chat: "default" };

const STATE_LABEL = { idle: "WAIT", running: "RUNNING", pass: "PASS", warn: "WARN", fail: "FAIL", skipped: "SKIP" };
const VERDICT = { running: "验证中", pass: "已验证", warn: "已验证 · 有警告", fail: "未通过", blocked: "未发送", error: "错误" };
const BADGE = { running: "验证中", pass: "已验证", warn: "警告", fail: "未通过", blocked: "未发送", error: "错误" };
const SECTION_TITLE = { cvm: "① 机器与代码", channel: "② 加密通道", gateway: "③ 推理链路", tamper: "篡改测试" };

const worst = (checks) => {
  const s = checks.map((c) => c.status);
  return s.includes("FAIL") ? "fail" : s.includes("WARN") ? "warn" : "pass";
};
const INTERRUPTED = /^Operation interrupted\b/;
const clock = (t) => new Date(t).toLocaleTimeString("zh-CN", { hour12: false });
const errText = (e) => (e && e.message ? e.message : String(e));

async function ensureTools() {
  if (!state.quoteVerifier) state.quoteVerifier = await V.createQuoteVerifier(PCCS_URL);
  if (!state.source) {
    const r = await fetch("app.py", { cache: "no-store" });
    if (!r.ok) throw new Error(`app.py HTTP ${r.status}`);
    state.source = new Uint8Array(await r.arrayBuffer());
  }
}

function newRecord(kind, title) {
  const rec = {
    id: ++state.seq, kind, title, time: Date.now(), status: "running",
    stages: { cvm: "idle", channel: "idle", gateway: "idle", tamper: "idle" },
    sections: {}, seen: new Set(), open: new Set(), folds: new Set(), counts: null, elapsed: null, result: null, context: null,
    reply: null, auth: null, blocked: false, serviceError: null, error: null, simulated: false, provider: null, model: null,
    chat: state.chat, uid: V.randomHex(8), base: state.base,
  };
  state.records.push(rec);
  return rec;
}

const HEAD = ["kind", "title", "time", "status", "stages", "sections", "counts", "elapsed", "reply", "auth", "blocked", "serviceError",
              "error", "simulated", "provider", "model", "chat", "renewed", "agent", "internet", "stream", "attachments", "stopped"];
let dbOpen = null;

function recordDb() {
  if (!dbOpen) {
    try { indexedDB.deleteDatabase("pa-records"); } catch {}
    dbOpen = new Promise((ok, no) => {
      const r = indexedDB.open("pa-verify", 1);
      r.onupgradeneeded = () => {
        r.result.createObjectStore("heads", { keyPath: "key" }).createIndex("base", "base");
        r.result.createObjectStore("bodies", { keyPath: "key" });
      };
      r.onsuccess = () => ok(r.result);
      r.onerror = () => no(r.error);
    }).catch(() => null);
  }
  return dbOpen;
}

function idb(req) {
  return new Promise((ok, no) => { req.onsuccess = () => ok(req.result); req.onerror = () => no(req.error); });
}

async function storedHeads(base) {
  const d = await recordDb();
  if (!d) return [];
  return idb(d.transaction("heads").objectStore("heads").index("base").getAll(base));
}

async function dropRecords(keys) {
  const d = await recordDb();
  if (!d || !keys.length) return;
  const t = d.transaction(["heads", "bodies"], "readwrite");
  await Promise.all(keys.flatMap((k) => [idb(t.objectStore("heads").delete(k)), idb(t.objectStore("bodies").delete(k))]));
}

function plain(v, token, path = new WeakSet()) {
  if (typeof v === "string") return token && token.length >= 8 && v.includes(token) ? v.split(token).join("********") : v;
  if (typeof v === "function") return undefined;
  if (v === null || typeof v !== "object") return v;
  if (ArrayBuffer.isView(v) || v instanceof ArrayBuffer) return v;
  if (v instanceof Node || path.has(v)) return undefined;
  path.add(v);
  try {
    if (v instanceof Set || Array.isArray(v)) return [...v].map((x) => plain(x, token, path));
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      const y = plain(x, token, path);
      if (y !== undefined) o[k] = y;
    }
    return o;
  } finally {
    path.delete(v);
  }
}

async function saveRecord(rec) {
  if (!rec.base || rec.partial || rec.status === "running") return;
  try {
    const d = await recordDb();
    if (!d) return;
    const head = {};
    for (const k of HEAD) head[k] = rec[k];
    head.attachments = (rec.attachments || []).map(({ name, type, size, thumb, path, image }) => ({ name, type, size, thumb, path, image }));
    head.stages = { ...rec.stages, tamper: rec.stages.tamper === "running" ? "idle" : rec.stages.tamper };
    const { session = null, agent = null, ...ctx } = rec.context || {};
    head.context = { session, agent };
    const ref = session && state.records.find((r) => r.id === session.recId);
    const result = { ...(rec.result || {}) };
    if (ref) {
      delete ctx.res;
      delete ctx.report;
      delete result.raw_attestation;
    }
    const key = `${rec.base}|${rec.uid}`;
    const t = d.transaction(["heads", "bodies"], "readwrite");
    await Promise.all([
      idb(t.objectStore("heads").put({ key, base: rec.base, uid: rec.uid, time: rec.time, kind: rec.kind, chat: rec.chat,
                                       ref: ref ? ref.uid : null, rec: plain(head, state.token) })),
      idb(t.objectStore("bodies").put({ key, result: plain(result, state.token), context: plain(ctx, state.token) })),
    ]);
    await pruneRecords(rec.base);
  } catch {}
}

async function pruneRecords(base) {
  const all = (await storedHeads(base)).sort((a, b) => b.time - a.time);
  const msgs = all.filter((x) => x.kind === "message").slice(0, 150);
  const keep = new Set([...msgs.map((x) => x.key), ...all.filter((x) => x.kind !== "message").slice(0, 5).map((x) => x.key)]);
  for (const m of msgs) if (m.ref) keep.add(`${base}|${m.ref}`);
  await dropRecords(all.filter((x) => !keep.has(x.key)).map((x) => x.key));
}

async function forgetChats(base, gone) {
  try {
    await dropRecords((await storedHeads(base)).filter((x) => x.kind === "message" && gone(x.chat)).map((x) => x.key));
  } catch {}
}

async function loadRecords(base) {
  let heads = [];
  try { heads = await storedHeads(base); } catch {}
  heads.sort((a, b) => a.time - b.time);
  const byUid = new Map();
  const recs = heads.map((x) => {
    const rec = { ...x.rec, id: ++state.seq, uid: x.uid, base, restored: true, partial: true, refUid: x.ref,
                  seen: new Set(), open: new Set(), folds: new Set(), result: null };
    byUid.set(x.uid, rec);
    return rec;
  });
  for (const rec of recs) {
    const ses = rec.context && rec.context.session;
    if (ses) ses.recId = rec.refUid && byUid.has(rec.refUid) ? byUid.get(rec.refUid).id : null;
  }
  return recs;
}

function loadBody(rec) {
  if (!rec.partial) return Promise.resolve();
  if (!rec.loading) {
    rec.loading = (async () => {
      const d = await recordDb();
      const body = d && (await idb(d.transaction("bodies").objectStore("bodies").get(`${rec.base}|${rec.uid}`)));
      const ref = rec.refUid && state.records.find((r) => r.uid === rec.refUid);
      if (ref) await loadBody(ref);
      const from = ref && !ref.partial ? ref : null;
      rec.context = { ...(from ? { res: from.context.res, report: from.context.report } : {}), ...((body && body.context) || {}),
                      session: rec.context.session, agent: rec.context.agent };
      rec.result = body ? { ...body.result, ...(from && !body.result.raw_attestation ? { raw_attestation: from.result.raw_attestation } : {}) } : null;
      rec.partial = false;
    })().catch(() => { rec.loading = null; });
  }
  return rec.loading;
}

function apply(rec, kind, data) {
  if (kind === "stage") rec.stages[data] = "running";
  else if (kind === "section") {
    const [key, checks] = data;
    rec.sections[key] = checks;
    if (key !== "info") rec.stages[key] = worst(checks);
  } else if (kind === "blocked") {
    rec.blocked = true;
    rec.stages.channel = "skipped";
    rec.stages.gateway = "skipped";
  } else if (kind === "error") rec.serviceError = data;
  else if (kind === "renew") rec.renewed = data;
  else if (kind === "reply") rec.reply = data;
  else if (kind === "auth") rec.auth = data;
  else if (kind === "done") {
    Object.assign(rec, { counts: data.counts, elapsed: data.elapsed, result: data.result, context: data.context });
    if (rec.stages.gateway === "idle") rec.stages.gateway = "skipped";
    rec.status = rec.blocked ? "blocked" : data.counts.FAIL ? "fail" : data.counts.WARN ? "warn" : "pass";
  }
}

function failRecord(rec, e) {
  rec.status = "error";
  rec.error = errText(e);
  for (const k of Object.keys(rec.stages)) if (rec.stages[k] === "running") rec.stages[k] = "fail";
}

const log = {
  add(text, cls = "") {
    const li = el("li", cls, text);
    $("#login-log").appendChild(li);
    return li;
  },
  set(li, text, cls) { li.textContent = text; li.className = cls; },
  clear() { $("#login-log").textContent = ""; },
};

async function onLogin(ev) {
  ev.preventDefault();
  if (state.busy) return;
  const base = $("#cvm-url").value.trim().replace(/\/+$/, "");
  const token = $("#access-key").value;
  state.busy = true;
  $("#login-btn").disabled = true;
  log.clear();
  let rec;
  try {
    let line = log.add("verifier", "typing");
    await ensureTools();
    log.set(line, "verifier  ok", "ok");
    state.base = base;
    state.token = token;
    state.local = LOCAL.test(base);
    state.cvmVerifier = state.local ? V.localQuoteVerifier() : state.quoteVerifier;
    const restored = await loadRecords(base);
    rec = newRecord("login", "登录");
    line = log.add(state.local ? "attest  本地调试" : "attest", "typing");
    state.sessionId = V.randomHex(16);
    state.nonces = new Set();
    for await (const [kind, data] of V.run(base, { quoteVerifier: state.quoteVerifier, cvmQuoteVerifier: state.cvmVerifier, token,
                                                   approved: state.local ? null : APPROVED,
                                                   expectSource: state.source, authOnly: true, sessionId: state.sessionId,
                                                   knownNonces: state.nonces, reverify: true })) {
      apply(rec, kind, data);
      if (kind === "section" && data[0] === "cvm") {
        const checks = data[1].filter((c) => c.status !== "INFO");
        const fails = checks.filter((c) => c.status === "FAIL");
        log.set(line, fails.length ? `attest  ${fails.map((c) => label(c.name)).join(" · ")}` : `attest  ${checks.length}/${checks.length}`, fails.length ? "err" : "ok");
      } else if (kind === "stage" && data === "channel") {
        line = log.add("auth", "typing");
      } else if (kind === "auth") {
        log.set(line, data.ok ? "auth  ok" : data.error === "unauthorized" ? "auth  密钥无效" : `auth  ${data.error || "失败"}`, data.ok ? "ok" : "err");
      } else if (kind === "section" && data[0] === "channel" && worst(data[1]) === "fail") {
        log.set(line, "auth  加密通道校验失败", "err");
      }
    }
    if (rec.blocked || !rec.auth || !rec.auth.ok || rec.counts.FAIL) {
      state.token = null;
      state.records = state.records.filter((r) => r !== rec);
      if (rec.auth && rec.auth.error === "unauthorized") try { sessionStorage.removeItem("pa-login"); } catch {}
      return;
    }
    state.records.unshift(...restored);
    state.providers = rec.auth.providers || { phala: { ready: true, model: rec.auth.mode } };
    state.session = sessionFrom(rec);
    state.agent = Boolean(rec.auth.agent);
    state.models = rec.auth.models || {};
    state.history = [];
    if (state.agent) {
      $("#internet").checked = rec.auth.internet !== false;
      line = log.add("history", "typing");
      try {
        let saved = null;
        try { saved = localStorage.getItem("pa-chat"); } catch {}
        const out = (saved && (await fetchHistory(saved).catch(() => null))) || (await fetchHistory(null));
        mergeChats(out.chats || []);
        const live = new Set((out.chats || []).map((c) => c.id));
        if (live.size) {
          forgetChats(base, (id) => !live.has(id));
          state.records = state.records.filter((r) => !(r.restored && r.kind === "message" && !live.has(r.chat)));
        }
        state.retentionDays = out.retention_days;
        state.chat = out.session;
        rec.chat = out.session;
        const c = chatOf(out.session);
        state.history = out.messages || [];
        c.histSeen = state.history.length;
        c.loaded = true;
        log.set(line, `history  ${state.history.length}`, "ok");
      } catch (e) {
        log.set(line, `history  ${errText(e)}`, "err");
      }
    }
    state.provider = ORDER.find((k) => k === state.provider && providerReady(k)) || ORDER.find(providerReady) || "phala";
    enterApp(rec);
    try { sessionStorage.setItem("pa-login", JSON.stringify({ base, token })); } catch {}
    saveRecord(rec);
  } catch (e) {
    log.add(errText(e), "err");
    state.token = null;
    if (rec) state.records = state.records.filter((r) => r !== rec);
  } finally {
    state.busy = false;
    $("#login-btn").disabled = false;
  }
}

function enterApp(loginRec) {
  $("#access-key").value = "";
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#target").textContent = new URL(state.base).host;
  const m = (loginRec.result && loginRec.result.measurements) || {};
  const chip = $("#session-chip");
  chip.textContent = state.local ? "LOCAL DEV · 模拟 TDX" : `${m.image || "TDX"} · TDX`;
  chip.classList.toggle("local", state.local);
  renderProviders();
  renderModelSelect();
  $("#attach-btn").hidden = !state.agent;
  $("#net-toggle").hidden = !state.agent;
  $("#chat-tabs").hidden = !state.agent;
  showThread(state.chat);
  addHistory(state.history || [], true, state.chat);
  addTurn(loginRec);
  select(loginRec.id);
  renderTabs();
  $("#msg").focus();
}

function chatOf(id) {
  if (!state.chats[id]) state.chats[id] = { id, title: "会话", busy: false, running: false, histSeen: 0, loaded: false, selected: null };
  return state.chats[id];
}

function threadEl(id) {
  let t = [...$("#threads").children].find((x) => x.dataset.chat === id);
  if (!t) {
    t = el("ol", "thread");
    t.dataset.chat = id;
    t.hidden = id !== state.chat;
    $("#threads").append(t);
  }
  return t;
}

function showThread(id) {
  for (const t of $("#threads").children) t.hidden = t.dataset.chat !== id;
  threadEl(id);
}

function mergeChats(list) {
  if (!list.length) return;
  for (const c of list) Object.assign(chatOf(c.id), { title: c.title, running: c.running, updated: c.updated });
  state.chatOrder = list.map((c) => c.id);
  renderTabs();
}

function renderTabs() {
  const box = $("#chat-tabs");
  if (!state.agent) return;
  box.textContent = "";
  for (const id of state.chatOrder) {
    const c = chatOf(id);
    const b = el("button", "chat-tab" + (id === state.chat ? " on" : ""));
    b.type = "button";
    b.title = c.title;
    if (c.busy || c.running) b.append(el("i", "dot"));
    b.append(el("span", null, c.title));
    b.addEventListener("click", () => switchChat(id));
    if (id === state.chat && !(c.busy || c.running)) {
      const x = el("i", "close", "×");
      x.title = "删除会话";
      x.addEventListener("click", (e) => { e.stopPropagation(); deleteChat(id); });
      b.append(x);
    }
    box.append(b);
  }
  const add = el("button", "chat-tab add", "+ 新会话");
  add.type = "button";
  add.title = state.retentionDays ? `保留 ${state.retentionDays} 天` : "";
  add.disabled = state.busy;
  add.addEventListener("click", newChat);
  box.append(add);
}

function updateComposer() {
  const c = state.agent ? chatOf(state.chat) : null;
  const busy = Boolean(c && c.busy);
  const stop = busy && !$("#msg").value.trim();
  const btn = $("#send-btn");
  btn.disabled = state.busy || Boolean(stop && c.stopping);
  btn.textContent = stop ? (c.stopping ? "停止中" : "停止") : busy ? "补充" : "发送";
  btn.title = busy && !stop ? "补充给正在进行的这一轮，agent 下一步会看到（回车）" : "";
  btn.classList.toggle("stop", stop);
  $("#interrupt-btn").hidden = !busy || stop;
  $("#interrupt-btn").disabled = Boolean(c && c.stopping);
}

function interruptSend() {
  const c = state.agent ? chatOf(state.chat) : null;
  const text = $("#msg").value.trim();
  if (!c || !c.busy || !text) return;
  $("#msg").value = "";
  runChat(state.chat, { text, simulate: $("#simulate").checked });
  stopChat(state.chat);
  updateComposer();
}

async function runChat(chat, next) {
  const c = chatOf(chat);
  if (c.busy) {
    c.next = c.next ? { ...c.next, text: `${c.next.text}\n${next.text}` } : next;
    return;
  }
  c.busy = true;
  updateComposer();
  renderTabs();
  try {
    while (next) {
      await onSendAgent(next.text, next.simulate, chat);
      next = c.next;
      c.next = null;
    }
  } finally {
    c.busy = false;
    updateComposer();
    renderTabs();
    if (chat === state.chat) $("#msg").focus();
  }
}

async function steerChat(chat, text) {
  const rec = [...state.records].reverse().find((r) => r.chat === chat && r.agent && r.status === "running");
  const item = { kind: "steer", text, state: "sending" };
  if (rec) { rec.stream.items.push(item); paintSoon(rec); }
  let sent = false;
  try {
    const { checks, out } = await V.chat(state.base, state.session.res, { agent: "steer", chat, text }, state.token,
                                         { sessionId: state.sessionId, knownNonces: state.nonces });
    if ((checks || []).some((c) => c.status === "FAIL")) item.unverified = true;
    sent = Boolean(out && out.ok);
  } catch (e) {
    item.error = errText(e);
  }
  item.state = sent ? "sent" : "later";
  if (!sent) runChat(chat, { text, simulate: false });
  if (rec) paintSoon(rec);
}

async function stopChat(chat) {
  const c = chatOf(chat);
  if (c.stopping || !state.session) return;
  c.stopping = true;
  for (const r of state.records) if (r.chat === chat && r.agent && r.status === "running") { r.stopping = true; paintSoon(r); }
  updateComposer();
  try {
    const { out } = await V.chat(state.base, state.session.res, { agent: "stop", chat }, state.token,
                                 { sessionId: state.sessionId, knownNonces: state.nonces });
    if (!out || !out.ok) throw new Error((out && out.error) || "没有返回");
  } catch (e) {
    flash(`停止失败：${errText(e)}`);
  } finally {
    c.stopping = false;
    updateComposer();
  }
}

async function switchChat(id) {
  if (id === state.chat) return;
  state.chat = id;
  try { localStorage.setItem("pa-chat", id); } catch {}
  showThread(id);
  renderTabs();
  updateComposer();
  const c = chatOf(id);
  const recs = state.records.filter((r) => r.chat === id);
  select(c.selected && recs.some((r) => r.id === c.selected) ? c.selected : recs.length ? recs[recs.length - 1].id : null);
  const t = threadEl(id);
  t.scrollTop = t.scrollHeight;
  $("#msg").focus();
  if (!c.loaded && sessionFresh()) {
    c.loaded = true;
    try {
      const out = await fetchHistory(id);
      addHistory(out.messages || [], true, id);
      c.histSeen = (out.messages || []).length;
      mergeChats(out.chats || []);
      t.prepend(...[...t.children].filter((li) => ["history", "hist-mark", "restored"].some((c) => li.classList.contains(c))));
    } catch (e) {
      c.loaded = false;
      flash(`加载失败：${errText(e)}`);
    }
  }
}

async function newChat() {
  if (state.busy || !sessionFresh()) return;
  try {
    const { out } = await V.chat(state.base, state.session.res, { agent: "new_chat" }, state.token,
                                 { sessionId: state.sessionId, knownNonces: state.nonces });
    if (!out || !out.ok) throw new Error((out && out.error) || "新建失败");
    mergeChats(out.chats || []);
    chatOf(out.chat.id).loaded = true;
    await switchChat(out.chat.id);
  } catch (e) {
    flash(`新建失败：${errText(e)}`);
  }
}

async function deleteChat(id) {
  const c = chatOf(id);
  if (c.busy || c.running || !sessionFresh()) return;
  if (!confirm(`删除「${c.title}」？删除后无法恢复。`)) return;
  try {
    const { out } = await V.chat(state.base, state.session.res, { agent: "delete_chat", chat: id }, state.token,
                                 { sessionId: state.sessionId, knownNonces: state.nonces });
    if (!out || !out.ok) throw new Error((out && out.error) || "删除失败");
    delete state.chats[id];
    const t = [...$("#threads").children].find((x) => x.dataset.chat === id);
    if (t) t.remove();
    state.records = state.records.filter((r) => r.chat !== id);
    forgetChats(state.base, (c) => c === id);
    mergeChats(out.chats || []);
    await switchChat(state.chatOrder.find((x) => x !== id) || state.chatOrder[0]);
  } catch (e) {
    flash(`删除失败：${errText(e)}`);
  }
}

async function setInternet(on) {
  const box = $("#internet");
  box.disabled = true;
  try {
    const { out } = await V.chat(state.base, state.session.res, { agent: "internet", on }, state.token,
                                 { sessionId: state.sessionId, knownNonces: state.nonces });
    box.checked = out && out.ok ? out.internet : !on;
  } catch (e) {
    box.checked = !on;
    flash(`切换失败：${errText(e)}`);
  } finally {
    box.disabled = false;
  }
}

function setPanel(open) {
  $(".columns").classList.toggle("collapsed", !open);
  $("#panel-btn").textContent = open ? "收起验证" : "展开验证";
  $("#panel-btn").setAttribute("aria-expanded", String(open));
  try { localStorage.setItem("pa-panel", open ? "1" : "0"); } catch {}
  if (open) renderPanel();
}

function sessionFrom(rec) {
  const c = rec.context;
  return { res: c.res, report: c.report, nonce: c.nonce, verifiedAt: rec.result.verified_at, recId: rec.id };
}

function sessionFresh() {
  const s = state.session;
  if (!s) return false;
  const now = Date.now() / 1000;
  const notAfter = (s.res.keyset || {}).not_after;
  return now - s.verifiedAt < V.SESSION_TTL && (!Number.isInteger(notAfter) || notAfter - now > 3600);
}

function providerReady(k) {
  return k === "phala" || Boolean((state.providers[k] || {}).ready);
}

const shortModel = (m) => String(m || "").split("/").pop();

function renderProviders() {
  const box = $("#providers");
  box.textContent = "";
  for (const k of ORDER) {
    const p = state.providers[k] || {};
    const on = state.provider === k;
    const b = el("button", "prov" + (on ? " on" : ""));
    b.type = "button";
    b.setAttribute("role", "radio");
    b.setAttribute("aria-checked", String(on));
    b.disabled = !providerReady(k) || (state.agent && !(state.models[k] || []).length);
    const sub = state.agent ? (modelFor(k) || {}).id : p.model;
    b.title = sub || "";
    b.append(document.createTextNode(PROVIDERS[k].name), el("small", null, b.disabled ? "未配置" : p.ready ? shortModel(sub) : "echo"));
    b.addEventListener("click", () => {
      if (state.busy || state.provider === k) return;
      state.provider = k;
      renderProviders();
      renderModelSelect();
      renderAtts();
      $("#msg").focus();
    });
    box.append(b);
  }
}

function logout() {
  try { sessionStorage.removeItem("pa-login"); } catch {}
  Object.assign(state, { token: null, conversation: [], records: [], selected: null, providers: {}, session: null, sessionId: null,
                         nonces: new Set(), reverifyNext: false });
  $("#threads").textContent = "";
  Object.assign(state, { chats: {}, chatOrder: [], chat: "default" });
  $("#chat-tabs").textContent = "";
  $("#panel").textContent = "";
  log.clear();
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#access-key").focus();
}

function inline(line) {
  const frag = document.createDocumentFragment();
  const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let last = 0;
  for (const m of line.matchAll(re)) {
    if (m.index > last) frag.append(line.slice(last, m.index));
    const t = m[0];
    frag.append(t.startsWith("`") ? el("code", null, t.slice(1, -1)) : el("b", null, t.slice(2, -2)));
    last = m.index + t.length;
  }
  if (last < line.length) frag.append(line.slice(last));
  return frag;
}

function md(text) {
  const box = el("div", "md");
  const parts = String(text || "").split(/^```[^\n]*\n?/m);
  parts.forEach((part, i) => {
    if (i % 2) {
      box.append(el("pre", null, part.replace(/\n$/, "")));
      return;
    }
    let list = null;
    for (const block of part.split(/\n{2,}/)) {
      const lines = block.split("\n").filter((l, k, all) => l.trim() || (k > 0 && k < all.length - 1));
      if (!lines.length) continue;
      for (const l of lines) {
        const h = l.match(/^#{1,6}\s+(.*)$/);
        const b = l.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
        if (b) {
          if (!list) { list = el("ul"); box.append(list); }
          const li = el("li");
          li.append(inline(b[1]));
          list.append(li);
          continue;
        }
        list = null;
        const node = el(h ? "h4" : "p");
        node.append(inline(h ? h[1] : l));
        box.append(node);
      }
      list = null;
    }
  });
  return box;
}

function attRow(atts) {
  const row = el("div", "att-row");
  for (const a of atts) {
    const image = a.image ?? String(a.type || "").startsWith("image/");
    const src = a.url || a.thumb;
    let node;
    if (image && src) {
      node = el("img");
      node.src = src;
      node.alt = a.name;
    } else if (image) node = el("span", "att att-image", "图片 · 点击查看");
    else node = el("span", "att", a.size ? `${a.name} · ${fmtSize(a.size)}` : a.name);
    if (a.url || a.path) {
      node.classList.add("clickable");
      node.title = image ? "查看原图" : "下载";
      node.addEventListener("click", (e) => { e.stopPropagation(); openAttachment(a, image); });
    }
    row.append(node);
  }
  return row;
}

const fullFiles = new Map();

async function openAttachment(a, image) {
  let url = a.url || fullFiles.get(a.path);
  if (!url) {
    if (!state.session) return;
    const box = image ? lightbox(null, a.name) : null;
    try {
      const { out } = await V.chat(state.base, state.session.res, { agent: "file", path: a.path }, state.token,
                                   { sessionId: state.sessionId, knownNonces: state.nonces, b64: true });
      if (!out || !out.ok) throw new Error((out && out.error) || "没有返回");
      url = URL.createObjectURL(new Blob([V.b64ToBytes(out.data)], { type: out.type }));
      fullFiles.set(a.path, url);
    } catch (e) {
      if (box) box.remove();
      flash(`打开失败：${errText(e)}`);
      return;
    }
    if (box) { box.remove(); lightbox(url, a.name); return; }
  }
  if (image) lightbox(url, a.name);
  else {
    const link = el("a");
    link.href = url;
    link.download = a.name;
    document.body.append(link);
    link.click();
    link.remove();
  }
}

function lightbox(url, name) {
  const box = el("div", "lightbox");
  box.append(url ? Object.assign(el("img"), { src: url, alt: name }) : el("span", "lightbox-wait", "加载原图…"));
  const close = () => { box.remove(); document.removeEventListener("keydown", esc); };
  const esc = (e) => { if (e.key === "Escape") close(); };
  box.addEventListener("click", close);
  document.addEventListener("keydown", esc);
  document.body.append(box);
  return box;
}

async function thumbOf(file) {
  try {
    const bmp = await createImageBitmap(file);
    const k = Math.min(1, 320 / Math.max(bmp.width, bmp.height));
    const c = document.createElement("canvas");
    c.width = Math.max(1, Math.round(bmp.width * k));
    c.height = Math.max(1, Math.round(bmp.height * k));
    c.getContext("2d").drawImage(bmp, 0, 0, c.width, c.height);
    for (const q of [0.75, 0.55, 0.35]) {
      const url = c.toDataURL("image/jpeg", q);
      if (url.length < 120000) return url;
    }
  } catch {}
  return null;
}

const fmtSize = (n) => (n >= 1 << 20 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} B`);

function keepOpen(d, it, dflt) {
  d.open = it.open ?? dflt;
  d.addEventListener("toggle", () => { if (it.open !== undefined || d.open !== dflt) it.open = d.open; });
  return d;
}

function thinkBlock(it) {
  const d = keepOpen(el("details", "think"), it, Boolean(it.live) && !it.aux);
  const what = it.aux ? "辅助调用" : it.live ? "思考中" : "思考";
  d.append(el("summary", null, `${what} · ${it.text.length} 字`), el("div", null, it.text));
  if (it.live) requestAnimationFrame(() => { const b = d.lastElementChild; b.scrollTop = b.scrollHeight; });
  return d;
}

const STEER_STATE = { sending: "发送中", later: "这一轮结束后作为新消息发送", lost: "没送到" };

function steerNote(it) {
  const d = el("div", "steer");
  d.append(el("span", "steer-mark", "补充"), el("span", null, it.text));
  const tag = it.unverified ? "回执未通过验证" : STEER_STATE[it.state];
  if (tag) d.append(el("span", "steer-state", tag));
  return d;
}

function toolCard(it) {
  const d = keepOpen(el("details", "tool-card"), it, false);
  const s = el("summary");
  const mark = it.status === "running" ? ["t-run", "…"] : it.status === "failed" ? ["t-bad", "✗"] : ["t-ok", "✓"];
  s.append(el("span", mark[0], mark[1]), el("b", null, it.name || "tool"), el("span", null, String(it.preview || "").slice(0, 120)));
  d.append(s);
  if (it.args) d.append(el("pre", null, typeof it.args === "string" ? it.args : pretty(it.args)));
  if (it.result) d.append(el("pre", "t-res", it.result));
  return d;
}

function attachResults(items, msgs) {
  const tools = items.filter((it) => it.kind === "tool" && !it.result);
  for (const m of msgs) {
    if (m.role !== "tool") continue;
    const t = tools.find((it) => !it.result && (!m.tool_name || it.name === m.tool_name)) || tools.find((it) => !it.result);
    if (t) t.result = m.content || "（空）";
    else items.push({ kind: "tool", name: m.tool_name || "tool", result: m.content || "（空）", status: "done" });
  }
}

function renderAgentBubble(a, rec) {
  a.textContent = "";
  a.classList.remove("error");
  const items = ((rec.stream && rec.stream.items) || []).filter((it) => !(rec.stopped && it.kind === "text" && INTERRUPTED.test(it.text)));
  for (const it of items) {
    if (it.kind === "steer") {
      a.append(steerNote(it));
      continue;
    }
    if (it.kind !== "text") {
      a.append(it.kind === "think" ? thinkBlock(it) : toolCard(it));
      continue;
    }
    const box = md(it.text);
    if (it.pending || it.failed) {
      box.classList.add(it.failed ? "unverified" : "pending");
      box.prepend(el("div", "verify-tag", it.failed ? "未通过验证" : "待验证"));
    }
    a.append(box);
  }
  const failed = rec.blocked || rec.error || rec.serviceError;
  if (failed) {
    a.classList.toggle("error", !items.some((it) => it.kind === "text" && it.text));
    a.append(el("div", null, rec.blocked ? "未发送：证明未通过" : rec.error || rec.serviceError));
  } else if (rec.stopped) a.append(el("div", "agent-status", "已停止"));
  else if (rec.status === "running" && rec.stopping) a.append(el("div", "agent-status", "正在停止…"));
  else if (rec.status === "running") {
    if (!items.some((it) => it.kind === "text" && it.text)) a.append(el("span", "typing-dots"));
    const st = rec.stream && callStatus(rec.stream);
    if (st) a.append(st);
  }
  const net = (rec.stream && rec.stream.net) || [];
  if (net.length) {
    const ok = [...new Set(net.filter((e) => e.allowed).map((e) => e.host))];
    const no = net.filter((e) => !e.allowed).length;
    a.append(el("div", "agent-net" + (ok.length ? "" : " off"),
                (ok.length ? `外网 · ${ok.slice(0, 6).join("  ")}${ok.length > 6 ? ` 等 ${ok.length} 个` : ""}` : "外网") +
                (no ? ` · 拒绝 ${no} 次` : "")));
  }
  const meta = el("div", "bubble-meta");
  const calls = rec.context && rec.context.agent ? rec.context.agent.calls.length : null;
  meta.append(el("span", null, `${PROVIDERS[rec.provider].name} · ${shortModel(rec.model)}` + (calls ? ` · ${calls} 次模型调用` : "") +
                                (rec.internet === false ? " · 未联网" : "")));
  a.append(meta);
}

function onAgentEvent(rec, ev) {
  const s = rec.stream;
  const lastText = () => {
    const l = s.items[s.items.length - 1];
    if (l && l.kind === "text") return l;
    const t = { kind: "text", text: "" };
    s.items.push(t);
    return t;
  };
  const live = (kind, n, aux) => {
    const l = s.items[s.items.length - 1];
    if (l && l.kind === kind && l.call === n) return l;
    const t = { kind, text: "", call: n, streamed: true, live: kind === "think", aux, pending: rec.provider !== "chutes" };
    s.items.push(t);
    return t;
  };
  if (ev.type === "model.delta" && typeof ev.delta === "string") {
    live(ev.kind === "content" ? "text" : "think", ev.n, ev.kind === "aux").text += ev.delta;
  }
  else if (ev.type === "assistant.delta" && typeof ev.delta === "string") lastText().text += ev.delta;
  else if (ev.type === "assistant.commentary" && ev.text && !ev.already_streamed) {
    const l = s.items[s.items.length - 1];
    const same = l && l.kind === "text" && l.streamed && l.text.trim() && ev.text.trim().includes(l.text.trim().slice(0, 200));
    if (same) l.text = ev.text;
    else lastText().text += ev.text;
  }
  else if (ev.type === "tool.started") s.items.push({ kind: "tool", name: ev.tool_name || ev.name, preview: ev.preview, args: ev.args, status: "running" });
  else if (ev.type === "tool.completed" || ev.type === "tool.failed") {
    const t = [...s.items].reverse().find((it) => it.kind === "tool" && it.status === "running" && (!ev.tool_name || it.name === ev.tool_name));
    if (t) t.status = ev.type === "tool.failed" ? "failed" : "done";
  } else if (ev.type === "assistant.completed" && typeof ev.content === "string") {
    const l = s.items[s.items.length - 1];
    if (l && l.kind === "text") l.text = ev.content;
    else if (ev.content) s.items.push({ kind: "text", text: ev.content });
  } else if (ev.type === "turn.queued") s.queued = true;
  else if (ev.type === "turn.started") s.queued = false;
  else if (ev.type === "model.started") s.call = { n: ev.n, model: ev.model, running: true, aux: ev.aux };
  else if (ev.type === "egress") (s.net = s.net || []).push(ev);
  else if (ev.type === "model.completed") {
    for (const it of s.items) {
      if (it.call !== ev.n) continue;
      it.live = false;
      it.pending = false;
      if (!ev.ok) it.failed = true;
    }
    s.call = { n: ev.n, model: ev.model, running: false, error: ev.ok ? null : ev.error };
    if (!ev.ok) s.failures = (s.failures || 0) + 1;
  } else if (ev.type === "run.cancelled") rec.stopped = true;
  if (ev.pending_steer && !rec.replayed && (ev.type === "run.completed" || ev.type === "run.cancelled" || ev.type === "run.failed")) {
    rec.replayed = true;
    for (const it of s.items) if (it.kind === "steer" && it.state === "sent") it.state = "later";
    runChat(rec.chat, { text: String(ev.pending_steer), simulate: false });
  }
  else if (ev.type === "run.failed" || ev.type === "error") rec.serviceError = ev.error || ev.type;
}

function callStatus(s) {
  if (s.queued) return el("div", "agent-status", "排队中");
  const c = s.call;
  if (!c) return null;
  if (c.running) return el("div", "agent-status", `${c.aux ? "辅助调用" : "模型调用"} #${c.n} · ${shortModel(c.model)} …`);
  if (c.error) return el("div", "agent-status bad", `第 ${c.n} 次调用失败：${String(c.error).slice(0, 140)}`);
  return null;
}

async function readFiles(files) {
  for (const f of files) {
    if (state.atts.length >= 8) break;
    if (f.size > 20 * 1048576) { flash(`${f.name} 超过 20 MB`); continue; }
    const bytes = new Uint8Array(await f.arrayBuffer());
    const image = (f.type || "").startsWith("image/");
    state.atts.push({ name: f.name || "file", type: f.type || "application/octet-stream", size: f.size, data: V.bytesToB64(bytes),
                      url: image ? URL.createObjectURL(f) : null, thumb: image ? await thumbOf(f) : null });
  }
  renderAtts();
}

function flash(text) {
  const n = el("div", "banner warn", text);
  $("#atts").hidden = false;
  $("#atts").append(n);
  setTimeout(() => { n.remove(); renderAtts(); }, 2500);
}

function modelFor(k) {
  const list = state.models[k] || [];
  return list.find((m) => m.id === state.modelSel[k]) || list[0] || null;
}

const currentModel = () => modelFor(state.provider);

function renderAtts() {
  const box = $("#atts");
  box.textContent = "";
  box.hidden = !state.atts.length;
  const m = currentModel();
  state.atts.forEach((a, i) => {
    const chip = el("span", "att");
    if (a.url) {
      const img = el("img");
      img.src = a.url;
      img.alt = a.name;
      chip.append(img);
    }
    chip.append(el("span", null, `${a.name} · ${fmtSize(a.size)}`));
    const x = el("button", null, "×");
    x.type = "button";
    x.addEventListener("click", () => { state.atts.splice(i, 1); renderAtts(); });
    chip.append(x);
    box.append(chip);
  });
  if (state.atts.some((a) => a.type.startsWith("image/")) && m && !m.vision) {
    box.append(el("span", "att", "当前模型不支持图片，将作为文件上传"));
  }
}

function renderModelSelect() {
  const sel = $("#model");
  const list = state.models[state.provider] || [];
  sel.hidden = !state.agent || !list.length;
  sel.textContent = "";
  for (const m of list) {
    const o = el("option", null, `${shortModel(m.id)}${m.vision ? " · 识图" : ""}`);
    o.value = m.id;
    sel.append(o);
  }
  const cur = currentModel();
  if (cur) sel.value = cur.id;
}

function historyTurns(msgs) {
  const turns = [];
  let agent = null;
  for (const m of msgs) {
    const ms = m.timestamp ? m.timestamp * 1000 : null;
    const time = ms ? clock(ms) : "";
    if (m.role === "user" && m.steer && agent) {
      agent.items.push({ kind: "steer", text: m.content });
      continue;
    }
    if (m.role === "user") {
      turns.push({ role: "user", text: m.content, time, ms, atts: m.attachments || [] });
      agent = null;
      continue;
    }
    if (!agent) turns.push((agent = { role: "agent", items: [], time, ms }));
    if (m.role === "assistant") {
      if (m.content && INTERRUPTED.test(m.content)) agent.items.push({ kind: "text", text: "已停止" });
      else if (m.content) agent.items.push({ kind: "text", text: m.content });
      for (const t of m.tool_calls || []) agent.items.push({ kind: "tool", name: t.name || t, args: t.args, status: "done" });
    } else attachResults(agent.items, [m]);
  }
  return turns;
}

function matchRestored(pool, t) {
  const text = t.text || "";
  let best = null;
  for (const r of pool) {
    if (r.blocked || (t.ms && (r.time > t.ms + 60e3 || t.ms - r.time > 15 * 60e3))) continue;
    if (r.title !== "（附件）" && text !== r.title && !text.startsWith(r.title + "\n")) continue;
    if (!best || Math.abs(t.ms - r.time) < Math.abs(t.ms - best.time)) best = r;
  }
  return best;
}

function addHistory(msgs, mark, chat) {
  const thread = threadEl(chat);
  const turns = historyTurns(msgs);
  const pool = mark ? state.records.filter((r) => r.restored && r.kind === "message" && r.chat === chat && !r.placed) : [];
  if (!turns.length && !pool.length) return;
  pool.sort((a, b) => a.time - b.time);
  const place = (r) => { pool.splice(pool.indexOf(r), 1); r.placed = true; addTurn(r); updateTurn(r); };
  const before = (ms) => { while (pool.length && pool[0].time <= ms) place(pool[0]); };
  if (mark && turns.length) thread.append(el("li", "hist-mark", `历史 · ${turns.filter((t) => t.role === "user").length} 轮`));
  for (let i = 0; i < turns.length; i++) {
    const t = turns[i];
    if (t.role === "user") {
      const r = matchRestored(pool, t);
      if (r) {
        before(r.time - 1);
        if (t.atts && t.atts.length) r.attachments = t.atts;
        place(r);
        if (turns[i + 1] && turns[i + 1].role === "agent") i++;
        continue;
      }
      if (t.ms) before(t.ms);
    }
    const li = el("li", "turn history");
    const b = el("div", t.role === "user" ? "bubble user" : "bubble agent");
    if (t.role === "user") {
      if (t.text) b.append(md(t.text));
      if (t.atts && t.atts.length) b.append(attRow(t.atts));
    }
    else for (const it of t.items) b.append(it.kind === "text" ? md(it.text) : it.kind === "steer" ? steerNote(it) : toolCard(it));
    const meta = el("div", "bubble-meta");
    meta.append(el("span", null, t.time));
    b.append(meta);
    li.append(b);
    thread.append(li);
  }
  while (pool.length) place(pool[0]);
  if (chat === state.chat) thread.scrollTop = thread.scrollHeight;
}

async function fetchHistory(chat) {
  const s = state.session;
  if (!s) throw new Error("还没有通过验证");
  const { out } = await V.chat(state.base, s.res, { agent: "history", ...(chat ? { chat } : {}) }, state.token,
                               { sessionId: state.sessionId, knownNonces: state.nonces });
  if (!out || !out.ok) throw new Error((out && out.error) || "没有返回");
  return out;
}

async function pollHistory() {
  if (!state.agent || state.busy || !state.base || !sessionFresh()) return;
  const id = state.chat;
  const c = chatOf(id);
  if (c.busy) return;
  try {
    const out = await fetchHistory(id);
    mergeChats(out.chats || []);
    state.retentionDays = out.retention_days;
    if (!$("#internet").disabled) $("#internet").checked = out.internet !== false;
    const msgs = out.messages || [];
    if (msgs.length > c.histSeen && !c.busy) {
      addHistory(msgs.slice(c.histSeen), false, id);
      c.histSeen = msgs.length;
    }
  } catch {}
}

let painting = null;
function paintSoon(rec) {
  if (painting === rec) return;
  painting = rec;
  requestAnimationFrame(() => { painting = null; updateTurn(rec); });
}

async function onSendAgent(text, simulate, chat) {
  const atts = state.atts.splice(0);
  renderAtts();
  const m = currentModel();
  const rec = newRecord("message", text || "（附件）");
  Object.assign(rec, { simulated: simulate, provider: state.provider, model: m ? m.id : null, agent: true, internet: $("#internet").checked, chat,
                       stream: { items: [] }, attachments: atts.map(({ name, type, size, url, thumb }) => ({ name, type, size, url, thumb })) });
  addTurn(rec);
  select(rec.id);
  const source = simulate ? V.concat(state.source, "\n# demo: one extra local line\n") : state.source;
  const reuse = !simulate && sessionFresh();
  try {
    for await (const [kind, data] of V.runAgent(state.base, {
      quoteVerifier: state.quoteVerifier, cvmQuoteVerifier: state.cvmVerifier, token: state.token, expectSource: source,
      approved: state.local ? null : APPROVED,
      session: reuse ? state.session : null, sessionId: state.sessionId, knownNonces: state.nonces, reverify: !reuse || state.reverifyNext,
      provider: rec.provider, model: rec.model, input: text,
      attachments: atts.map(({ name, type, data, thumb }) => ({ name, type, data, ...(thumb ? { thumb } : {}) })),
      chat,
    })) {
      if (kind === "agent") {
        onAgentEvent(rec, data);
        paintSoon(rec);
      } else {
        apply(rec, kind, data);
        refresh(rec);
      }
    }
  } catch (e) {
    failRecord(rec, e);
  }
  const final = [...rec.stream.items].reverse().find((it) => it.kind === "text" && it.text);
  rec.reply = final ? { text: final.text, mode: rec.provider, model: rec.model } : null;
  refresh(rec);
  if (rec.context && rec.context.fresh && !simulate) {
    const ok = !rec.blocked && rec.result && !(rec.result.cvm || []).some((c) => c.status === "FAIL");
    state.session = ok ? sessionFrom(rec) : null;
    if (ok) state.reverifyNext = false;
  }
  try {
    const out = await fetchHistory(chat);
    const msgs = out.messages || [];
    const lastUser = msgs.map((m) => m.role).lastIndexOf("user");
    attachResults(rec.stream.items, msgs.slice(lastUser + 1));
    chatOf(chat).histSeen = msgs.length;
    mergeChats(out.chats || []);
    refresh(rec);
  } catch {}
  saveRecord(rec);
}

async function onSend(ev) {
  ev.preventDefault();
  const text = $("#msg").value.trim();
  const simulate = $("#simulate").checked;
  if (state.agent && chatOf(state.chat).busy) {
    if (text) {
      $("#msg").value = "";
      updateComposer();
      steerChat(state.chat, text);
    } else if (ev.submitter === $("#send-btn")) stopChat(state.chat);
    return;
  }
  if ((!text && !(state.agent && state.atts.length)) || state.busy) return;
  if (state.agent) {
    $("#msg").value = "";
    await runChat(state.chat, { text, simulate });
    return;
  }
  state.busy = true;
  $("#send-btn").disabled = true;
  $("#msg").value = "";
  const rec = newRecord("message", text);
  rec.simulated = simulate;
  rec.provider = state.provider;
  rec.model = (state.providers[state.provider] || {}).model || null;
  addTurn(rec);
  select(rec.id);
  const source = simulate ? V.concat(state.source, "\n# demo: one extra local line\n") : state.source;
  const reuse = !simulate && sessionFresh();
  try {
    for await (const [kind, data] of V.run(state.base, {
      quoteVerifier: state.quoteVerifier, cvmQuoteVerifier: state.cvmVerifier, token: state.token, expectSource: source,
      approved: state.local ? null : APPROVED,
      session: reuse ? state.session : null, sessionId: state.sessionId, knownNonces: state.nonces,
      reverify: !reuse || state.reverifyNext,
      provider: rec.provider, messages: [...state.conversation, { role: "user", content: text }],
    })) {
      apply(rec, kind, data);
      refresh(rec);
    }
  } catch (e) {
    failRecord(rec, e);
  }
  refresh(rec);
  if (rec.context && rec.context.fresh && !simulate) {
    const ok = !rec.blocked && rec.result && !(rec.result.cvm || []).some((c) => c.status === "FAIL");
    state.session = ok ? sessionFrom(rec) : null;
    if (ok) state.reverifyNext = false;
  }
  if (rec.reply && rec.reply.text && !rec.blocked && rec.status !== "error" && rec.status !== "fail") {
    state.conversation.push({ role: "user", content: text }, { role: "assistant", content: rec.reply.text });
  }
  saveRecord(rec);
  state.busy = false;
  $("#send-btn").disabled = false;
  $("#msg").focus();
}

function addTurn(rec) {
  const li = el("li", rec.restored ? "turn restored" : "turn");
  li.dataset.id = rec.id;
  const meta = el("div", "bubble-meta");
  meta.append(el("span", "badge " + rec.status, BADGE[rec.status]), el("span", null, clock(rec.time)));
  if (rec.kind === "login" || rec.kind === "verify") {
    const b = el("button", "bubble system");
    b.type = "button";
    b.append(el("span", null, rec.kind === "login" ? "已登录" : "已重新验证"), meta);
    b.addEventListener("click", () => select(rec.id, true));
    li.append(b);
  } else {
    meta.append(el("span", null, `· ${PROVIDERS[rec.provider].name}`));
    const reused = rec.restored ? Boolean(rec.context && rec.context.session) : sessionFresh();
    if (reused && !rec.simulated) meta.append(el("span", "reuse-tag", "· 沿用验证"));
    if (rec.simulated) meta.append(el("span", null, "· 模拟篡改"));
    if (rec.restored) meta.append(el("span", "reuse-tag", "· 之前的验证记录"));
    const u = el("button", "bubble user");
    u.type = "button";
    u.append(el("div", null, rec.title));
    if (rec.attachments && rec.attachments.length) u.append(attRow(rec.attachments));
    u.append(meta);
    u.addEventListener("click", () => select(rec.id));
    const a = el("div", "bubble agent");
    a.append(el("span", "typing-dots"));
    a.addEventListener("click", () => select(rec.id));
    li.append(u, a);
  }
  const badge = $(".badge", li);
  badge.title = "查看验证";
  badge.addEventListener("click", (e) => { e.stopPropagation(); select(rec.id, true); });
  const t = threadEl(rec.chat || state.chat);
  t.append(li);
  if (t.dataset.chat === state.chat) t.scrollTop = t.scrollHeight;
}

function updateTurn(rec) {
  const li = $(`#threads .turn[data-id="${rec.id}"]`);
  if (!li) return;
  const badge = $(".badge", li);
  badge.className = "badge " + rec.status;
  badge.textContent = BADGE[rec.status];
  const a = $(".bubble.agent", li);
  if (a && rec.agent) {
    const t = li.parentElement;
    const pinned = t.scrollHeight - t.scrollTop - t.clientHeight < 120;
    renderAgentBubble(a, rec);
    if (pinned) t.scrollTop = t.scrollHeight;
    return;
  }
  if (!a || rec.status === "running") return;
  a.textContent = "";
  a.classList.remove("error");
  if (rec.reply && rec.reply.text && !rec.blocked) {
    a.append(el("div", null, rec.reply.text));
    const meta = el("div", "bubble-meta");
    meta.append(el("span", null, rec.reply.mode === "echo" ? "echo" : `${PROVIDERS[rec.provider].name} · ${rec.reply.model}`));
    a.append(meta);
    return;
  }
  a.classList.add("error");
  a.append(el("div", null, rec.blocked ? "未发送：证明未通过" : rec.error || rec.serviceError || "无响应"));
}

function select(id, open = false) {
  state.selected = id;
  const rec = state.records.find((r) => r.id === id);
  if (rec && state.chats[rec.chat]) state.chats[rec.chat].selected = id;
  for (const li of document.querySelectorAll("#threads .turn")) li.classList.toggle("selected", Number(li.dataset.id) === id);
  if (open && $(".columns").classList.contains("collapsed")) setPanel(true);
  else renderPanel();
  if (rec && rec.partial) loadBody(rec).then(() => { if (state.selected === id) renderPanel(); });
}

function refresh(rec) {
  updateTurn(rec);
  if (state.selected === rec.id) renderPanel();
}

function renderPanel() {
  const panel = $("#panel");
  const same = panel.dataset.rec === String(state.selected);
  const top = panel.scrollTop;
  panel.textContent = "";
  panel.dataset.rec = String(state.selected);
  const rec = state.records.find((r) => r.id === state.selected);
  if (!rec) { panel.append(el("div", "panel-empty", "暂无记录")); return; }

  const head = el("div", "rec-head");
  const left = el("div");
  left.append(el("div", "rec-kicker mono", `VERIFICATION #${rec.id}`),
              el("div", "rec-title", rec.kind === "message" ? rec.title : rec.kind === "login" ? "登录" : "重新验证"),
              el("div", "rec-time mono", new Date(rec.time).toLocaleString("zh-CN", { hour12: false })));
  const actions = el("div", "rec-actions");
  const tamperBtn = el("button", "btn ghost small", rec.stages.tamper === "running" ? "测试中" : "篡改测试");
  tamperBtn.type = "button";
  tamperBtn.disabled = !(rec.context && rec.context.res && rec.context.res.collateral) || rec.stages.tamper === "running";
  tamperBtn.addEventListener("click", () => runTamper(rec));
  const dl = el("button", "btn ghost small", "report.json");
  dl.type = "button";
  dl.disabled = !rec.result;
  dl.addEventListener("click", () => download(rec));
  actions.append(tamperBtn, dl);
  head.append(left, actions);
  panel.append(head, renderFlow(rec));

  const sum = el("div", "summary");
  sum.append(el("div", "verdict " + rec.status, VERDICT[rec.status]));
  if (rec.counts) {
    const c = el("div", "counts");
    for (const [k, cls] of [["PASS", "p"], ["WARN", "w"], ["FAIL", "f"]]) {
      const s = el("span", cls);
      s.append(el("b", null, String(rec.counts[k])), document.createTextNode(k));
      c.append(s);
    }
    c.append(el("span", null, `${rec.elapsed.toFixed(1)}s`));
    sum.append(c);
  }
  panel.append(sum);

  if (rec.simulated) panel.append(el("div", "banner warn", "模拟源码篡改"));
  if (rec.renewed) panel.append(el("div", "banner warn", rec.renewed));
  if (rec.restored) panel.append(el("div", "banner info", "之前的验证记录 · 保存在这个浏览器里，没有重新验证"));
  const ses = rec.context && rec.context.session;
  if (ses) {
    const b = el("div", "banner info");
    const ago = `${Math.max(0, Math.round((rec.time / 1000 - ses.verifiedAt) / 60))} 分钟前`;
    b.append(el("span", null, ses.recId != null ? `沿用 #${ses.recId} 的验证 · ${ago}` : `沿用登录时的验证 · ${ago}`));
    if (ses.recId != null) {
      const go = el("button", "btn ghost small", `查看 #${ses.recId}`);
      go.type = "button";
      go.addEventListener("click", () => select(ses.recId));
      b.append(go);
    }
    panel.append(b);
  }
  if (rec.blocked) panel.append(el("div", "banner fail", "证明未通过，消息未发送"));
  if (rec.error) panel.append(el("div", "banner fail", rec.error));
  if (rec.serviceError) panel.append(el("div", "banner fail", rec.serviceError));
  if (rec.auth && !rec.auth.ok) panel.append(el("div", "banner fail", rec.auth.error === "unauthorized" ? "密钥无效" : rec.auth.error || "登录失败"));

  for (const key of ["cvm", "channel", "gateway", "tamper"]) {
    if (key === "tamper" && rec.stages.tamper === "idle") continue;
    if (key === "gateway" && rec.kind !== "message") continue;
    panel.append(renderSection(rec, key));
  }
  const links = renderLinks(rec);
  if (links) panel.append(links);
  if (same) panel.scrollTop = top;
}

function renderFlow(rec) {
  const flow = el("div", "flow");
  const st = rec.stages;
  const cvm = st.channel === "fail" || st.cvm === "fail" ? "fail"
    : st.cvm === "running" || st.channel === "running" ? "running"
    : st.cvm === "idle" ? "idle" : [st.cvm, st.channel].includes("warn") ? "warn" : st.cvm;
  const meta = PROVIDERS[rec.provider || state.provider] || PROVIDERS.phala;
  let gw = rec.kind !== "message" ? "skipped" : st.gateway;
  let model;
  if (rec.kind !== "message") model = "skipped";
  else if (rec.provider === "phala" || !rec.provider) {
    const up = (rec.sections.gateway || []).find((c) => c.name.includes("upstream.verified"));
    model = up ? (up.status === "PASS" ? "pass" : "fail") : gw === "skipped" ? "skipped" : gw === "running" ? "running" : "idle";
  } else {
    model = gw;
    if (!["idle", "running", "skipped"].includes(gw)) gw = rec.reply && rec.reply.text ? "pass" : "fail";
  }
  const nodes = [["客户端", "LOCAL", "pass local"], [rec.agent ? "CVM · agent" : "CVM", (state.local ? "模拟 TDX" : "INTEL TDX") + (rec.agent ? " · hermes" : ""), cvm],
                 [...meta.relay, gw], [...meta.model, model]];
  const links = [cvm, gw, model];
  nodes.forEach(([name, tag, s], i) => {
    const n = el("div", "node " + s);
    n.append(el("b", null, name), el("span", null, tag));
    flow.append(n);
    if (i < 3) {
      const l = links[i];
      flow.append(el("div", "link " + (l === "running" ? "running" : l === "fail" ? "fail" : l === "pass" || l === "warn" ? "pass" : "")));
    }
  });
  return flow;
}

function renderSection(rec, key) {
  const st = rec.stages[key];
  const sec = el("section", "section " + st);
  sec.dataset.key = key;
  const head = el("div", "section-head");
  const title = key === "gateway" && rec.provider ? `${SECTION_TITLE[key]} · ${PROVIDERS[rec.provider].name}` : SECTION_TITLE[key];
  head.append(el("div", "section-title", title), el("span", "state " + st, STATE_LABEL[st] || st));
  sec.append(head);
  const checks = rec.sections[key];
  if (checks && checks.length) sec.append(renderChecks(rec, key, checks));
  if (key === "cvm" && rec.sections.info && rec.sections.info.length) {
    const det = el("details", "ref");
    det.append(el("summary", null, "度量值与配置"), renderChecks(rec, "info", rec.sections.info));
    sec.append(det);
  }
  return sec;
}

function renderChecks(rec, key, checks) {
  const ul = el("ul", "checks");
  checks.forEach((c, i) => {
    const id = `${key}:${i}`;
    const li = el("li", "check");
    if (!rec.seen.has(id)) {
      rec.seen.add(id);
      li.classList.add("enter");
      li.style.animationDelay = `${Math.min(i, 20) * 40}ms`;
    }
    const row = el("button", "check-row");
    row.type = "button";
    const pill = key === "tamper" ? (c.status === "PASS" ? "CAUGHT" : "MISSED") : c.status;
    row.append(el("span", "pill " + c.status, pill), el("span", "check-name", label(c.name)), el("span", "chev", "›"));
    li.append(row);
    const detail = key === "tamper" ? c.detail.replace(/^被拦下：(.*)$/, (_, n) => `拦截于 ${label(n)}`) : c.detail;
    scope = { rec, id };
    const ev = evidenceFor(rec, key, c);
    scope = null;
    if (detail || ev) {
      if (detail && !(key === "tamper" && ev)) li.append(el("div", "check-detail", detail));
      if (ev) {
        const box = el("div", "evidence");
        box.append(...[].concat(ev));
        li.append(box);
      }
      if (rec.open.has(id)) li.classList.add("open");
      row.addEventListener("click", () => {
        li.classList.toggle("open");
        if (li.classList.contains("open")) rec.open.add(id); else rec.open.delete(id);
      });
    } else {
      li.classList.add("static");
      row.tabIndex = -1;
    }
    ul.append(li);
  });
  return ul;
}

const RUNTIME_EVENTS = {
  "system-preparing": "运行时度量起点",
  "app-id": "应用 ID",
  "compose-hash": "sha256(app_compose)",
  "init-script-hash": "初始化脚本哈希",
  "gpu-policy-hash": "GPU 策略哈希",
  "gpu-attestation": "GPU 证明结果",
  "instance-id": "实例 ID",
  "boot-mr-done": "启动度量结束",
  "mr-kms": "KMS 度量",
  "os-image-hash": "系统镜像哈希",
  "key-provider": "密钥提供方",
  "storage-fs": "数据盘文件系统",
  "storage-encrypted": "数据盘加密（1 = 是）",
  "system-ready": "准备完成，启动容器",
};
const HASH_EVENTS = new Set(["app-id", "compose-hash", "init-script-hash", "gpu-policy-hash", "gpu-attestation",
                             "instance-id", "mr-kms", "os-image-hash"]);
const BOOT_EVENTS = {
  0x4: ["EV_SEPARATOR", "阶段分隔"],
  0x6: ["EV_EVENT_TAG", "内核命令行 / initrd"],
  0xa: ["EV_PLATFORM_CONFIG_FLAGS", "ACPI 表"],
  0x80000001: ["EV_EFI_VARIABLE_DRIVER_CONFIG", "Secure Boot 变量"],
  0x80000002: ["EV_EFI_VARIABLE_BOOT", "启动项变量"],
  0x80000003: ["EV_EFI_BOOT_SERVICES_APPLICATION", "加载内核"],
  0x80000007: ["EV_EFI_ACTION", "固件动作"],
  0x8000000a: ["EV_EFI_PLATFORM_FIRMWARE_BLOB2", "TDVF 配置固件卷"],
  0x8000000b: ["EV_EFI_HANDOFF_TABLES2", "固件移交表"],
};
const TD_FIELDS = [
  ["tee_tcb_svn", "TDX 模块安全版本"],
  ["mr_seam", "TDX 模块度量"],
  ["mr_signer_seam", "TDX 模块签名者"],
  ["seam_attributes", "TDX 模块属性"],
  ["td_attributes", "TD 属性"],
  ["xfam", "CPU 扩展特性"],
  ["mr_td", "初始内存，虚拟固件"],
  ["mr_config_id", "01 ‖ compose_hash"],
  ["mr_owner", "所有者"],
  ["mr_owner_config", "所有者配置"],
  ["rt_mr0", "固件配置与虚拟硬件"],
  ["rt_mr1", "内核"],
  ["rt_mr2", "内核命令行与 initrd"],
  ["rt_mr3", "运行时事件"],
  ["report_data", "公钥集与 nonce 的绑定"],
];
const TD_ATTR_BITS = [[0, "DEBUG"], [28, "SEPT_VE_DISABLE"], [30, "PKS"], [31, "KL"], [63, "PERFMON"]];
const RECEIPT_EVENTS = {
  "request.received": "网关收到的请求体",
  "middleware.forwarded": "中间件处理后的请求体",
  "route.selected": "选定的上游路由",
  "request.forwarded": "转发给上游的请求体",
  "upstream.verified": "网关签名的声明；GPU 证明取决于路由到的上游",
  "response.received": "上游返回的响应体",
  "response.returned": "返回给调用方的响应体",
};

let scope = null;
const pretty = (v) => JSON.stringify(v, null, 2);
const utc = (t) => new Date(t * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
const textBytes = (t) => new TextEncoder().encode(t);

function utf8(hex) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(V.hexToBytes(hex)); } catch { return null; }
}

function prettyText(t) {
  try { return pretty(JSON.parse(t)); } catch { return t; }
}

function kv(rows) {
  const dl = el("dl", "kv");
  for (const [k, v, sub] of rows) {
    if (v === undefined) continue;
    const dt = el("dt", null, k);
    if (sub) dt.append(el("small", null, sub));
    const dd = el("dd");
    if (v instanceof Node) dd.append(v);
    else dd.textContent = v === null ? "null" : String(v);
    dl.append(dt, dd);
  }
  return dl;
}

function code(text) {
  return el("pre", "code", text);
}

function mark(ok, text) {
  return el("span", "mark " + (ok ? "ok" : "bad"), text);
}

function compare(rows) {
  const vals = rows.map((r) => r[1]);
  const missing = vals.some((v) => v === null || v === undefined);
  const ok = !missing && vals.every((v) => v === vals[0]);
  const box = kv(rows.map(([k, v, sub]) => [k, v ?? null, sub]));
  const dd = el("dd");
  dd.append(mark(ok, missing ? "无对照值" : ok ? "一致" : "不一致"));
  box.append(el("dt"), dd);
  return box;
}

function blob(value, bytes) {
  const b = el("div", "blob");
  const meta = el("span", null, `${bytes.length} B`);
  V.sha256(bytes).then((h) => { meta.textContent = `${bytes.length} B · sha256 ${V.bytesToHex(h)}`; });
  const btn = el("button", "btn ghost small", "复制");
  btn.type = "button";
  btn.addEventListener("click", async () => {
    btn.textContent = (await copyText(value)) ? "已复制" : "复制失败";
    setTimeout(() => { btn.textContent = "复制"; }, 1600);
  });
  b.append(meta, btn);
  return b;
}

function fold(title, ...nodes) {
  const d = el("details", "fold");
  const { rec, id } = scope;
  const key = `${id}/${title}`;
  if (rec.folds.has(key)) d.open = true;
  d.addEventListener("toggle", () => { if (d.open) rec.folds.add(key); else rec.folds.delete(key); });
  const body = el("div", "fold-body");
  body.append(...nodes.flat().filter(Boolean));
  d.append(el("summary", null, title), body);
  return d;
}

function jsonView(v) {
  const text = pretty(v);
  if (text.length < 4000 || !v || typeof v !== "object" || Array.isArray(v)) return code(text);
  return kv(Object.entries(v).map(([k, x]) => {
    if (typeof x === "string") return [k, /^[A-Za-z0-9+/=]{256,}$/.test(x) ? blob(x, textBytes(x)) : x];
    const t = pretty(x);
    return [k, t.length > 4000 ? blob(t, textBytes(t)) : code(t)];
  }));
}

function readable(bytes) {
  const runs = [];
  let cur = "";
  for (const x of bytes) {
    if (x >= 0x20 && x < 0x7f) cur += String.fromCharCode(x);
    else { if (cur.length >= 4) runs.push(cur); cur = ""; }
  }
  if (cur.length >= 4) runs.push(cur);
  for (const off of [0, 1]) {
    let u = "";
    for (let i = off; i + 1 < bytes.length; i += 2) {
      if (bytes[i + 1] === 0 && bytes[i] >= 0x20 && bytes[i] < 0x7f) u += String.fromCharCode(bytes[i]);
      else { if (u.length >= 2) runs.push(u); u = ""; }
    }
    if (u.length >= 2) runs.push(u);
  }
  return [...new Set(runs)].join(" · ");
}

function payloadView(e, runtime) {
  const hex = e.event_payload || "";
  if (!hex) return "";
  const t = utf8(hex);
  if (runtime && !HASH_EVENTS.has(e.event) && t !== null) return /^[[{]/.test(t) ? code(prettyText(t)) : t;
  if (!runtime && t !== null && /^[\x20-\x7e]*\0*$/.test(t)) return t.replace(/\0+$/, "");
  if (runtime) return hex;
  const box = el("div");
  const r = readable(V.hexToBytes(hex));
  if (r) box.append(el("div", "readable", r));
  box.append(el("div", null, hex));
  return box;
}

function eventCard(e, i, after, cross) {
  const type = Number(e.event_type);
  const runtime = type === V.DSTACK_RUNTIME_EVENT_TYPE;
  const boot = BOOT_EVENTS[type];
  const name = runtime ? e.event : boot ? boot[0] : `0x${type.toString(16)}`;
  const desc = runtime ? RUNTIME_EVENTS[e.event] : [boot && boot[1], e.event].filter(Boolean).join(" · ");
  const card = el("div", "evt");
  const head = el("div", "evt-head");
  head.append(el("span", "evt-idx", `#${i}`), el("span", "evt-name", name), el("span", "evt-tag", `IMR ${e.imr}`));
  card.append(head);
  if (desc) card.append(el("div", "evt-desc", desc));
  const rows = [["payload", payloadView(e, runtime), `${(e.event_payload || "").length / 2} B`], ["digest", e.digest || ""], [`→ RTMR${e.imr}`, after]];
  if (cross && cross.length) {
    const box = el("div", "marks");
    for (const [l, ok] of cross) box.append(mark(ok, `${ok ? "=" : "≠"} ${l}`));
    rows.push(["对照", box]);
  }
  card.append(kv(rows));
  return card;
}

function runtimeCross(e, t, gw) {
  const p = String(e.event_payload || "").toLowerCase();
  const out = [];
  if (e.event === "app-id") {
    const subj = t.keyset && t.keyset.subject;
    if (typeof subj === "string") out.push(["workload_keyset.subject", subj.endsWith(p)]);
    if (!gw && state.base && !state.local) out.push(["访问域名", new URL(state.base).host.startsWith(p + "-")]);
  } else if (e.event === "compose-hash") {
    if (t.compose) out.push(["sha256(app_compose)", t.compose.sha256 === p]);
    const cid = t.quote && t.quote.fields.mr_config_id;
    if (cid && cid.startsWith("01")) out.push(["quote.mr_config_id", cid.slice(2, 66) === p]);
  } else if (e.event === "os-image-hash") {
    if (t.image_ref) out.push([`${t.image_ref.name} 发布值`, t.image_ref.os_image_hash === p]);
    if (t.vm_config && t.vm_config.os_image_hash) out.push(["vm_config.os_image_hash", t.vm_config.os_image_hash === p]);
  }
  return out;
}

function bootCards(t, imr) {
  const b = t.boot && t.boot[imr];
  if (!b) return [];
  return [compare([[`重放 RTMR${imr}`, b.mr], [`quote RTMR${imr}`, b.quote]]),
          ...b.steps.map((st) => eventCard(t.events[st.index], st.index, st.rtmr, null))];
}

function receiptCards(receipt) {
  return (receipt.event_log || []).map((e, i) => {
    const card = el("div", "evt");
    const head = el("div", "evt-head");
    head.append(el("span", "evt-idx", `#${i}`), el("span", "evt-name", e.type));
    card.append(head);
    if (RECEIPT_EVENTS[e.type]) card.append(el("div", "evt-desc", RECEIPT_EVENTS[e.type]));
    card.append(kv(Object.entries(e).filter(([k]) => k !== "type").map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)])));
    return card;
  });
}

function collateralView(col) {
  const out = [];
  const rows = [];
  for (const [k, v] of Object.entries(col)) {
    const s = typeof v === "string" ? v : pretty(v);
    if (s.startsWith("-----BEGIN")) out.push(fold(k, code(s)));
    else if (/^[[{]/.test(s)) out.push(fold(k, code(prettyText(s))));
    else if (/^[0-9a-f]+$/i.test(s) && s.length > 256) rows.push([k, blob(s, V.hexToBytes(s))]);
    else rows.push([k, s]);
  }
  return [kv(rows), ...out];
}

function receiptOf(s, ctx) {
  return s.gw ? s.g && s.g.receipt : ctx.channel && ctx.channel.receipt;
}

function receiptHashCompare(receipt, type, localLabel, local) {
  return compare([[localLabel, local], [`回执 ${type}`, V.receiptHash(V.receiptEvent(receipt, type))]]);
}

const EVIDENCE = {
  "本次随机 nonce（防重放）": (s) => kv([["请求", `GET ${state.base}/v1/attestation?nonce=${s.nonce}`]]),
  "硬件证明：Intel TDX quote 签名链": ({ t, r }) => {
    const q = t.quote;
    if (!q) return null;
    const f = q.fields;
    const nodes = [];
    if (t.tcb) {
      nodes.push(kv([
        ["TCB 状态", t.tcb.status],
        ["安全公告", t.tcb.advisory_ids.length ? t.tcb.advisory_ids.join(", ") : "无"],
        ["FMSPC", (r.collateral && V.fmspcOf(r.collateral)) || undefined],
        ["抵押品", t.collateral_given ? COLLATERAL_NOTE : PCCS_URL],
        ["验证时间", utc(t.now)],
      ]));
    }
    nodes.push(fold(`Quote · ${q.size} B`,
      kv([["version", String(f.version)], ["tee_type", `0x${f.tee_type.toString(16)}`, "TDX"],
          ["att_key_type", String(f.att_key_type), "ECDSA P-256"], ["qe_vendor_id", f.qe_vendor_id],
          ...TD_FIELDS.map(([k, d]) => [k, f[k], d])]),
      blob(q.hex, V.hexToBytes(q.hex))));
    if (r.collateral) nodes.push(fold("Intel 抵押品", collateralView(r.collateral)));
    return nodes;
  },
  "非调试模式（TD_ATTRIBUTES.DEBUG = 0）": ({ t }) => {
    if (!t.quote) return null;
    const hex = t.quote.fields.td_attributes;
    const b = V.hexToBytes(hex);
    return kv([["td_attributes", hex], ...TD_ATTR_BITS.map(([n, name]) => [name, String((b[n >> 3] >> (n & 7)) & 1), `bit ${n}`])]);
  },
  "绑定公钥与 nonce（report_data）": (s) => EVIDENCE["绑定公钥与 nonce"](s),
  "绑定公钥与 nonce": ({ t }) => {
    if (!t.keyset) return null;
    const nodes = [fold("workload_keyset", code(pretty(t.keyset))),
                   fold("JCS(workload_keyset)", code(new TextDecoder().decode(V.jcs(t.keyset))))];
    const b = t.binding;
    if (b) {
      nodes.push(kv([["keyset_digest", b.keyset_digest, "sha256(JCS)"], ["nonce", b.nonce ?? "null"], ["statement", code(b.statement)]]),
                 compare([["sha256(statement) ‖ 0×32", b.expected], ["quote.report_data", b.actual]]));
    }
    return nodes;
  },
  "公钥集有效期": ({ t }) => {
    const ks = t.keyset;
    if (!ks) return null;
    const na = ks.not_after ?? (ks.keyset_epoch || {}).not_after;
    if (!Number.isInteger(na)) return null;
    return kv([["not_after", `${na} · ${utc(na)}`], ["验证时间", `${t.now} · ${utc(t.now)}`], ["剩余", `${((na - t.now) / 86400).toFixed(1)} 天`]]);
  },
  "事件日志重放 = quote 中的 RTMR3": ({ t, gw }) => {
    const rp = t.replay;
    if (!rp) return null;
    return [compare([["重放 RTMR3", rp.result], ["quote RTMR3", rp.quote]]),
            ...rp.steps.map((st) => eventCard(t.events[st.index], st.index, st.rtmr3, runtimeCross(t.events[st.index], t, gw)))];
  },
  "系统镜像是官方正式版（固件、内核、rootfs 的度量）": ({ t }) => {
    const m = t.mrs;
    if (!m) return null;
    const ref = t.image_ref;
    const osEvent = (t.events || []).find((e) => e.event === "os-image-hash");
    const nodes = [];
    if (ref) nodes.push(kv([["镜像", ref.name], ["发布包", RELEASES[ref.name]]]));
    nodes.push(
      compare([["MRTD · quote", m.mrtd], ["MRTD · 参考值", ref ? (ref.mrtd.includes(m.mrtd) ? m.mrtd : ref.mrtd.join("\n")) : null]]),
      compare([["RTMR1 · quote", m.rtmr1], ["RTMR1 · 参考值", ref ? ref.rtmr1 : null]]),
      compare([["RTMR2 · quote", m.rtmr2], ["RTMR2 · 参考值", ref ? ref.rtmr2 : null]]),
      compare([["os_image_hash · 参考值", ref ? ref.os_image_hash : null],
               ["os-image-hash 事件", osEvent ? String(osEvent.event_payload).toLowerCase() : null],
               ["vm_config.os_image_hash", (t.vm_config || {}).os_image_hash ?? null]]));
    for (const i of [1, 2]) if (t.boot && t.boot[i]) nodes.push(fold(`RTMR${i} 启动事件 · ${t.boot[i].steps.length}`, bootCards(t, i)));
    return nodes;
  },
  "虚拟硬件配置（RTMR0）与参考值一致": ({ t }) => {
    const m = t.mrs;
    if (!m) return null;
    const nodes = [compare([["RTMR0 · quote", m.rtmr0], ["RTMR0 · 参考值", t.rtmr0_ref ? m.rtmr0 : null, t.rtmr0_ref || undefined]])];
    if (t.vm_config) nodes.push(fold("vm_config", code(pretty(t.vm_config))));
    if (t.boot && t.boot[0]) nodes.push(fold(`RTMR0 启动事件 · ${t.boot[0].steps.length}`, bootCards(t, 0)));
    return nodes;
  },
  "部署配置哈希：sha256(app_compose) = 度量值": ({ t }) => {
    const c = t.compose;
    if (!c) return null;
    const cid = t.quote.fields.mr_config_id;
    const rows = [["sha256(app_compose)", c.sha256], ["compose-hash 事件", c.measured]];
    if (cid.startsWith("01")) rows.push(["quote.mr_config_id", cid.slice(2, 66), "去掉前缀 01"]);
    const nodes = [compare(rows)];
    const ac = t.app_compose;
    if (ac) {
      nodes.push(fold("app_compose", kv(Object.entries(ac).filter(([k]) => k !== "docker_compose_file").map(([k, v]) =>
        [k, typeof v === "string" ? (v.includes("\n") || v.length > 200 ? code(v) : v) : code(pretty(v))]))));
      if (typeof ac.docker_compose_file === "string") nodes.push(fold("docker_compose_file", code(ac.docker_compose_file)));
    }
    nodes.push(fold("app_compose 原文", blob(c.raw, textBytes(c.raw))));
    return nodes;
  },
  "部署配置哈希（compose-hash）": (s) => EVIDENCE["部署配置哈希：sha256(app_compose) = 度量值"](s),
  "镜像按 digest 固定": ({ t }) => (t.images && t.images.length ? kv(t.images.map((im, i) => [`image ${i + 1}`, im])) : null),
  "无法用 SSH 公钥 / root 密码登录": ({ t }) => {
    const l = t.login_envs;
    if (!l) return null;
    return kv([["allowed_envs", l.allowed_envs.join("\n") || "[]"], ["登录类变量", l.watched.join("\n")],
               ["重合", l.risky.join(", ") || "无"], ["系统镜像", t.image_ref ? t.image_ref.name : "未知"]]);
  },
  "内嵌源码与本地文件一致": ({ t }) => {
    const s = t.source;
    if (!s) return null;
    return [compare([["部署配置内嵌", s.sha256, "sha256"], ["本地 app.py", s.expected_sha256, "sha256"]]),
            fold(`内嵌 app.py · ${s.text.split("\n").length - 1} 行`, code(s.text))];
  },
  "加密通道：消息用证明里的公钥加密，CVM 解密并加密回复": (s, ctx) => {
    const ch = ctx.channel;
    if (!ch) return null;
    const env = ch.request.envelope;
    const resp = ch.response.envelope;
    return [
      kv([["算法", ch.server_key.algo], ["CVM 公钥", ch.server_key.public_key, ch.server_key.key_id],
          ["本地临时公钥", ch.client_public_key, "X25519"],
          ["会话密钥", "HKDF-SHA256(X25519 共享密钥, info = pa-mvp/e2ee/v1 ‖ 本地公钥 ‖ CVM 公钥)"],
          ["请求 AAD", `pa-mvp/req/v1|${ch.keyset_digest}`],
          ["响应 AAD", `pa-mvp/resp/v1|${ch.keyset_digest}|${env.nonce}`]]),
      fold("请求密文", kv([["key_id", env.key_id], ["client_public_key", env.client_public_key], ["nonce", env.nonce],
                          ["ciphertext", blob(env.ciphertext, V.hexToBytes(env.ciphertext))]])),
      fold("响应密文", kv([["nonce", resp.nonce], ["ciphertext", resp.ciphertext ? blob(resp.ciphertext, V.hexToBytes(resp.ciphertext)) : null]])),
    ];
  },
  "加密通道：只有被证明的 CVM 能解开": (s, ctx) => EVIDENCE["加密通道：消息用证明里的公钥加密，CVM 解密并加密回复"](s, ctx),
  "加密流：每帧单独加密，序号连续": (s, ctx) => {
    const ch = ctx.channel;
    if (!ch) return null;
    const env = ch.request.envelope;
    return [kv([["算法", ch.server_key.algo], ["CVM 公钥", ch.server_key.public_key, ch.server_key.key_id], ["本地临时公钥", ch.client_public_key, "X25519"],
                ["请求 AAD", `pa-mvp/req/v1|${ch.keyset_digest}`], ["帧 AAD", `pa-mvp/stream/v1|${ch.keyset_digest}|${env.nonce}|<序号>`],
                ["帧数", String(ch.response.frames)], ["解密后", `${ch.response.size} B · ${ch.response.sha256}`]]),
            fold("请求信封", kv(Object.entries(env).map(([k, v]) => [k, String(v)])))];
  },
  "CVM 回执：流式回复哈希 = 我收到的全部帧": (s, ctx) => {
    const ch = ctx.channel;
    if (!ch || !ch.receipt) return null;
    return [receiptHashCompare(ch.receipt, "response.returned", "sha256 · 全部帧明文（换行连接）", ch.response.sha256)];
  },
  "回执签名（公钥来自已验证的证明）": (s, ctx) => {
    const receipt = receiptOf(s, ctx);
    const keyset = s.gw ? s.t.keyset : ctx.res.trace && ctx.res.trace.keyset;
    if (!receipt) return null;
    const key = ((keyset && keyset.receipt_signing_keys) || []).find((k) => k.key_id === receipt.key_id);
    const doc = { ...receipt };
    delete doc.signature;
    return [
      kv([["key_id", receipt.key_id ?? null], ["公钥", key ? key.public_key : null, key ? key.algo : undefined], ["signature", receipt.signature ?? null]]),
      fold("回执", code(pretty(receipt))),
      fold("签名内容 · JCS(回执 − signature)", code(new TextDecoder().decode(V.jcs(doc)))),
    ];
  },
  "CVM 回执：公钥集摘要一致": (s, ctx) => {
    const receipt = receiptOf(s, ctx);
    return receipt ? compare([["回执 workload_keyset_digest", receipt.workload_keyset_digest ?? null], ["已验证公钥集", ctx.res.keyset_digest]]) : null;
  },
  "CVM 回执：请求哈希 = 我发出的内容": (s, ctx) => {
    const ch = ctx.channel;
    if (!ch || !ch.receipt) return null;
    return [receiptHashCompare(ch.receipt, "request.received", "sha256 · 本地请求明文", ch.request.sha256),
            fold(`请求明文 · ${ch.request.size} B`, code(pretty(ch.request.plain)))];
  },
  "CVM 回执：回复哈希 = 我收到的内容": (s, ctx) => {
    const ch = ctx.channel;
    if (!ch || !ch.receipt || !ch.response.plain) return null;
    return [receiptHashCompare(ch.receipt, "response.returned", "sha256 · 解密后的回复", ch.response.sha256),
            fold(`回复明文 · ${ch.response.size} B`, jsonView(ch.response.plain))];
  },
  "源码出处（与度量配置中的 REPO_COMMIT 比对）": ({ r }) => {
    if (!r.provenance) return null;
    const measured = V.composeRepoCommits(r.app_compose);
    return [compare([["source_provenance.repo_commit", String(r.provenance.repo_commit ?? "").toLowerCase() || null],
                     ["PRIVATE_AI_GATEWAY_REPO_COMMIT", measured.join(", ") || null, "度量配置 docker_compose_file"]]),
            fold("source_provenance", code(pretty(r.provenance)))];
  },
  "推理请求经网关返回": ({ g }) => (g ? kv([
    ["请求", `POST ${GATEWAY_URL}/v1/chat/completions`], ["HTTP", g.status], ["模型", g.model],
    ["x-receipt-id", g.receipt_id], ["请求体", `${g.request.size} B`], ["响应体", `${g.response.size} B`],
  ]) : null),
  "CVM 发给网关的就是我的消息（未被改写）": ({ g }) => (g ? [
    fold(`CVM 发出的请求体 · ${g.request.size} B`, code(prettyText(g.request.text))),
    fold("我的消息", code(pretty(g.messages))),
  ] : null),
  "网关回执：公钥集摘要 = 刚验证过的网关": (s) => {
    const receipt = s.g && s.g.receipt;
    return receipt ? compare([["回执 workload_keyset_digest", receipt.workload_keyset_digest ?? null], ["已验证网关公钥集", s.r.keyset_digest]]) : null;
  },
  "网关回执：workload_id 一致": (s) => {
    const receipt = s.g && s.g.receipt;
    return receipt ? compare([["回执 workload_id", receipt.workload_id ?? null], ["网关证明 workload_id", s.g.attestation.workload_id ?? null]]) : null;
  },
  "网关回执：请求哈希 = CVM 实际发出的字节": ({ g }) => (g && g.receipt ? [
    receiptHashCompare(g.receipt, "request.received", "sha256 · CVM 发出的字节", g.request.sha256),
    fold(`请求体 · ${g.request.size} B`, code(prettyText(g.request.text))),
  ] : null),
  "网关回执：回复哈希 = CVM 实际收到的字节": ({ g }) => (g && g.receipt ? [
    receiptHashCompare(g.receipt, "response.returned", "sha256 · CVM 收到的字节", g.response.sha256),
    fold(`响应体 · ${g.response.size} B`, code(prettyText(g.response.text))),
  ] : null),
  "网关回执：上游 TEE 已验证（网关声明，upstream.verified）": ({ g }) => {
    if (!g || !g.receipt) return null;
    const up = V.receiptEvent(g.receipt, "upstream.verified");
    const route = V.receiptEvent(g.receipt, "route.selected");
    return [kv([["性质", "网关签名的声明；GPU 证明取决于路由到的上游，见 session_id"],
                ["上游路由", route ? route.target_route_id : undefined]]),
            up ? kv(Object.entries(up).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)])) : null,
            fold(`回执事件 · ${(g.receipt.event_log || []).length}`, receiptCards(g.receipt))];
  },
  "CVM→网关 TLS 公钥在证明里": ({ t, g }) => {
    if (!g) return null;
    const keys = (t.keyset && t.keyset.tls_public_keys) || [];
    const ev = ((g.attestation.attestation || {}).evidence || {}).downstream_tls_binding;
    const nodes = [kv([["观察到", g.spki, "TLS 证书公钥 sha256"]])];
    nodes.push(kv(keys.map((k, i) => {
      const box = el("div");
      box.append(el("div", null, k.spki_sha256));
      if (V.hostMatches(k.domain, V.GATEWAY_HOST)) box.append(mark(k.spki_sha256 === g.spki, k.spki_sha256 === g.spki ? "= 观察到" : "≠ 观察到"));
      return [k.domain || `tls ${i + 1}`, box, "tls_public_keys"];
    })));
    if (ev) nodes.push(fold("downstream_tls_binding", code(pretty(ev))));
    return nodes;
  },
};

function quoteFold(hex, title) {
  const q = V.hexToBytes(hex);
  const f = V.parseTdReport(q);
  const rows = TD_FIELDS.map(([k, d]) => [k, f[k] instanceof Uint8Array ? V.bytesToHex(f[k]) : String(f[k]), d === "公钥集与 nonce 的绑定" ? undefined : d]);
  return fold(`${title} · ${q.length} B`, kv(rows), blob(hex, q));
}

function claimRows(c) {
  return kv(Object.entries(c).filter(([, v]) => typeof v !== "object").map(([k, v]) => [k, String(v)]));
}

function deployCards(list) {
  return list.slice().reverse().map((a, i) => {
    const card = el("div", "evt");
    const head = el("div", "evt-head");
    head.append(el("span", "evt-idx", `#${list.length - i}`), el("span", "evt-name", `${a.tag ?? ""} · ${a.file ?? ""}`), el("span", "evt-tag", a.timestamp ? a.timestamp.slice(0, 19).replace("T", " ") : ""));
    card.append(head, kv([["commit", a.commit ?? null], ["file_sha256", a.file_sha256 ?? undefined], ["services", (a.services || []).join(", ") || undefined]]));
    return card;
  });
}

const pickRef = (list, v) => (list.includes(v) ? v : list.join("\n"));

const UPSTREAM = {
  "沿用本会话的上游验证": (t) => (t.reused ? kv([["上次验证", new Date(t.reused.verified_at * 1000).toLocaleString("zh-CN", { hour12: false })],
                                               ["那次的随机数", t.nonce, "本会话之前发出过"],
                                               ["说明", "沿用本会话的模型机证明，以下为浏览器复核"]]) : null),
  "本次随机数": (t, p) => kv([["nonce", t.nonce], ["请求", p === "chutes"
    ? `CVM → GET api.chutes.ai/instances/${t.up.instance_id ?? "…"}/evidence?nonce=…`
    : "CVM → GET cloud-api.near.ai/v1/attestation/report?signing_algo=ed25519&nonce=…"], ["模型", t.model]]),
  "跳过未通过验证的实例": (t) => kv((t.up.attempts || []).map((a, i) => [`#${i + 1}`, `${a.instance_id || a.signing_address}\n${a.error}`])),
  "证据签名（实例证书）": (t) => [
    kv([["instance_id", t.up.instance_id], ["证书公钥", t.cert_spki_sha256, "sha256(SPKI)"], ["signature", blob(t.up.evidence.signature, Uint8Array.from(atob(t.up.evidence.signature), (x) => x.charCodeAt(0)))]]),
    fold("签名覆盖的原始响应 attested_body", jsonView(t.doc)),
    fold("实例证书（DER, base64）", code(t.up.evidence.certificate)),
  ],
  "证据里的随机数是本次的": (t) => compare([["证据 nonce", t.doc.nonce ?? null], ["本次 nonce", t.nonce]]),
  "Intel TDX quote 签名链": (t) => [kv([["抵押品", COLLATERAL_NOTE]]), quoteFold(t.quote, "Quote")],
  "非调试模式": (t) => kv([["td_attributes", V.bytesToHex(V.parseTdReport(V.hexToBytes(t.quote)).td_attributes)]]),
  "quote 绑定实例证书（report_data[32:64]）": (t) => compare([["sha256(实例证书 SPKI)", t.cert_spki_sha256], ["quote.report_data[32:64]", t.report_data.slice(64)]]),
  "quote 绑定本次随机数和加密公钥（report_data[0:32]）": (t) => [
    kv([["nonce", t.binding.nonce], ["e2e_pubkey", blob(t.binding.e2e_pubkey, new TextEncoder().encode(t.binding.e2e_pubkey)), "ML-KEM-768，base64"]]),
    compare([["sha256(nonce ‖ e2e_pubkey)", t.binding.expected], ["quote.report_data[0:32]", t.binding.actual]]),
  ],
  "度量值命中参考值快照（MRTD、RTMR0-3）": (t) => {
    const row = t.row;
    const im = row ? V.CHUTES_PINS.images[row[0]] : null;
    return [kv([["参考值", row ? `Chutes ${row[0]} · ${row[1]}` : "无"], ["快照", `${V.CHUTES_PINS.source} · ${V.CHUTES_PINS.fetched}`],
                ["GPU", row ? `${row[4]} × ${row[3].join("/")}` : undefined]]),
            ...["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"].map((k) => compare([[`${k.toUpperCase()} · quote`, t.regs[k]],
              [`${k.toUpperCase()} · 参考值`, row ? (k === "rtmr0" ? row[2] : im[k]) : null]]))];
  },
  "NVIDIA GPU 证明（NRAS）": (t) => (t.nras ? [kv([["令牌", `${t.nras.tokens} 个 ES384 JWT`], ["签名证书", "x5c 链到 NVIDIA Attestation Service GPU Intermediate（固定 SPKI）"]]),
    fold("总体结论", claimRows(t.nras.overall))] : null),
  "GPU 状态与型号": (t) => (t.nras ? t.nras.gpus.map((c, i) => fold(`GPU ${i} · ${c.hwmodel}`, claimRows(c))) : null),
  "CVM 发出的就是我的消息": (t) => [fold("CVM 加密前的请求", code(pretty(t.up.request || t.up.plain_messages || null))), fold("我的消息", code(pretty(t.messages)))],
  "加密发送，只有这台实例能解开": (t) => [
    kv([["算法", "ML-KEM-768 封装 + HKDF-SHA256 + ChaCha20-Poly1305"], ["加密公钥", "e2e_pubkey，已绑定在 quote 的 report_data[0:32]"],
        ["请求密文", `${t.up.request_ciphertext_bytes} B`], ["回复密文", `${t.up.response_ciphertext_bytes} B`],
        ["验证耗时", `${t.up.verify_seconds}s`], ["推理耗时", `${t.up.invoke_seconds}s`]]),
    t.up.response ? fold("解密后的回复", jsonView(t.up.response)) : null,
  ],
  "quote 绑定模型公钥（report_data[0:32]）": (t) => compare([["signing_address（Ed25519 公钥）", t.key], ["quote.report_data[0:32]", t.report_data.slice(0, 64)]]),
  "quote 绑定本次随机数（report_data[32:64]）": (t) => compare([["本次 nonce", t.nonce], ["quote.report_data[32:64]", t.report_data.slice(64)]]),
  "事件日志重放 = quote 中的 RTMR3": (t) => (t.replay ? [compare([["重放 RTMR3", t.replay.result], ["quote RTMR3", t.replay.quote]]),
    ...t.replay.steps.map((st) => eventCard(t.events[st.index], st.index, st.rtmr3, null))] : null),
  "部署配置哈希：sha256(app_compose) = 度量值": (t) => [compare([["sha256(app_compose)", t.compose.sha256], ["compose-hash 事件", t.compose.measured]]),
    t.app_compose && typeof t.app_compose.docker_compose_file === "string" ? fold("docker_compose_file", code(t.app_compose.docker_compose_file)) : null,
    t.app_compose && t.app_compose.pre_launch_script ? fold("pre_launch_script", code(t.app_compose.pre_launch_script)) : null],
  "系统镜像与虚拟硬件（MRTD、RTMR0-2）": (t) => {
    const P = V.NEAR_PINS;
    return [kv([["参考值", `${P.image}：MRTD、RTMR1 由 dstack-mr 从官方 dstack 0.5.12 发布包算出；RTMR2（NVIDIA 版内核参数）、RTMR0 为 ${P.observed} 实测`]]),
            compare([["MRTD · quote", t.regs.mrtd], ["MRTD · 参考值", pickRef(P.mrtd, t.regs.mrtd)]]),
            compare([["RTMR0 · quote", t.regs.rtmr0], ["RTMR0 · 参考值", pickRef(P.rtmr0, t.regs.rtmr0), `已固定 ${P.rtmr0.length} 台`]]),
            compare([["RTMR1 · quote", t.regs.rtmr1], ["RTMR1 · 参考值", P.rtmr1]]),
            compare([["RTMR2 · quote", t.regs.rtmr2], ["RTMR2 · 参考值", P.rtmr2]])];
  },
  "os-image-hash 与参考值一致": (t) => compare([["os-image-hash 事件", String(((t.events || []).find((e) => e.event === "os-image-hash") || {}).event_payload ?? "").toLowerCase() || null],
                                                ["参考值", V.NEAR_PINS.os_image_hash]]),
  "密钥来自固定的 NEAR KMS（key-provider）": (t) => compare([["key-provider 事件里的 KMS 公钥", t.kms], ["参考值", V.NEAR_PINS.kms]]),
  "app-id 和部署配置是固定的那一份": (t) => [compare([["app-id 事件", t.app_id], ["参考值", pickRef(V.NEAR_PINS.app_ids, t.app_id)]]),
                                         compare([["compose-hash", t.compose.sha256], ["参考值", pickRef(V.NEAR_PINS.compose_hashes, t.compose.sha256),
                                                  `已固定 ${V.NEAR_PINS.compose_hashes.length} 台`]])],
  "模型公钥由同一应用的多台机器共用": (t) => kv([["模型公钥", t.key], ["app-id", t.app_id], ["本次验证的机器", t.instance_id, "instance-id"],
                                               ["已固定的机器", `${V.NEAR_PINS.compose_hashes.length} 台（部署配置只差主机名和 compose-manager 默认镜像）`],
                                               ["密钥来源", "NEAR KMS 按 app-id 派生"]]),
  "部署日志 · Intel TDX quote 签名链": (t) => (t.cm_quote ? quoteFold(t.cm_quote, "部署日志 Quote") : null),
  "部署日志和模型在同一台机器（MRTD、RTMR0-3）": (t) => {
    if (!t.cm_quote) return null;
    const f = V.parseTdReport(V.hexToBytes(t.cm_quote));
    return ["mr_td", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3"].map((k) => compare([[`${k} · 部署日志`, V.bytesToHex(f[k])], [`${k} · 模型`, V.bytesToHex(V.parseTdReport(V.hexToBytes(t.quote))[k])]]));
  },
  "部署日志哈希绑定在 quote 里": (t) => (t.cm ? [kv([["actions_hash", t.cm.actions_hash], ["nonce_source", t.cm.nonce_source ?? undefined]]),
    compare([["quote.report_data[0:32]", V.bytesToHex(V.parseTdReport(V.hexToBytes(t.cm_quote)).report_data).slice(0, 64)], ["actions_hash", t.cm.actions_hash]]),
    fold(`actions · ${(t.cm.actions || []).length}`, code(pretty(t.cm.actions)))] : null),
  "模型代码由 compose-manager 运行时部署，不在硬件度量里": (t) => [
    kv([["含义", "硬件度量只覆盖 compose-manager；proxy 在运行时部署，不在 RTMR3 里"],
        ["部署配置仓库", "github.com/nearai/cvm-compose-files"]]),
    fold(`部署记录 · ${(t.deploys || []).length}`, deployCards(t.deploys || [])),
  ],
  "GPU 证据用的是本次随机数": (t) => kv([["本次 nonce", t.nonce]]),
  "加密发送，只有这台模型机能解开": (t) => [
    kv([["客户端公钥", t.up.client_public_key, "X-Client-Pub-Key，明文请求头"], ["模型公钥", t.key, "X-Model-Pub-Key"],
        ["验证耗时", `${t.up.verify_seconds}s`], ["推理耗时", `${t.up.invoke_seconds}s`]]),
    t.up.reasoning ? fold("思考过程（CVM 解密后）", code(t.up.reasoning)) : null,
    t.request ? fold("发给 NEAR 的请求（正文已加密）", code(prettyText(t.request.text))) : null,
    t.response ? fold("NEAR 返回（正文已加密）", code(prettyText(t.response.text))) : null,
  ],
  "回复签名（模型机密钥）": (t) => {
    if (!t.signature) return null;
    const [model, req, resp] = String(t.signature.text || "").split(":");
    return [kv([["签名内容", code(`模型   ${model}\n请求   ${req}\n回复   ${resp}`)], ["signature", t.signature.signature, "Ed25519"],
                ["签名者", t.signature.signing_address], ["类型", t.signature.signature_kind ?? null, "provider_tee = 模型机 TEE 里签的"]]),
            compare([["签名者", String(t.signature.signing_address || "").replace(/^0x/, "").toLowerCase()], ["已验证的模型公钥", t.key]])];
  },
  "签名覆盖的请求 = CVM 发出的字节": (t) => (t.signature && t.request ? compare([["签名里的请求哈希", String(t.signature.text).split(":").slice(-2)[0]], ["sha256(CVM 发出的字节)", t.request.sha256]]) : null),
  "签名覆盖的回复 = CVM 收到的字节": (t) => (t.signature && t.response ? compare([["签名里的回复哈希", String(t.signature.text).split(":").slice(-1)[0]], ["sha256(CVM 收到的字节)", t.response.sha256]]) : null),
};

function upstreamLinks(u) {
  const t = u.trace || {};
  const out = [];
  if (u.provider === "chutes") {
    out.push(["Chutes TEE 验证说明", "https://github.com/chutesai/chutes-api/blob/main/docs/tee-verification.md"],
             ["Chutes 参考值（公开接口）", V.CHUTES_PINS.source],
             ["Chutes 模型 · confidential_compute", "https://llm.chutes.ai/v1/models"],
             ["Chutes 系统镜像 sek8s", "https://github.com/chutesai/sek8s"]);
  } else {
    const last = (t.deploys || []).slice(-1)[0];
    out.push(["NEAR 官方验证器", "https://github.com/nearai/nearai-cloud-verifier"]);
    if (last && /^[0-9a-f]{40}$/.test(last.commit || "")) out.push([`部署配置 ${last.tag} · ${last.file}`, `https://github.com/nearai/cvm-compose-files/blob/${last.commit}/${last.file}`]);
    out.push(["NEAR inference-proxy 源码", "https://github.com/nearai/inference-proxy"],
             ["NEAR compose-manager 源码", "https://github.com/nearai/compose-manager"],
             ["NEAR 模型列表", "https://cloud-api.near.ai/v1/models"]);
  }
  out.push(["NVIDIA NRAS 公钥", "https://nras.attestation.nvidia.com/.well-known/jwks.json"]);
  if (MODEL_PAGES[u.model]) out.push([`模型 ${u.model}`, MODEL_PAGES[u.model]]);
  return out;
}

function tamperEvidence(c) {
  const rows = [...(c.change || [])];
  if (c.hit) rows.push(["拦截于", label(c.hit.name)], ["原因", c.hit.detail]);
  else if (c.change) rows.push(["结果", c.detail]);
  return rows.length ? kv(rows) : null;
}

function evidenceFor(rec, key, c) {
  const ctx = rec.context;
  if (key === "tamper") return tamperEvidence(c);
  if (!ctx || !ctx.res || key === "info") return null;
  if (key === "gateway" && ctx.upstream) {
    const fn = UPSTREAM[c.name.replace(/^(Chutes|NEAR) · /, "")];
    if (!fn) return null;
    try {
      const nodes = [].concat(fn(ctx.upstream.trace, ctx.upstream.provider) || []).filter(Boolean);
      return nodes.length ? nodes : null;
    } catch {
      return null;
    }
  }
  const base = c.name.replace(/^网关 · /, "");
  const fn = EVIDENCE[base];
  if (!fn) return null;
  let s;
  if (key === "gateway") {
    const gw = ctx.gateway;
    if (!gw) return null;
    s = { t: (gw.report && gw.report.trace) || {}, r: gw.report || {}, gw: true, nonce: gw.nonce, g: gw.trace };
  } else s = { t: ctx.res.trace || {}, r: ctx.res, gw: false, nonce: ctx.nonce, g: null };
  try {
    const out = fn(s, ctx);
    const nodes = [].concat(out || []).filter(Boolean);
    return nodes.length ? nodes : null;
  } catch {
    return null;
  }
}

function dockerHubUrl(image) {
  const m = image.match(/^([a-z0-9._-]+):([\w.-]+)@sha256:([0-9a-f]{64})$/);
  return m ? [`${m[1]}:${m[2]}`, `https://hub.docker.com/layers/library/${m[1]}/${m[2]}/images/sha256-${m[3]}`] : null;
}

function publicLinks(rec) {
  const ctx = rec.context;
  if (!ctx || !ctx.res) return [];
  const m = ctx.res.measurements || {};
  const out = [["CVM 证明原文", `${state.base}/v1/attestation?nonce=${ctx.nonce}`]];
  const host = new URL(state.base).host.match(/^([0-9a-f]{40})-\d+\.(.+)$/);
  if (host) out.push(["CVM 系统信息", `https://${host[1]}-8090.${host[2]}/`]);
  if (RELEASES[m.image]) out.push([`系统镜像 ${m.image}`, RELEASES[m.image]]);
  const fmspc = ctx.res.collateral && V.fmspcOf(ctx.res.collateral);
  if (fmspc) out.push([`Intel TCB · FMSPC ${fmspc}`, `https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=${fmspc}`]);
  try {
    for (const img of V.composeImages(JSON.parse(ctx.report.attestation.evidence.app_compose))) {
      const hub = dockerHubUrl(img);
      if (hub) out.push([`基础镜像 ${hub[0]}`, hub[1]]);
    }
  } catch {}
  out.push(["源码 app.py", new URL("app.py", location.href).href]);
  const g = ctx.gateway;
  if (g) {
    out.push(["网关证明原文", `${GATEWAY_URL}/v1/aci/attestation?nonce=${g.nonce}`]);
    const gm = (g.report && g.report.measurements) || {};
    if (RELEASES[gm.image]) out.push([`网关系统镜像 ${gm.image}`, RELEASES[gm.image]]);
    const gf = g.report && g.report.collateral && V.fmspcOf(g.report.collateral);
    if (gf) out.push([`网关 Intel TCB · FMSPC ${gf}`, `https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=${gf}`]);
    const prov = g.report && g.report.provenance;
    if (prov && /^https:\/\/github\.com\//.test(prov.repo_url || "") && /^[0-9a-f]{40}$/.test(prov.repo_commit || "")) {
      out.push([`网关源码 @ ${prov.repo_commit.slice(0, 7)}`, `${prov.repo_url.replace(/\.git$/, "")}/tree/${prov.repo_commit}`]);
    }
    out.push(["模型列表 · is_tee", `${GATEWAY_URL}/v1/models`]);
    if (MODEL_PAGES[g.model]) out.push([`模型 ${g.model}`, MODEL_PAGES[g.model]]);
  }
  if (ctx.upstream) out.push(...upstreamLinks(ctx.upstream));
  return [...out, ...REFERENCES];
}

function renderLinks(rec) {
  const links = publicLinks(rec);
  if (!links.length) return null;
  const sec = el("section", "section links");
  const head = el("div", "section-head");
  head.append(el("div", "section-title", "公开校验"));
  sec.append(head);
  const ul = el("ul", "link-list");
  for (const [name, url] of links) {
    const li = el("li");
    const a = el("a", "link-row");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.append(el("span", "link-name", name), el("span", "link-url mono", url.replace(/^https?:\/\//, "")), el("span", "link-arrow", "↗"));
    li.append(a);
    ul.append(li);
  }
  const quote = rec.context.report.attestation.evidence.quote;
  const li = el("li", "link-tools");
  const ex = el("a", "link-row");
  ex.href = "https://proof.t16z.com/";
  ex.target = "_blank";
  ex.rel = "noopener noreferrer";
  ex.append(el("span", "link-name", "Quote Explorer"), el("span", "link-url mono", "proof.t16z.com"), el("span", "link-arrow", "↗"));
  const copy = el("button", "btn ghost small", "复制 Quote");
  copy.type = "button";
  copy.addEventListener("click", async () => {
    copy.textContent = (await copyText(quote)) ? "已复制" : "复制失败";
    setTimeout(() => { copy.textContent = "复制 Quote"; }, 1600);
  });
  li.append(ex, copy);
  ul.append(li);
  sec.append(ul);
  return sec;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = el("textarea", "clip");
    ta.value = text;
    ta.readOnly = true;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

function reveal(rec, key, behavior) {
  if (state.selected !== rec.id) return;
  const sec = $(`#panel .section[data-key="${key}"]`);
  if (sec) sec.scrollIntoView({ block: "start", behavior });
}

async function runTamper(rec) {
  if (!rec.context || rec.partial || rec.stages.tamper === "running") return;
  rec.stages.tamper = "running";
  rec.sections.tamper = [];
  refresh(rec);
  reveal(rec, "tamper", "auto");
  try {
    const rows = await V.tamperDemo(rec.context.report, rec.context.nonce, rec.context.res, { quoteVerifier: state.quoteVerifier });
    rec.sections.tamper = rows;
    rec.stages.tamper = worst(rows);
    if (rec.result) rec.result.tamper_demo = rows;
  } catch (e) {
    rec.stages.tamper = "fail";
    rec.sections.tamper = [{ name: "篡改测试", status: "FAIL", detail: errText(e) }];
  }
  rec.sections.tamper.forEach((_, i) => rec.open.add(`tamper:${i}`));
  refresh(rec);
  reveal(rec, "tamper", "smooth");
  saveRecord(rec);
}

function download(rec) {
  const { raw_attestation, ...rest } = rec.result;
  const url = URL.createObjectURL(new Blob([JSON.stringify({ ...rest, raw_attestation }, null, 2)], { type: "application/json" }));
  const a = el("a");
  a.href = url;
  a.download = `report-${rec.id}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const hashArgs = new URLSearchParams(location.hash.slice(1));
let resume = null;
try { resume = JSON.parse(sessionStorage.getItem("pa-login") || "null"); } catch {}
$("#cvm-url").value = hashArgs.get("endpoint") || new URLSearchParams(location.search).get("endpoint") || (resume && resume.base) || "";
if (hashArgs.get("key")) $("#access-key").value = hashArgs.get("key");
else if (resume && resume.base === $("#cvm-url").value) $("#access-key").value = resume.token || "";
if (location.hash) history.replaceState(null, "", location.pathname + location.search);
$("#login-form").addEventListener("submit", onLogin);
$("#composer").addEventListener("submit", onSend);
$("#logout-btn").addEventListener("click", logout);
$("#internet").addEventListener("change", () => setInternet($("#internet").checked));
$("#panel-btn").addEventListener("click", () => setPanel($(".columns").classList.contains("collapsed")));
try { if (localStorage.getItem("pa-panel") === "0") setPanel(false); } catch {}
$("#model").addEventListener("change", () => { state.modelSel[state.provider] = $("#model").value; renderProviders(); renderAtts(); });
$("#attach-btn").addEventListener("click", () => $("#file-input").click());
$("#file-input").addEventListener("change", async (e) => { await readFiles([...e.target.files]); e.target.value = ""; });
$("#msg").addEventListener("paste", (e) => {
  const files = [...(e.clipboardData ? e.clipboardData.files : [])];
  if (state.agent && files.length) { e.preventDefault(); readFiles(files); }
});
for (const t of ["dragover", "dragleave", "drop"]) {
  $("#composer").addEventListener(t, (e) => {
    if (!state.agent) return;
    e.preventDefault();
    $("#composer").classList.toggle("drag", t === "dragover");
    if (t === "drop") readFiles([...e.dataTransfer.files]);
  });
}
setInterval(pollHistory, 15000);
$("#msg").addEventListener("input", updateComposer);
$("#interrupt-btn").addEventListener("click", interruptSend);
$("#msg").addEventListener("keydown", (e) => {
  if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
  e.preventDefault();
  if ((e.metaKey || e.ctrlKey) && state.agent && chatOf(state.chat).busy) interruptSend();
  else $("#composer").requestSubmit();
});
(["#cvm-url", "#access-key"].map((q) => $(q)).find((x) => !x.value) || $("#login-btn")).focus();
if (resume && resume.base === $("#cvm-url").value && $("#access-key").value) $("#login-form").requestSubmit();
