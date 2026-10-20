import * as V from "./verify.js";

const CVM_URL = "https://c3fd4ff7f667603320296795348aa605e214d51b-8080.dstack-pha-prod5.phala.network";
const PCCS_URL = "https://pccs.phala.network";
const GATEWAY_URL = "https://inference.phala.com";

const RELEASES = {
  "dstack-0.6.1": "https://github.com/Dstack-TEE/dstack/releases/tag/mkosi-os-v0.6.1",
  "dstack-0.5.12": "https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.12",
  "dstack-0.5.9": "https://github.com/Dstack-TEE/meta-dstack/releases/tag/v0.5.9",
};
const MODEL_PAGES = { "z-ai/glm-5.3-flash": "https://huggingface.co/zai-org/GLM-5.3-Flash" };
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
  "把部署配置改一个字（换镜像）": "篡改 compose",
  "拿旧证明冒充（换一个 nonce 验证）": "重放旧证明",
  "中间人换掉加密公钥": "替换加密公钥",
  "改 quote 里一个比特（伪造硬件证明）": "篡改 Quote",
};

const label = (name) => {
  const base = name.replace(/^网关 · /, "");
  return LABELS[base] || base;
};

const $ = (sel, el = document) => el.querySelector(sel);
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

const state = { base: null, token: null, source: null, quoteVerifier: null, conversation: [], records: [], selected: null, busy: false, seq: 0 };

const STATE_LABEL = { idle: "WAIT", running: "RUNNING", pass: "PASS", warn: "WARN", fail: "FAIL", skipped: "SKIP" };
const VERDICT = { running: "验证中", pass: "已验证", warn: "已验证 · 有警告", fail: "未通过", blocked: "未发送", error: "错误" };
const BADGE = { running: "验证中", pass: "已验证", warn: "警告", fail: "未通过", blocked: "未发送", error: "错误" };
const SECTION_TITLE = { cvm: "① 机器与代码", channel: "② 加密通道", gateway: "③ 推理链路", tamper: "篡改测试" };

const worst = (checks) => {
  const s = checks.map((c) => c.status);
  return s.includes("FAIL") ? "fail" : s.includes("WARN") ? "warn" : "pass";
};
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
    reply: null, auth: null, blocked: false, serviceError: null, error: null, simulated: false,
  };
  state.records.push(rec);
  return rec;
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
    rec = newRecord("login", "登录");
    line = log.add("attest", "typing");
    for await (const [kind, data] of V.run(base, { quoteVerifier: state.quoteVerifier, token, expectSource: state.source, authOnly: true })) {
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
      return;
    }
    enterApp(rec);
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
  $("#session-chip").textContent = `${m.image || "TDX"} · TDX`;
  addTurn(loginRec);
  select(loginRec.id);
  $("#msg").focus();
}

function logout() {
  Object.assign(state, { token: null, conversation: [], records: [], selected: null });
  $("#thread").textContent = "";
  $("#panel").textContent = "";
  log.clear();
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#access-key").focus();
}

async function onSend(ev) {
  ev.preventDefault();
  const text = $("#msg").value.trim();
  if (!text || state.busy) return;
  state.busy = true;
  $("#send-btn").disabled = true;
  $("#msg").value = "";
  const simulate = $("#simulate").checked;
  const rec = newRecord("message", text);
  rec.simulated = simulate;
  addTurn(rec);
  select(rec.id);
  const source = simulate ? V.concat(state.source, "\n# demo: one extra local line\n") : state.source;
  try {
    for await (const [kind, data] of V.run(state.base, {
      quoteVerifier: state.quoteVerifier, token: state.token, expectSource: source,
      messages: [...state.conversation, { role: "user", content: text }],
    })) {
      apply(rec, kind, data);
      refresh(rec);
    }
  } catch (e) {
    failRecord(rec, e);
  }
  refresh(rec);
  if (rec.reply && rec.reply.text && !rec.blocked && rec.status !== "error") {
    state.conversation.push({ role: "user", content: text }, { role: "assistant", content: rec.reply.text });
  }
  state.busy = false;
  $("#send-btn").disabled = false;
  $("#msg").focus();
}

function addTurn(rec) {
  const li = el("li", "turn");
  li.dataset.id = rec.id;
  const meta = el("div", "bubble-meta");
  meta.append(el("span", "badge " + rec.status, BADGE[rec.status]), el("span", null, clock(rec.time)));
  if (rec.kind === "login") {
    const b = el("button", "bubble system");
    b.type = "button";
    b.append(el("span", null, "已登录"), meta);
    b.addEventListener("click", () => select(rec.id));
    li.append(b);
  } else {
    if (rec.simulated) meta.append(el("span", null, "· 模拟篡改"));
    const u = el("button", "bubble user");
    u.type = "button";
    u.append(el("div", null, rec.title), meta);
    u.addEventListener("click", () => select(rec.id));
    const a = el("div", "bubble agent");
    a.append(el("span", "typing-dots"));
    a.addEventListener("click", () => select(rec.id));
    li.append(u, a);
  }
  $("#thread").append(li);
  li.scrollIntoView({ block: "end", behavior: "smooth" });
}

function updateTurn(rec) {
  const li = $(`#thread .turn[data-id="${rec.id}"]`);
  if (!li) return;
  const badge = $(".badge", li);
  badge.className = "badge " + rec.status;
  badge.textContent = BADGE[rec.status];
  const a = $(".bubble.agent", li);
  if (!a || rec.status === "running") return;
  a.textContent = "";
  a.classList.remove("error");
  if (rec.reply && rec.reply.text && !rec.blocked) {
    a.append(el("div", null, rec.reply.text));
    const meta = el("div", "bubble-meta");
    meta.append(el("span", null, rec.reply.mode === "phala" ? rec.reply.model : "echo"));
    a.append(meta);
    return;
  }
  a.classList.add("error");
  a.append(el("div", null, rec.blocked ? "未发送：证明未通过" : rec.error || rec.serviceError || "无响应"));
}

function select(id) {
  state.selected = id;
  for (const li of document.querySelectorAll("#thread .turn")) li.classList.toggle("selected", Number(li.dataset.id) === id);
  renderPanel();
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
              el("div", "rec-title", rec.kind === "login" ? "登录" : rec.title),
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
  if (rec.blocked) panel.append(el("div", "banner fail", "证明未通过，消息未发送"));
  if (rec.error) panel.append(el("div", "banner fail", rec.error));
  if (rec.serviceError) panel.append(el("div", "banner fail", rec.serviceError));
  if (rec.auth && !rec.auth.ok) panel.append(el("div", "banner fail", rec.auth.error === "unauthorized" ? "密钥无效" : rec.auth.error || "登录失败"));

  for (const key of ["cvm", "channel", "gateway", "tamper"]) {
    if (key === "tamper" && rec.stages.tamper === "idle") continue;
    if (key === "gateway" && rec.kind === "login") continue;
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
  const gw = rec.kind === "login" ? "skipped" : st.gateway;
  const up = (rec.sections.gateway || []).find((c) => c.name.includes("upstream.verified"));
  const model = rec.kind === "login" ? "skipped" : up ? (up.status === "PASS" ? "pass" : "fail")
    : gw === "skipped" ? "skipped" : gw === "running" ? "running" : "idle";
  const nodes = [["客户端", "LOCAL", "pass local"], ["CVM", "INTEL TDX", cvm], ["推理网关", "INTEL TDX", gw], ["上游模型", "TEE · 网关声明", model]];
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
  head.append(el("div", "section-title", SECTION_TITLE[key]), el("span", "state " + st, STATE_LABEL[st] || st));
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
  "system-preparing": "开始初始化，运行时度量起点",
  "app-id": "应用 ID，部署时确定，KMS 按它派发密钥",
  "compose-hash": "部署配置 app_compose 的 sha256",
  "init-script-hash": "初始化脚本的 sha256",
  "gpu-policy-hash": "app_compose 里 requirements.gpu_policy 的哈希，未设置时为 sha256(\"{}\")",
  "gpu-attestation": "GPU TEE 证明结果",
  "instance-id": "实例 ID，由实例种子和 app_id 哈希得到",
  "boot-mr-done": "启动度量结束，接着向 KMS 取密钥",
  "mr-kms": "KMS 的聚合度量值",
  "os-image-hash": "向 KMS 取密钥时 KMS 返回的系统镜像哈希",
  "key-provider": "密钥提供方：KMS 及其公钥",
  "storage-fs": "数据盘文件系统",
  "storage-encrypted": "数据盘加密，1 为加密",
  "system-ready": "数据盘已挂载，系统准备阶段结束，之后才启动容器",
};
const HASH_EVENTS = new Set(["app-id", "compose-hash", "init-script-hash", "gpu-policy-hash", "gpu-attestation",
                             "instance-id", "mr-kms", "os-image-hash"]);
const BOOT_EVENTS = {
  0x4: ["EV_SEPARATOR", "阶段分隔"],
  0x6: ["EV_EVENT_TAG", "内核命令行 / initrd"],
  0xa: ["EV_PLATFORM_CONFIG_FLAGS", "ACPI 表，描述虚拟硬件"],
  0x80000001: ["EV_EFI_VARIABLE_DRIVER_CONFIG", "Secure Boot 变量"],
  0x80000002: ["EV_EFI_VARIABLE_BOOT", "启动项变量"],
  0x80000003: ["EV_EFI_BOOT_SERVICES_APPLICATION", "加载内核"],
  0x80000007: ["EV_EFI_ACTION", "固件动作"],
  0x8000000a: ["EV_EFI_PLATFORM_FIRMWARE_BLOB2", "TDVF 配置固件卷 CFV，UEFI 变量存储初值"],
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
  "upstream.verified": "网关对上游 TEE 的验证结果，网关签名声明；是否有 GPU 证明取决于当次路由到哪家",
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
    if (!gw && state.base) out.push(["访问域名", new URL(state.base).host.startsWith(p + "-")]);
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
        ["抵押品", PCCS_URL],
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
    return [kv([["性质", "网关签名的声明；是否有 GPU 证明取决于当次路由到哪家上游，详情在会话 session_id 里"],
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
  if (!rec.context || rec.stages.tamper === "running") return;
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

$("#cvm-url").value = CVM_URL;
$("#login-form").addEventListener("submit", onLogin);
$("#composer").addEventListener("submit", onSend);
$("#logout-btn").addEventListener("click", logout);
$("#msg").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); $("#composer").requestSubmit(); }
});
$("#access-key").focus();
