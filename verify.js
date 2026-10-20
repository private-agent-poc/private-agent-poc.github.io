import init, { js_get_collateral, js_verify } from "./dcap-qvl-web.js";

export const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;
export const STATEMENT_PURPOSE = "aci.report_data.v1";
export const MVP_E2EE_ALGO = "pa-mvp-x25519-aes256gcm-v1";
const MVP_HKDF_INFO = "pa-mvp/e2ee/v1";

export const KNOWN_PROD_IMAGES = {
  "dstack-0.6.1": {
    os_image_hash: "ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6",
    mrtd: ["2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
           "83baf004a06c83f6371d4d9e19c8bb1ead734ba7696e56d6b52271011394a6f24efecc27af3b5c1da41594dbfa706e97"],
    rtmr1: "89ef86c5125b986c325f0a94acfa87718a4ef3a4d4f237dbb72dda3cf777fd2c054555fb4407eb53338d7d67329a7333",
    rtmr2: "e9000e338f33233e8f51b7fd031e1c158bdcf8572eab041c0bc8eb7fef48b23259a6a556e6c8e2af99999fc39c793179",
  },
  "dstack-0.5.12": {
    os_image_hash: "8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd",
    mrtd: ["7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
           "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b"],
    rtmr1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
    rtmr2: "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
  },
  "dstack-0.5.9": {
    os_image_hash: "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
    mrtd: ["f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
           "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"],
    rtmr1: "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
    rtmr2: "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858",
  },
};
export const KNOWN_RTMR0 = {
  "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96":
    "1 vCPU / 2 GB（Phala tdx.small，QEMU 8.2.2）",
  "46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b":
    "32 vCPU / 32 GB（Phala 推理网关，QEMU 8.2.2）",
};
const LOGIN_ENVS = ["DSTACK_AUTHORIZED_KEYS", "DSTACK_ROOT_PASSWORD", "DSTACK_ROOT_PUBLIC_KEY"];
const TCB_PASS = new Set(["UpToDate", "SWHardeningNeeded"]);
const TCB_WARN = new Set(["ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDate", "OutOfDateConfigurationNeeded"]);
const HEX64 = /^[0-9a-f]{64}$/;
const COLLATERAL_TTL_MS = 10 * 60 * 1000;

const enc = new TextEncoder();
const subtle = globalThis.crypto.subtle;

export function hexToBytes(h) {
  h = String(h || "");
  if (h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new Error(`不是十六进制：${h.slice(0, 20)}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function concat(...parts) {
  const bufs = parts.map((p) => (typeof p === "string" ? enc.encode(p) : p));
  const out = new Uint8Array(bufs.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of bufs) { out.set(b, o); o += b.length; }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

async function sha384(data) {
  return new Uint8Array(await subtle.digest("SHA-384", data));
}

export async function sha256Tag(data) {
  return "sha256:" + bytesToHex(await sha256(data));
}

export function randomHex(n = 32) {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(n)));
}

export function jcs(obj) {
  return enc.encode(canonical(obj));
}

function canonical(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("JCS: 文档里有浮点数，本实现不支持");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  }
  throw new Error(`JCS: 不支持的类型 ${typeof v}`);
}

export async function keysetDigest(keyset) {
  return sha256Tag(jcs(keyset));
}

export function statement(digest, nonceHex) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error("公钥集摘要格式不对");
  let n;
  if (nonceHex === null || nonceHex === undefined) n = "null";
  else if (HEX64.test(nonceHex)) n = `"${nonceHex}"`;
  else throw new Error("nonce 必须是 64 位小写十六进制");
  return enc.encode(`{"keyset_digest":"${digest}","nonce":${n},"purpose":"${STATEMENT_PURPOSE}"}`);
}

export async function expectedReportData(digest, nonceHex) {
  return concat(await sha256(statement(digest, nonceHex)), new Uint8Array(32));
}

export function parseTdReport(quote) {
  if (quote.length < 48) throw new Error("quote 太短");
  const dv = new DataView(quote.buffer, quote.byteOffset, quote.byteLength);
  const version = dv.getUint16(0, true);
  const teeType = dv.getUint32(4, true);
  if (teeType !== 0x81) throw new Error(`不是 TDX quote（tee_type ${teeType}）`);
  let off;
  if (version === 4) off = 48;
  else if (version === 5) off = 54;
  else throw new Error(`不支持的 quote 版本 ${version}`);
  if (quote.length < off + 584) throw new Error("quote 太短");
  const f = (start, len) => quote.slice(off + start, off + start + len);
  return {
    version, tee_type: teeType, att_key_type: dv.getUint16(2, true), qe_vendor_id: quote.slice(12, 28),
    tee_tcb_svn: f(0, 16), mr_seam: f(16, 48), mr_signer_seam: f(64, 48), seam_attributes: f(112, 8),
    td_attributes: f(120, 8), xfam: f(128, 8), mr_td: f(136, 48), mr_config_id: f(184, 48),
    mr_owner: f(232, 48), mr_owner_config: f(280, 48),
    rt_mr0: f(328, 48), rt_mr1: f(376, 48), rt_mr2: f(424, 48), rt_mr3: f(472, 48),
    report_data: f(520, 64),
  };
}

export async function replayImr(events, imr) {
  let mr = new Uint8Array(48);
  const steps = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (Number(e.imr) !== imr) continue;
    mr = await sha384(concat(mr, hexToBytes(e.digest || "")));
    steps.push({ index: i, rtmr: bytesToHex(mr) });
  }
  return { mr: bytesToHex(mr), steps };
}

export function parseEventLog(eventLog) {
  if (typeof eventLog === "string") eventLog = JSON.parse(eventLog);
  if (!Array.isArray(eventLog)) throw new Error("event_log 不是数组");
  return eventLog;
}

export function runtimeEventPreimage(e) {
  const payload = hexToBytes(e.event_payload || "");
  if (Number(e.version ?? 1) === 2) {
    return jcs({ name: e.event, payload: bytesToHex(payload), type: DSTACK_RUNTIME_EVENT_TYPE });
  }
  const t = new Uint8Array(4);
  new DataView(t.buffer).setUint32(0, DSTACK_RUNTIME_EVENT_TYPE, true);
  return concat(t, ":", e.event, ":", payload);
}

export async function replayRtmr3(events) {
  let mr = new Uint8Array(48);
  const named = {};
  const errors = [];
  const steps = [];
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (Number(e.imr) !== 3) continue;
    let digest = hexToBytes(e.digest || "");
    if (Number(e.event_type) !== DSTACK_RUNTIME_EVENT_TYPE) {
      errors.push(`第 ${i} 条事件不是 dstack 运行时事件，无法核对内容`);
    } else {
      const pre = runtimeEventPreimage(e);
      if (e.preimage && !bytesEqual(hexToBytes(e.preimage), pre)) {
        errors.push(`第 ${i} 条事件（${e.event}）的 preimage 不是规范形式`);
      }
      const h = await sha384(pre);
      if (!digest.length) digest = h;
      else if (!bytesEqual(h, digest)) errors.push(`第 ${i} 条事件（${e.event}）的摘要和内容对不上`);
      (named[e.event] ||= []).push(String(e.event_payload || "").toLowerCase());
    }
    mr = await sha384(concat(mr, digest));
    steps.push({ index: i, event: e.event, payload: String(e.event_payload || ""), digest: bytesToHex(digest), rtmr3: bytesToHex(mr) });
  }
  return { mr, named, errors, steps };
}

export function embeddedSource(composeText, marker = "PYEOF") {
  const lines = composeText.split("\n");
  const start = lines.findIndex((l) => l.trimEnd().endsWith(`<<'${marker}'`));
  if (start < 0) return null;
  let end = -1;
  for (let i = start + 1; i < lines.length; i++) if (lines[i].trim() === marker) { end = i; break; }
  if (end < 0) return null;
  const pad = lines[end].length - lines[end].trimStart().length;
  const body = lines.slice(start + 1, end).map((l) => (l.trim() ? l.slice(pad) : ""));
  return enc.encode((body.join("\n") + "\n").replaceAll("$$", "$"));
}

export function composeImages(appCompose) {
  const text = appCompose.docker_compose_file || "";
  return Array.from(text.matchAll(/^\s*image:\s*["']?([^\s"'#]+)/gm), (m) => m[1]);
}

class Result {
  constructor() {
    this.checks = [];
    this.keyset = null;
    this.keyset_digest = null;
    this.compose_hash = null;
    this.app_id = null;
    this.collateral = null;
    this.measurements = {};
    this.trace = {};
  }
  add(name, status, detail = "") { this.checks.push({ name, status, detail }); }
  get failed() { return this.checks.filter((c) => c.status === "FAIL"); }
}

function ts(t) {
  const d = new Date(t * 1000);
  const p = (x) => String(x).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

function vmConfig(ev) {
  const v = ev.vm_config;
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return {}; } }
  return v || {};
}

function decodeUtf8(h) {
  if (!h) return null;
  try { return new TextDecoder("utf-8", { fatal: true }).decode(hexToBytes(h)); } catch { return h; }
}

function errText(e) {
  return e && e.message ? e.message : String(e);
}

export async function verifyReport(report, nonceHex, opts = {}) {
  const {
    label = "", quoteVerifier, collateral = null, requireCompose = true, expectComposeHash = null,
    expectImage = null, expectSource = null, allowImages = null, allowRtmr0 = null, strictTcb = false,
  } = opts;
  const now = Math.floor(opts.now ?? Date.now() / 1000);
  const r = new Result();
  const p = label || "";
  const att = report.attestation || {};
  const ev = att.evidence || {};
  const keyset = att.workload_keyset;

  let quote, td;
  try {
    quote = hexToBytes(String(ev.quote).replace(/^0x/, ""));
    td = parseTdReport(quote);
    r.trace.quote = { size: quote.length, sha256: bytesToHex(await sha256(quote)), hex: bytesToHex(quote),
                      fields: Object.fromEntries(Object.entries(td).map(([k, v]) => [k, v instanceof Uint8Array ? bytesToHex(v) : v])) };
  } catch (e) {
    r.add(`${p}读取 quote`, "FAIL", `无法解析：${errText(e)}`);
    return r;
  }

  try {
    const v = await quoteVerifier(quote, collateral, now);
    r.collateral = v.collateral;
    r.trace.tcb = { status: v.status, advisory_ids: v.advisory_ids || [] };
    const adv = (v.advisory_ids || []).join(", ");
    const detail = `TCB 状态 ${v.status}` + (adv ? `；公告 ${adv}` : "");
    if (TCB_PASS.has(v.status)) r.add(`${p}硬件证明：Intel TDX quote 签名链`, "PASS", detail);
    else if (TCB_WARN.has(v.status) && !strictTcb) {
      r.add(`${p}硬件证明：Intel TDX quote 签名链`, "WARN", detail + "（签名有效，但平台补丁不是最新）");
    } else r.add(`${p}硬件证明：Intel TDX quote 签名链`, "FAIL", detail);
  } catch (e) {
    r.add(`${p}硬件证明：Intel TDX quote 签名链`, "FAIL", errText(e));
  }

  const debug = Boolean(td.td_attributes[0] & 0x01);
  r.add(`${p}非调试模式（TD_ATTRIBUTES.DEBUG = 0）`, debug ? "FAIL" : "PASS", debug ? "调试模式下宿主机可以读内存" : "");

  if (!keyset || typeof keyset !== "object" || Array.isArray(keyset)) {
    r.add(`${p}绑定公钥与 nonce`, "FAIL", "报告里没有 workload_keyset");
  } else {
    r.keyset = keyset;
    const digest = await keysetDigest(keyset);
    r.keyset_digest = digest;
    const claimed = report.workload_keyset_digest;
    if (claimed !== undefined && claimed !== null && claimed !== digest) {
      r.add(`${p}绑定公钥与 nonce`, "FAIL", `报告声称摘要 ${claimed}，重算得 ${digest}`);
    } else {
      const want = await expectedReportData(digest, nonceHex);
      const ok = bytesEqual(td.report_data, want);
      r.trace.binding = { nonce: nonceHex, keyset_digest: digest, statement: new TextDecoder().decode(statement(digest, nonceHex)),
                          expected: bytesToHex(want), actual: bytesToHex(td.report_data) };
      r.add(`${p}绑定公钥与 nonce（report_data）`, ok ? "PASS" : "FAIL", ok
        ? `sha256(公钥集+本次 nonce) = ${bytesToHex(want.slice(0, 32))}`
        : `quote 里是 ${bytesToHex(td.report_data)}，应为 ${bytesToHex(want)}`);
    }
    let notAfter = keyset.not_after;
    if (notAfter === undefined || notAfter === null) notAfter = (keyset.keyset_epoch || {}).not_after;
    if (!Number.isInteger(notAfter)) r.add(`${p}公钥集有效期`, "FAIL", "缺少 not_after");
    else if (now >= notAfter) r.add(`${p}公钥集有效期`, "FAIL", `已于 ${ts(notAfter)} 过期`);
    else if (notAfter > now + 400 * 86400) r.add(`${p}公钥集有效期`, "WARN", "到期时间过远，相当于不过期");
    else r.add(`${p}公钥集有效期`, "PASS", `到 ${ts(notAfter)}`);
  }

  let named = {};
  try {
    const events = parseEventLog(ev.event_log);
    const rep = await replayRtmr3(events);
    named = rep.named;
    r.trace.events = events;
    r.trace.replay = { steps: rep.steps, result: bytesToHex(rep.mr), quote: bytesToHex(td.rt_mr3) };
    r.trace.boot = {};
    for (const i of [0, 1, 2]) r.trace.boot[i] = { ...(await replayImr(events, i)), quote: bytesToHex(td[`rt_mr${i}`]) };
    if (rep.errors.length) r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "FAIL", rep.errors.slice(0, 3).join("；"));
    else if (!bytesEqual(rep.mr, td.rt_mr3)) {
      r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "FAIL", "重算值和 quote 不一致，事件日志被改过");
    } else {
      const n = Object.values(named).reduce((s, v) => s + v.length, 0);
      r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "PASS", `${n} 条运行时事件逐条核对`);
    }
  } catch (e) {
    r.add(`${p}事件日志重放 = quote 中的 RTMR3`, "FAIL", errText(e));
  }
  const appId = (named["app-id"] || [null])[0];
  r.app_id = appId;

  const mrs = { mrtd: bytesToHex(td.mr_td), rtmr0: bytesToHex(td.rt_mr0), rtmr1: bytesToHex(td.rt_mr1), rtmr2: bytesToHex(td.rt_mr2) };
  const refImages = { ...KNOWN_PROD_IMAGES, ...(allowImages || {}) };
  const image = Object.keys(refImages).find((n) => {
    const ref = refImages[n];
    return ref.mrtd.includes(mrs.mrtd) && mrs.rtmr1 === ref.rtmr1 && mrs.rtmr2 === ref.rtmr2;
  }) || null;
  if (image) {
    r.add(`${p}系统镜像是官方正式版（固件、内核、rootfs 的度量）`, "PASS", `${image}：MRTD、RTMR1、RTMR2 与发布包算出的值一致`);
  } else {
    r.add(`${p}系统镜像是官方正式版（固件、内核、rootfs 的度量）`, "WARN",
      `MRTD ${mrs.mrtd} RTMR2 ${mrs.rtmr2} 不在已知正式镜像里；dev 镜像可被 SSH 登录。` +
      "核对后用 dstack-mr 算出参考值，用 --allow-image 加入");
  }
  const rtmr0s = { ...KNOWN_RTMR0, ...(allowRtmr0 || {}) };
  r.add(`${p}虚拟硬件配置（RTMR0）与参考值一致`, mrs.rtmr0 in rtmr0s ? "PASS" : "WARN",
    rtmr0s[mrs.rtmr0] || `RTMR0 ${mrs.rtmr0} 没有参考值；用 dstack-mr diagnose 按 vm_config 算出后用 --allow-rtmr0 加入`);

  const measured = named["compose-hash"] || [];
  const raw = ev.app_compose;
  let appCompose = null;
  if (measured.length !== 1) {
    r.add(`${p}部署配置哈希（compose-hash）`, requireCompose ? "FAIL" : "WARN", `事件日志里有 ${measured.length} 条 compose-hash`);
  } else if (typeof raw !== "string") {
    r.add(`${p}部署配置哈希（compose-hash）`, requireCompose ? "FAIL" : "WARN", "报告没给出 app_compose 原文，无法核对代码");
  } else {
    const h = bytesToHex(await sha256(raw));
    r.compose_hash = measured[0];
    r.trace.compose = { raw, sha256: h, measured: measured[0] };
    const ok = h === measured[0];
    r.add(`${p}部署配置哈希：sha256(app_compose) = 度量值`, ok ? "PASS" : "FAIL",
      ok ? `compose_hash ${measured[0]}` : `原文哈希 ${h}，度量值 ${measured[0]}`);
    if (ok) { try { appCompose = JSON.parse(raw); } catch { appCompose = null; } }
  }

  if (appCompose !== null && typeof appCompose === "object") {
    const images = composeImages(appCompose);
    const unpinned = images.filter((i) => !i.includes("@sha256:"));
    if (!images.length) r.add(`${p}镜像按 digest 固定`, "WARN", "docker_compose_file 里没找到 image");
    else if (unpinned.length) {
      r.add(`${p}镜像按 digest 固定`, "WARN", `未固定：${unpinned.join(", ")}（标签可被替换，compose-hash 锁不住代码）`);
    } else r.add(`${p}镜像按 digest 固定`, "PASS", images.join("；"));
    const allowed = new Set(appCompose.allowed_envs || []);
    const risky = LOGIN_ENVS.filter((e) => allowed.has(e)).sort();
    if (!risky.length) r.add(`${p}无法用 SSH 公钥 / root 密码登录`, "PASS", "allowed_envs 不含登录凭据变量");
    else if (image) {
      r.add(`${p}无法用 SSH 公钥 / root 密码登录`, "PASS", `allowed_envs 含 ${risky.join(", ")}，但 ${image} 正式镜像没有 sshd 和 login`);
    } else {
      r.add(`${p}无法用 SSH 公钥 / root 密码登录`, "FAIL", `allowed_envs 含 ${risky.join(", ")}，且系统镜像不是已知正式版`);
    }
    if (expectImage) {
      const want = expectImage.split("@").pop();
      const ok = want.startsWith("sha256:") && images.some((i) => i.split("@").pop() === want);
      r.add(`${p}镜像 digest 与我们发布的一致`, ok ? "PASS" : "FAIL", `预期 ${want}`);
    }
    if (expectSource !== null && expectSource !== undefined) {
      const got = embeddedSource(appCompose.docker_compose_file || "");
      if (got !== null) r.trace.source = { text: new TextDecoder().decode(got), sha256: bytesToHex(await sha256(got)), expected_sha256: bytesToHex(await sha256(expectSource)) };
      if (got === null) r.add(`${p}内嵌源码与本地文件一致`, "FAIL", "部署配置里没有内嵌源码");
      else {
        const ok = bytesEqual(got, expectSource);
        r.add(`${p}内嵌源码与本地文件一致`, ok ? "PASS" : "FAIL",
          `sha256 ${bytesToHex(await sha256(got))}` + (ok ? "" : `，本地为 ${bytesToHex(await sha256(expectSource))}`));
      }
    }
    const settings = {};
    for (const k of ["name", "runner", "kms_enabled", "gateway_enabled", "public_logs", "public_sysinfo",
                     "secure_time", "no_instance_id", "allowed_envs"]) {
      if (k in appCompose) settings[k] = appCompose[k];
    }
    if (appCompose.pre_launch_script) settings.pre_launch_script = "有（已被 compose-hash 覆盖）";
    r.measurements.app_compose_settings = settings;
    r.trace.app_compose = appCompose;
    r.trace.images = images;
    r.trace.login_envs = { allowed_envs: appCompose.allowed_envs || [], risky, watched: LOGIN_ENVS };
  }
  if (expectComposeHash) {
    const ok = r.compose_hash === expectComposeHash.toLowerCase().replace(/^0x/, "");
    r.add(`${p}compose-hash 与发布记录一致`, ok ? "PASS" : "FAIL", `预期 ${expectComposeHash}`);
  }

  const osHashes = named["os-image-hash"] || [];
  r.trace.vm_config = vmConfig(ev);
  r.trace.mrs = { ...mrs, rtmr3: bytesToHex(td.rt_mr3) };
  r.trace.now = now;
  r.trace.image_ref = image ? { name: image, ...refImages[image] } : null;
  r.trace.rtmr0_ref = rtmr0s[mrs.rtmr0] || null;
  r.trace.keyset = keyset ?? null;
  Object.assign(r.measurements, {
    mr_td: mrs.mrtd, rtmr0: mrs.rtmr0, rtmr1: mrs.rtmr1, rtmr2: mrs.rtmr2,
    rtmr3: bytesToHex(td.rt_mr3),
    image,
    app_id: appId,
    compose_hash: r.compose_hash,
    instance_id: (named["instance-id"] || [null])[0],
    os_image_hash: image ? refImages[image].os_image_hash ?? null : null,
    os_image_hash_self_reported: osHashes.length === 1 ? osHashes[0] : null,
    os_image_hash_host_claimed: vmConfig(ev).os_image_hash ?? null,
    key_provider: decodeUtf8((named["key-provider"] || [null])[0]),
  });
  return r;
}

export function receiptEvent(receipt, etype) {
  return (receipt.event_log || []).find((e) => e.type === etype) || null;
}

export function receiptHash(event) {
  if (!event) return null;
  return event.body_hash || event.wire_hash || null;
}

export async function verifyReceiptSignature(receipt, keyset) {
  const name = "回执签名（公钥来自已验证的证明）";
  const keys = keyset.receipt_signing_keys || [];
  let key = keys.find((k) => k.key_id === receipt.key_id) || null;
  if (key === null && keys.length === 1 && !("key_id" in receipt)) key = keys[0];
  if (key === null) return { name, status: "FAIL", detail: `key_id ${receipt.key_id ?? "None"} 不在已证明的公钥集里` };
  const doc = { ...receipt };
  delete doc.signature;
  let payload;
  try { payload = jcs(doc); } catch (e) { return { name, status: "FAIL", detail: errText(e) }; }
  if (key.algo !== "ed25519") {
    return { name, status: "WARN", detail: `本脚本未实现 ${key.algo} 验签，可用 Phala 的 pap verify 交叉核对` };
  }
  try {
    const pub = await subtle.importKey("raw", hexToBytes(key.public_key), { name: "Ed25519" }, false, ["verify"]);
    const ok = await subtle.verify({ name: "Ed25519" }, pub, hexToBytes(receipt.signature || ""), payload);
    return ok ? { name, status: "PASS", detail: `Ed25519，key_id ${key.key_id}` } : { name, status: "FAIL", detail: "签名无效 " };
  } catch (e) {
    return { name, status: "FAIL", detail: `签名无效 ${errText(e)}` };
  }
}

export function findE2eeKey(keyset, algo = MVP_E2EE_ALGO) {
  return (keyset.e2ee_public_keys || []).find((k) => k.algo === algo) || null;
}

export class ClientChannel {
  static async create(serverKey, digest) {
    const ch = new ClientChannel();
    ch.serverKey = serverKey;
    ch.digest = digest;
    const serverPub = hexToBytes(serverKey.public_key);
    const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    ch.clientPub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
    const peer = await subtle.importKey("raw", serverPub, { name: "X25519" }, false, []);
    const shared = await subtle.deriveBits({ name: "X25519", public: peer }, kp.privateKey, 256);
    const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const keyBytes = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: concat(MVP_HKDF_INFO, ch.clientPub, serverPub) }, hk, 256);
    ch.key = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    return ch;
  }

  async seal(plaintext) {
    this.reqNonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle.encrypt(
      { name: "AES-GCM", iv: this.reqNonce, additionalData: concat("pa-mvp/req/v1|", this.digest) }, this.key, plaintext));
    return { key_id: this.serverKey.key_id, client_public_key: bytesToHex(this.clientPub),
             nonce: bytesToHex(this.reqNonce), ciphertext: bytesToHex(ct) };
  }

  async open(resp) {
    try {
      return new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(resp.nonce), additionalData: concat("pa-mvp/resp/v1|", this.digest, "|", this.reqNonce) },
        this.key, hexToBytes(resp.ciphertext)));
    } catch {
      throw new Error("解密失败");
    }
  }
}

async function collateralKey(quote) {
  return bytesToHex(await sha256(quote.slice(Math.max(0, quote.length - 4096))));
}

export function verifierFrom(api, pccsUrl) {
  const cache = new Map();
  return async (quote, collateral, now) => {
    let col = collateral;
    if (!col) {
      const key = await collateralKey(quote);
      const hit = cache.get(key);
      if (hit && Date.now() - hit.at < COLLATERAL_TTL_MS) col = hit.col;
      else {
        col = await api.js_get_collateral(pccsUrl, quote);
        cache.set(key, { col, at: Date.now() });
      }
    }
    const v = api.js_verify(quote, col, BigInt(Math.floor(now)));
    return { status: v.status, advisory_ids: v.advisory_ids || [], collateral: col };
  };
}

let wasmReady = null;

export async function createQuoteVerifier(pccsUrl) {
  wasmReady ||= init({ module_or_path: new URL("./dcap-qvl-web_bg.wasm", import.meta.url) });
  await wasmReady;
  return verifierFrom({ js_get_collateral, js_verify }, pccsUrl);
}

export function fmspcOf(collateral) {
  try {
    const t = typeof collateral.tcb_info === "string" ? JSON.parse(collateral.tcb_info) : collateral.tcb_info;
    return (t.fmspc || t.tcbInfo?.fmspc || "").toUpperCase() || null;
  } catch {
    return null;
  }
}

export class ServiceError extends Error {}

export async function httpJson(method, url, body) {
  let r;
  try {
    r = await fetch(url, { method, cache: "no-store", headers: body ? { "Content-Type": "application/json" } : {},
                          body: body ? JSON.stringify(body) : undefined });
  } catch {
    throw new ServiceError("连接失败");
  }
  const text = await r.text();
  if (!r.ok) throw new ServiceError(`HTTP ${r.status}`);
  try { return JSON.parse(text); } catch { throw new ServiceError("响应格式错误"); }
}

function eqCheck(name, got, want) {
  const same = got !== null && got !== undefined && JSON.stringify(got) === JSON.stringify(want);
  return { name, status: same ? "PASS" : "FAIL",
           detail: same ? "" : `得到 ${JSON.stringify(got)}，应为 ${JSON.stringify(want)}` };
}

export async function verifyCvm(base, args) {
  const nonce = randomHex(32);
  const report = await httpJson("GET", `${base}/v1/attestation?nonce=${nonce}`);
  const res = await verifyReport(report, nonce, {
    quoteVerifier: args.quoteVerifier, requireCompose: true, expectComposeHash: args.expectComposeHash,
    expectImage: args.expectImage, expectSource: args.expectSource, strictTcb: args.strictTcb,
  });
  res.checks.unshift({ name: "本次随机 nonce（防重放）", status: "INFO", detail: nonce });
  return { res, report, nonce };
}

export async function chat(base, res, inner, token) {
  const checks = [];
  const key = findE2eeKey(res.keyset);
  if (key === null) return { checks: [{ name: "加密通道", status: "FAIL", detail: "证明里没有本 MVP 的加密公钥" }], out: null };
  const ch = await ClientChannel.create(key, res.keyset_digest);
  const gatewayNonce = randomHex(32);
  const body = { ...inner, gateway_nonce: gatewayNonce };
  if (token) body.access_token = token;
  const reqPlain = new TextEncoder().encode(JSON.stringify(body));
  const envelope = await ch.seal(reqPlain);
  const resp = await httpJson("POST", `${base}/v1/chat`, envelope);
  const shown = token ? { ...body, access_token: "*".repeat(8) } : body;
  const trace = { server_key: key, client_public_key: bytesToHex(ch.clientPub), keyset_digest: res.keyset_digest,
                  request: { envelope, plain: shown, size: reqPlain.length, sha256: await sha256Tag(reqPlain) },
                  response: { envelope: { nonce: resp.nonce, ciphertext: resp.ciphertext } }, receipt: resp.receipt || null };
  let respPlain;
  try {
    respPlain = await ch.open(resp);
  } catch (e) {
    return { checks: [{ name: "加密通道：只有被证明的 CVM 能解开", status: "FAIL", detail: errText(e) }], out: null, trace };
  }
  const respText = new TextDecoder().decode(respPlain);
  trace.response.plain = JSON.parse(respText);
  trace.response.size = respPlain.length;
  trace.response.sha256 = await sha256Tag(respPlain);
  checks.push({ name: "加密通道：消息用证明里的公钥加密，CVM 解密并加密回复", status: "PASS",
                detail: `X25519 + AES-256-GCM，公钥 ${key.public_key}` });
  const out = JSON.parse(respText);
  const receipt = resp.receipt || {};
  checks.push(await verifyReceiptSignature(receipt, res.keyset));
  checks.push(eqCheck("CVM 回执：公钥集摘要一致", receipt.workload_keyset_digest, res.keyset_digest));
  checks.push(eqCheck("CVM 回执：请求哈希 = 我发出的内容", receiptHash(receiptEvent(receipt, "request.received")), await sha256Tag(reqPlain)));
  checks.push(eqCheck("CVM 回执：回复哈希 = 我收到的内容", receiptHash(receiptEvent(receipt, "response.returned")), await sha256Tag(respPlain)));
  out._gateway_nonce = gatewayNonce;
  out._messages = inner.messages;
  return { checks, out, trace };
}

function b64ToBytes(s) {
  return Uint8Array.from(atob(s || ""), (c) => c.charCodeAt(0));
}

export async function verifyGateway(out, args) {
  const checks = [];
  if (out.error) return { checks: [{ name: "推理调用", status: "FAIL", detail: out.error }], report: null, trace: null };
  const gw = out.gateway_attestation || {};
  let gres = null;
  if (!("attestation" in gw)) {
    checks.push({ name: "网关证明", status: "FAIL", detail: `没拿到网关证明：${JSON.stringify(gw)}` });
  } else {
    gres = await verifyReport(gw, out._gateway_nonce, { label: "网关 · ", quoteVerifier: args.quoteVerifier,
                                                        requireCompose: false, strictTcb: args.strictTcb });
    checks.push(...gres.checks);
    const prov = (gw.attestation || {}).source_provenance || {};
    if (Object.keys(prov).length) {
      gres.provenance = prov;
      checks.push({ name: "网关 · 源码出处（未被 quote 直接绑定，仅展示）", status: "INFO",
                    detail: `${prov.repo_url ?? "None"} @ ${prov.repo_commit ?? "None"}` });
    }
  }
  const st = out.upstream_status;
  checks.push({ name: "推理请求经网关返回", status: st === 200 ? "PASS" : "FAIL", detail: `HTTP ${st ?? "None"}，模型 ${out.model ?? "None"}` });
  const reqBytes = b64ToBytes(out.upstream_request_b64);
  const respBytes = b64ToBytes(out.upstream_response_b64);
  const dec = new TextDecoder();
  const trace = { attestation: gw, status: st ?? null, model: out.model ?? null, receipt_id: out.receipt_id ?? null,
                  receipt: out.receipt || null, messages: out._messages, spki: out.observed_tls_spki_sha256 ?? null,
                  request: { text: dec.decode(reqBytes), size: reqBytes.length, sha256: await sha256Tag(reqBytes) },
                  response: { text: dec.decode(respBytes), size: respBytes.length, sha256: await sha256Tag(respBytes) } };
  let sentMsgs = null;
  try { sentMsgs = JSON.parse(new TextDecoder().decode(reqBytes)).messages ?? null; } catch { sentMsgs = null; }
  checks.push(eqCheck("CVM 发给网关的就是我的消息（未被改写）", sentMsgs, out._messages));

  const receipt = out.receipt;
  if (!receipt) {
    checks.push({ name: "网关回执", status: "FAIL", detail: `没拿到回执（receipt id ${out.receipt_id ?? "None"}）` });
    return { checks, report: gres, trace };
  }
  if (gres === null || gres.keyset === null) {
    checks.push({ name: "网关回执", status: "FAIL", detail: "网关证明未通过，回执无从核对" });
    return { checks, report: gres, trace };
  }
  checks.push(await verifyReceiptSignature(receipt, gres.keyset));
  checks.push(eqCheck("网关回执：公钥集摘要 = 刚验证过的网关", receipt.workload_keyset_digest, gres.keyset_digest));
  if (gw.workload_id && receipt.workload_id) checks.push(eqCheck("网关回执：workload_id 一致", receipt.workload_id, gw.workload_id));
  checks.push(eqCheck("网关回执：请求哈希 = CVM 实际发出的字节", receiptHash(receiptEvent(receipt, "request.received")), await sha256Tag(reqBytes)));
  checks.push(eqCheck("网关回执：回复哈希 = CVM 实际收到的字节", receiptHash(receiptEvent(receipt, "response.returned")), await sha256Tag(respBytes)));
  const up = receiptEvent(receipt, "upstream.verified") || {};
  const good = up.result === "verified" && up.required === true && Boolean(up.session_id);
  checks.push({ name: "网关回执：上游 GPU TEE 已验证（upstream.verified）", status: good ? "PASS" : "FAIL",
                detail: `result=${up.result ?? "None"} required=${up.required === undefined ? "None" : up.required ? "True" : "False"} ` +
                        `model=${up.model_id ?? "None"} session=${up.session_id ?? "None"}` });
  const tls = (gres.keyset.tls_public_keys || []).map((k) => k.spki_sha256);
  const spki = out.observed_tls_spki_sha256;
  if (!tls.length) {
    checks.push({ name: "CVM→网关 TLS 公钥在证明里", status: "WARN", detail: "网关证明没列出 TLS 公钥，这一段只能依赖普通 HTTPS 证书" });
  } else {
    checks.push({ name: "CVM→网关 TLS 公钥在证明里", status: tls.includes(spki) ? "PASS" : "FAIL", detail: `观察到 ${spki}` });
  }
  return { checks, report: gres, trace };
}

export async function tamperDemo(report, nonce, res, args) {
  const firstFail = async (rep, n, needle) => {
    const r = await verifyReport(rep, n, { quoteVerifier: args.quoteVerifier, collateral: res.collateral, requireCompose: true });
    return r.checks.find((c) => c.status === "FAIL" && c.name.includes(needle)) || null;
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const r1 = clone(report);
  r1.attestation.evidence.app_compose = (r1.attestation.evidence.app_compose || "").replace("@sha256:", "@sha256:0", 1) + " ";
  const r3 = clone(report);
  const oldKey = r3.attestation.workload_keyset.e2ee_public_keys[0].public_key;
  const newKey = randomHex(32);
  r3.attestation.workload_keyset.e2ee_public_keys[0].public_key = newKey;
  delete r3.workload_keyset_digest;
  const r4 = clone(report);
  const q = hexToBytes(r4.attestation.evidence.quote);
  const before = q[200];
  q[200] ^= 0x01;
  r4.attestation.evidence.quote = bytesToHex(q);
  const replayNonce = randomHex(32);
  const byte = (b) => "0x" + b.toString(16).padStart(2, "0");
  const cases = [
    ["把部署配置改一个字（换镜像）", r1, nonce, "部署配置", [["app_compose", "第一个 @sha256: 改为 @sha256:0，末尾加一个空格"]]],
    ["拿旧证明冒充（换一个 nonce 验证）", report, replayNonce, "绑定", [["原 nonce", nonce], ["验证用 nonce", replayNonce]]],
    ["中间人换掉加密公钥", r3, nonce, "绑定", [["原公钥", oldKey], ["替换为", newKey]]],
    ["改 quote 里一个比特（伪造硬件证明）", r4, nonce, "硬件证明", [["quote[200]", `${byte(before)} → ${byte(q[200])}`]]],
  ];
  const rows = [];
  for (const [title, rep, n, needle, change] of cases) {
    const hit = await firstFail(rep, n, needle);
    rows.push({ name: title, status: hit ? "PASS" : "FAIL", detail: hit ? `被拦下：${hit.name}` : "没被发现！", change, hit });
  }
  return rows;
}

function pyDumps(v) {
  if (v === null || v === undefined) return "null";
  if (Array.isArray(v)) return "[" + v.map(pyDumps).join(", ") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).map((k) => JSON.stringify(k) + ": " + pyDumps(v[k])).join(", ") + "}";
  return JSON.stringify(v);
}

function infoChecks(m) {
  if (!("mr_td" in m)) return [];
  return [
    { name: "app_id", status: "INFO", detail: String(m.app_id ?? "None") },
    { name: "compose_hash（和发布记录比对）", status: "INFO", detail: String(m.compose_hash ?? "None") },
    { name: "系统镜像 os_image_hash（官方发布包）", status: "INFO", detail: `${m.image ?? "None"}：${m.os_image_hash ?? "None"}` },
    { name: "密钥来源（key-provider）", status: "INFO", detail: String(m.key_provider ?? "None") },
    { name: "app-compose 设置", status: "INFO", detail: pyDumps(m.app_compose_settings ?? null) },
    { name: "MRTD / RTMR0-2（固件、虚拟硬件、内核、rootfs，已和参考值比对）", status: "INFO",
      detail: `MRTD  ${m.mr_td}\nRTMR0 ${m.rtmr0}\nRTMR1 ${m.rtmr1}\nRTMR2 ${m.rtmr2}\nRTMR3 ${m.rtmr3}` },
  ];
}

export async function* run(base, args) {
  const t0 = Date.now() / 1000;
  yield ["stage", "cvm"];
  const { res, report, nonce } = await verifyCvm(base, args);
  yield ["section", ["cvm", res.checks]];
  const m = res.measurements;
  const info = infoChecks(m);
  if (info.length) yield ["section", ["info", info]];

  const result = { url: base, verified_at: Math.floor(t0), cvm: res.checks, measurements: m };
  const all = [...res.checks];
  const context = { report, nonce, res, channel: null, gateway: null };
  let blocked = false;
  if (res.failed.length) {
    blocked = true;
    yield ["blocked", "证明验证未通过，不发送消息。"];
  } else {
    yield ["stage", "channel"];
    const inner = args.authOnly ? { auth_only: true } : { messages: args.messages };
    const { checks: cchecks, out, trace: ctrace } = await chat(base, res, inner, args.token);
    context.channel = ctrace;
    yield ["section", ["channel", cchecks]];
    all.push(...cchecks);
    result.channel = cchecks;
    if (out !== null) {
      if (args.authOnly) {
        yield ["auth", { ok: out.ok === true, mode: out.mode ?? null, error: out.error ?? null }];
      } else {
        if (out.mode === "phala") {
          yield ["stage", "gateway"];
          const { checks: gchecks, report: gres, trace: gtrace } = await verifyGateway(out, args);
          context.gateway = { nonce: out._gateway_nonce, report: gres, model: out.model ?? null, trace: gtrace };
          yield ["section", ["gateway", gchecks]];
          all.push(...gchecks);
          result.gateway = gchecks;
          result.gateway_receipt = out.receipt ?? null;
        } else if (out.error) {
          yield ["error", out.error];
        }
        yield ["reply", { text: out.reply ?? null, mode: out.mode ?? null, model: out.model ?? null }];
        result.reply = out.reply ?? null;
        result.mode = out.mode ?? null;
      }
    }
  }
  const counts = { PASS: 0, WARN: 0, FAIL: 0 };
  for (const c of all) if (c.status in counts) counts[c.status]++;
  result.raw_attestation = report;
  yield ["done", { counts, elapsed: Date.now() / 1000 - t0, result, blocked, context }];
}
