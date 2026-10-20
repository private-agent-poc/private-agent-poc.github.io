import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

DSTACK_SOCKET = os.environ.get("DSTACK_SOCKET", "/var/run/dstack.sock")
PORT = int(os.environ.get("PORT", "8080"))
PHALA_API_KEY = os.environ.get("PHALA_API_KEY", "")
PHALA_BASE_URL = os.environ.get("PHALA_BASE_URL", "https://inference.phala.com")
MODEL = os.environ.get("MODEL", "z-ai/glm-5.2")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "")
KEYSET_TTL = int(os.environ.get("KEYSET_TTL_SECONDS", str(7 * 86400)))
MAX_BODY = 1 << 20

E2EE_ALGO = "pa-mvp-x25519-aes256gcm-v1"
HKDF_INFO = b"pa-mvp/e2ee/v1"
E2EE_KEY_ID = "mvp-e2ee-1"
RECEIPT_KEY_ID = "mvp-receipt-1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_tag(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def guest_agent(path: str, body: dict) -> dict:
    conn = UnixHTTPConnection(DSTACK_SOCKET)
    try:
        conn.request("POST", path, body=json.dumps(body), headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        data = r.read()
    finally:
        conn.close()
    if r.status != 200:
        raise RuntimeError(f"guest agent {path} 返回 {r.status}: {data[:200]!r}")
    return json.loads(data)


class Workload:
    def __init__(self):
        self.e2ee_priv = X25519PrivateKey.generate()
        self.receipt_priv = Ed25519PrivateKey.generate()
        self.e2ee_pub = self.e2ee_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        receipt_pub = self.receipt_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        info = guest_agent("/Info", {})
        tcb = info.get("tcb_info") or {}
        if isinstance(tcb, str):
            tcb = json.loads(tcb)
        self.app_compose = tcb.get("app_compose")
        self.info = {k: info.get(k) for k in ("app_id", "instance_id", "app_name", "compose_hash",
                                              "os_image_hash", "device_id") if info.get(k) is not None}
        self.keyset = {
            "e2ee_public_keys": [{"algo": E2EE_ALGO, "key_id": E2EE_KEY_ID, "public_key": self.e2ee_pub.hex()}],
            "not_after": int(time.time()) + KEYSET_TTL,
            "receipt_signing_keys": [{"algo": "ed25519", "key_id": RECEIPT_KEY_ID, "public_key": receipt_pub.hex()}],
            "subject": f"dstack-app://{info.get('app_id', 'unknown')}",
            "tls_public_keys": [],
        }
        self.digest = sha256_tag(jcs(self.keyset))

    def attestation(self, nonce_hex: str) -> dict:
        statement = (f'{{"keyset_digest":"{self.digest}","nonce":"{nonce_hex}",'
                     f'"purpose":"aci.report_data.v1"}}').encode()
        report_data = hashlib.sha256(statement).digest() + b"\x00" * 32
        q = guest_agent("/GetQuote", {"report_data": report_data.hex()})
        return {
            "api_version": "pa-mvp/1",
            "workload_keyset_digest": self.digest,
            "attestation": {
                "tee_type": "tdx",
                "workload_keyset": self.keyset,
                "report_data": report_data[:32].hex(),
                "evidence": {
                    "quote": q["quote"],
                    "quote_report_data": q.get("report_data"),
                    "event_log": q["event_log"],
                    "vm_config": q.get("vm_config"),
                    "app_compose": self.app_compose,
                },
            },
            "info": self.info,
        }

    def _key(self, client_pub: bytes) -> bytes:
        shared = self.e2ee_priv.exchange(X25519PublicKey.from_public_bytes(client_pub))
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=HKDF_INFO + client_pub + self.e2ee_pub).derive(shared)

    def chat(self, req: dict) -> dict:
        if req.get("key_id") != E2EE_KEY_ID:
            raise ValueError("未知 key_id")
        client_pub = bytes.fromhex(req["client_public_key"])
        req_nonce = bytes.fromhex(req["nonce"])
        key = self._key(client_pub)
        plaintext = AESGCM(key).decrypt(req_nonce, bytes.fromhex(req["ciphertext"]),
                                        b"pa-mvp/req/v1|" + self.digest.encode())
        inner = json.loads(plaintext)
        if ACCESS_TOKEN and not hmac.compare_digest(str(inner.get("access_token", "")), ACCESS_TOKEN):
            result = {"error": "unauthorized"}
        elif inner.get("auth_only") is True:
            result = {"ok": True, "mode": "phala" if PHALA_API_KEY else "echo"}
        else:
            result = handle(inner)
        resp_plain = json.dumps(result, ensure_ascii=False).encode()
        resp_nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(resp_nonce, resp_plain,
                                 b"pa-mvp/resp/v1|" + self.digest.encode() + b"|" + req_nonce)
        return {"nonce": resp_nonce.hex(), "ciphertext": ct.hex(),
                "receipt": self.receipt(plaintext, resp_plain)}

    def receipt(self, req_plain: bytes, resp_plain: bytes) -> dict:
        doc = {
            "api_version": "pa-mvp/1",
            "receipt_id": "rcpt-" + secrets.token_hex(12),
            "endpoint": "/v1/chat",
            "method": "POST",
            "served_at": int(time.time()),
            "workload_keyset_digest": self.digest,
            "event_log": [
                {"type": "request.received", "body_hash": sha256_tag(req_plain)},
                {"type": "response.returned", "body_hash": sha256_tag(resp_plain)},
            ],
            "key_id": RECEIPT_KEY_ID,
        }
        doc["signature"] = self.receipt_priv.sign(jcs(doc)).hex()
        return doc


def handle(inner: dict) -> dict:
    messages = inner.get("messages")
    if not isinstance(messages, list) or not messages or not all(
            isinstance(m, dict) and isinstance(m.get("role"), str) and isinstance(m.get("content"), str)
            for m in messages):
        return {"error": "messages 格式不对"}
    if not PHALA_API_KEY:
        return {"mode": "echo",
                "reply": f"[演示模式，未接模型] CVM 在 TEE 内解密到你的消息：{messages[-1]['content']}"}
    try:
        return call_phala(messages, inner.get("gateway_nonce"))
    except Exception as e:
        return {"mode": "phala", "error": f"{type(e).__name__}: {e}"}


def phala_request(method: str, path: str, body: bytes | None = None):
    u = urllib.parse.urlsplit(PHALA_BASE_URL)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=180,
                                       context=ssl.create_default_context())
    try:
        headers = {"Authorization": f"Bearer {PHALA_API_KEY}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        der = conn.sock.getpeercert(binary_form=True)
        spki = hashlib.sha256(x509.load_der_x509_certificate(der).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        r = conn.getresponse()
        data = r.read()
        return r.status, data, {k.lower(): v for k, v in r.getheaders()}, spki
    finally:
        conn.close()


def call_phala(messages: list, gateway_nonce) -> dict:
    out = {"mode": "phala", "model": MODEL}

    if isinstance(gateway_nonce, str) and HEX64.fullmatch(gateway_nonce):
        st, data, _, _ = phala_request("GET", f"/v1/aci/attestation?nonce={gateway_nonce}")
        out["gateway_attestation"] = json.loads(data) if st == 200 else {"error": st, "body": data[:500].decode("utf-8", "replace")}

    req_bytes = json.dumps({"model": MODEL, "messages": messages, "provider": {"aci_verified": True}},
                           ensure_ascii=False, separators=(",", ":")).encode()
    st, resp_bytes, headers, spki = phala_request("POST", "/v1/chat/completions", req_bytes)
    out.update({
        "upstream_status": st,
        "upstream_request_b64": base64.b64encode(req_bytes).decode(),
        "upstream_response_b64": base64.b64encode(resp_bytes).decode(),
        "observed_tls_spki_sha256": spki,
        "receipt_id": headers.get("x-receipt-id"),
    })
    try:
        out["reply"] = json.loads(resp_bytes)["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        out["reply"] = None

    rid = headers.get("x-receipt-id")
    if rid:
        for _ in range(6):
            st, data, _, _ = phala_request("GET", "/v1/aci/receipts/" + urllib.parse.quote(rid, safe=""))
            if st == 200:
                out["receipt"] = json.loads(data)
                break
            time.sleep(0.5)
    return out


WORKLOAD: Workload | None = None


CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "pa-mvp/1"

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/health":
            return self._send(200, {"ok": True, "workload_keyset_digest": WORKLOAD.digest})
        if u.path == "/v1/attestation":
            nonce = (urllib.parse.parse_qs(u.query).get("nonce") or [""])[0]
            if not HEX64.fullmatch(nonce):
                return self._send(400, {"error": "nonce 必须是 64 位小写十六进制（32 字节随机数）"})
            try:
                return self._send(200, WORKLOAD.attestation(nonce))
            except Exception as e:
                return self._send(500, {"error": f"取 quote 失败: {e}"})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/v1/chat":
            return self._send(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413, {"error": "body 太大或为空"})
        try:
            req = json.loads(self.rfile.read(n))
            return self._send(200, WORKLOAD.chat(req))
        except InvalidTag:
            return self._send(400, {"error": "解密失败"})
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, {"error": f"请求格式不对: {e}"})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.command, urllib.parse.urlsplit(self.path).path))


def main():
    global WORKLOAD
    WORKLOAD = Workload()
    mode = "phala" if PHALA_API_KEY else "echo"
    print(f"pa-mvp listening on :{PORT} mode={mode} keyset={WORKLOAD.digest}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
