import asyncio
import base64
import gzip
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import selectors
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dcap_qvl
import nacl.bindings as nb
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

DSTACK_SOCKET = os.environ.get("DSTACK_SOCKET", "/var/run/dstack.sock")
PORT = int(os.environ.get("PORT", "8080"))
PHALA_API_KEY = os.environ.get("PHALA_API_KEY", "").strip()
PHALA_BASE_URL = os.environ.get("PHALA_BASE_URL", "https://inference.phala.com")
MODEL = os.environ.get("MODEL", "z-ai/glm-5.2")
CHUTES_API_KEY = os.environ.get("CHUTES_API_KEY", "").strip()
CHUTES_MODEL = os.environ.get("CHUTES_MODEL", "Qwen/Qwen3.8-27B-TEE")
NEAR_API_KEY = os.environ.get("NEAR_API_KEY", "").strip()
NEAR_MODEL = os.environ.get("NEAR_MODEL", "Qwen/Qwen3.8-27B")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "").strip()
KEYSET_TTL = int(os.environ.get("KEYSET_TTL_SECONDS", str(7 * 86400)))
SESSION_TTL = min(int(os.environ.get("SESSION_TTL_SECONDS", "900")), 3000)
MAX_BODY = 1 << 20
MAX_STREAM_BODY = 48 << 20
PROXY_PORT = int(os.environ.get("PROXY_PORT", "0"))
PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
EGRESS_PORT = int(os.environ.get("EGRESS_PORT", "0"))
EGRESS_HOST = os.environ.get("EGRESS_HOST", "0.0.0.0")
EGRESS_UPSTREAM = os.environ.get("EGRESS_UPSTREAM", "").strip()
AGENT_NET_ISOLATED = os.environ.get("AGENT_NET_ISOLATED", "") == "1"
PROXY_TOKEN = os.environ.get("PROXY_TOKEN", "").strip()
AGENT_URL = os.environ.get("AGENT_URL", "").rstrip("/")
AGENT_KEY = os.environ.get("AGENT_KEY", "").strip()
AGENT_UPLOAD_DIR = os.environ.get("AGENT_UPLOAD_DIR", "")
AGENT_UPLOAD_PATH = os.environ.get("AGENT_UPLOAD_PATH", "/opt/data/uploads")
AGENT_STATE_DIR = os.environ.get("AGENT_STATE_DIR", "")
AGENT_PROVIDER = os.environ.get("AGENT_PROVIDER", "tee")
MAX_FILE = 20 << 20

E2EE_ALGO = "pa-mvp-x25519-aes256gcm-v1"
HKDF_INFO = b"pa-mvp/e2ee/v1"
E2EE_KEY_ID = "mvp-e2ee-1"
RECEIPT_KEY_ID = "mvp-receipt-1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")

CHUTES_API = "https://api.chutes.ai"
CHUTES_LLM = "https://llm.chutes.ai"
NEAR_API = "https://cloud-api.near.ai"
NRAS = "https://nras.attestation.nvidia.com"
DSTACK_RUNTIME_EVENT = 0x08000001
TCB_OK = {"UpToDate", "SWHardeningNeeded"}

NEAR_PINS = {
    "image": "dstack-nvidia-0.5.12",
    "observed": "2026-10-28、2026-11-04",
    "mrtd": ["7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173", "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b"],
    "rtmr0": ["bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590", "f0f303d15fb7619b87ec60daf0db241e937b30a4e1f2c405b5420f14b27c6e301735094feea9693a33b868d00eeb07f9"],
    "rtmr1": "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
    "rtmr2": "bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71",
    "os_image_hash": "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829",
    "kms": "3059301306072a8648ce3d020106082a8648ce3d03010703420004394aaed2c745e6a457cb835f7f47423f57ff3ead71b92abff6bdc14d905b319f2e13961b42c50740dae4498d9c51dd7a2e227660c9e5c504083cda06b6c11682",
    "app_ids": ["2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"],
    "compose_hashes": ["5e513dbd72e1c0f291f748ad06d4dbc1df55659869e649376213ac7b3c9d2e29", "31d3b2389e06a4450e342f3a45fdbb5d7ce4c607c359f5b291635548b0b80007"],
}

CHUTES_PINS = {
    "source": "https://api.chutes.ai/servers/tee/measurements",
    "fetched": "2026-10-28",
    "images": {
        "1.3.1": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "9b8b2915351a3166f742024edafb6cce244c1df4056eb1f9eb608c3616b9d63729ae00c98d1dc108009c0978b19dc207", "rtmr2": "8471360414fe80b4343fb17dd59e442bdc55b5955df0adf610b1de15ad7b454e98fb8e9d38cc188b82369f4f620b6968", "rtmr3": "51204be641a2af357f5f4e6a121d348d6cb1cbe53c4c35d9dcc3364196b4d41a6e1de75025bb2e76f3b00cc7192f9433"},
        "1.4.0": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed", "rtmr2": "8feee49b83c0f912f9ab9366a7423f65417bb60223c1871a5d55e84d92d741c80017b3f856317c45295255db70f8dc3e", "rtmr3": "7e7adbc834a3e746278f28c607a94ba93407a7b25055daca4836cc6003e9bfb5f48836fa0e1d6ab6637c187dd142e5f6"},
        "1.4.1": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed", "rtmr2": "da23f73e0fddeb8128f706ecfbecbcf8cee34af7e4907d8fbc85e9b216acee27bf6cc3655eaf4d33cab76adea79fa153", "rtmr3": "d9dc4c6079fb12a21ad2aa8e329d8bfa61aaa13d3ffd10a93a2c4e82f0e35efbf28f5cf3bed0c0c1b517a7c327a25226"},
        "1.5.0": {"mrtd": "261ce538b435e2d0e85fc97e254bc99154c507b7a8e13d59b69f8532384f1d0bfaadfddf3fccc6e0a411203840bbee8d", "rtmr1": "d3a862ff47357f374fc72c7f02a480a13790d1805e24aaa8de1f03994256625ce0f593ae35ea8f0c24d09f7df36cb0ed", "rtmr2": "e1de99043052f3e1ab5a4463d3310b5680e851631adf10e071b15cbd8b4d664ea435b0ec33e7f18e908dda60734056f7", "rtmr3": "9617be835beac8c62093a9db424f015f3e12651235d0101c112729e7225b7a70836a184dee0b45f28cd190f1871afe6e"}
    },
    "rows": [
        ["1.3.1", "8xh200 [10.2.1]", "212d8284fe29a52a033cd662763e452915d2002bcc3c3e73aa660b100087bd3cce8aef414c3d7012f6a857f392c1919b", ["h200"], 8],
        ["1.3.1", "8xh200 [10.2.1, NVSW0]", "c90a27d633d97e2f785a0a65c4a7ee2258872655e3bada2cad0e719e313db542fd35c6889897d9ae6369f82e39877861", ["h200"], 8],
        ["1.3.1", "8xh200 [10.2.1, FLAT]", "b237753a1c8a05042209947fc0f98c8459783db7f3411860c38249c5abd4efd8c6fb7820036ff19b5099138aaf9e0bd1", ["h200"], 8],
        ["1.3.1", "8xh200 [10.1.0]", "7e76988fae31dda82f0043b331d908f0716e9da24fed80b6ea6cec9b6615ff84f24321056a8befbea3fff67bd1e59205", ["h200"], 8],
        ["1.3.1", "8xh200 [10.1.0, NVSW0]", "cdf7169a9f90c4d2fd29f89579f4ad7b90c272d607bc7ba2365e91560a248b9eafe01940f3c1e9d6bd6987573080b6c1", ["h200"], 8],
        ["1.3.1", "8xh200 [10.1.0-flat]", "ed373dfcc4e3b9cc57282773784c88445699f95705ec0995959c4aa95f9dec454c76da891fa56f820f547b02db8c1f2f", ["h200"], 8],
        ["1.3.1", "8xRTX_PRO_6000 [10.1.0]", "0917443cc41e9a5afebc8e87e69a63f32208c47d4b4b4fd410fbc1a705e1880c1383a4ad51903a5ed20cb4090420185a", ["pro_6000"], 8],
        ["1.3.1", "8xRTX_PRO_6000 [10.2.1, NUMA2-4/4]", "5fc09d108ef74d5505b876690de5ab5da02af463ba84bb33299efd1c02144b5d7a6ba579b3ff31ef9118350468e9faf2", ["pro_6000"], 8],
        ["1.3.1", "8xRTX_PRO_6000 [10.2.1, NUMA2-3/5]", "1de32a41a8116e042f33e9cb813f1f6edfef1452c8b2cf54df5451a848ef8931e97f40927191acabfd111c8b8d66796a", ["pro_6000"], 8],
        ["1.3.1", "8xRTX_PRO_6000 [10.2.1, FLAT]", "e9f0b31ce30e4917767d22ad26ad0a8f4edc095b8d9f4bbb36c9cc24fe274aa2dfe16ce3c961dac2d8cef3e6ae2e901d", ["pro_6000"], 8],
        ["1.3.1", "8xRTX_PRO_6000 [10.2.1, FLAT, MSI-GNR]", "872d965083f0bab7d080bd7d40155ba1b2b911d883f391ab7d6b9d810abeefd058e04129d72c088cf4fd05c099a57704", ["pro_6000"], 8],
        ["1.3.1", "8xb200 [10.2.1]", "35038cbb04f872ac6d2784b05c912c438007583e58960dc66fb02d1b04462dd5994f94536da37b5877ccd3dd27d8d54d", ["b200"], 8],
        ["1.3.1", "8xb200 [10.2.1, IB4]", "555fc635cd49723dc33d53a9d53be82fd161be351174e5449a465bbeffbcbd01f36d89dcd25fad61bf4c9e65c570f5d6", ["b200"], 8],
        ["1.3.1", "8xb200 [10.2.1, XEON6]", "65fd972e40ac4d8a933d10ebfc31f07336cf1e45a3864523427b454df5d3b9dd0043f10e975da39677b62d45860c13e3", ["b200"], 8],
        ["1.3.1", "8xb200 [10.2.1, XEON6, 272CPU]", "9673907ceb0c9ca79337437bb91695e7a3d19e82df1e41de1b0d2db8081fccb5d82f26d479a5016553cb20964d5948b9", ["b200"], 8],
        ["1.3.1", "8xb200 [10.2.1, XEON6, SNC3]", "ccef43242ef633a542405dbfe55d04d823a50586b0a07510d058ea88ad8d1f8281f227f00c664435d92b23431c4d1c3c", ["b200"], 8],
        ["1.3.1", "8xb200 [10.2.1, ubuntu3]", "ff42d0f7b03cbe84f9e252d8f912b465852c8ee92584c5c047de134a46c8f1e1545683e713bbdd64e2af7d10e8bafaae", ["b200"], 8],
        ["1.3.1", "8xb300", "91adf9667ba4c65bec5345a8c9b98010708d903847bf838c4526c3ebbc35561719e2127e48a3f6f77f651d71d2cbc8d4", ["b300"], 8],
        ["1.3.1", "8xb300 [10.2.1, numa-256c]", "f24aaec75a6c8783222ab141f003f2180fce573ef9cc6ea3dcdc2fcb91c051650fcd74ec85f02e367f06ed71328d319b", ["b300"], 8],
        ["1.4.0", "8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4", ["b300"], 8],
        ["1.4.0", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
        ["1.4.0", "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9", ["h200"], 8],
        ["1.4.0", "8xb300 [10.2.1, numa-252c-2304g]", "b60b5c5817c762e3297ccec4e6a49289781fc5511738230bbc88e253e120635526b6082f8f4f6c31a2b3821d30a8b221", ["b300"], 8],
        ["1.4.0", "8xpro_6000 [10.2.1, numa-124c-768g]", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60", ["pro_6000"], 8],
        ["1.4.1", "8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4", ["b300"], 8],
        ["1.4.1", "8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]", "a9cac743d296a96c7a0d6348f03be1e1a407f18ec215f0039e3dc1ea4c132eb1e4a5fe3783022ff3d252d4b30f1dbf9f", ["h200"], 8],
        ["1.4.1", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node0]", "052183ad6cca5ad4aef7e31dc3f6c47be2ba90c288a55420bf432301374f1bd9932ea7d6b5da999c4fecf578c4b0a21a", ["h200"], 8],
        ["1.4.1", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
        ["1.4.1", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
        ["1.4.1", "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9", ["h200"], 8],
        ["1.4.1", "8xpro_6000 [10.2.1, flat-188c-768g]", "0e53740f96063640ec986e9f95a2cb601bd686c34229882a05fe7a4350d78735fc3dc2439b6052665ef888e38a292076", ["pro_6000"], 8],
        ["1.4.1", "8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)", "bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6", ["pro_6000"], 8],
        ["1.4.1", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]", "ba81dbf034d968fd4be0975c031cbe6451295d63cb509cd857372fc915dada1b24fc4e1b0486db4a276a9efb49d415e6", ["h200"], 8],
        ["1.4.1", "8xh200 [10.2.1, numa-188c-987g]", "8bf87f63caf5265365315fcdeea36e791c6d16216898aa313a1f4ac6fb0181adef223b2b62ad94914b06e0066ceb4751", ["h200"], 7],
        ["1.4.1", "8xb200 [10.2.1, flat-272c-1536g]", "44efeea3a647090c2969cca7f29963dde696d99542c28536a20ad3586a639ef7e230d8d4e325c55f3597dc7b58b30903", ["b200"], 8],
        ["1.4.1", "8xb300 [10.2.1, numa-flatpci-252c-2304g]", "e861504d4a05ba1e949618ef759d6fbf0c69e4774b667e9fb876b664cb1bb70e3094d2cddc9ac6c52d4b5d352ba2e1d3", ["b300"], 8],
        ["1.4.1", "8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60", ["pro_6000"], 8],
        ["1.4.1", "8xb300 [10.2.1, flat-188c-2304g]", "bfaaf9a018fb3f10518b2706731ed010bc7d75f3ea3eabcc562ce4a794ab4ee88eba199e38f9013e96e1099a1cf7c49e", ["b300"], 8],
        ["1.4.1", "8xb300 [10.2.1, numa-flatpci-188c-2304g]", "34c932b17fa65b230d848ad0ca6b8186dc347b129f926f968f6b607dae07e1968177684d209a1830d37b5d0486c97618", ["b300"], 8],
        ["1.4.1", "8xpro_6000 [10.2.1, numa-204c-768g]", "a5488b5f4cf1484da23001e013a5ad3ff177836bf2cfdbde55dacded21b3eece5de43d4c4a2d5279f8ed8d24b9e072d6", ["pro_6000"], 8],
        ["1.5.0", "8xb300 [10.2.1, flat-252c-1944g]", "fc71a5a8edcb1f6d307d59e62ce257365df0f233ae2334691f99d2136832d911f8be975b92f88036db8a4906574519c4", ["b300"], 8],
        ["1.5.0", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
        ["1.5.0", "8xh200 [10.2.1, flat-188c-1128g-nvsw4]", "b72208e4b39593a82bbdbc394569bd6f8395f76bdcff5bce2bc72f4e2ca0b3202238d3b78952b497d725e04999e45435", ["h200"], 8],
        ["1.5.0", "8xh200 [10.2.1, numa-236c-1128g-nvsw-node1]", "a9cac743d296a96c7a0d6348f03be1e1a407f18ec215f0039e3dc1ea4c132eb1e4a5fe3783022ff3d252d4b30f1dbf9f", ["h200"], 8],
        ["1.5.0", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node0]", "052183ad6cca5ad4aef7e31dc3f6c47be2ba90c288a55420bf432301374f1bd9932ea7d6b5da999c4fecf578c4b0a21a", ["h200"], 8],
        ["1.5.0", "8xb300 [10.2.1, numa-flatpci-188c-2304g]", "34c932b17fa65b230d848ad0ca6b8186dc347b129f926f968f6b607dae07e1968177684d209a1830d37b5d0486c97618", ["b300"], 8],
        ["1.5.0", "8xpro_6000 [10.2.1, flat-252c-768g] (2f9da10068f0)", "c2857dd69249c2f976ad070359b7bebc828c9d39a899bebc1fc9077072d97c6137f626b9ce7280fff0aa7e68481f16c6", ["pro_6000"], 8],
        ["1.5.0", "8xb300 [10.2.1, flat-188c-2304g]", "bfaaf9a018fb3f10518b2706731ed010bc7d75f3ea3eabcc562ce4a794ab4ee88eba199e38f9013e96e1099a1cf7c49e", ["b300"], 8],
        ["1.5.0", "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "5b509103a3bf3c10dbf27a7da030a3d7ba93a81c0c8844de20e5dfee77611644a39cc7236313e9d0a99a8a8a703bbfc9", ["h200"], 8],
        ["1.5.0", "8xpro_6000 [10.2.1, flat-188c-768g]", "0e53740f96063640ec986e9f95a2cb601bd686c34229882a05fe7a4350d78735fc3dc2439b6052665ef888e38a292076", ["pro_6000"], 8],
        ["1.5.0", "8xpro_6000 [10.2.1, numa-124c-768g] (58443435b208)", "bacb4abf7b19aba4a8307ebc7244706745de4fa627e669e7f06fd35c3303eea1903f58dc143d27b557da1a986e0e95f6", ["pro_6000"], 8],
        ["1.5.0", "8xh200 [10.2.1, numa-188c-1128g-nvsw-node1]", "ba81dbf034d968fd4be0975c031cbe6451295d63cb509cd857372fc915dada1b24fc4e1b0486db4a276a9efb49d415e6", ["h200"], 8],
        ["1.5.0", "8xh200 [10.2.1, numa-188c-987g]", "8bf87f63caf5265365315fcdeea36e791c6d16216898aa313a1f4ac6fb0181adef223b2b62ad94914b06e0066ceb4751", ["h200"], 7],
        ["1.5.0", "8xb200 [10.2.1, flat-272c-1536g]", "44efeea3a647090c2969cca7f29963dde696d99542c28536a20ad3586a639ef7e230d8d4e325c55f3597dc7b58b30903", ["b200"], 8],
        ["1.5.0", "8xb200 [10.2.1, flat-208c-1536g]", "0e990b232dc6df68c5208dac9eb23f777950b7b9ce638b8299dd44ba97902cbcc035c97b704cb28a23643771f8438cbc", ["b200"], 8],
        ["1.5.0", "8xb300 [10.2.1, numa-flatpci-252c-2304g]", "e861504d4a05ba1e949618ef759d6fbf0c69e4774b667e9fb876b664cb1bb70e3094d2cddc9ac6c52d4b5d352ba2e1d3", ["b300"], 8],
        ["1.5.0", "8xpro_6000 [10.2.1, numa-124c-768g] (f2ab1d61fa64)", "5e939a6213a6751f162617c6e9a50461786b3f9a6a679ebf7706fa705e7934180825b2fae43a60877ea9117a1e4d4f60", ["pro_6000"], 8],
        ["1.5.0", "8xpro_6000 [10.2.1, numa-204c-768g]", "a5488b5f4cf1484da23001e013a5ad3ff177836bf2cfdbde55dacded21b3eece5de43d4c4a2d5279f8ed8d24b9e072d6", ["pro_6000"], 8]
    ],
    "gpu_models": {"h200": ["GH100"], "b200": ["GB100"], "pro_6000": ["GB20X"]},
    "nras_intermediates": ["ba14d00377699189b6762c22c744a9dbdc62aa9396097ada7150426c6ff39afc", "fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896"],
}


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
        try:
            col = collateral(bytes.fromhex(q["quote"]))
        except Exception:
            col = None
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
                    "collateral": col,
                },
            },
            "info": self.info,
        }

    def _key(self, client_pub: bytes) -> bytes:
        shared = self.e2ee_priv.exchange(X25519PublicKey.from_public_bytes(client_pub))
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=HKDF_INFO + client_pub + self.e2ee_pub).derive(shared)

    def _open(self, req: dict):
        if req.get("key_id") != E2EE_KEY_ID:
            raise ValueError("未知 key_id")
        client_pub = bytes.fromhex(req["client_public_key"])
        req_nonce = bytes.fromhex(req["nonce"])
        key = self._key(client_pub)
        ct = base64.b64decode(req["ciphertext_b64"]) if "ciphertext_b64" in req else bytes.fromhex(req["ciphertext"])
        plaintext = AESGCM(key).decrypt(req_nonce, ct, b"pa-mvp/req/v1|" + self.digest.encode())
        inner = json.loads(plaintext)
        if ACCESS_TOKEN and not hmac.compare_digest(str(inner.get("access_token", "")), ACCESS_TOKEN):
            return key, req_nonce, plaintext, inner, "unauthorized"
        return key, req_nonce, plaintext, inner, fresh_request(client_pub + req_nonce, inner.get("sent_at"))

    def chat(self, req: dict) -> dict:
        key, req_nonce, plaintext, inner, problem = self._open(req)
        if problem:
            result = {"error": problem}
        elif inner.get("auth_only") is True:
            session_of(inner)
            result = {"ok": True, "mode": "phala" if PHALA_API_KEY else "echo", "providers": providers(),
                      "models": model_catalog(), "agent": bool(AGENT_URL), "internet": internet_on()}
        elif "agent" in inner:
            result = agent_request(inner)
        else:
            result = handle(inner)
        resp_plain = json.dumps(result, ensure_ascii=False).encode()
        resp_nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(resp_nonce, resp_plain,
                                 b"pa-mvp/resp/v1|" + self.digest.encode() + b"|" + req_nonce)
        return {"nonce": resp_nonce.hex(), "ciphertext": ct.hex(),
                "receipt_sealed": self.seal_receipt(key, req_nonce, self.receipt(plaintext, resp_plain))}

    def chat_stream(self, req: dict, send, opened=None):
        key, req_nonce, plaintext, inner, problem = opened or self._open(req)
        digest = self.digest.encode()
        frames, lock, closed = [], threading.Lock(), []

        def emit(obj: dict):
            body = json.dumps(obj, ensure_ascii=False).encode()
            body += b" " * (next(n for n in (256, 1024, 4096, 16384, 1 << 30) if n >= len(body)) - len(body) if len(body) < 16384 else 0)
            with lock:
                if closed:
                    return
                seq = len(frames)
                iv = os.urandom(12)
                ct = AESGCM(key).encrypt(iv, body, b"pa-mvp/stream/v1|" + digest + b"|" + req_nonce + b"|" + str(seq).encode())
                frames.append(body)
                send({"seq": seq, "nonce": iv.hex(), "ciphertext": ct.hex()})

        if problem:
            emit({"type": "error", "error": problem})
        else:
            try:
                agent_turn(inner, emit)
            except Exception as e:
                emit({"type": "error", "error": scrub(f"{type(e).__name__}: {e}")})
        with lock:
            closed.append(True)
            send({"done": True, "frames": len(frames),
                  "receipt_sealed": self.seal_receipt(key, req_nonce, self.receipt(plaintext, b"\n".join(frames), "/v1/chat/stream"))})

    def seal_receipt(self, key: bytes, req_nonce: bytes, receipt: dict) -> dict:
        iv = os.urandom(12)
        ct = AESGCM(key).encrypt(iv, json.dumps(receipt).encode(), b"pa-mvp/receipt/v1|" + self.digest.encode() + b"|" + req_nonce)
        return {"nonce": iv.hex(), "ciphertext": ct.hex()}

    def receipt(self, req_plain: bytes, resp_plain: bytes, endpoint: str = "/v1/chat") -> dict:
        doc = {
            "api_version": "pa-mvp/1",
            "receipt_id": "rcpt-" + secrets.token_hex(12),
            "endpoint": endpoint,
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


REPLAY_WINDOW = 300
SEEN: dict = {}
SEEN_LOCK = threading.Lock()


def fresh_request(key: bytes, sent_at) -> str | None:
    now = time.time()
    if not isinstance(sent_at, (int, float)) or isinstance(sent_at, bool) or abs(now - sent_at) > REPLAY_WINDOW:
        return "请求时间不对：没带发送时间，或和 CVM 时间相差超过 5 分钟（重放的旧请求也会这样）"
    with SEEN_LOCK:
        for k in [k for k, t in SEEN.items() if now - t > 2 * REPLAY_WINDOW]:
            SEEN.pop(k, None)
        if key in SEEN:
            return "重复的请求：同一份密文已经处理过（重放）"
        SEEN[key] = now
    return None


def providers() -> dict:
    return {"phala": {"ready": bool(PHALA_API_KEY), "model": MODEL},
            "chutes": {"ready": bool(CHUTES_API_KEY), "model": CHUTES_MODEL},
            "near": {"ready": bool(NEAR_API_KEY), "model": NEAR_MODEL}}


SESSIONS: dict = {}


def session_of(inner: dict) -> dict:
    sid = inner.get("session_id")
    if not (isinstance(sid, str) and HEX32.fullmatch(sid)):
        return {}
    now = time.time()
    for k in [k for k, v in SESSIONS.items() if now - v["seen"] > 2 * SESSION_TTL]:
        SESSIONS.pop(k, None)
    while len(SESSIONS) >= 500 and sid not in SESSIONS:
        SESSIONS.pop(min(SESSIONS, key=lambda k: SESSIONS[k]["seen"]))
    sess = SESSIONS.setdefault(sid, {})
    if inner.get("reverify") is True:
        sess.clear()
    sess["seen"] = now
    return sess


def cached(sess: dict, provider: str):
    c = sess.get(provider)
    if c and time.time() - c["verified_at"] < SESSION_TTL:
        return c
    sess.pop(provider, None)
    return None


def handle(inner: dict) -> dict:
    messages = inner.get("messages")
    if not isinstance(messages, list) or not messages or not all(
            isinstance(m, dict) and isinstance(m.get("role"), str) and isinstance(m.get("content"), str)
            for m in messages):
        return {"error": "messages 格式不对"}
    provider = inner.get("provider") or "phala"
    nonce = inner.get("gateway_nonce")
    if provider == "phala":
        if not PHALA_API_KEY:
            return {"mode": "echo",
                    "reply": f"[演示模式，未接模型] CVM 在 TEE 内解密到你的消息：{messages[-1]['content']}"}
        call = call_phala
    elif provider == "chutes" and CHUTES_API_KEY:
        call = call_chutes
    elif provider == "near" and NEAR_API_KEY:
        call = call_near
    else:
        return {"mode": provider, "error": f"{provider} 未配置"}
    try:
        return call(messages, nonce, session_of(inner))
    except Exception as e:
        return {"mode": provider, "error": scrub(f"{type(e).__name__}: {e}")}


def scrub(text: str) -> str:
    for k in (PHALA_API_KEY, CHUTES_API_KEY, NEAR_API_KEY, ACCESS_TOKEN, PROXY_TOKEN, AGENT_KEY):
        if k:
            text = text.replace(k, "***")
    return text


def connect(host: str, port: int, timeout: int):
    ctx = ssl.create_default_context()
    proxy = urllib.request.getproxies().get("https")
    if proxy and not urllib.request.proxy_bypass(host):
        p = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
        conn = http.client.HTTPSConnection(p.hostname, p.port or 80, timeout=timeout, context=ctx)
        conn.set_tunnel(host, port)
        return conn
    return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)


def fetch(method: str, url: str, body: bytes | None = None, headers: dict | None = None, timeout: int = 180, on_chunk=None, pin=None):
    u = urllib.parse.urlsplit(url)
    conn = connect(u.hostname, u.port or 443, timeout)
    try:
        path = u.path + ("?" + u.query if u.query else "")
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        spki = hashlib.sha256(x509.load_der_x509_certificate(der).public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        if pin is not None:
            pin(spki)
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        if on_chunk is None or r.status != 200:
            data = r.read()
        else:
            parts = []
            while chunk := r.read1(65536):
                parts.append(chunk)
                on_chunk(chunk)
            data = b"".join(parts)
        return r.status, data, {k.lower(): v for k, v in r.getheaders()}, spki
    finally:
        conn.close()


class SSE:
    def __init__(self, on_data):
        self.on_data, self.buf, self.done = on_data, b"", False

    def feed(self, chunk: bytes):
        *lines, self.buf = (self.buf + chunk).split(b"\n")
        for line in lines:
            line = line.rstrip(b"\r")
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                self.done = True
            elif data:
                try:
                    obj = json.loads(data)
                except ValueError:
                    continue
                self.on_data(obj)


class Completion:
    def __init__(self, on_delta=None):
        self.on_delta, self.head, self.content, self.reasoning = on_delta, {}, "", ""
        self.calls, self.finish, self.usage = {}, None, None

    def add(self, chunk: dict):
        if isinstance(chunk.get("error"), (dict, str)):
            raise Rejected(f"上游流里返回错误：{str(chunk['error'])[:300]}")
        for k in ("id", "created", "model", "system_fingerprint"):
            if chunk.get(k) is not None:
                self.head.setdefault(k, chunk[k])
        if chunk.get("usage"):
            self.usage = chunk["usage"]
        for ch in chunk.get("choices") or []:
            if ch.get("index", 0) != 0:
                continue
            d = ch.get("delta") or {}
            for kind, text in (("reasoning", d.get("reasoning_content") or d.get("reasoning")), ("content", d.get("content"))):
                if isinstance(text, str) and text:
                    if kind == "content":
                        self.content += text
                    else:
                        self.reasoning += text
                    if self.on_delta:
                        self.on_delta(kind, text)
            for tc in d.get("tool_calls") or []:
                slot = self.calls.setdefault(tc.get("index", len(self.calls)), {"id": None, "type": "function",
                                                                                "function": {"name": "", "arguments": ""}})
                slot["id"] = tc.get("id") or slot["id"]
                slot["type"] = tc.get("type") or slot["type"]
                fn = tc.get("function") or {}
                slot["function"]["name"] = slot["function"]["name"] or fn.get("name") or ""
                slot["function"]["arguments"] += fn.get("arguments") or ""
            self.finish = ch.get("finish_reason") or self.finish

    def result(self) -> dict:
        msg = {"role": "assistant", "content": self.content or (None if self.calls else "")}
        if self.reasoning:
            msg["reasoning_content"] = self.reasoning
        if self.calls:
            msg["tool_calls"] = [{**self.calls[i], "id": self.calls[i]["id"] or f"call_{secrets.token_hex(8)}"} for i in sorted(self.calls)]
        return {**self.head, "object": "chat.completion", "usage": self.usage,
                "choices": [{"index": 0, "message": msg, "finish_reason": self.finish or ("tool_calls" if self.calls else "stop")}]}


def phala_request(method: str, path: str, body: bytes | None = None, on_chunk=None, pin=None):
    headers = {"Authorization": f"Bearer {PHALA_API_KEY}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    extra = {k: v for k, v in (("on_chunk", on_chunk), ("pin", pin)) if v is not None}
    return fetch(method, PHALA_BASE_URL.rstrip("/") + path, body, headers, 300 if on_chunk else 180, **extra)


GATEWAY_HOST = urllib.parse.urlsplit(PHALA_BASE_URL).hostname or "inference.phala.com"
DSTACK_IMAGES = {
    "dstack-0.6.1": {"mrtd": {"2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
                              "83baf004a06c83f6371d4d9e19c8bb1ead734ba7696e56d6b52271011394a6f24efecc27af3b5c1da41594dbfa706e97"},
                     "rtmr1": "89ef86c5125b986c325f0a94acfa87718a4ef3a4d4f237dbb72dda3cf777fd2c054555fb4407eb53338d7d67329a7333",
                     "rtmr2": "e9000e338f33233e8f51b7fd031e1c158bdcf8572eab041c0bc8eb7fef48b23259a6a556e6c8e2af99999fc39c793179"},
    "dstack-0.5.12": {"mrtd": {"7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
                               "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b"},
                      "rtmr1": "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
                      "rtmr2": "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d"},
    "dstack-0.5.9": {"mrtd": {"f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
                              "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217"},
                     "rtmr1": "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
                     "rtmr2": "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858"},
}
GATEWAY_RTMR0 = {"46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b"}


def host_matches(domain, host: str) -> bool:
    d = str(domain or "").lower().removesuffix(".")
    h = str(host or "").lower()
    if d.startswith("*."):
        return h.endswith(d[1:]) and "." not in h[:-(len(d) - 1)]
    return d == h


def verify_gateway(doc: dict, nonce: str, col: dict | None = None) -> dict:
    att = doc.get("attestation") or {}
    ev = att.get("evidence") or {}
    keyset = att.get("workload_keyset") or {}
    need(ev.get("quote"), "网关证明里没有 quote")
    tcb, td, col = verify_tdx(unhex(ev["quote"]), col)
    digest = sha256_tag(jcs(keyset))
    need(doc.get("workload_keyset_digest") in (None, digest), "网关公钥集摘要和公钥集对不上")
    stmt = f'{{"keyset_digest":"{digest}","nonce":"{nonce}","purpose":"aci.report_data.v1"}}'.encode()
    need(bytes(td.report_data) == hashlib.sha256(stmt).digest() + b"\0" * 32, "网关 quote 没有绑定它的公钥集和本次随机数")
    r = regs(td)
    image = next((n for n, i in DSTACK_IMAGES.items() if r["mrtd"] in i["mrtd"] and (r["rtmr1"], r["rtmr2"]) == (i["rtmr1"], i["rtmr2"])), None)
    need(image, "网关的系统镜像不是已知的 dstack 正式版")
    need(r["rtmr0"] in GATEWAY_RTMR0, "网关的虚拟硬件（RTMR0）不在参考值里")
    events = ev.get("event_log")
    mr, named = replay_rtmr3(json.loads(events) if isinstance(events, str) else events or [])
    need(mr == bytes(td.rt_mr3), "网关事件日志重放和 quote 的 RTMR3 不一致")
    compose = ev.get("app_compose")
    need(isinstance(compose, str) and one(named, "compose-hash") == hashlib.sha256(compose.encode()).hexdigest(),
         "网关的部署配置和度量的 compose-hash 对不上")
    need(int(keyset.get("not_after") or 0) > time.time(), "网关公钥集已过期")
    entries = keyset.get("tls_public_keys") or []
    mine = [k for k in entries if host_matches(k.get("domain"), GATEWAY_HOST)] if any(k.get("domain") for k in entries) else entries
    need(mine, f"网关证明里没有 {GATEWAY_HOST} 的 TLS 公钥")
    need(any(k.get("algo") == "ed25519" for k in keyset.get("receipt_signing_keys") or []), "网关证明里没有回执签名公钥")
    return {"tcb": tcb, "image": image, "keyset": keyset, "digest": digest, "api_version": doc.get("api_version"),
            "tls_spki": sorted({k.get("spki_sha256") for k in mine}), "collateral": col}


def verify_gateway_receipt(receipt: dict, v: dict, req_bytes: bytes, resp_bytes: bytes) -> dict:
    need(isinstance(receipt, dict) and receipt, "没拿到网关回执")
    need(receipt.get("api_version") == (v.get("api_version") or "aci/1"), "网关回执的 api_version 和证明不一致")
    key = next((k for k in v["keyset"].get("receipt_signing_keys") or [] if k.get("key_id") == receipt.get("key_id")), None)
    need(key and key.get("algo") == "ed25519", "回执的签名公钥不在网关证明里")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key"])).verify(
            bytes.fromhex(receipt.get("signature") or ""), jcs({k: x for k, x in receipt.items() if k != "signature"}))
    except (InvalidSignature, ValueError) as e:
        raise Rejected("网关回执签名无效") from e
    need(receipt.get("workload_keyset_digest") == v["digest"], "网关回执的公钥集摘要和证明不一致")
    events = {e.get("type"): e for e in receipt.get("event_log") or []}
    h = lambda t: (events.get(t) or {}).get("body_hash") or (events.get(t) or {}).get("wire_hash")
    need(h("request.received") == sha256_tag(req_bytes), "网关回执里的请求哈希不是 CVM 发出的字节")
    need(h("response.returned") == sha256_tag(resp_bytes), "网关回执里的回复哈希不是 CVM 收到的字节")
    up = events.get("upstream.verified") or {}
    need(up.get("result") == "verified" and up.get("required") is True and up.get("session_id"), "网关回执没有声明上游 TEE 已验证")
    return {"receipt_id": receipt.get("receipt_id"), "upstream_session": up.get("session_id"), "model": up.get("model_id"),
            "request_sha256": sha256_tag(req_bytes), "response_sha256": sha256_tag(resp_bytes)}


def call_phala(messages: list, gateway_nonce, sess: dict | None = None, req: dict | None = None, on_delta=None) -> dict:
    model = (req or {}).get("model") or MODEL
    out = {"mode": "phala", "model": model}
    sess = {} if sess is None else sess
    c = cached(sess, "phala")
    if c:
        v = c["result"]
        out.update({"gateway_attestation": c["attestation"], "gateway_collateral": c["collateral"], "gateway_nonce": c["nonce"],
                    "reused": {"verified_at": c["verified_at"]}})
    else:
        if not (isinstance(gateway_nonce, str) and HEX64.fullmatch(gateway_nonce)):
            out["error"] = "缺少本次随机数，消息未发送"
            return out
        st, data, _, _ = phala_request("GET", f"/v1/aci/attestation?nonce={gateway_nonce}")
        out["gateway_attestation"] = json.loads(data) if st == 200 else {"error": st, "body": data[:500].decode("utf-8", "replace")}
        out["gateway_nonce"] = gateway_nonce
        try:
            need(st == 200, f"网关证明接口 HTTP {st}")
            q = unhex(out["gateway_attestation"]["attestation"]["evidence"]["quote"])
            out["gateway_collateral"] = collateral(q)
            v = verify_gateway(out["gateway_attestation"], gateway_nonce, out["gateway_collateral"])
        except Exception as e:
            out.setdefault("gateway_collateral", None)
            out["error"] = scrub(f"网关证明未通过，消息未发送：{e}")
            return out
        sess["phala"] = {"verified_at": time.time(), "attestation": out["gateway_attestation"],
                         "collateral": out["gateway_collateral"], "nonce": gateway_nonce, "result": v}

    def pin(spki: str):
        out["observed_tls_spki_sha256"] = spki
        need(spki in v["tls_spki"], f"CVM 连到的 {GATEWAY_HOST} TLS 公钥不在网关证明里，消息未发送")

    body = {k: x for k, x in (req or {"messages": messages}).items() if k not in ("stream", "stream_options")}
    acc = Completion(on_delta) if on_delta else None
    req_bytes = json.dumps({**body, "model": model, **({"stream": True} if acc else {}), "provider": {"aci_verified": True}},
                           ensure_ascii=False, separators=(",", ":")).encode()
    try:
        st, resp_bytes, headers, spki = phala_request("POST", "/v1/chat/completions", req_bytes, SSE(acc.add).feed if acc else None, pin)
    except Rejected as e:
        sess.pop("phala", None)
        out["error"] = str(e)
        return out
    out.update({
        "upstream_status": st,
        "upstream_request_b64": base64.b64encode(req_bytes).decode(),
        "upstream_response_b64": base64.b64encode(resp_bytes).decode(),
        "observed_tls_spki_sha256": spki,
        "receipt_id": headers.get("x-receipt-id"),
    })
    try:
        out["response"] = acc.result() if acc and st == 200 else json.loads(resp_bytes)
        out["reply"] = out["response"]["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        out["reply"] = None
    rid = headers.get("x-receipt-id")
    if rid:
        for _ in range(6):
            rst, data, _, _ = phala_request("GET", "/v1/aci/receipts/" + urllib.parse.quote(rid, safe=""))
            if rst == 200:
                out["receipt"] = json.loads(data)
                break
            time.sleep(0.5)
    if st == 200:
        try:
            out["verified"] = verify_gateway_receipt(out.get("receipt"), v, req_bytes, resp_bytes)
        except Rejected as e:
            sess.pop("phala", None)
            out["error"] = f"网关回执核对没通过，回答不交给 agent：{e}"
    return out


class Rejected(Exception):
    pass


def need(cond, why: str):
    if not cond:
        raise Rejected(why)


def upstream_error(name: str, st: int, data: bytes) -> str:
    try:
        err = json.loads(data)
        err = err.get("error", err) if isinstance(err, dict) else err
        msg = err.get("message") or err.get("detail") if isinstance(err, dict) else None
    except ValueError:
        msg = None
    return f"{name} 返回 HTTP {st}：{msg or data[:200].decode('utf-8', 'replace')}"


def api_json(method: str, url: str, key: str, body=None, timeout: int = 120):
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(body).encode()
    st, data, _, _ = fetch(method, url, body, headers, timeout)
    need(st == 200, upstream_error(urllib.parse.urlsplit(url).hostname, st, data))
    return json.loads(data)


def collateral(quote: bytes) -> dict:
    async def get():
        return await dcap_qvl.get_collateral(dcap_qvl.PHALA_PCCS_URL, quote)
    return json.loads(asyncio.run(get()).to_json())


def verify_tdx(quote: bytes, col: dict | None = None):
    col = col or collateral(quote)
    v = dcap_qvl.verify(quote, dcap_qvl.QuoteCollateralV3.from_json(json.dumps(col)), int(time.time()))
    need(v.status in TCB_OK, f"TCB {v.status}")
    td = dcap_qvl.parse_quote(quote).report
    need(bytes(td.td_attributes)[0] & 1 == 0, "TD 处于调试模式")
    return v.status, td, col


def regs(td) -> dict:
    return {"mrtd": bytes(td.mr_td).hex(), **{f"rtmr{i}": bytes(getattr(td, f"rt_mr{i}")).hex() for i in range(4)}}


JWKS: dict = {}
JWKS_AT = [0.0]


def nras_keys(kids) -> dict:
    if time.time() - JWKS_AT[0] > 3600 or not all(k in JWKS for k in kids):
        st, data, _, _ = fetch("GET", f"{NRAS}/.well-known/jwks.json", timeout=60)
        need(st == 200, f"NVIDIA JWKS HTTP {st}")
        JWKS.clear()
        JWKS.update({k["kid"]: k["x5c"] for k in json.loads(data)["keys"]})
        JWKS_AT[0] = time.time()
    return {k: JWKS[k] for k in kids if k in JWKS}


def b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwt_claims(token: str, x5c: list) -> dict:
    h64, p64, s64 = token.split(".")
    need(json.loads(b64url(h64)).get("alg") == "ES384", "NRAS 令牌算法不是 ES384")
    leaf = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
    inter = x509.load_der_x509_certificate(base64.b64decode(x5c[1]))
    spki = inter.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    need(hashlib.sha256(spki).hexdigest() in CHUTES_PINS["nras_intermediates"], "NRAS 签名证书不在固定的 NVIDIA 中间证书下")
    leaf.verify_directly_issued_by(inter)
    now = time.time()
    need(leaf.not_valid_before_utc.timestamp() <= now <= leaf.not_valid_after_utc.timestamp(), "NRAS 签名证书不在有效期内")
    sig = b64url(s64)
    leaf.public_key().verify(encode_dss_signature(int.from_bytes(sig[:48], "big"), int.from_bytes(sig[48:], "big")),
                             f"{h64}.{p64}".encode(), ec.ECDSA(hashes.SHA384()))
    claims = json.loads(b64url(p64))
    need(claims.get("exp", 0) > time.time(), "NRAS 令牌已过期")
    return claims


def nras(arch: str, evidence: list, nonce_hex: str, models: set | None = None) -> dict:
    body = {"nonce": nonce_hex, "arch": arch, "evidence_list": [{"evidence": e["evidence"], "certificate": e["certificate"]} for e in evidence]}
    st, data, _, _ = fetch("POST", f"{NRAS}/v3/attest/gpu", json.dumps(body).encode(), {"Content-Type": "application/json"})
    need(st == 200, f"NVIDIA NRAS HTTP {st}")
    out = json.loads(data)
    tokens = [out[0][1], *out[1].values()]
    kids = [json.loads(b64url(t.split(".")[0]))["kid"] for t in tokens]
    keys = nras_keys(set(kids))
    need(all(k in keys for k in kids), "NRAS 令牌的 kid 不在 NVIDIA 公钥列表里")
    claims = [jwt_claims(t, keys[k]) for t, k in zip(tokens, kids)]
    need(claims[0].get("x-nvidia-overall-att-result") is True, "NVIDIA 判定 GPU 证明未通过")
    need(claims[0].get("eat_nonce") == nonce_hex, "GPU 证明里的随机数不对")
    sub = claims[0].get("submods") or {}
    need(len(evidence) >= 1 and len(out[1]) == len(evidence) == len(sub) and set(sub) == set(out[1]),
         "NVIDIA 单卡令牌和 GPU 证据数量对不上")
    for name, t in out[1].items():
        need(sub[name] == ["DIGEST", ["SHA-256", hashlib.sha256(t.encode()).hexdigest()]], f"{name} 的单卡令牌不是整体令牌里登记的那一份")
    for c in claims[1:]:
        need(c.get("eat_nonce") == nonce_hex, "单卡令牌里的随机数不对")
        need(c.get("measres") == "success" and c.get("secboot") is True and c.get("dbgstat") == "disabled",
             f"GPU {c.get('hwmodel')} 度量、安全启动或调试状态不符合要求")
        need(models is None or c.get("hwmodel") in models, f"GPU 型号 {c.get('hwmodel')} 和参考值不符")
    return {"tokens": tokens, "keys": keys, "gpus": [c.get("hwmodel") for c in claims[1:]]}


CHUTE_IDS: dict = {}
E2E_POOL: dict = {}


def chute_id(model: str) -> str:
    if model not in CHUTE_IDS:
        st, data, _, _ = fetch("GET", f"{CHUTES_LLM}/v1/models", timeout=60)
        need(st == 200, f"Chutes 模型列表 HTTP {st}")
        for m in json.loads(data)["data"]:
            if m.get("confidential_compute") is True and m.get("chute_id"):
                CHUTE_IDS[m["id"]] = m["chute_id"]
    need(model in CHUTE_IDS, f"{model} 不是 Chutes 的 TEE 模型")
    return CHUTE_IDS[model]


def e2e_instances(cid: str) -> list:
    expires, instances = E2E_POOL.get(cid, (0, []))
    if time.time() >= expires or not any(i["nonces"] for i in instances):
        data = api_json("GET", f"{CHUTES_API}/e2e/instances/{cid}", CHUTES_API_KEY)
        instances = data["instances"]
        E2E_POOL[cid] = (time.time() + min(50, int(data.get("nonce_expires_in", 60)) - 5), instances)
    return [i for i in instances if i["nonces"]]


def chutes_row(r: dict):
    for version, image in CHUTES_PINS["images"].items():
        if all(image[k] == r[k] for k in ("mrtd", "rtmr1", "rtmr2", "rtmr3")):
            for row in CHUTES_PINS["rows"]:
                if row[0] == version and row[2] == r["rtmr0"]:
                    return row
    return None


def verify_chutes(ev: dict, nonce: str, e2e_pubkey: str) -> dict:
    need(ev.get("attested_body") and ev.get("signature"), "证据没有签名的原始响应")
    body = base64.b64decode(ev["attested_body"])
    cert = x509.load_der_x509_certificate(base64.b64decode(ev["certificate"]))
    cert.public_key().verify(base64.b64decode(ev["signature"]), body, padding.PKCS1v15(), hashes.SHA256())
    doc = json.loads(body)
    inner = doc.get("evidence") or {}
    need(doc.get("nonce", nonce) == nonce, "证据里的随机数不是本次的")
    raw = inner.get("tdx_quote") or inner.get("quote")
    need(raw, "证据里没有 quote")
    tcb, td, col = verify_tdx(base64.b64decode(raw))
    rd = bytes(td.report_data).hex()
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    need(rd[64:] == hashlib.sha256(spki).hexdigest(), "quote 没有绑定这张证书")
    need(rd[:64] == hashlib.sha256((nonce + e2e_pubkey).encode()).hexdigest(), "quote 没有绑定本次随机数和这把加密公钥")
    r = regs(td)
    row = chutes_row(r)
    need(row is not None, "度量值不在 Chutes 参考值快照里")
    gpu = inner.get("nvtrust_evidence")
    gpu = json.loads(gpu) if isinstance(gpu, str) else gpu
    need(gpu and len(gpu) <= row[4], "GPU 数量和参考值不符")
    models = set().union(*(CHUTES_PINS["gpu_models"].get(g, []) for g in row[3]))
    g = nras(gpu[0]["arch"], gpu, rd[:64], models)
    return {"tcb": tcb, "measurement": f"{row[0]} {row[1]}", "gpus": g["gpus"], "nras": g, "collateral": col}


def mlkem_key(ss: bytes, ct: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=ct[:16], info=info).derive(ss)


def call_chutes(messages: list, nonce, sess: dict | None = None, req: dict | None = None, on_delta=None) -> dict:
    need(isinstance(nonce, str) and HEX64.fullmatch(nonce), "缺少本次随机数")
    sess = {} if sess is None else sess
    model = (req or {}).get("model") or CHUTES_MODEL
    out = {"mode": "chutes", "model": model}
    t0 = time.time()
    cid = chute_id(model)
    slot = "chutes" if model == CHUTES_MODEL else "chutes:" + model
    up = {"nonce": nonce, "chute_id": cid, "attempts": []}
    out["upstream"] = up
    instances = e2e_instances(cid)
    full = set()
    for _ in range(3):
        chosen = chutes_pick(sess, slot, instances, nonce, up, full)
        up["verify_seconds"] = round(time.time() - t0, 2)
        if chosen is None:
            out["error"] = (f"{out['error']}（已换过 {len(full)} 个实例）" if full else "没有通过验证的 Chutes 实例，消息未发送")
            return out
        sent = chutes_invoke(chosen, cid, model, messages, req, on_delta, up)
        st, data = sent["status"], sent["data"]
        if st != 429:
            break
        sess.pop(slot, None)
        full.add(chosen[0]["instance_id"])
        out["error"] = upstream_error("Chutes", st, data)
        up["attempts"].append({"instance_id": chosen[0]["instance_id"], "error": out["error"]})
    else:
        out["error"] = f"{out['error']}（已换过 {len(full)} 个实例）"
        return out
    out.pop("error", None)
    i = chosen[0]
    up["invoke_seconds"] = sent["seconds"]
    up["request"] = sent["request"]
    up["request_ciphertext_bytes"] = len(sent["blob"])
    if st != 200:
        sess.pop(slot, None)
        out["error"] = upstream_error("Chutes", st, data)
        return out
    up["response_ciphertext_bytes"] = len(data)
    if sent["acc"]:
        up["response"] = sent["acc"].result()
    else:
        rct, rest = data[:1088], data[1088:]
        up["response"] = json.loads(gzip.decompress(ChaCha20Poly1305(mlkem_key(sent["sk"].decapsulate(rct), rct, b"e2e-resp-v1"))
                                                    .decrypt(rest[:12], rest[12:], None)))
    out["response"] = up["response"]
    out["verified"] = {"instance_id": i["instance_id"], "e2e": "ML-KEM-768 + ChaCha20-Poly1305", "stream_chunks": up.get("stream_chunks"),
                       "reused": bool(up.get("reused"))}
    try:
        out["reply"] = up["response"]["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError, AttributeError):
        out["reply"] = None
    return out


def chutes_pick(sess: dict, slot: str, instances: list, nonce: str, up: dict, skip: set):
    c = cached(sess, slot)
    if c and c["instance_id"] not in skip:
        i = next((x for x in instances if x["instance_id"] == c["instance_id"] and x["e2e_pubkey"] == c["e2e_pubkey"] and x["nonces"]), None)
        if i:
            up.update(nonce=c["nonce"], reused={"verified_at": c["verified_at"]})
            return i, c["evidence"], c["result"]
        sess.pop(slot, None)
    up.pop("reused", None)
    up["nonce"] = nonce
    tried = {a["instance_id"] for a in up["attempts"]}
    for i in [x for x in instances if x["instance_id"] not in skip and x["instance_id"] not in tried and x["nonces"]][:3]:
        try:
            ev = api_json("GET", f"{CHUTES_API}/instances/{i['instance_id']}/evidence?nonce={nonce}", CHUTES_API_KEY)
            result = verify_chutes(ev, nonce, i["e2e_pubkey"])
            sess[slot] = {"verified_at": time.time(), "instance_id": i["instance_id"], "e2e_pubkey": i["e2e_pubkey"],
                          "evidence": ev, "result": result, "nonce": nonce}
            return i, ev, result
        except Exception as e:
            up["attempts"].append({"instance_id": i["instance_id"], "error": f"{type(e).__name__}: {e}"})
    return None


def chutes_invoke(chosen, cid: str, model: str, messages: list, req: dict | None, on_delta, up: dict) -> dict:
    i, ev, v = chosen
    up.update({"instance_id": i["instance_id"], "e2e_pubkey": i["e2e_pubkey"],
               "evidence": {k: ev.get(k) for k in ("attested_body", "signature", "certificate")}, **v})
    response_sk = MLKEM768PrivateKey.generate()
    response_pk = response_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    acc = Completion(on_delta) if on_delta else None
    request = {**{k: v for k, v in (req or {"messages": messages}).items() if k != "stream_options"}, "model": model, "stream": bool(acc)}
    ss, ct = MLKEM768PublicKey.from_public_bytes(base64.b64decode(i["e2e_pubkey"])).encapsulate()
    sealed = gzip.compress(json.dumps({**request, "e2e_response_pk": base64.b64encode(response_pk).decode()}).encode())
    iv = os.urandom(12)
    blob = ct + iv + ChaCha20Poly1305(mlkem_key(ss, ct, b"e2e-req-v1")).encrypt(iv, sealed, None)
    t1 = time.time()
    headers = {"Authorization": f"Bearer {CHUTES_API_KEY}", "Content-Type": "application/octet-stream",
               "X-Chute-Id": cid, "X-Instance-Id": i["instance_id"], "X-E2E-Nonce": i["nonces"].pop(0),
               "X-E2E-Stream": "true" if acc else "false", "X-E2E-Path": "/v1/chat/completions"}
    if acc:
        inner, chan = SSE(acc.add), {"key": None, "seq": 0}

        def frame(obj: dict):
            if "e2e_init" in obj:
                need(chan["key"] is None, "Chutes 流里出现了第二次密钥封装")
                kct = base64.b64decode(obj["e2e_init"])
                chan["key"] = mlkem_key(response_sk.decapsulate(kct), kct, b"e2e-stream-v1")
            elif "e2e" in obj:
                need(chan["key"] is not None, "Chutes 流缺少密钥封装")
                raw = base64.b64decode(obj["e2e"])
                need(int.from_bytes(raw[4:12], "little") == chan["seq"], "Chutes 流的分块序号不连续")
                chan["seq"] += 1
                inner.feed(ChaCha20Poly1305(chan["key"]).decrypt(raw[:12], raw[12:], None))
            elif obj.get("error"):
                raise Rejected(f"Chutes 流里返回错误：{str(obj['error'])[:300]}")

        st, data, _, _ = fetch("POST", f"{CHUTES_API}/e2e/invoke", blob, headers, 300, on_chunk=SSE(frame).feed)
        up["stream_chunks"] = chan["seq"]
        if st == 200:
            need(inner.done, "Chutes 流没有正常结束（缺少 [DONE]）")
    else:
        st, data, _, _ = fetch("POST", f"{CHUTES_API}/e2e/invoke", blob, headers, 300)
    return {"status": st, "data": data, "sk": response_sk, "acc": acc, "blob": blob, "request": request,
            "seconds": round(time.time() - t1, 2)}


def runtime_preimage(e: dict) -> bytes:
    payload = bytes.fromhex(e.get("event_payload") or "")
    if int(e.get("version", 1)) == 2:
        return jcs({"name": e["event"], "payload": payload.hex(), "type": DSTACK_RUNTIME_EVENT})
    return DSTACK_RUNTIME_EVENT.to_bytes(4, "little") + b":" + e["event"].encode() + b":" + payload


def replay_rtmr3(events: list):
    mr, named = b"\0" * 48, {}
    for e in events:
        if int(e["imr"]) != 3:
            continue
        need(int(e["event_type"]) == DSTACK_RUNTIME_EVENT, "RTMR3 里有非 dstack 事件")
        pre = runtime_preimage(e)
        digest = bytes.fromhex(e.get("digest") or "") or hashlib.sha384(pre).digest()
        need(hashlib.sha384(pre).digest() == digest, f"事件 {e['event']} 的摘要和内容对不上")
        named.setdefault(e["event"], []).append((e.get("event_payload") or "").lower())
        mr = hashlib.sha384(mr + digest).digest()
    return mr, named


def one(named: dict, name: str) -> str:
    v = named.get(name) or []
    need(len(v) == 1, f"事件日志里有 {len(v)} 条 {name}")
    return v[0]


def unhex(s: str) -> bytes:
    s = s.removeprefix("0x")
    return bytes.fromhex(s) if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s) else base64.b64decode(s)


def verify_near(att: dict, nonce: str) -> dict:
    tcb, td, col = verify_tdx(unhex(att["intel_quote"]))
    rd = bytes(td.report_data).hex()
    key = att["signing_address"].removeprefix("0x").lower()
    need(len(key) == 64 and rd[:64] == key, "quote 没有绑定这把 Ed25519 公钥")
    need(rd[64:] == nonce, "quote 没有绑定本次随机数")
    events = att["event_log"]
    events = json.loads(events) if isinstance(events, str) else events
    mr, named = replay_rtmr3(events)
    need(mr == bytes(td.rt_mr3), "事件日志重放和 quote 的 RTMR3 不一致")
    r, pin = regs(td), NEAR_PINS
    need(r["mrtd"] in pin["mrtd"] and r["rtmr1"] == pin["rtmr1"] and r["rtmr2"] == pin["rtmr2"], f"系统镜像不是固定的 {pin['image']}")
    need(r["rtmr0"] in pin["rtmr0"], "虚拟硬件（RTMR0）不在参考值里")
    need(one(named, "os-image-hash") == pin["os_image_hash"], "os-image-hash 和参考值不符")
    need(json.loads(bytes.fromhex(one(named, "key-provider"))).get("id") == pin["kms"], "密钥不是来自固定的 NEAR KMS")
    need(one(named, "app-id") in pin["app_ids"], "app-id 不在参考值里")
    info = att.get("info") or {}
    info = json.loads(info) if isinstance(info, str) else info
    tcb_info = info.get("tcb_info") or {}
    tcb_info = json.loads(tcb_info) if isinstance(tcb_info, str) else tcb_info
    compose = tcb_info.get("app_compose") or ""
    compose_hash = hashlib.sha256(compose.encode()).hexdigest()
    need(one(named, "compose-hash") == compose_hash, "compose-hash 和 app_compose 对不上")
    need(compose_hash in pin["compose_hashes"], "部署配置（compose-hash）不在参考值里")
    cm = att.get("compose_manager_attestation")
    cm = json.loads(cm) if isinstance(cm, str) else cm
    need(isinstance(cm, dict), "缺少 compose-manager 部署日志")
    _, ctd, ccol = verify_tdx(unhex(cm["quote"]))
    need(regs(ctd) == regs(td), "部署日志的 quote 和模型 quote 不是同一台机器")
    actions_hash = hashlib.sha256(jcs(cm["actions"])).hexdigest()
    crd = bytes(ctd.report_data).hex()
    need(actions_hash == cm.get("actions_hash") and crd[:64] == actions_hash, "部署日志哈希和 quote 对不上")
    need(crd[64:] == nonce, "部署日志的 quote 没有绑定本次随机数")
    p = att.get("nvidia_payload")
    p = json.loads(p) if isinstance(p, str) else p
    need(p and str(p.get("nonce", "")).lower() == nonce, "GPU 证明里的随机数不是本次的")
    g = nras(p["arch"], p["evidence_list"], nonce)
    return {"tcb": tcb, "compose_hash": compose_hash, "gpus": g["gpus"], "nras": g, "collateral": col, "cm_collateral": ccol,
            "deploys": sum(1 for a in cm["actions"] if a.get("action") == "compose_up")}


def near_key(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ed25519_encryption").derive(shared)


def near_seal(model_key_hex: str, text: str, client_pub: bytes, label: str) -> str:
    aad = b"nearai-e2ee-request-v3\x02" + client_pub + b"\x00" + label.encode()
    peer = nb.crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(model_key_hex))
    eph, iv = os.urandom(32), os.urandom(24)
    ct = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(text.encode(), aad, iv, near_key(nb.crypto_scalarmult(eph, peer)))
    return (nb.crypto_scalarmult_base(eph) + iv + ct).hex()


NEAR_MESSAGE_FIELDS = ("content", "reasoning_content", "reasoning", "name", "refusal")


NEAR_PARAMS = {"model", "messages", "tools", "tool_choice", "stream", "stream_options", "max_tokens", "max_completion_tokens",
               "temperature", "top_p", "top_k", "min_p", "seed", "presence_penalty", "frequency_penalty", "repetition_penalty",
               "n", "parallel_tool_calls", "reasoning_effort", "logprobs", "top_logprobs"}
NEAR_MESSAGE_KEYS = {"role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content", "reasoning", "refusal"}


def near_inline_schema(req: dict | None) -> dict | None:
    rf = (req or {}).get("response_format")
    if not (isinstance(rf, dict) and rf.get("type") == "json_schema" and isinstance(rf.get("json_schema"), dict)):
        return req
    note = ("Reply with a single JSON object that matches this JSON Schema, and nothing else:\n" +
            json.dumps(rf["json_schema"], ensure_ascii=False))
    msgs = list(req.get("messages") or [])
    first = msgs[0] if msgs else {}
    if first.get("role") == "system" and isinstance(first.get("content"), str):
        msgs[0] = {**first, "content": f"{first['content']}\n\n{note}"}
    elif first.get("role") == "system" and isinstance(first.get("content"), list):
        msgs[0] = {**first, "content": [*first["content"], {"type": "text", "text": note}]}
    else:
        msgs.insert(0, {"role": "system", "content": note})
    return {**req, "messages": msgs, "response_format": {"type": "json_object"}}


def near_check_body(body: dict):
    rf = body.get("response_format")
    need(rf is None or rf in ({"type": "json_object"}, {"type": "text"}), "response_format 里带 schema 等内容，NEAR 不加密，CVM 不发送")
    extra = sorted(set(body) - NEAR_PARAMS - {"response_format"})
    need(not extra, f"NEAR 第 3 版加密不覆盖这些字段，CVM 不发送：{', '.join(extra)}")
    for m in body.get("messages") or []:
        extra = sorted(set(m) - NEAR_MESSAGE_KEYS)
        need(not extra, f"消息里有 NEAR 不加密的字段，CVM 不发送：{', '.join(extra)}")
        for tc in m.get("tool_calls") or []:
            need(set(tc) <= {"id", "type", "function", "index"} and set(tc.get("function") or {}) <= {"name", "arguments"},
                 "工具调用里有 NEAR 不加密的字段，CVM 不发送")
    for t in body.get("tools") or []:
        need(t.get("type") == "function" and set(t) <= {"type", "function"} and isinstance(t.get("function"), dict)
             and set(t["function"]) <= {"name", "description", "parameters", "strict"}, "只能发送 function 类型的工具定义，其他类型 NEAR 不加密")
    tc = body.get("tool_choice")
    need(tc is None or tc in ("auto", "none", "required") or
         (isinstance(tc, dict) and set(tc) <= {"type", "function"} and set(tc.get("function") or {}) <= {"name"}), "tool_choice 格式 NEAR 不加密")
    need(set(body.get("stream_options") or {}) <= {"include_usage"}, "stream_options 里有不支持的字段")


def near_seal_body(body: dict, model_key: str, client_pub: bytes) -> dict:
    seal = lambda label, v: near_seal(model_key, v if isinstance(v, str) else json.dumps(v, ensure_ascii=False), client_pub, label)
    out = {k: v for k, v in body.items() if k not in ("messages", "tools", "tool_choice")}
    msgs = []
    for m in body.get("messages") or []:
        m = dict(m)
        for f in NEAR_MESSAGE_FIELDS:
            if m.get(f) not in (None, ""):
                m[f] = seal(f"messages[].{f}", m[f])
        if isinstance(m.get("tool_calls"), list):
            m["tool_calls"] = [{**tc, "function": {**tc.get("function", {}), **{
                f: seal(f"messages[].tool_calls[].function.{f}", tc["function"][f])
                for f in ("name", "arguments") if (tc.get("function") or {}).get(f) not in (None, "")}}} for tc in m["tool_calls"]]
        msgs.append(m)
    out["messages"] = msgs
    if body.get("tools"):
        out["tools"] = [{**t, "function": {**t["function"], **{
            f: seal(f"tools[].function.{f}", t["function"][f])
            for f in ("name", "description", "parameters") if t["function"].get(f) not in (None, "")}}}
            if isinstance(t.get("function"), dict) else t for t in body["tools"]]
    tc = body.get("tool_choice")
    if isinstance(tc, dict) and isinstance(tc.get("function"), dict) and tc["function"].get("name"):
        out["tool_choice"] = {**tc, "function": {**tc["function"], "name": seal("tool_choice.function.name", tc["function"]["name"])}}
    elif tc is not None:
        out["tool_choice"] = tc
    return out


def near_open_message(client: Ed25519PrivateKey, msg: dict) -> dict:
    m = dict(msg)
    for f in NEAR_MESSAGE_FIELDS:
        if isinstance(m.get(f), str) and m[f]:
            m[f] = near_open(client, m[f])
    if isinstance(m.get("tool_calls"), list):
        m["tool_calls"] = [{**tc, "function": {**tc.get("function", {}), **{
            f: near_open(client, tc["function"][f]) for f in ("name", "arguments")
            if isinstance((tc.get("function") or {}).get(f), str) and tc["function"][f]}}} for tc in m["tool_calls"]]
    return m


def near_open(client: Ed25519PrivateKey, blob_hex: str) -> str:
    pub = client.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = nb.crypto_sign_ed25519_sk_to_curve25519(client.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) + pub)
    blob = bytes.fromhex(blob_hex)
    return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(blob[56:], None, blob[32:56],
                                                         near_key(nb.crypto_scalarmult(x, blob[:32]))).decode()


def near_signature_problem(sig, model_key: str, req: bytes, resp: bytes, model: str = None):
    if not isinstance(sig, dict):
        return "没取到签名"
    if str(sig.get("signing_address", "")).removeprefix("0x").lower() != model_key:
        return "签名者不是刚验证的模型公钥"
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(model_key)).verify(unhex(str(sig.get("signature", ""))), str(sig.get("text", "")).encode())
    except Exception:
        return "签名无效"
    parts = str(sig["text"]).split(":")
    if sig.get("signature_kind") != "provider_tee":
        return f"签名类型是 {sig.get('signature_kind')}，不是模型机签的"
    if len(parts) != 3 or parts[0] != (model or NEAR_MODEL):
        return "签名里的模型不对"
    if parts[1] != hashlib.sha256(req).hexdigest():
        return "签名覆盖的请求不是 CVM 发出的字节"
    if parts[2] != hashlib.sha256(resp).hexdigest():
        return "签名覆盖的回复不是 CVM 收到的字节"
    return None


def call_near(messages: list, nonce, sess: dict | None = None, req: dict | None = None, on_delta=None) -> dict:
    need(isinstance(nonce, str) and HEX64.fullmatch(nonce), "缺少本次随机数")
    sess = {} if sess is None else sess
    model = (req or {}).get("model") or NEAR_MODEL
    req = near_inline_schema(req)
    near_check_body(req or {"messages": messages})
    slot = "near" if model == NEAR_MODEL else "near:" + model
    out = {"mode": "near", "model": model}
    t0 = time.time()
    q = urllib.parse.urlencode({"model": model, "signing_algo": "ed25519", "nonce": nonce})
    up = {"nonce": nonce, "attempts": []}
    out["upstream"] = up
    chosen = None
    c = cached(sess, slot)
    if c:
        chosen = (c["attestation"], c["result"])
        up.update(nonce=c["nonce"], reused={"verified_at": c["verified_at"]})
    for _ in range(0 if chosen else 3):
        report = api_json("GET", f"{NEAR_API}/v1/attestation/report?{q}", NEAR_API_KEY, timeout=180)
        for att in (report.get("model_attestations") or [])[:3]:
            try:
                chosen = (att, verify_near(att, nonce))
                sess[slot] = {"verified_at": time.time(), "attestation": att, "result": chosen[1], "nonce": nonce}
                break
            except Exception as e:
                up["attempts"].append({"signing_address": att.get("signing_address"), "error": f"{type(e).__name__}: {e}"})
        if chosen:
            break
    up["verify_seconds"] = round(time.time() - t0, 2)
    if chosen is None:
        out["error"] = "NEAR 模型机证明未通过，消息未发送"
        return out
    att, v = chosen
    model_key = att["signing_address"].removeprefix("0x").lower()
    up.update({"attestation": {k: att.get(k) for k in ("intel_quote", "event_log", "info", "nvidia_payload", "signing_address",
                                                       "signing_algo", "compose_manager_attestation")}, **v})
    client = Ed25519PrivateKey.generate()
    client_raw = client.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_pub = client_raw.hex()
    body = {k: v for k, v in (req or {"messages": messages}).items() if k not in ("stream_options",)}
    acc = Completion(on_delta) if on_delta else None
    req_bytes = json.dumps({**near_seal_body(body, model_key, client_raw), "model": model, "stream": bool(acc)},
                           separators=(",", ":")).encode()
    t1 = time.time()
    headers = {"Authorization": f"Bearer {NEAR_API_KEY}", "Content-Type": "application/json", "X-Signing-Algo": "ed25519",
               "X-Client-Pub-Key": client_pub, "X-Model-Pub-Key": model_key, "X-Encryption-Version": "3"}
    if acc:
        opened = lambda c: acc.add({**c, "choices": [{**ch, "delta": near_open_message(client, ch.get("delta") or {})}
                                                     for ch in c.get("choices") or []]})
        st, data, _, _ = fetch("POST", f"{NEAR_API}/v1/chat/completions", req_bytes, headers, 300, on_chunk=SSE(opened).feed)
    else:
        st, data, _, _ = fetch("POST", f"{NEAR_API}/v1/chat/completions", req_bytes, headers, 300)
    up["invoke_seconds"] = round(time.time() - t1, 2)
    up.update({"client_public_key": client_pub, "request_b64": base64.b64encode(req_bytes).decode(),
               "response_b64": base64.b64encode(data).decode(), "plain_messages": messages})
    if st != 200:
        sess.pop(slot, None)
        out["error"] = upstream_error("NEAR", st, data)
        return out
    if acc:
        opened = resp = acc.result()
    else:
        resp = json.loads(data)
        opened = {**resp, "choices": [{**ch, "message": near_open_message(client, ch.get("message") or {})} for ch in resp.get("choices") or []]}
    out["response"] = opened
    msg = opened["choices"][0]["message"]
    out["reply"] = (msg.get("content") or "").strip()
    if msg.get("reasoning_content"):
        up["reasoning"] = msg["reasoning_content"]
    for _ in range(6):
        sq = urllib.parse.urlencode({"model": model, "signing_algo": "ed25519"})
        st, sig, _, _ = fetch("GET", f"{NEAR_API}/v1/signature/{urllib.parse.quote(resp['id'], safe='')}?{sq}", None,
                              {"Authorization": f"Bearer {NEAR_API_KEY}"}, 60)
        if st == 200:
            up["signature"] = json.loads(sig)
            break
        time.sleep(0.5)
    why = near_signature_problem(up.get("signature"), model_key, req_bytes, data, model)
    up["signature_verified"] = why is None
    if why:
        sess.pop(slot, None)
        out["error"] = f"NEAR 回复签名验证失败：{why}"
    else:
        out["verified"] = {"signing_address": model_key, "request_sha256": sha256_tag(req_bytes), "response_sha256": sha256_tag(data)}
    return out


def env_list(name: str, default: list) -> list:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()] or default


MODELS = {"phala": env_list("PHALA_MODELS", [MODEL]),
          "chutes": env_list("CHUTES_MODELS", [CHUTES_MODEL, "zai-org/GLM-5.2-TEE", "deepseek-ai/DeepSeek-V4-Flash-0731-TEE",
                                               "moonshotai/Kimi-K2.6-TEE"]),
          "near": env_list("NEAR_MODELS", [NEAR_MODEL])}
VISION = set(env_list("VISION_MODELS", ["Qwen/Qwen3.8-27B-TEE", "Qwen/Qwen3.8-27B", "moonshotai/Kimi-K2.6-TEE"]))
CALLERS = {"phala": call_phala, "chutes": call_chutes, "near": call_near}


def model_catalog() -> dict:
    ready = providers()
    return {p: [{"id": m, "vision": m in VISION} for m in ms] for p, ms in MODELS.items() if ready[p]["ready"]}


TURNS: dict = {}
CHAT_LOCKS: dict = {}
CHAT_TURNS: dict = {}
CHATS_LOCK = threading.RLock()
TURN_TOKEN = re.compile(r"t-[0-9a-f]{8}")
VISION_STUB = "[图片：当前模型不能看图，CVM 已把图片去掉]"


def turn_of(name: str):
    token, _, rest = name.partition("/")
    if TURN_TOKEN.fullmatch(token):
        turn = TURNS.get(token)
        return (turn if turn and turn["active"] else None), rest
    return None, name


def active_turns() -> list:
    return [t for t in list(TURNS.values()) if t["active"]]


def internet_on() -> bool:
    try:
        with open(os.path.join(AGENT_STATE_DIR, "internet")) as f:
            return f.read().strip() == "1"
    except (OSError, TypeError):
        return False


def set_internet(on: bool):
    need(AGENT_STATE_DIR, "没有配置 agent 状态目录")
    path = os.path.join(AGENT_STATE_DIR, "internet")
    with open(path + ".tmp", "w") as f:
        f.write("1" if on else "0")
    os.replace(path + ".tmp", path)
    if not on:
        cut_tunnels(lambda t: True)


def init_agent_state():
    if AGENT_STATE_DIR and not os.path.exists(os.path.join(AGENT_STATE_DIR, "internet")):
        os.makedirs(AGENT_STATE_DIR, exist_ok=True)
        set_internet(os.environ.get("AGENT_INTERNET_DEFAULT", "0") == "1")


def strip_images(messages: list) -> list:
    out = []
    for m in messages:
        c = m.get("content")
        if isinstance(c, list) and any(isinstance(p, dict) and p.get("type") in ("image_url", "input_image") for p in c):
            m = {**m, "content": [{"type": "text", "text": VISION_STUB} if isinstance(p, dict) and p.get("type") in ("image_url", "input_image")
                                  else p for p in c]}
        out.append(m)
    return out


class Deltas:
    def __init__(self, emit, n: int, aux: bool = False):
        self.emit, self.n, self.aux, self.kind, self.buf, self.at = emit, n, aux, None, "", time.time()

    def __call__(self, kind: str, text: str):
        if self.buf and kind != self.kind:
            self.flush()
        self.kind, self.buf = kind, self.buf + text
        if time.time() - self.at > 0.1:
            self.flush()

    def flush(self):
        if self.buf:
            self.emit({"type": "model.delta", "n": self.n, "kind": "aux" if self.aux else self.kind, "delta": self.buf})
        self.buf, self.at = "", time.time()


def proxy_completion(body: dict):
    name = str(body.get("model") or "")
    turn, routed = turn_of(name)
    provider, _, model = routed.partition("/")
    if provider not in CALLERS or model not in MODELS.get(provider, []) or not providers()[provider]["ready"]:
        return 404, {"error": {"message": f"未知模型 {name}", "type": "invalid_request_error"}}
    if turn is None:
        return 403, {"error": {"message": "这次模型调用不属于任何一轮进行中的对话（标记缺失或已失效），CVM 拒绝", "type": "permission_error"}}
    if (provider, model) != (turn["provider"], turn["model"]):
        return 403, {"error": {"message": f"本轮批准的是 {turn['provider']}/{turn['model']}，不能改用 {provider}/{model}",
                               "type": "permission_error"}}
    if model not in VISION:
        body = {**body, "messages": strip_images(body.get("messages") or [])}
    removed = []
    if turn is not None and not internet_on() and body.get("tools"):
        tool = lambda t: str((t.get("function") or {}).get("name", ""))
        removed = [tool(t) for t in body["tools"] if tool(t).startswith(NET_TOOLS)]
        body = {**body, "tools": [t for t in body["tools"] if not tool(t).startswith(NET_TOOLS)]}
    nonce, sess = turn["nonce"], turn["sess"]
    t0 = time.time()
    deltas = None
    if turn is not None:
        aux = not body.get("tools")
        turn["emit"]({"type": "model.started", "provider": provider, "model": model, "n": len(turn["calls"]) + 1, "aux": aux})
        deltas = Deltas(lambda ev: None if turn.get("stopped") else turn["emit"](ev), len(turn["calls"]) + 1, aux)
    box = {}

    def call():
        try:
            box["out"] = CALLERS[provider](body.get("messages") or [], nonce, sess, {**body, "model": model}, *([deltas] if deltas else []))
        except Exception as e:
            box["out"] = {"mode": provider, "model": model, "error": scrub(f"{type(e).__name__}: {e}")}
    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    while worker.is_alive() and not turn.get("stopped"):
        worker.join(0.5)
    out = box.get("out") or {"mode": provider, "model": model, "error": "这一轮已被停止"}
    if deltas:
        deltas.flush()
    resp = out.get("response") if provider != "phala" or out.get("upstream_status") == 200 else None
    up = out.get("upstream") or {}
    msg = ((resp or {}).get("choices") or [{}])[0].get("message") or {}
    if turn is not None:
        turn["calls"].append({"provider": provider, "model": model, "aux": not body.get("tools"), "net_tools_removed": removed,
                              "verified": out.get("verified") if not out.get("error") else None,
                              "reused": bool(up.get("reused") or out.get("reused")),
                              "seconds": round(time.time() - t0, 2), "ok": resp is not None and not out.get("error"),
                              "error": out.get("error"), "tool_calls": [tc.get("function", {}).get("name") for tc in msg.get("tool_calls") or []]})
        best, aux = turn["evidence"].get(provider), not body.get("tools")
        cut_short = turn.get("stopped") and out.get("error")
        if not cut_short and (best is None or best.get("error") or (best.get("aux") and not aux and not out.get("error"))):
            turn["evidence"][provider] = {**out, "aux": aux, "call": len(turn["calls"])}
        turn["emit"]({"type": "model.completed", "n": len(turn["calls"]), **turn["calls"][-1]})
    if resp is None or out.get("error"):
        return 502, {"error": {"message": out.get("error") or "上游没有返回结果", "type": "upstream_error"}}
    return 200, {**resp, "model": name}


def sse_from_completion(resp: dict) -> bytes:
    ch = (resp.get("choices") or [{}])[0]
    msg = ch.get("message") or {}
    delta = {"role": "assistant", **{k: msg[k] for k in ("content", "reasoning_content") if msg.get(k)}}
    if msg.get("tool_calls"):
        delta["tool_calls"] = [{"index": i, **tc} for i, tc in enumerate(msg["tool_calls"])]
    base = {"id": resp.get("id"), "object": "chat.completion.chunk", "created": resp.get("created", int(time.time())), "model": resp.get("model")}
    frames = [{**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
              {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": ch.get("finish_reason") or "stop"}], "usage": resp.get("usage")}]
    return b"".join(b"data: " + json.dumps(f, ensure_ascii=False).encode() + b"\n\n" for f in frames) + b"data: [DONE]\n\n"


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "pa-mvp-proxy/1"

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return not PROXY_TOKEN or hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {PROXY_TOKEN}")

    def do_GET(self):
        if not self._authorized():
            return self._send(401, {"error": {"message": "unauthorized"}})
        path = urllib.parse.urlsplit(self.path).path
        items = [{"id": f"{p}/{m['id']}", "object": "model", "owned_by": p} for p, ms in model_catalog().items() for m in ms]
        if path == "/v1/models":
            return self._send(200, {"object": "list", "data": items})
        if path.startswith("/v1/models/"):
            asked = path[len("/v1/models/"):]
            hit = next((x for x in items if x["id"] == turn_of(asked)[1]), None)
            return self._send(200, {**hit, "id": asked}) if hit else self._send(404, {"error": {"message": "not found"}})
        self._send(404, {"error": {"message": "not found"}})

    def do_POST(self):
        if not self._authorized():
            return self._send(401, {"error": {"message": "unauthorized"}})
        if urllib.parse.urlsplit(self.path).path != "/v1/chat/completions":
            return self._send(404, {"error": {"message": "not found"}})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_STREAM_BODY:
            return self._send(413, {"error": {"message": "body 太大或为空"}})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self._send(400, {"error": {"message": "不是 JSON"}})
        code, resp = proxy_completion(body)
        if code != 200 or not body.get("stream"):
            return self._send(code, resp)
        data = sse_from_completion(resp)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write("proxy %s %s\n" % (self.command, urllib.parse.urlsplit(self.path).path))


AGENT_SID: list = []


def agent_http(method: str, path: str, body=None, timeout: int = 60):
    u = urllib.parse.urlsplit(AGENT_URL)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    conn.request(method, path, body=None if body is None else json.dumps(body, ensure_ascii=False).encode(),
                 headers={"Authorization": f"Bearer {AGENT_KEY}", "Content-Type": "application/json"})
    return conn, conn.getresponse()


def agent_json(method: str, path: str, body=None):
    conn, r = agent_http(method, path, body)
    try:
        data = r.read()
    finally:
        conn.close()
    need(r.status in (200, 201), f"agent {method} {path.split('?')[0]} HTTP {r.status}: {data[:200].decode('utf-8', 'replace')}")
    return json.loads(data)


def agent_session() -> str:
    if AGENT_SID:
        return AGENT_SID[0]
    path = os.path.join(AGENT_STATE_DIR, "shared_session") if AGENT_STATE_DIR else ""
    sid = open(path).read().strip() if path and os.path.isfile(path) else ""
    if sid:
        try:
            agent_json("GET", f"/api/sessions/{urllib.parse.quote(sid)}")
        except Rejected:
            sid = ""
    if not sid:
        listed = agent_json("GET", "/api/sessions?limit=200")
        items = listed.get("sessions") or listed.get("data") or []
        sid = next((x.get("id") for x in items if x.get("title") == "共享会话"), "") or \
            agent_json("POST", "/api/sessions", {"title": "共享会话"})["session"]["id"]
        if path:
            with open(path, "w") as f:
                f.write(sid)
    AGENT_SID.append(sid)
    return sid


def chats_path() -> str:
    return os.path.join(AGENT_STATE_DIR, "chats.json") if AGENT_STATE_DIR else ""


RETENTION_DAYS = float(os.environ.get("AGENT_RETENTION_DAYS", "0"))
PRUNED_AT = [0.0]


def load_registry() -> list:
    path = chats_path()
    if path and os.path.isfile(path):
        with open(path) as f:
            return json.load(f)
    return []


def chat_registry() -> list:
    if not chats_path():
        return [{"id": agent_session(), "created": int(time.time())}]
    with CHATS_LOCK:
        return load_registry() or [new_chat()]


def save_registry(reg: list):
    tmp = chats_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(reg, f, ensure_ascii=False)
    os.replace(tmp, chats_path())


def delete_chat(sid: str, why: str = "deleted"):
    with CHATS_LOCK:
        lock = CHAT_LOCKS.get(sid)
        need(not (lock and lock.locked()), "这个会话正在运行，等这一轮结束再删")
        conn, r = agent_http("DELETE", f"/api/sessions/{urllib.parse.quote(sid)}")
        try:
            r.read()
        finally:
            conn.close()
        need(r.status in (200, 204, 404), f"agent 删除会话失败：HTTP {r.status}")
        save_registry([c for c in chat_registry() if c["id"] != sid])
        CHAT_LOCKS.pop(sid, None)


def prune_old(meta: dict):
    now = time.time()
    if not chats_path() or RETENTION_DAYS <= 0 or now - PRUNED_AT[0] < 600:
        return
    PRUNED_AT[0] = now
    cutoff = now - RETENTION_DAYS * 86400
    for c in list(chat_registry()):
        last = (meta.get(c["id"]) or {}).get("last_active") or c.get("created") or now
        if last < cutoff:
            try:
                delete_chat(c["id"], "expired")
            except Rejected:
                pass
    if AGENT_UPLOAD_DIR and os.path.isdir(AGENT_UPLOAD_DIR):
        for name in os.listdir(AGENT_UPLOAD_DIR):
            path = os.path.join(AGENT_UPLOAD_DIR, name)
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.unlink(path)


def chat_id(inner: dict) -> str:
    sid = inner.get("chat") or chat_registry()[0]["id"]
    need(any(c["id"] == sid for c in chat_registry()), "没有这个会话")
    return sid


def list_chats() -> list:
    listed = agent_json("GET", "/api/sessions?limit=200")
    meta = {x.get("id"): x for x in listed.get("sessions") or listed.get("data") or []}
    prune_old(meta)
    out = []
    for c in chat_registry():
        m = meta.get(c["id"]) or {}
        lock = CHAT_LOCKS.get(c["id"])
        out.append({"id": c["id"], "title": m.get("title") or c.get("title") or "会话", "created": c.get("created"),
                    "messages": m.get("message_count"), "updated": m.get("last_active") or m.get("updated_at") or m.get("started_at"),
                    "running": bool(lock and lock.locked())})
    return out


def new_chat() -> dict:
    with CHATS_LOCK:
        reg = load_registry()
        need(len(reg) < 50, "会话太多了（上限 50 个）")
        listed = (lambda d: d.get("sessions") or d.get("data") or [])(agent_json("GET", "/api/sessions?limit=200"))
        taken = {x.get("title") for x in listed} | {x.get("title") for x in reg}
        n = len(reg) + 1
        while f"会话 {n}" in taken:
            n += 1
        made = agent_json("POST", "/api/sessions", {})
        sid = (made.get("session") or made).get("id")
        need(sid, "agent 没有返回会话 id")
        reg.append({"id": sid, "title": f"会话 {n}", "created": int(time.time())})
        save_registry(reg)
        return reg[-1]


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") if isinstance(p, dict) and p.get("type") in ("text", "input_text") else "[image]" for p in content)
    return ""


def tool_call_of(tc: dict) -> dict:
    fn = tc.get("function") or {}
    args = fn.get("arguments")
    return {"name": fn.get("name"), "args": (args if isinstance(args, str) else json.dumps(args, ensure_ascii=False))[:4000]}


def agent_request(inner: dict) -> dict:
    if not AGENT_URL:
        return {"error": "agent 未配置"}
    op = inner.get("agent")
    try:
        if op == "new_chat":
            need(chats_path(), "没有配置 agent 状态目录")
            return {"ok": True, "chat": new_chat(), "chats": list_chats()}
        if op == "internet":
            set_internet(inner.get("on") is True)
            return {"ok": True, "internet": internet_on()}
        if op == "delete_chat":
            need(chats_path(), "没有配置 agent 状态目录")
            delete_chat(chat_id(inner))
            return {"ok": True, "chats": list_chats()}
        if op == "stop":
            return {"ok": True, "stopped": stop_chat(chat_id(inner))}
        if op == "steer":
            return steer_chat(chat_id(inner), str(inner.get("text") or ""))
        if op != "history":
            return {"error": "未知操作"}
        sid = chat_id(inner)
        data = agent_json("GET", f"/api/sessions/{urllib.parse.quote(sid)}/messages?inline_images=false")
        chats = list_chats()
    except Exception as e:
        return {"error": scrub(f"{type(e).__name__}: {e}")}
    out = []
    for m in data.get("messages") or data.get("data") or []:
        if m.get("role") not in ("user", "assistant", "tool") or m.get("display_kind") == "hidden":
            continue
        steer = m.get("display_kind") == "steer"
        text = text_of(m.get("content"))
        out.append({"role": m["role"], "content": (STEER_WRAP.sub("", text).strip() if steer else text)[:20000],
                    "timestamp": m.get("timestamp"), "tool_calls": [tool_call_of(tc) for tc in m.get("tool_calls") or []],
                    "tool_name": m.get("tool_name") or m.get("name"), **({"steer": True} if steer else {})})
    return {"ok": True, "session": sid, "messages": out[-400:], "chats": chats, "internet": internet_on(), "retention_days": RETENTION_DAYS}


def save_upload(name: str, data: bytes) -> str:
    safe = re.sub(r"[^\w.\-一-龥]+", "_", name)[-80:] or "file"
    fname = f"{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}-{safe}"
    os.makedirs(AGENT_UPLOAD_DIR, exist_ok=True)
    with open(os.path.join(AGENT_UPLOAD_DIR, fname), "wb") as f:
        f.write(data)
    return f"{AGENT_UPLOAD_PATH.rstrip('/')}/{fname}"


def slim_evidence(out: dict) -> dict:
    keep = {k: v for k, v in out.items() if k != "response"}
    up = dict(keep.get("upstream") or {})
    if up.get("request"):
        up["request"] = {"messages": len(up["request"].get("messages") or []), "tools": len(up["request"].get("tools") or [])}
    if up.get("response"):
        up["response"] = {"usage": up["response"].get("usage"), "finish": ((up["response"].get("choices") or [{}])[0]).get("finish_reason")}
    if up.get("plain_messages"):
        up["plain_messages"] = len(up["plain_messages"])
    keep["upstream"] = up
    return keep


AGENT_EVENTS = {"run.started", "assistant.delta", "assistant.commentary", "assistant.completed", "tool.started",
                "tool.completed", "tool.failed", "run.completed", "run.failed", "run.cancelled"}


def agent_turn(inner: dict, emit):
    need(AGENT_URL, "agent 未配置")
    provider, model = inner.get("provider"), inner.get("model")
    need(provider in MODELS and model in MODELS[provider] and providers()[provider]["ready"], "未知的方案或模型")
    nonce = inner.get("gateway_nonce")
    need(isinstance(nonce, str) and HEX64.fullmatch(nonce), "缺少本次随机数")
    text = str(inner.get("input") or "")
    parts, notes, names = [], [], []
    for a in (inner.get("attachments") or [])[:8]:
        data = base64.b64decode(a.get("data") or "")
        need(len(data) <= MAX_FILE, f"{a.get('name')} 超过 {MAX_FILE >> 20} MB")
        kind = str(a.get("type") or "application/octet-stream")
        names.append({"name": a.get("name"), "type": kind, "bytes": len(data)})
        if kind.startswith("image/") and model in VISION:
            parts.append({"type": "image_url", "image_url": {"url": f"data:{kind};base64,{base64.b64encode(data).decode()}"}})
        else:
            need(AGENT_UPLOAD_DIR, "没有配置附件目录")
            notes.append(f"[附件] {a.get('name')}（{len(data)} 字节）已保存到 {save_upload(str(a.get('name') or 'file'), data)}，需要时用文件工具读取。")
    content = "\n".join([text, *notes]).strip()
    need(content or parts, "消息是空的")
    payload = [{"type": "text", "text": content}, *parts] if parts else content
    sid = chat_id(inner)
    token = "t-" + secrets.token_hex(4)
    turn = {"active": False, "stopped": False, "run_id": None, "nonce": nonce, "sess": session_of(inner), "calls": [],
            "evidence": {}, "emit": emit, "egress": [], "chat": sid, "token": token, "provider": provider, "model": model}
    with CHATS_LOCK:
        lock = CHAT_LOCKS.setdefault(sid, threading.Lock())
        CHAT_TURNS.setdefault(sid, []).append(turn)
    internet = internet_on()
    try:
        if not wait_turn(turn, lock, emit):
            emit({"type": "run.cancelled", "chat": sid})
        else:
            try:
                TURNS[token] = turn
                turn["active"] = not turn["stopped"]
                emit({"type": "turn.started", "provider": provider, "model": model, "attachments": names, "session": sid, "chat": sid,
                      "internet": internet, "egress": bool(EGRESS_PORT), "isolated": AGENT_NET_ISOLATED})
                routed = f"{token}/{provider}/{model}"
                agent_json("POST", f"/api/sessions/{urllib.parse.quote(sid)}/model", {"model": routed, "provider": AGENT_PROVIDER})
                conn, r = agent_http("POST", f"/api/sessions/{urllib.parse.quote(sid)}/chat/stream",
                                     {"input": payload, "model": routed, "provider": AGENT_PROVIDER,
                                      **({} if internet else {"system_message": NET_OFF_NOTE})}, timeout=900)
                try:
                    if r.status != 200:
                        raise Rejected(f"agent HTTP {r.status}: {r.read()[:200].decode('utf-8', 'replace')}")
                    event = None
                    for raw in r:
                        line = raw.decode("utf-8", "replace").rstrip("\r\n")
                        if line.startswith("event:"):
                            event = line[6:].strip()
                        elif line.startswith("data:") and event in AGENT_EVENTS:
                            try:
                                data = json.loads(line[5:].strip())
                            except ValueError:
                                continue
                            if not turn["run_id"] and data.get("run_id"):
                                turn["run_id"] = str(data["run_id"])
                                if turn["stopped"]:
                                    stop_turn(turn)
                            emit({"type": event, **{k: data[k] for k in ("delta", "content", "text", "tool", "name", "tool_name", "args",
                                                                          "arguments", "result", "preview", "error", "usage", "message_id",
                                                                          "already_streamed", "pending_steer") if k in data}})
                            if event in ("run.completed", "run.failed", "run.cancelled"):
                                break
                        elif not line:
                            event = None
                finally:
                    conn.close()
            finally:
                turn["active"] = False
                TURNS.pop(token, None)
                lock.release()
                cut_tunnels(lambda t: not any(k in TURNS for k in t["tokens"]))
    finally:
        with CHATS_LOCK:
            left = [t for t in CHAT_TURNS.get(sid, []) if t is not turn]
            if left:
                CHAT_TURNS[sid] = left
            else:
                CHAT_TURNS.pop(sid, None)
    emit({"type": "upstream", "nonce": nonce, "calls": turn["calls"], "internet": internet, "internet_now": internet_on(),
          "egress": turn["egress"], "egress_port": bool(EGRESS_PORT), "isolated": AGENT_NET_ISOLATED,
          "stopped": turn["stopped"], "evidence": {p: slim_evidence(o) for p, o in turn["evidence"].items()}})


def wait_turn(turn: dict, lock, emit) -> bool:
    if not lock.acquire(blocking=False):
        emit({"type": "turn.queued", "chat": turn["chat"]})
        deadline = time.time() + 900
        while not lock.acquire(timeout=0.5):
            if turn["stopped"]:
                return False
            need(time.time() < deadline, "这个会话上一轮 15 分钟还没结束，稍后再试")
    if turn["stopped"]:
        lock.release()
        return False
    return True


def stop_turn(turn: dict):
    turn["stopped"] = True
    turn["active"] = False
    cut_tunnels(lambda t: not any(TURNS.get(k, {}).get("active") for k in t["tokens"]))
    if turn.get("run_id"):
        try:
            conn, r = agent_http("POST", f"/v1/runs/{urllib.parse.quote(turn['run_id'], safe='')}/stop", {})
            r.read()
            conn.close()
        except Exception:
            pass


STEER_WRAP = re.compile(r"\[OUT-OF-BAND USER MESSAGE[^\]]*\]|\[/OUT-OF-BAND USER MESSAGE\]")


def steer_chat(sid: str, text: str) -> dict:
    need(text.strip(), "补充的内容是空的")
    need(len(text) <= 20000, "补充的内容太长")
    with CHATS_LOCK:
        running = [t for t in CHAT_TURNS.get(sid, []) if t.get("active") and t.get("run_id") and not t.get("stopped")]
    if not running:
        return {"ok": False, "error": "not_running"}
    conn, r = agent_http("POST", f"/v1/runs/{urllib.parse.quote(running[0]['run_id'], safe='')}/steer", {"input": text.strip()})
    try:
        r.read()
    finally:
        conn.close()
    return {"ok": True} if r.status == 200 else {"ok": False, "error": "not_running"}


def stop_chat(sid: str) -> int:
    with CHATS_LOCK:
        turns = list(CHAT_TURNS.get(sid, []))
    for t in turns:
        stop_turn(t)
    return len(turns)

NET_TOOLS = ("web_", "browser_")
NET_OFF_NOTE = ("本轮用户关闭了联网：web_search、web_extract 和 browser_* 工具不可用，终端里访问外网也会被拒绝。"
                "不要尝试联网；需要联网才能回答的部分，直接说明现在无法联网，再给出不联网能做的回答。")
EGRESS_PORTS = {80, 443}


def egress_target(host: str, port: int):
    turns = active_turns()
    if not turns:
        return turns, None, "不在对话中"
    if not internet_on():
        return turns, None, "上网已关闭"
    if port not in EGRESS_PORTS:
        return turns, None, "只允许 80 / 443 端口"
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except OSError:
        return turns, None, "域名解析失败"
    if not ips or not all(ipaddress.ip_address(ip.split("%")[0]).is_global for ip in ips):
        return turns, None, "目标是内网地址"
    return turns, sorted(ips)[0], None


def egress_open(host: str, port: int, ip: str) -> socket.socket:
    if not EGRESS_UPSTREAM:
        return socket.create_connection((ip, port), timeout=30)
    p = urllib.parse.urlsplit(EGRESS_UPSTREAM if "://" in EGRESS_UPSTREAM else "http://" + EGRESS_UPSTREAM)
    s = socket.create_connection((p.hostname, p.port or 80), timeout=30)
    s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        need(chunk and len(head) < 65536, "上级代理没有响应")
        head += chunk
    need(head.split(b"\r\n", 1)[0].split()[1:2] == [b"200"], "上级代理拒绝了连接")
    return s


TUNNELS: dict = {}


def cut_tunnels(pred):
    for t in list(TUNNELS.values()):
        if pred(t):
            t["cut"] = True
            for sock in t["socks"]:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def relay(a: socket.socket, b: socket.socket, first: bytes = b"", tunnel: dict | None = None) -> tuple:
    sent, got = len(first), 0
    sel = selectors.DefaultSelector()
    try:
        if first:
            b.sendall(first)
        sel.register(a, selectors.EVENT_READ, b)
        sel.register(b, selectors.EVENT_READ, a)
        while not (tunnel and tunnel.get("cut")):
            ready = sel.select(timeout=300)
            if not ready:
                break
            for key, _ in ready:
                data = key.fileobj.recv(65536)
                if not data or (tunnel and tunnel.get("cut")):
                    return sent, got
                key.data.sendall(data)
                if key.fileobj is a:
                    sent += len(data)
                else:
                    got += len(data)
    except OSError:
        pass
    finally:
        sel.close()
    return sent, got


class EgressHandler(BaseHTTPRequestHandler):
    server_version = "pa-mvp-egress/1"
    rbufsize = 0

    def log_message(self, *a):
        pass

    def _tunnel(self, host: str, port: int, first: bytes = b""):
        turns, ip, why = egress_target(host, port)
        rec = {"host": host, "port": port, "allowed": why is None, "reason": why, "at": round(time.time(), 3), "shared": len(turns)}
        for turn in turns:
            turn["egress"].append(rec)
            turn["emit"]({"type": "egress", **rec})
        if why:
            self.send_error(403, "egress denied", why)
            return
        try:
            up = egress_open(host, port, ip)
        except Exception as e:
            rec.update(allowed=False, reason=scrub(f"连接失败：{type(e).__name__}"))
            self.send_error(502, "egress failed", "连接失败")
            return
        tid = secrets.token_hex(8)
        tunnel = {"socks": (self.connection, up), "tokens": [t["token"] for t in turns], "cut": False}
        TUNNELS[tid] = tunnel
        try:
            if not internet_on() or not any(t["active"] for t in turns):
                tunnel["cut"] = True
            elif not first:
                self.send_response(200, "Connection Established")
                self.end_headers()
            rec["up"], rec["down"] = relay(self.connection, up, first, tunnel)
            rec["cut"] = tunnel["cut"]
        finally:
            TUNNELS.pop(tid, None)
            up.close()
        self.close_connection = True

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(":")
        if not host or not port.isdigit():
            return self.send_error(400, "bad target", "CONNECT 目标格式不对")
        self._tunnel(host.strip("[]"), int(port))

    def _plain(self):
        u = urllib.parse.urlsplit(self.path)
        if u.scheme != "http" or not u.hostname:
            return self.send_error(400, "bad target", "只转发 http:// 绝对地址")
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self.send_error(411, "chunked body", "不支持分块上传")
        body, n = b"", int(self.headers.get("Content-Length") or 0)
        while len(body) < n:
            chunk = self.rfile.read(n - len(body))
            if not chunk:
                return self.send_error(400, "short body", "请求体不完整")
            body += chunk
        skip = {"proxy-connection", "proxy-authorization", "connection", "keep-alive"}
        lines = [f"{self.command} {u.path or '/'}{'?' + u.query if u.query else ''} HTTP/1.1"]
        lines += [f"{k}: {v}" for k, v in self.headers.items() if k.lower() not in skip] + ["Connection: close", "", ""]
        self._tunnel(u.hostname, u.port or 80, "\r\n".join(lines).encode("latin-1") + body)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _plain


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
        path = urllib.parse.urlsplit(self.path).path
        if path == "/v1/chat/stream":
            return self._stream()
        if path != "/v1/chat":
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

    def _stream(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_STREAM_BODY:
            return self._send(413, {"error": "body 太大或为空"})
        try:
            req = json.loads(self.rfile.read(n))
            opened = WORKLOAD._open(req)
        except InvalidTag:
            return self._send(400, {"error": "解密失败"})
        except (ValueError, KeyError, TypeError) as e:
            return self._send(400, {"error": f"请求格式不对: {e}"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def send(obj: dict):
            self.wfile.write(b"data: " + json.dumps(obj, ensure_ascii=False).encode() + b"\n\n")
            self.wfile.flush()

        try:
            WORKLOAD.chat_stream(req, send, opened)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.command, urllib.parse.urlsplit(self.path).path))


def main():
    global WORKLOAD
    WORKLOAD = Workload()
    ready = ",".join(k for k, v in providers().items() if v["ready"]) or "echo"
    if AGENT_URL:
        need(len(ACCESS_TOKEN) >= 16, "接入 agent 时必须设置 ACCESS_TOKEN（至少 16 个字符）：拿到它就能读全部历史、让 agent 执行命令")
        need(AGENT_STATE_DIR, "接入 agent 时必须设置 AGENT_STATE_DIR（不能挂给 hermes 的目录）")
        init_agent_state()
    if PROXY_PORT:
        need(len(PROXY_TOKEN) >= 16, "启用模型代理时必须设置 PROXY_TOKEN（至少 16 个字符）")
        threading.Thread(target=ThreadingHTTPServer((PROXY_HOST, PROXY_PORT), ProxyHandler).serve_forever, daemon=True).start()
    if EGRESS_PORT:
        threading.Thread(target=ThreadingHTTPServer((EGRESS_HOST, EGRESS_PORT), EgressHandler).serve_forever, daemon=True).start()
    print(f"pa-mvp listening on :{PORT} providers={ready} proxy={PROXY_PORT or '-'} egress={EGRESS_PORT or '-'} agent={AGENT_URL or '-'} keyset={WORKLOAD.digest}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
