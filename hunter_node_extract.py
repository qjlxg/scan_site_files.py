import asyncio
import aiohttp
import yaml
import csv
import json
import time
import hashlib
import ipaddress
import logging
import base64
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from typing import Any, Dict, List, Tuple


# ==========================================================
# 配置
# ==========================================================

DRIVE_ROOT = Path(".")
DATA_DIR = DRIVE_ROOT / "data"
CONFIG_DIR = DRIVE_ROOT / "config"
ARCHIVE_DIR = DRIVE_ROOT / "archive"  # 定义独立存放带时间戳 yaml 的目录

DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

# 生成当前时间戳字符串，例如：2026-06-07_14-30-15
TIME_TAG = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# 修改此处：将原本的 scan_results.csv 改为读取 success_urls.txt
INPUT_TXT = DRIVE_ROOT / "success_urls.txt"

# unique.yaml 加上时间戳并单独存放到 archive 目录中
OUTPUT_FILE = ARCHIVE_DIR / f"unique_{TIME_TAG}.yaml"

# 其他统计与 URL 文件保持在 data/ 目录下不变
CSV_FILE = DATA_DIR / "unique_stats.csv"
UNIQUE_URLS_FILE = DATA_DIR / "unique_urls.txt"

RULES_FILE = CONFIG_DIR / "rules.yaml"
EXCLUDE_FILE = CONFIG_DIR / "exclude.txt"

BAD_WORDS = [
    "cf优选",
    "cf官方优选",
    "cloudflare优选",
    "免费测速",
    "剩余流量",
]


# ==========================================================
# 抓取参数
# ==========================================================

CONCURRENCY = 100
LIMIT_PER_HOST = 20

CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10

# 单个响应最大读取量
MAX_RESPONSE_SIZE = 20 * 1024 * 1024

# 防止一次性创建大量 asyncio task
BATCH_SIZE = max(100, CONCURRENCY * 10)

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0"
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


# ==========================================================
# 正则
# ==========================================================

PROTOCOL_RE = re.compile(
    r"(?i)"
    r"(?:vless|vmess|trojan|ss|socks|socks5|hysteria2|hy2|tuic|wireguard|anytls|hysteria)"
    r"://[^\s\"'<>]+"
)

B64_KEY_RE = re.compile(
    r"""(?ix)
    ["']?
    (?:base64|b64|data|config|sub|subscription|content|
       content-base64|encoded|decode|payload|raw|value)
    ["']?
    \s*[:=]\s*
    ["']([A-Za-z0-9+/=_-]{16,})["']
    """
)


# ==========================================================
# 黑名单
# ==========================================================

BAD_SERVER_VALUES = {
    "1.0.0.1",
    "1.1.1.1",
    "8.8.8.8",
    "255.255.255.255",
    "255.255.0.0",
    "255.0.0.0",
    "0.0.0.0",
    "127.0.0.1",
    "localhost",
}


# ==========================================================
# 排除列表
# ==========================================================

def load_exclude_list() -> set:
    exclude_set = set()

    if not EXCLUDE_FILE.exists():
        return exclude_set

    try:
        with open(EXCLUDE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                exclude_set.add(line.rstrip("/"))

    except Exception as e:
        logger.warning(f"读取排除列表失败: {e}")

    return exclude_set


# ==========================================================
# Server 检查
# ==========================================================

def is_valid_server(server: Any) -> bool:

    if not server:
        return False

    if not isinstance(server, str):
        return False

    server = server.strip().strip("[]").lower()

    if not server:
        return False

    if server in BAD_SERVER_VALUES:
        return False

    try:
        ip = ipaddress.ip_address(server)

        return ip.is_global

    except ValueError:

        # 域名
        if len(server) > 253:
            return False

        if any(c.isspace() for c in server):
            return False

        if server.startswith("."):
            return False

        if server.endswith("."):
            return False

        return True


# ==========================================================
# 基础工具
# ==========================================================

def _safe_int(value: Any, default: int = 0) -> int:

    try:

        if isinstance(value, bool):
            return default

        return int(str(value).strip())

    except Exception:

        return default


def _first(
    query: Dict[str, List[str]],
    *keys: str,
    default: str = ""
) -> str:

    for key in keys:

        values = query.get(key)

        if not values:
            continue

        value = values[0]

        if value is not None and str(value) != "":
            return str(value)

    return default


def _decode_url_component(value: Any) -> str:

    if value is None:
        return ""

    value = str(value)

    value = value.replace("\\/", "/")
    value = value.replace("\\u0026", "&")
    value = value.replace("\\u003d", "=")
    value = value.replace("\\u002f", "/")
    value = value.replace("\\u003a", ":")

    try:
        return unquote(value)

    except Exception:
        return value


# ==========================================================
# Base64
# ==========================================================

def _b64decode_loose(value: str) -> str:

    try:

        if not isinstance(value, str):
            return ""

        s = re.sub(r"\s+", "", value.strip())

        if not s:
            return ""

        if len(s) < 4:
            return ""

        # data URI
        if s.lower().startswith("data:"):

            comma = s.find(",")

            if comma >= 0:
                s = s[comma + 1:]

        # 自动补 padding
        s += "=" * ((4 - len(s) % 4) % 4)

        try:

            raw = base64.b64decode(
                s,
                altchars=b"-_",
                validate=False
            )

        except Exception:

            raw = base64.urlsafe_b64decode(s)

        if not raw:
            return ""

        # 常见编码
        for encoding in (
            "utf-8",
            "utf-8-sig",
            "gb18030",
            "latin-1",
        ):

            try:

                decoded = raw.decode(
                    encoding,
                    errors="ignore"
                )

                if decoded:
                    return decoded

            except Exception:
                continue

    except Exception:
        pass

    return ""


def _looks_like_b64(value: str) -> bool:

    if not isinstance(value, str):
        return False

    s = re.sub(r"\s+", "", value.strip())

    if len(s) < 12:
        return False

    if len(s) > 8 * 1024 * 1024:
        return False

    if not re.fullmatch(
        r"[A-Za-z0-9+/=_-]+",
        s
    ):
        return False

    # Base64 不应该出现这种长度
    if len(s) % 4 == 1:
        return False

    # 明显不是 Base64
    if "://" in s:
        return False

    return True


def _decoded_is_interesting(decoded: str) -> bool:

    if not decoded:
        return False

    lower = decoded.lower()

    tokens = (
        "vless://",
        "vmess://",
        "trojan://",
        "ss://",
        "socks://",
        "socks5://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "wireguard://",
        "anytls://",
        "proxies:",
        "outbounds:",
        "proxy-providers:",
        "server_port",
        '"server"',
        '"type"',
        "server:",
    )

    if any(token in lower for token in tokens):
        return True

    if "{" in decoded and "}" in decoded:
        return True

    if "[" in decoded and "]" in decoded:
        return True

    return False


# ==========================================================
# 协议 URL 提取
# ==========================================================

def _clean_protocol_url(value: str) -> str:

    value = value.strip().strip('"\'`')

    value = value.replace("\\/", "/")
    value = value.replace("\\u0026", "&")
    value = value.replace("\\u003d", "=")
    value = value.replace("&amp;", "&")

    try:

        if "%3A%2F%2F" in value.upper():
            value = unquote(value)

    except Exception:
        pass

    return value


def _extract_protocol_strings(text: str) -> List[str]:

    if not text:
        return []

    result = []

    for match in PROTOCOL_RE.findall(text):

        value = _clean_protocol_url(match)

        value = value.rstrip("),]};")

        if value:
            result.append(value)

    return list(dict.fromkeys(result))


# ==========================================================
# 节点唯一哈希
# ==========================================================

def stable_hash(node: Dict) -> str:

    keys = [
        "type",
        "server",
        "port",
        "uuid",
        "username",
        "password",
        "cipher",
        "alterId",
        "servername",
        "sni",
        "path",
        "network",
        "flow",
        "client-fingerprint",
        "alpn",
        "host",
        "tls",
        "insecure",
        "serviceName",
        "udp",
        "ip",
        "public-key",
        "private-key",
    ]

    parts = []

    for key in keys:

        value = node.get(key, "")

        if isinstance(value, list):

            value = ",".join(
                map(str, value)
            )

        elif isinstance(value, dict):

            value = json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True
            )

        parts.append(str(value))

    reality_opts = node.get("reality-opts")

    if isinstance(reality_opts, dict):

        parts.append(
            str(
                reality_opts.get(
                    "public-key",
                    ""
                )
            )
        )

        parts.append(
            str(
                reality_opts.get(
                    "short-id",
                    ""
                )
            )
        )

    transport = node.get("transport")

    if isinstance(transport, dict):

        parts.append(
            json.dumps(
                transport,
                ensure_ascii=False,
                sort_keys=True
            )
        )

    raw = "|".join(parts)

    return hashlib.md5(
        raw.encode(
            "utf-8",
            errors="ignore"
        )
    ).hexdigest()


# ==========================================================
# 节点追加
# ==========================================================

def _append_node(
    nodes: List[Dict],
    node: Dict
) -> None:

    if not node:
        return

    if not isinstance(node, dict):
        return

    server = node.get("server")

    if not is_valid_server(server):
        return

    node["server"] = str(server).strip()

    port = _safe_int(
        node.get("port"),
        0
    )

    if port < 1 or port > 65535:
        return

    node["port"] = port

    node_type = str(
        node.get("type", "")
    ).lower().strip()

    if not node_type:
        return

    type_alias = {
        "shadowsocks": "ss",
        "socks": "socks5",
        "hy2": "hysteria2",
        "hysteria": "hysteria2",
        "wg": "wireguard",
    }

    node["type"] = type_alias.get(
        node_type,
        node_type
    )

    node_name = str(
        node.get("name", "")
        or ""
    ).strip()

    if not node_name:

        node["name"] = (
            f"{node['type']}-"
            f"{node['server']}:"
            f"{node['port']}"
        )

    lower_name = node["name"].lower()

    if any(
        bad.lower() in lower_name
        for bad in BAD_WORDS
    ):
        return

    # 删除 None / 空字段
    for key in list(node.keys()):

        if node[key] is None:
            node.pop(key, None)

        elif node[key] == "":
            node.pop(key, None)

    nodes.append(node)


# ==========================================================
# 通用 URL 参数
# ==========================================================

def _parse_query_common(
    query: Dict[str, List[str]],
    node: Dict
) -> None:

    path = _first(
        query,
        "path",
        "ws-path"
    )

    host = _first(
        query,
        "host",
        "ws-host"
    )

    sni = _first(
        query,
        "sni",
        "servername"
    )

    alpn = _first(
        query,
        "alpn"
    )

    fp = _first(
        query,
        "fp",
        "fingerprint"
    )

    flow = _first(
        query,
        "flow"
    )

    network = _first(
        query,
        "type",
        "net",
        "network",
        default=""
    )

    if network:
        node["network"] = network.lower()

    if path:
        node["path"] = _decode_url_component(path)

    if host:
        node["host"] = _decode_url_component(host)

    if sni:
        node["servername"] = _decode_url_component(sni)

    if alpn:

        node["alpn"] = [
            _decode_url_component(x)
            for x in alpn.split(",")
            if x
        ]

    if fp:
        node["client-fingerprint"] = (
            _decode_url_component(fp)
        )

    if flow:
        node["flow"] = (
            _decode_url_component(flow)
        )

    security = _first(
        query,
        "security",
        default=""
    ).lower()

    pbk = _first(
        query,
        "pbk",
        "public-key"
    )

    sid = _first(
        query,
        "sid",
        "short-id"
    )

    if security in (
        "tls",
        "reality"
    ):
        node["tls"] = True

    if security == "reality" or pbk:

        reality = {}

        if pbk:
            reality["public-key"] = (
                _decode_url_component(pbk)
            )

        if sid:
            reality["short-id"] = (
                _decode_url_component(sid)
            )

        if reality:
            node["reality-opts"] = reality


# ==========================================================
# 协议解析
# ==========================================================

def parse_proxy_line(line: str) -> Dict:

    line = _clean_protocol_url(
        line.strip()
    )

    if not line:
        return {}

    if line.startswith("#"):
        return {}

    match = PROTOCOL_RE.search(line)

    if match:

        line = (
            match.group(0)
            .rstrip("),]};")
        )

    try:

        lower = line.lower()

        # --------------------------------------------------
        # VLESS
        # --------------------------------------------------

        if lower.startswith("vless://"):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 443
            uuid = parsed.username

            if not server or not uuid:
                return {}

            name = (
                unquote(parsed.fragment)
                if parsed.fragment
                else f"VLESS-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            node = {
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": _decode_url_component(uuid),
                "network": _first(
                    query,
                    "type",
                    "net",
                    "network",
                    default="tcp"
                ).lower(),
            }

            _parse_query_common(
                query,
                node
            )

            return node

        # --------------------------------------------------
        # VMess
        # --------------------------------------------------

        elif lower.startswith("vmess://"):

            b64_part = line[8:].split(
                "#",
                1
            )[0]

            b64_part = unquote(
                b64_part
            )

            decoded = _b64decode_loose(
                b64_part
            )

            if not decoded:
                return {}

            decoded = decoded.strip().strip('"')

            try:

                config = json.loads(
                    decoded
                )

            except Exception:

                # 有些来源 JSON 外面还有杂物
                match_json = re.search(
                    r"\{.*\}",
                    decoded,
                    re.S
                )

                if not match_json:
                    return {}

                try:

                    config = json.loads(
                        match_json.group(0)
                    )

                except Exception:
                    return {}

            if not isinstance(
                config,
                dict
            ):
                return {}

            server = (
                config.get("add")
                or config.get("server")
            )

            port = _safe_int(
                config.get("port")
                or config.get("server_port"),
                443
            )

            uuid = (
                config.get("id")
                or config.get("uuid")
            )

            if not server or not uuid:
                return {}

            tls_value = str(
                config.get("tls", "")
            ).lower()

            tls = tls_value in (
                "tls",
                "true",
                "1",
                "yes"
            )

            node = {
                "name": config.get(
                    "ps",
                    "VMess"
                ),
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": uuid,
                "alterId": _safe_int(
                    config.get(
                        "aid",
                        config.get(
                            "alterId",
                            0
                        )
                    ),
                    0
                ),
                "cipher": (
                    config.get(
                        "scy",
                        config.get(
                            "cipher",
                            "auto"
                        )
                    )
                    or "auto"
                ),
                "network": (
                    config.get(
                        "net",
                        config.get(
                            "network",
                            "tcp"
                        )
                    )
                    or "tcp"
                ),
                "tls": tls,
            }

            field_aliases = {
                "sni": "servername",
                "servername": "servername",
                "path": "path",
                "host": "host",
                "alpn": "alpn",
                "fp": "client-fingerprint",
                "fingerprint": "client-fingerprint",
                "flow": "flow",
            }

            for src, dst in field_aliases.items():

                if config.get(src) in (
                    None,
                    ""
                ):
                    continue

                value = config[src]

                if (
                    dst == "alpn"
                    and isinstance(value, str)
                ):
                    value = [
                        x.strip()
                        for x in value.split(",")
                        if x.strip()
                    ]

                node[dst] = value

            return node

        # --------------------------------------------------
        # Trojan
        # --------------------------------------------------

        elif lower.startswith("trojan://"):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username

            if not server or not password:
                return {}

            name = (
                unquote(parsed.fragment)
                if parsed.fragment
                else f"Trojan-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            node = {
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": _decode_url_component(
                    password
                ),
                "tls": True,
            }

            _parse_query_common(
                query,
                node
            )

            # Clash Trojan 常用 sni
            if node.get("servername"):

                node["sni"] = (
                    node["servername"]
                )

                node.pop(
                    "servername",
                    None
                )

            return node

        # --------------------------------------------------
        # Shadowsocks
        # --------------------------------------------------

        elif lower.startswith("ss://"):

            parts = line[5:].split(
                "#",
                1
            )

            name = (
                unquote(parts[1])
                if len(parts) > 1
                else "Shadowsocks"
            )

            main_part = parts[0]

            if "@" in main_part:

                user_info, host_port = (
                    main_part.rsplit(
                        "@",
                        1
                    )
                )

                decoded_user = (
                    _b64decode_loose(
                        user_info
                    )
                )

                if (
                    decoded_user
                    and ":" in decoded_user
                ):

                    cipher, password = (
                        decoded_user.split(
                            ":",
                            1
                        )
                    )

                else:

                    if ":" not in user_info:
                        return {}

                    cipher, password = (
                        user_info.split(
                            ":",
                            1
                        )
                    )

                parsed_host = urlparse(
                    "//" + host_port
                )

                server = parsed_host.hostname
                port = parsed_host.port

            else:

                decoded = _b64decode_loose(
                    main_part
                )

                if (
                    not decoded
                    or "@" not in decoded
                ):
                    return {}

                cipher_pass, host_port = (
                    decoded.rsplit(
                        "@",
                        1
                    )
                )

                if ":" not in cipher_pass:
                    return {}

                cipher, password = (
                    cipher_pass.split(
                        ":",
                        1
                    )
                )

                parsed_host = urlparse(
                    "//" + host_port
                )

                server = parsed_host.hostname
                port = parsed_host.port

            if not server or not port:
                return {}

            return {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": cipher,
                "password": password,
            }

        # --------------------------------------------------
        # SOCKS
        # --------------------------------------------------

        elif lower.startswith(
            (
                "socks://",
                "socks5://"
            )
        ):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 1080

            if not server:
                return {}

            node = {
                "name": (
                    unquote(parsed.fragment)
                    if parsed.fragment
                    else f"SOCKS5-{server}"
                ),
                "type": "socks5",
                "server": server,
                "port": port,
            }

            if parsed.username:
                node["username"] = unquote(
                    parsed.username
                )

            if parsed.password:
                node["password"] = unquote(
                    parsed.password
                )

            return node

        # --------------------------------------------------
        # Hysteria2
        # --------------------------------------------------

        elif lower.startswith(
            (
                "hysteria2://",
                "hy2://"
            )
        ):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username

            if not server or not password:
                return {}

            name = (
                unquote(parsed.fragment)
                if parsed.fragment
                else f"Hysteria2-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            node = {
                "name": name,
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": _decode_url_component(
                    password
                ),
                "tls": True,
            }

            sni = _first(
                query,
                "sni",
                "servername"
            )

            alpn = _first(
                query,
                "alpn"
            )

            insecure = _first(
                query,
                "insecure",
                "allowInsecure"
            )

            if sni:
                node["sni"] = (
                    _decode_url_component(sni)
                )

            if alpn:
                node["alpn"] = [
                    _decode_url_component(x)
                    for x in alpn.split(",")
                    if x
                ]

            if insecure:
                node["insecure"] = (
                    insecure.lower()
                    in (
                        "1",
                        "true",
                        "yes"
                    )
                )

            return node

        # --------------------------------------------------
        # TUIC
        # --------------------------------------------------

        elif lower.startswith("tuic://"):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 443
            uuid = parsed.username

            if not server or not uuid:
                return {}

            name = (
                unquote(parsed.fragment)
                if parsed.fragment
                else f"TUIC-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            node = {
                "name": name,
                "type": "tuic",
                "server": server,
                "port": port,
                "uuid": _decode_url_component(uuid),
            }

            password = _first(query, "password")
            if password:
                node["password"] = _decode_url_component(password)

            _parse_query_common(query, node)

            return node

        # --------------------------------------------------
        # WireGuard
        # --------------------------------------------------

        elif lower.startswith("wireguard://"):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 51820

            if not server:
                return {}

            name = (
                unquote(parsed.fragment)
                if parsed.fragment
                else f"WireGuard-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            node = {
                "name": name,
                "type": "wireguard",
                "server": server,
                "port": port,
            }

            ip = _first(query, "ip", "address")
            public_key = _first(query, "publickey", "public-key")
            private_key = _first(query, "privatekey", "private-key")

            if ip:
                node["ip"] = ip
            if public_key:
                node["public-key"] = public_key
            if private_key:
                node["private-key"] = private_key

            return node

        # --------------------------------------------------
        # AnyTLS
        # --------------------------------------------------

        elif lower.startswith("anytls://"):

            parsed = urlparse(line)

            server = parsed.hostname
            port = parsed.port or 443
            password = parsed.username

            if not server or not password:
                return {}

            name = (
                unquote(parsed.fragment)
                if parsed.fragment
                else f"AnyTLS-{server}"
            )

            query = parse_qs(
                parsed.query,
                keep_blank_values=True
            )

            node = {
                "name": name,
                "type": "anytls",
                "server": server,
                "port": port,
                "password": _decode_url_component(password),
                "tls": True,
            }

            _parse_query_common(query, node)

            return node

    except Exception:
        return {}

    return {}


# ==========================================================
# Sing-box outbound 转换
# ==========================================================

def _normalize_singbox_outbound(
    item: Dict
) -> Dict:

    if not isinstance(item, dict):
        return {}

    ob_type = str(
        item.get(
            "type",
            item.get(
                "protocol",
                ""
            )
        )
    ).lower().strip()

    server = (
        item.get("server")
        or item.get("address")
        or item.get("add")
    )

    port = (
        item.get("server_port")
        or item.get("port")
        or item.get("remote_port")
    )

    if not ob_type or not server or not port:
        return {}

    port = _safe_int(
        port,
        0
    )

    if port < 1 or port > 65535:
        return {}

    type_map = {
        "shadowsocks": "ss",
        "socks": "socks5",
        "hysteria": "hysteria2",
        "hysteria2": "hysteria2",
        "hy2": "hysteria2",
        "vless": "vless",
        "vmess": "vmess",
        "trojan": "trojan",
        "tuic": "tuic",
        "wireguard": "wireguard",
        "anytls": "anytls",
        "http": "http",
        "https": "http",
    }

    clash_type = type_map.get(
        ob_type
    )

    if not clash_type:
        return {}

    node = {
        "name": (
            item.get("tag")
            or item.get("name")
            or f"{ob_type}-{server}"
        ),
        "type": clash_type,
        "server": server,
        "port": port,
    }

    if ob_type == "vless":

        uuid = item.get("uuid")

        if not uuid:
            return {}

        node["uuid"] = uuid

        if item.get("flow"):
            node["flow"] = item["flow"]

        tls = item.get("tls")

        if isinstance(tls, dict):

            if tls.get("enabled") is not False:
                node["tls"] = True

            sni = tls.get(
                "server_name"
            )

            if sni:
                node["servername"] = sni

            if tls.get("alpn"):
                node["alpn"] = tls["alpn"]

            utls = tls.get(
                "utls"
            )

            if isinstance(utls, dict):

                fp = utls.get(
                    "fingerprint"
                )

                if fp:
                    node[
                        "client-fingerprint"
                    ] = fp

            reality = tls.get(
                "reality"
            )

            if isinstance(
                reality,
                dict
            ) and reality.get(
                "enabled"
            ):

                opts = {}

                if reality.get(
                    "public_key"
                ):
                    opts[
                        "public-key"
                    ] = reality[
                        "public_key"
                    ]

                if reality.get(
                    "short_id"
                ):
                    opts[
                        "short-id"
                    ] = reality[
                        "short_id"
                    ]

                if opts:
                    node[
                        "reality-opts"
                    ] = opts

        transport = item.get(
            "transport"
        )

        if isinstance(
            transport,
            dict
        ):

            transport_type = (
                transport.get(
                    "type",
                    "tcp"
                )
            )

            node[
                "network"
            ] = transport_type

            if transport_type == "ws":

                if transport.get("path"):
                    node[
                        "path"
                    ] = transport["path"]

                headers = transport.get(
                    "headers"
                )

                if isinstance(
                    headers,
                    dict
                ):

                    host = (
                        headers.get("Host")
                        or headers.get("host")
                    )

                    if host:
                        node["host"] = host

            elif transport_type == "grpc":

                service_name = (
                    transport.get(
                        "service_name"
                    )
                )

                if service_name:
                    node[
                        "grpc-opts"
                    ] = {
                        "grpc-service-name":
                            service_name
                    }

    elif ob_type == "vmess":

        uuid = item.get("uuid")

        if not uuid:
            return {}

        node["uuid"] = uuid

        node["cipher"] = (
            item.get(
                "security",
                "auto"
            )
            or "auto"
        )

        node["network"] = "tcp"

        tls = item.get("tls")

        if isinstance(
            tls,
            dict
        ):

            node["tls"] = (
                tls.get(
                    "enabled",
                    True
                )
            )

            if tls.get(
                "server_name"
            ):
                node[
                    "servername"
                ] = tls[
                    "server_name"
                ]

            if tls.get("alpn"):
                node["alpn"] = tls["alpn"]

            utls = tls.get(
                "utls"
            )

            if isinstance(
                utls,
                dict
            ):

                fp = utls.get(
                    "fingerprint"
                )

                if fp:
                    node[
                        "client-fingerprint"
                    ] = fp

        transport = item.get(
            "transport"
        )

        if isinstance(
            transport,
            dict
        ):

            network = transport.get(
                "type"
            )

            if network:
                node[
                    "network"
                ] = network

            if network == "ws":

                if transport.get(
                    "path"
                ):
                    node[
                        "path"
                    ] = transport[
                        "path"
                    ]

                headers = transport.get(
                    "headers"
                )

                if isinstance(
                    headers,
                    dict
                ):

                    host = (
                        headers.get("Host")
                        or headers.get("host")
                    )

                    if host:
                        node["host"] = host

    elif ob_type == "trojan":

        password = item.get(
            "password"
        )

        if not password:
            return {}

        node["password"] = password
        node["tls"] = True

        tls = item.get(
            "tls"
        )

        if isinstance(
            tls,
            dict
        ):

            if tls.get(
                "server_name"
            ):
                node[
                    "sni"
                ] = tls[
                    "server_name"
                ]

            if tls.get("alpn"):
                node[
                    "alpn"
                ] = tls["alpn"]

        transport = item.get(
            "transport"
        )

        if isinstance(
            transport,
            dict
        ):

            network = transport.get(
                "type"
            )

            if network:
                node[
                    "network"
                ] = network

            if network == "ws":

                if transport.get(
                    "path"
                ):
                    node[
                        "path"
                    ] = transport[
                        "path"
                    ]

                headers = transport.get(
                    "headers"
                )

                if isinstance(
                    headers,
                    dict
                ):

                    host = (
                        headers.get("Host")
                        or headers.get("host")
                    )

                    if host:
                        node[
                            "host"
                        ] = host

    elif ob_type == "shadowsocks":

        method = item.get(
            "method"
        )

        password = item.get(
            "password"
        )

        if not method or not password:
            return {}

        node[
            "cipher"
        ] = method

        node[
            "password"
        ] = password

    elif ob_type == "socks":

        if item.get("username"):
            node[
                "username"
            ] = item[
                "username"
            ]

        if item.get("password"):
            node[
                "password"
            ] = item[
                "password"
            ]

    elif ob_type in (
        "hysteria",
        "hysteria2",
        "hy2"
    ):

        password = item.get(
            "password"
        )

        if password:
            node[
                "password"
            ] = password

        tls = item.get(
            "tls"
        )

        if isinstance(
            tls,
            dict
        ):

            node[
                "tls"
            ] = tls.get(
                "enabled",
                True
            )

            if tls.get(
                "server_name"
            ):
                node[
                    "sni"
                ] = tls[
                    "server_name"
                ]

            if tls.get("alpn"):
                node[
                    "alpn"
                ] = tls[
                    "alpn"
                ]

            if tls.get(
                "insecure"
            ):
                node[
                    "insecure"
                ] = True

    elif ob_type == "tuic":

        uuid = item.get("uuid")
        if not uuid:
            return {}
        node["uuid"] = uuid
        if item.get("password"):
            node["password"] = item["password"]
        node["tls"] = True
        if item.get("congestion_control"):
            node["congestion-control"] = item["congestion_control"]

    elif ob_type == "wireguard":

        if item.get("ip"):
            node["ip"] = item["ip"]
        if item.get("public_key"):
            node["public-key"] = item["public_key"]
        elif item.get("public-key"):
            node["public-key"] = item["public-key"]
        if item.get("private_key"):
            node["private-key"] = item["private_key"]
        elif item.get("private-key"):
            node["private-key"] = item["private-key"]

    elif ob_type == "anytls":

        if item.get("password"):
            node["password"] = item["password"]
        node["tls"] = True

    elif ob_type in (
        "http",
        "https"
    ):

        if item.get("username"):
            node[
                "username"
            ] = item[
                "username"
            ]

        if item.get("password"):
            node[
                "password"
            ] = item[
                "password"
            ]

    return node


# ==========================================================
# 普通结构化节点
# ==========================================================

def _normalize_structured_node(
    item: Dict
) -> Dict:

    if not isinstance(
        item,
        dict
    ):
        return {}

    raw_type = (
        item.get("type")
        or item.get("protocol")
    )

    server = (
        item.get("server")
        or item.get("add")
        or item.get("address")
    )

    port = (
        item.get("port")
        or item.get("server_port")
        or item.get("remote_port")
    )

    if not raw_type or not server or not port:
        return {}

    raw_type = str(
        raw_type
    ).lower().strip()

    if raw_type in {
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "socks",
        "hysteria",
        "hysteria2",
        "hy2",
        "tuic",
        "wireguard",
        "anytls",
        "http",
        "https",
    }:

        if (
            "server_port" in item
            or "server" in item
            and any(
                key in item
                for key in (
                    "tag",
                    "tls",
                    "transport",
                    "method",
                    "server_port",
                )
            )
        ):

            sb = _normalize_singbox_outbound(
                item
            )

            if sb:
                return sb

    type_map = {
        "shadowsocks": "ss",
        "socks": "socks5",
        "hy2": "hysteria2",
        "hysteria": "hysteria2",
    }

    node_type = type_map.get(
        raw_type,
        raw_type
    )

    allowed = {
        "vless",
        "vmess",
        "trojan",
        "ss",
        "socks5",
        "hysteria2",
        "tuic",
        "wireguard",
        "anytls",
        "http",
        "https",
    }

    if node_type not in allowed:
        return {}

    node = {
        "name": (
            item.get("name")
            or item.get("tag")
            or f"{node_type}-{server}"
        ),
        "type": node_type,
        "server": server,
        "port": _safe_int(
            port,
            0
        ),
    }

    copy_fields = [
        "uuid",
        "password",
        "username",
        "cipher",
        "alterId",
        "network",
        "tls",
        "servername",
        "sni",
        "path",
        "host",
        "flow",
        "client-fingerprint",
        "alpn",
        "insecure",
        "udp",
        "serviceName",
        "ip",
        "public-key",
        "private-key",
        "congestion-control",
    ]

    aliases = {
        "alter_id": "alterId",
        "client_fingerprint":
            "client-fingerprint",
        "server_name":
            "servername",
        "allow_insecure":
            "insecure",
        "public_key": "public-key",
        "private_key": "private-key",
    }

    for key in copy_fields:

        if key in item:
            node[key] = item[key]

    for src, dst in aliases.items():

        if (
            src in item
            and dst not in node
        ):
            node[dst] = item[src]

    return node


# ==========================================================
# 任意 JSON/YAML 结构递归
# ==========================================================

def _extract_from_structure(
    obj: Any,
    nodes: List[Dict],
    depth: int,
    seen_b64: set,
    seen_obj: set,
) -> None:

    if depth > 5:
        return

    if isinstance(obj, dict):

        try:

            obj_key = hashlib.md5(
                json.dumps(
                    obj,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str
                ).encode(
                    "utf-8",
                    errors="ignore"
                )
            ).hexdigest()

            if obj_key in seen_obj:
                return

            seen_obj.add(obj_key)

        except Exception:
            pass

        node_type = obj.get(
            "type"
        )

        server = (
            obj.get("server")
            or obj.get("address")
        )

        port = (
            obj.get("port")
            or obj.get("server_port")
        )

        if (
            node_type
            and server
            and port
        ):

            normalized = (
                _normalize_structured_node(
                    obj
                )
            )

            if normalized:
                _append_node(
                    nodes,
                    normalized
                )

        for key, value in obj.items():

            key_lower = str(
                key
            ).lower()

            if key_lower in {
                "proxies",
                "nodes",
                "outbounds",
                "proxy-list",
                "proxylist",
                "servers",
            }:

                if isinstance(
                    value,
                    list
                ):

                    for item in value:

                        if isinstance(
                            item,
                            dict
                        ):

                            normalized = (
                                _normalize_structured_node(
                                    item
                                )
                            )

                            if normalized:
                                _append_node(
                                    nodes,
                                    normalized
                                )

                        _extract_from_structure(
                            item,
                            nodes,
                            depth + 1,
                            seen_b64,
                            seen_obj
                        )

                elif isinstance(
                    value,
                    dict
                ):

                    _extract_from_structure(
                        value,
                        nodes,
                        depth + 1,
                        seen_b64,
                        seen_obj
                    )

            elif key_lower == "proxy-providers":

                _extract_from_structure(
                    value,
                    nodes,
                    depth + 1,
                    seen_b64,
                    seen_obj
                )

            else:

                _extract_from_structure(
                    value,
                    nodes,
                    depth + 1,
                    seen_b64,
                    seen_obj
                )

    elif isinstance(
        obj,
        list
    ):

        for elem in obj:

            _extract_from_structure(
                elem,
                nodes,
                depth + 1,
                seen_b64,
                seen_obj
            )

    elif isinstance(
        obj,
        str
    ):

        value = obj.strip()

        if not value:
            return

        for proto_url in (
            _extract_protocol_strings(
                value
            )
        ):

            _append_node(
                nodes,
                parse_proxy_line(
                    proto_url
                )
            )

        compact = re.sub(
            r"\s+",
            "",
            value
        )

        if (
            depth < 5
            and _looks_like_b64(
                compact
            )
        ):

            decoded = (
                _b64decode_loose(
                    compact
                )
            )

            if (
                decoded
                and decoded != value
                and _decoded_is_interesting(
                    decoded
                )
            ):

                key = hashlib.md5(
                    decoded.encode(
                        "utf-8",
                        errors="ignore"
                    )
                ).hexdigest()

                if key not in seen_b64:

                    seen_b64.add(key)

                    _extract_recursive(
                        decoded,
                        nodes,
                        depth + 1,
                        seen_b64
                    )


# ==========================================================
# 主递归提取
# ==========================================================

def _extract_recursive(
    text: str,
    nodes: List[Dict],
    depth: int = 0,
    seen_b64: set = None,
) -> None:

    if not text:
        return

    if depth > 5:
        return

    if seen_b64 is None:
        seen_b64 = set()

    for proto_url in (
        _extract_protocol_strings(
            text
        )
    ):

        _append_node(
            nodes,
            parse_proxy_line(
                proto_url
            )
        )

    try:

        for match in B64_KEY_RE.finditer(
            text
        ):

            candidate = match.group(1)

            if not _looks_like_b64(
                candidate
            ):
                continue

            decoded = _b64decode_loose(
                candidate
            )

            if (
                not decoded
                or decoded == candidate
                or not _decoded_is_interesting(
                    decoded
                )
            ):
                continue

            key = hashlib.md5(
                decoded.encode(
                    "utf-8",
                    errors="ignore"
                )
            ).hexdigest()

            if key in seen_b64:
                continue

            seen_b64.add(key)

            _extract_recursive(
                decoded,
                nodes,
                depth + 1,
                seen_b64
            )

    except Exception:
        pass

    data = None

    try:

        data = yaml.safe_load(
            text
        )

    except Exception:

        data = None

    if data is None:

        try:

            data = json.loads(
                text
            )

        except Exception:

            data = None

    if data is not None:

        try:

            _extract_from_structure(
                data,
                nodes,
                depth,
                seen_b64,
                set()
            )

        except Exception:
            pass

    stripped = text.strip()

    if (
        depth < 5
        and _looks_like_b64(
            stripped
        )
    ):

        decoded = _b64decode_loose(
            stripped
        )

        if (
            decoded
            and decoded != stripped
            and _decoded_is_interesting(
                decoded
            )
        ):

            key = hashlib.md5(
                decoded.encode(
                    "utf-8",
                    errors="ignore"
                )
            ).hexdigest()

            if key not in seen_b64:

                seen_b64.add(key)

                _extract_recursive(
                    decoded,
                    nodes,
                    depth + 1,
                    seen_b64
                )

    for raw_line in text.splitlines():

        line = raw_line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        node = parse_proxy_line(
            line
        )

        _append_node(
            nodes,
            node
        )

        compact = re.sub(
            r"\s+",
            "",
            line
        )

        if not (
            depth < 5
            and _looks_like_b64(
                compact
            )
        ):
            continue

        decoded = _b64decode_loose(
            compact
        )

        if (
            not decoded
            or decoded == compact
            or not _decoded_is_interesting(
                decoded
            )
        ):
            continue

        key = hashlib.md5(
            decoded.encode(
                "utf-8",
                errors="ignore"
            )
        ).hexdigest()

        if key in seen_b64:
            continue

        seen_b64.add(key)

        for proto_url in (
            _extract_protocol_strings(
                decoded
            )
        ):

            _append_node(
                nodes,
                parse_proxy_line(
                    proto_url
                )
            )

        _extract_recursive(
            decoded,
            nodes,
            depth + 1,
            seen_b64
        )


# ==========================================================
# 对外提取函数
# ==========================================================

def extract_yaml_nodes(
    text: str
) -> List[Dict]:

    nodes = []

    _extract_recursive(
        text,
        nodes
    )

    unique = {}

    for node in nodes:

        try:

            unique[
                stable_hash(node)
            ] = node

        except Exception:
            continue

    return list(
        unique.values()
    )


# ==========================================================
# HTTP 抓取
# ==========================================================

async def fetch_yaml(
    session: aiohttp.ClientSession,
    host: str
) -> Tuple[str, int, str, float]:

    start_time = time.time()

    try:

        timeout = aiohttp.ClientTimeout(
            total=(
                CONNECT_TIMEOUT
                + READ_TIMEOUT
                + 5
            ),
            connect=CONNECT_TIMEOUT,
            sock_read=READ_TIMEOUT,
        )

        async with session.get(
            host,
            timeout=timeout,
            headers={
                "User-Agent": BROWSER_UA
            },
            allow_redirects=True,
            max_redirects=5,
        ) as response:

            content_length = (
                response.headers.get(
                    "Content-Length"
                )
            )

            if content_length:

                try:

                    if int(
                        content_length
                    ) > MAX_RESPONSE_SIZE:

                        cost = round(
                            time.time()
                            - start_time,
                            2
                        )

                        return (
                            str(response.url),
                            response.status,
                            "",
                            cost
                        )

                except Exception:
                    pass

            chunks = []
            total = 0

            async for chunk in (
                response.content.iter_chunked(
                    64 * 1024
                )
            ):

                total += len(chunk)

                if total > MAX_RESPONSE_SIZE:
                    break

                chunks.append(chunk)

            raw = b"".join(
                chunks
            )

            text = raw.decode(
                response.charset
                or "utf-8",
                errors="ignore"
            )

            cost = round(
                time.time()
                - start_time,
                2
            )

            return (
                str(response.url),
                response.status,
                text,
                cost
            )

    except Exception:

        return (
            host,
            0,
            "",
            0.0
        )


# ==========================================================
# 单 URL
# ==========================================================

async def process_source(
    session: aiohttp.ClientSession,
    source: str,
    semaphore: asyncio.Semaphore
):

    async with semaphore:

        real_url, status, text, cost = (
            await fetch_yaml(
                session,
                source
            )
        )

    if not text:

        return [
            source,
            real_url,
            "请求失败",
            0,
            status,
            cost,
            ""
        ], []

    nodes = extract_yaml_nodes(
        text
    )

    if not nodes:

        summary = (
            text[:500]
            .replace("\n", " ")
            .replace("\r", " ")
        )

        return [
            source,
            real_url,
            "无有效节点",
            0,
            status,
            cost,
            summary
        ], []

    return [
        source,
        real_url,
        "提取成功",
        len(nodes),
        status,
        cost,
        ""
    ], nodes


# ==========================================================
# rules.yaml
# ==========================================================

def _merge_rules_config(
    unique_nodes: List[Dict]
) -> Dict:

    final_config = {
        "proxies": unique_nodes
    }

    if not RULES_FILE.exists():
        return final_config

    try:

        with open(
            RULES_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            rules_data = (
                yaml.safe_load(f)
                or {}
            )

        if not isinstance(
            rules_data,
            dict
        ):
            rules_data = {}

        final_config = {
            **rules_data,
            "proxies": unique_nodes
        }

        if "proxy-groups" in final_config:

            node_names = [
                n.get("name")
                for n in unique_nodes
                if n.get("name")
            ]

            for group in (
                final_config[
                    "proxy-groups"
                ]
            ):

                if not isinstance(
                    group,
                    dict
                ):
                    continue

                if group.get("name") in [
                    "自动优选",
                    "手动选择",
                    "Nodes",
                ]:

                    current = (
                        group.get(
                            "proxies",
                            []
                        )
                    )

                    if not isinstance(
                        current,
                        list
                    ):
                        current = []

                    new_proxies = [
                        p
                        for p in current
                        if p not in node_names
                    ]

                    group[
                        "proxies"
                    ] = (
                        new_proxies
                        + node_names
                    )

    except Exception as e:

        logger.warning(
            f"读取 rules.yaml 失败：{e}"
        )

        final_config = {
            "proxies": unique_nodes
        }

    return final_config


# ==========================================================
# 主程序
# ==========================================================

async def main():

    # 修改此处：检查 success_urls.txt 是否存在
    if not INPUT_TXT.exists():

        logger.error(
            f"未找到输入文件: "
            f"{INPUT_TXT}"
        )

        return

    exclude_list = (
        load_exclude_list()
    )

    urls = set()

    try:
        # 修改此处：按行读取纯文本文件 success_urls.txt
        with open(
            INPUT_TXT,
            "r",
            encoding="utf-8"
        ) as f:

            for line in f:
                url = line.strip()

                if not url:
                    continue

                if url.startswith("#"):
                    continue

                url = url.rstrip("/")

                if url in exclude_list:
                    continue

                # ==========================================
                # 新增：限制扩展名为 .yaml 或 .txt（忽略参数）
                # ==========================================
                parsed_path = urlparse(url).path.lower()
                if not (parsed_path.endswith(".yaml") or parsed_path.endswith(".txt")):
                    continue
                # ==========================================

                urls.add(url)

    except Exception as e:

        logger.error(
            f"读取 success_urls.txt 失败: {e}"
        )

        return

    unique_urls = sorted(
        urls
    )

    with open(
        UNIQUE_URLS_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        if unique_urls:

            f.write(
                "\n".join(
                    unique_urls
                )
                + "\n"
            )

    logger.info(
        f"待处理 URL 总数: "
        f"{len(unique_urls)}"
    )

    if not unique_urls:

        logger.warning(
            "没有可处理的 URL"
        )

        return

    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=CONCURRENCY,
        limit_per_host=LIMIT_PER_HOST,
        ttl_dns_cache=300,
    )

    semaphore = asyncio.Semaphore(
        CONCURRENCY
    )

    results = []

    async with aiohttp.ClientSession(
        connector=connector
    ) as session:

        for start in range(
            0,
            len(unique_urls),
            BATCH_SIZE
        ):

            batch = unique_urls[
                start:
                start + BATCH_SIZE
            ]

            batch_results = (
                await asyncio.gather(
                    *(
                        process_source(
                            session,
                            url,
                            semaphore
                        )
                        for url in batch
                    ),
                    return_exceptions=True
                )
            )

            for result in batch_results:

                if isinstance(
                    result,
                    Exception
                ):

                    logger.debug(
                        f"URL 处理异常: "
                        f"{result}"
                    )

                    continue

                results.append(
                    result
                )

            current = min(
                start + BATCH_SIZE,
                len(unique_urls)
            )

            logger.info(
                f"抓取进度: "
                f"{current}/"
                f"{len(unique_urls)}"
            )

    stats = []
    all_nodes_map = {}

    total_extracted = 0

    for result in results:

        if not isinstance(
            result,
            tuple
        ):
            continue

        if len(result) != 2:
            continue

        stat, nodes = result

        stats.append(
            stat
        )

        for node in nodes:

            try:

                key = stable_hash(
                    node
                )

                all_nodes_map[
                    key
                ] = node

                total_extracted += 1

            except Exception:
                continue

    unique_nodes = list(
        all_nodes_map.values()
    )

    final_config = (
        _merge_rules_config(
            unique_nodes
        )
    )

    try:

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            yaml.dump(
                final_config,
                f,
                allow_unicode=True,
                sort_keys=False,
                width=1000
            )

    except Exception as e:

        logger.error(
            f"写入 YAML 失败: {e}"
        )

        return

    try:

        with open(
            CSV_FILE,
            "w",
            newline="",
            encoding="utf-8-sig"
        ) as f:

            writer = csv.writer(
                f
            )

            writer.writerow([
                "原始URL",
                "最终URL",
                "状态",
                "节点数",
                "HTTP码",
                "响应秒数",
                "摘要",
            ])

            writer.writerows(
                stats
            )

    except Exception as e:

        logger.error(
            f"写入统计 CSV 失败: {e}"
        )

    success_count = sum(
        1
        for stat in stats
        if (
            len(stat) > 2
            and stat[2] == "提取成功"
        )
    )

    logger.info("=" * 60)

    logger.info(
        f"URL 总数       : "
        f"{len(unique_urls)}"
    )

    logger.info(
        f"成功提取 URL   : "
        f"{success_count}"
    )

    logger.info(
        f"提取节点总量   : "
        f"{total_extracted}"
    )

    logger.info(
        f"全局唯一节点   : "
        f"{len(unique_nodes)}"
    )

    logger.info(
        f"输出文件       : "
        f"{OUTPUT_FILE}"
    )

    logger.info(
        f"统计文件       : "
        f"{CSV_FILE}"
    )

    logger.info("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
