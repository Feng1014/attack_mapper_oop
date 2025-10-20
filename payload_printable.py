from __future__ import annotations
import base64
import json
import re
from typing import Any, Dict, Iterable, List, Optional


class PayloadPrintableParser:
    """
    负责：
      1) 将字符串形式的 payloadPrintable 解析为 JSON（容忍单个对象/列表）
      2) 深度抽取常见 Wireshark/IDS 字段
      3) 基于 frame.protocols + layers 顺序推导 L7 协议（l7Protocol/proofType）
      4) 常用辅助（SSH 版本号提取；Base64 → 可读文本，用于 payload）
    """

    PP_KEYS = [
        "tcp.payload",
        "http.request.method",
        "http.request.full_uri",
        "http.referer",
        "http.user_agent",
        "User-Agent",
        "http.content_type",
        "dns.qry.name",
        "dns.qry.type",
        "smb.cmd",
        "smb.flags",
        "smb.flags2",
        "smb.wct",
        "smb.pid",
        "smb.uid",
        "smb.mid",
        "ssh.protocol",
        "ftp.request.command",
        "ftp.request.arg",
        "ftp.response.code",
        "ftp.response.arg",
        "nbns.name",
        "nbns.id",
        "data-text-lines",
        "frame.protocols",
    ]

    _CEF_HTTP_HINT_RE = re.compile(
        r"(?:\bCEF:|HTTP/1\.[01]|\bGET\s+/|\bPOST\s+/|\bUser-Agent:|\bContent-Type:)", re.IGNORECASE
    )
    _ASCII_TOKEN_RE = re.compile(r"[A-Za-z0-9._-]{4,}")
    _TLD_HINT = ("com", "net", "org", "cn", "io", "me", "xyz",
                 "top", "info", "biz", "co", "gov", "edu")

    # OSI 集合
    _L2 = {"eth", "vlan"}
    _L3 = {"ip", "ipv6", "arp"}
    _L4 = {"tcp", "udp", "icmp", "icmpv6"}

    # 显式过滤（这些不是 L4+ 应用层协议）
    _NON_L5P = {"data", "syslog", "vssmonitoring",
                "_ws.malformed", "_ws.short"}

    # 允许作为 L7 协议的白名单
    _L7_ALLOW = {"dns", "mdns", "llmnr", "nbns", "bootp",
                 "http", "tls", "ssh", "ftp", "smb", "smb2", "kerberos"}

    _PROTO_LABEL = {
        "dns": "DNS", "mdns": "mDNS", "llmnr": "LLMNR", "nbns": "NBNS",
        "bootp": "DHCP",
        "http": "HTTP", "tls": "TLS", "ssh": "SSH", "ftp": "FTP",
        "smb": "SMB", "smb2": "SMB2", "kerberos": "KERBEROS",
    }

    # -------------- 对外 API --------------

    def extract_fields(self, pp_text: str) -> Dict[str, Any]:
        """
        从 payloadPrintable（字符串）抽取常见字段（键见 PP_KEYS）。
        """
        out: Dict[str, Any] = {k: "" for k in self.PP_KEYS}
        if not pp_text:
            out["frame.protocols"] = ""
            return out

        pp_json = self._try_parse_json(pp_text)
        if pp_json is not None:
            found = self._deep_search(pp_json, self.PP_KEYS)
            out.update({k: found.get(k, "") for k in self.PP_KEYS})
            if not out.get("User-Agent") and not out.get("http.user_agent"):
                ua = self._re_pick(
                    r"User-Agent\s*[:\"]\s*([^\r\n\"]+)", json.dumps(pp_json))
                if ua:
                    out["User-Agent"] = ua
        else:
            def cap(key: str) -> str:
                return self._re_pick(rf'"{re.escape(key)}"\s*:\s*"(.*?)"', pp_text) or ""
            for k in self.PP_KEYS:
                out[k] = cap(k)
            if not out.get("User-Agent") and not out.get("http.user_agent"):
                out["User-Agent"] = self._re_pick(
                    r"User-Agent\s*[:\"]\s*([^\r\n\"]+)", pp_text) or ""
        return out

    def extract_orders(self, pp_text: str) -> List[List[str]]:
        """
        解析 payloadPrintable → JSON 列表 → 提取各项的协议顺序（order）
        """
        parsed_list = self._parse_pp_list(pp_text)
        return self._extract_orders_from_list(parsed_list)

    def derive_l7(self, orders: List[List[str]]) -> tuple[str, str]:
        """
        从多条 order 中选出最后出现的、位于 L4 之上的白名单协议，返回 (l7Protocol, proofType)
        """
        above_l4_seq: List[str] = []
        for order in orders:
            for tok in order:
                low = tok.lower()
                if tok == "frame" or low == "ethertype":
                    continue
                if low in self._L2 or low in self._L3 or low in self._L4:
                    continue
                if low in self._NON_L5P:
                    continue
                if low not in self._L7_ALLOW:
                    continue
                above_l4_seq.append(low)

        if not above_l4_seq:
            return "", ""
        last_proto = above_l4_seq[-1]
        label = self._PROTO_LABEL.get(last_proto, last_proto.upper())
        return label, label

    def only_ssh_version(self, banner: Any) -> str:
        s = banner if isinstance(banner, str) else str(banner or "")
        m = re.search(r"(SSH-\d\.\d)", s)
        return m.group(1) if m else ""

    # —— 用于 payload（Base64）的可读清洗，与原脚本保持一致 ——
    def decode_payload_for_sheet(self, b64s: str) -> str:
        if not b64s:
            return ""
        b = self._b64_to_bytes(b64s)
        if not b:
            return ""
        try:
            u = b.decode("utf-8", errors="strict")
            if self._has_cjk(u) or self._CEF_HTTP_HINT_RE.search(u):
                return self._clean_unicode(u)
        except UnicodeDecodeError:
            pass
        cleaned_ascii = self._clean_ascii_from_bytes(b)
        if not cleaned_ascii:
            return ""
        return self._prefer_single_token_or_full(cleaned_ascii)

    # -------------- 内部工具 --------------

    def _try_parse_json(self, text: str) -> Optional[Any]:
        try:
            return json.loads(text)
        except Exception:
            return None

    def _deep_search(self, obj: Any, target_keys: Iterable[str]) -> Dict[str, Any]:
        res: Dict[str, Any] = {}
        tset = set(target_keys)

        def _walk(x: Any):
            if isinstance(x, dict):
                for k, v in x.items():
                    if k in tset and k not in res:
                        res[k] = v
                    _walk(v)
            elif isinstance(x, list):
                for it in x:
                    _walk(it)
        _walk(obj)
        return res

    def _re_pick(self, pattern: str, text: str) -> Optional[str]:
        m = re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL)
        if m:
            return (m.group(1) or "").strip()
        return None

    def _parse_pp_list(self, pp_str: str) -> List[dict]:
        if pp_str is None:
            return []
        s = pp_str.strip()
        if not s:
            return []
        try:
            data = json.loads(s)
        except Exception:
            try:
                data = [json.loads(s)]
            except Exception:
                return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        return []

    def _list_order_from_layers(self, layers: dict) -> List[str]:
        frame = layers.get("frame", {})
        proto_str = frame.get("frame.protocols", "") or ""
        toks = [t for t in proto_str.split(":") if t]

        mapping = {
            "eth": "eth", "vlan": "vlan",
            "ip": "ip", "ipv6": "ipv6", "arp": "arp",
            "tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6",
            "dns": "dns", "mdns": "mdns", "llmnr": "llmnr", "nbns": "nbns",
            "dhcp": "bootp", "bootp": "bootp",
            "http": "http", "tls": "tls", "ssl": "tls",
            "ssh": "ssh", "ftp": "ftp",
            "smb": "smb", "smb2": "smb2",
            "kerberos": "kerberos",
            "data": "data", "syslog": "syslog",
            "_ws.malformed": "_ws.malformed", "_ws.short": "_ws.short",
            "vssmonitoring": "vssmonitoring",
        }

        order = []
        for t in toks:
            if t == "ethertype":
                continue
            key = mapping.get(t, t)
            if key in layers and key not in order:
                order.append(key)

        out = ["frame"]
        for k in order:
            if k not in out:
                out.append(k)
        for k in layers.keys():
            if k not in out:
                out.append(k)
        return out

    def _extract_orders_from_list(self, parsed_list: List[dict]) -> List[List[str]]:
        orders: List[List[str]] = []
        for entry in parsed_list:
            layers = entry.get("_source", {}).get("layers", {})
            if isinstance(layers, dict) and layers:
                order = self._list_order_from_layers(layers)
                orders.append(order)
        return orders

    # ---- payload 字节串 → 可读文本清洗 ----
    def _b64_to_bytes(self, b64s: str) -> bytes:
        s = re.sub(r"\s+", "", b64s)
        try:
            return base64.b64decode(s, validate=True)
        except Exception:
            try:
                return base64.b64decode(s, validate=False)
            except Exception:
                return b""

    def _has_cjk(self, s: str) -> bool:
        return re.search(r"[\u3400-\u4DBF\u4E00-\u9FFF\uF900-\uFAFF]", s) is not None

    def _clean_unicode(self, u: str) -> str:
        u = u.replace("\r", "\n")
        u = re.sub(r"[\x00-\x08\x0b-\x0c\x0e-\x1f]", "", u)
        u = re.sub(r"[ \t]+", " ", u)
        u = re.sub(r" *\n+ *", "\n", u)
        return u.strip()

    def _clean_ascii_from_bytes(self, b: bytes) -> str:
        if not b:
            return ""
        buf: List[str] = []
        for c in b:
            if c in (10, 13):
                buf.append("\n")
            elif 32 <= c <= 126:
                buf.append(chr(c))
            elif c == 9:
                buf.append(" ")
            else:
                buf.append(" ")
        s = "".join(buf).replace("\r", "\n")
        s = re.sub(r"[ \t\x0b\x0c]+", " ", s)
        s = re.sub(r" *\n+ *", "\n", s)
        return s.strip()

    def _score_token(self, tok: str) -> tuple[int, int]:
        low = tok.lower()
        ends = int(any(low.endswith(s) for s in self._TLD_HINT)) \
            or int(any(low.endswith("-"+s) for s in self._TLD_HINT)) \
            or int(any(low.endswith("."+s) for s in self._TLD_HINT))
        return (ends, len(tok))

    def _prefer_single_token_or_full(self, cleaned: str) -> str:
        toks = self._ASCII_TOKEN_RE.findall(cleaned)
        if not toks:
            return cleaned
        best = max(toks, key=self._score_token)
        if "\n" not in cleaned and len(cleaned) <= len(best) + 10 and len(toks) <= 2:
            return best
        return cleaned
