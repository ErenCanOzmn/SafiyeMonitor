"""Passive inventory of embedded endpoints and labelled credential candidates.

No target execution, credential validation, network access, or entropy-only claims.
"""
import hashlib
import base64
import json
import ipaddress
import re
from collections import Counter
from urllib.parse import unquote, urlsplit, urlunsplit, parse_qsl, urlencode


def label_kind(label):
    key = label.casefold().translate(str.maketrans("ışğüöç", "isguoc"))
    key = re.sub(r"[^a-z0-9]", "", key)
    if re.fullmatch(r"(?:db|database|sql|ftp|smtp|proxy|auth|login|admin|service)?(?:password|passwd|pwd|passphrase|sifre|parola)", key):
        return "password"
    if re.fullmatch(r"(?:db|database|sql|ftp|smtp|proxy|auth|admin|service)?(?:username|userid|uid|user|login|kullanici|kullaniciadi)", key):
        return "username"
    if key in {"apikey", "accesskey", "secretkey", "clientsecret", "appsecret", "secret", "token", "accesstoken", "authtoken", "bearertoken", "awssecretaccesskey"}:
        return "token"
    return None


_ASSIGN = re.compile(r'''(?<![\w])(?P<label>[\w.-]+(?:[ \t]+(?:id|name|adı|adi))?)["']?\s*[:=]\s*(?P<value>"(?:\\.|[^"\r\n]){0,4096}"|'(?:\\.|[^'\r\n]){0,4096}'|[^\s;,<>&"'{}]{1,4096})''', re.I)
_XML = re.compile(r"<(?P<label>[\w.-]+)>\s*(?P<value>[^<>\r\n]{1,4096}?)\s*</(?P=label)>", re.I)
_XML_SETTING = re.compile(r'''\b(?:name|key)\s*=\s*["'](?P<label>[\w .-]+)["']\s+value\s*=\s*(?P<value>"[^"\r\n]{0,4096}"|'[^'\r\n]{0,4096}')''', re.I)
_URL = re.compile(r'''\b(?:https?|wss?|ftp|sftp|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|ldap[s]?)://[^\s<>"'\x00]+''', re.I)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?:%[\w.-]+)?(?![\w:])")
_JWT = re.compile(r"(?<![\w.-])eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![\w.-])")
_PEM = re.compile(r"-----BEGIN (?P<kind>(?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----[\r\n]+(?P<data>[A-Za-z0-9+/=\r\n]{32,16384})-----END (?P=kind)-----")
_PLACEHOLDERS = {"password", "passwd", "username", "user", "secret", "token", "changeme", "change_me", "example", "sample", "dummy", "test", "none", "null", "true", "false", "undefined", "redacted", "masked", "sifre", "parola"}


def placeholder(value):
    low = value.strip().casefold()
    return (not low or low in _PLACEHOLDERS or len(set(low)) == 1 or
            bool(re.search(r"demo[_ -]?only|not[_ -]?a[_ -]?real|your[_ -](?:username|password|secret|token|key)|replace[_ -]?me|example[_ -]|dummy[_ -]", low)) or
            low.startswith(("${", "$(", "%", "{{", "<", "env:", "getenv(", "environment.")) or
            bool(re.fullmatch(r"(?:x+|\*+|0+|\{\d+\})", low)))


def safe_url(value):
    """Inventory URLs without leaking userinfo, query values, or fragment tokens."""
    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return None
        port = parsed.port  # also validates out-of-range/non-numeric ports
        host = parsed.hostname
        if ":" in host:
            ipaddress.IPv6Address(host.split("%", 1)[0])
            host = "[" + host + "]"
        elif re.fullmatch(r"[0-9.]+", host):
            ipaddress.IPv4Address(host)
        elif not re.fullmatch(r"[a-zA-Z0-9_\-\u0080-\uffff.]+", host):
            return None
        netloc = host + (":" + str(port) if port is not None else "")
        # Path segments can also be signed tokens; long opaque segments stay masked.
        route = re.sub(r"(?<=/)[A-Za-z0-9_.=-]{32,}(?=/|$)", "[redacted]", parsed.path)
        query = urlencode([(k, "[redacted]") for k, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit((parsed.scheme.lower(), netloc, route, query, ""))
    except ValueError:
        return None


def text_candidates(text):
    """Yield (kind, value, value-start, label, basis). No unrelated strings paired."""
    for pattern in (_ASSIGN, _XML, _XML_SETTING):
        for match in pattern.finditer(text):
            kind = label_kind(match["label"])
            if not kind:
                continue
            raw = match["value"]
            quoted = len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]
            value = raw[1:-1] if quoted else raw
            if not quoted and len(raw) == 4096 and match.end("value") < len(text) and not re.match(r"[\s;,<>&\"'{}]", text[match.end("value")]):
                continue  # never hash/display a prefix as though it were the full credential
            if placeholder(value) or (not quoted and re.search(r"[()$]|^[A-Za-z_]+\.[A-Za-z_]+$", value)):
                continue
            yield kind, value, match.start("value") + int(quoted), match["label"], "Explicit labelled literal; validity and impact are unverified."
    for match in _JWT.finditer(text):
        try:
            header, payload, _ = match[0].split(".")
            decoded = [json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))) for part in (header, payload)]
            if all(isinstance(part, dict) for part in decoded) and isinstance(decoded[0].get("alg"), str):
                yield "token", match[0], match.start(), "jwt", "JWT-shaped value with JSON header/payload; signature and usability were not checked."
        except (ValueError, UnicodeDecodeError):
            pass
    for match in _PEM.finditer(text):
        try:
            raw = base64.b64decode(re.sub(r"\s", "", match["data"]), validate=True)
            if len(raw) >= 24:
                yield "private_key", match[0], match.start(), "pem", "Complete PEM delimiters and base64 body; key parsing, ownership and use remain unverified."
        except ValueError:
            pass
    for match in _URL.finditer(text):
        value = match[0].rstrip(").,;]") if not match[0].endswith("]") else match[0].rstrip(").,;")
        endpoint = safe_url(value)
        if not endpoint:
            continue
        yield "url", value, match.start(), "endpoint", "Embedded endpoint reference; not a vulnerability."
        try:
            parsed = urlsplit(value)
            for kind, credential in (("username", parsed.username), ("password", parsed.password)):
                if credential and not placeholder(unquote(credential)):
                    start = value.find(credential, value.find("://") + 3)
                    yield kind, unquote(credential), match.start() + start, "url-userinfo", "Literal URL userinfo; credential usability is unverified."
        except ValueError:
            pass
    for pattern in (_IPV4, _IPV6):
        for match in pattern.finditer(text):
            value = match[0]
            try:
                address = ipaddress.ip_address(value.split("%", 1)[0])
            except ValueError:
                continue
            # Exclude obvious version labels; never classify an address as a secret.
            if re.search(r"(?:version|ver|build)\s*[:=v]?\s*$", text[max(0, match.start()-20):match.start()], re.I):
                continue
            yield "ip", value, match.start(), "address", "Validated IP syntax; not evidence of exposure or a vulnerability."


def iter_strings(blob):
    """UTF-8/ASCII and LE/BE wide strings, including Turkish Latin characters."""
    patterns = [
        ("utf-8", rb"[\x09\x0a\x0d\x20-\x7e\x80-\xff]{4,}"),
        ("utf-16-le", rb"(?:[\x09\x0a\x0d\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x02]){4,}"),
        ("utf-16-be", rb"(?:\x00[\x09\x0a\x0d\x20-\x7e\xa0-\xff]|[\x01-\x02][\x00-\xff]){4,}"),
    ]
    for encoding, pattern in patterns:
        for match in re.finditer(pattern, blob):
            raw = match[0]
            try:
                text = raw.decode(encoding)
                yield match.start(), encoding, text
            except UnicodeDecodeError:
                # Invalid surrounding binary bytes must not hide printable ASCII.
                for ascii_match in re.finditer(rb"[\x20-\x7e]{4,}", raw):
                    yield match.start() + ascii_match.start(), "ascii", ascii_match[0].decode("ascii")


def scan_blob(blob, reveal=False, max_items=1000):
    items, seen, string_bytes = [], {}, 0
    occurrence_offsets = {}
    truncated = False
    for base, encoding, text in iter_strings(blob):
        string_bytes += len(text.encode(encoding))
        # Scan whole runs so a boundary never turns a prefix into a false value.
        for kind, value, position, label, basis in text_candidates(text):
            character = position
            offset = base + len(text[:character].encode(encoding))
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            identity = (kind, digest)
            if identity in seen:
                item = seen[identity]
                if offset not in occurrence_offsets[identity]:
                    occurrence_offsets[identity].add(offset)
                    item["occurrences"] += 1
                    if len(item["offsets"]) < 20:
                        item["offsets"].append(offset)
                continue
            if len(items) >= max_items:
                truncated = True
                # Keep credential candidates available even in endpoint-heavy files.
                replace = next((i for i in reversed(items) if i["category"] in {"url", "ip"}), None) if kind not in {"url", "ip"} else None
                if replace is None:
                    continue
                old_identity = (replace["category"], replace["sha256"])
                items.remove(replace)
                seen.pop(old_identity)
                occurrence_offsets.pop(old_identity)
            endpoint = kind in {"url", "ip"}
            item = {"category": kind, "risk_label": "embedded_" + kind,
                    "severity": "INFO", "validation_status": "inventory" if endpoint else "needs_review",
                    "confidence": "high" if endpoint else "medium", "basis": basis,
                    "label": label, "offset": offset, "offsets": [offset], "occurrences": 1,
                    "context_ref": f"{encoding}:{base}",
                    "enc": encoding, "length": len(value), "sha256": digest,
                    "masked": safe_url(value) if kind == "url" else value if kind == "ip" else "[redacted]",
                    "value_truncated": False}
            if kind == "ip":
                address = ipaddress.ip_address(value.split("%", 1)[0])
                item["address_scope"] = "loopback" if address.is_loopback else "private" if address.is_private else "global" if address.is_global else "reserved"
            if reveal:
                item["value"] = value
            items.append(item)
            seen[identity] = item
            occurrence_offsets[identity] = {offset}
    items.sort(key=lambda item: (item["category"] in {"ip", "url"}, item["offset"]))
    return {"findings": items, "count": len(items), "counts": dict(Counter(i["category"] for i in items)),
            "string_bytes": min(string_bytes, len(blob)), "results_truncated": truncated,
            "limits": {"max_items": max_items, "max_literal_chars": 4096, "max_recorded_offsets": 20},
            "note": "Literal inventory only. No credential was tested and no endpoint was contacted."}
