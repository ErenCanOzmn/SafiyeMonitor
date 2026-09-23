"""Conservative observations from already captured data, never proof of a flaw."""
import hashlib
import re
from artifact_scan import text_candidates


def observation(title, description, evidence, category, confidence="medium"):
    return {"title": title, "description": description, "evidence": evidence,
            "severity": "INFO", "category": category, "confidence": confidence,
            "validation_status": "needs_review",
            "verification_steps": ["Review the recorded evidence and relevant source/configuration.",
                                   "Establish the affected security boundary and impact before confirming."],
            "exploitation_notes": "", "recommendation": "Determine whether this is intended behavior before proposing a change."}


def capture_from_session(events, snapshots):
    data = {key: [] for key in ("tcp_packets", "dll_events", "registry_events", "file_events", "crypto_events", "process_events")}
    for event in events:
        kind = event.get("type")
        key = {"tcp_in": "tcp_packets", "tcp_out": "tcp_packets", "dll_monitor": "dll_events",
               "crypto_event": "crypto_events", "process_spawn": "process_events"}.get(kind)
        if kind == "registry_file_monitor":
            key = "registry_events" if "reg" in str(event.get("api", "")).lower() else "file_events"
        if key:
            data[key].append(event)
    data["static_strings"] = snapshots.get("static_strings", {}).get("data", [])
    data["memory_strings"] = snapshots.get("memory_dump", {}).get("data", [])
    return data


def analyze_capture(data):
    observations = []
    seen = set()

    def add(item):
        key = (item["title"], item["evidence"])
        if key not in seen:
            seen.add(key)
            observations.append(item)

    def credentials(text, origin):
        for kind, value, position, label, basis in text_candidates(text):
            if kind not in {"password", "token"}:
                continue  # usernames/endpoints belong to inventory, not vulnerability claims
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            title = "Credential-like literal in binary strings" if origin == "static strings" else "Credential-like value in captured runtime data"
            add(observation(title,
                            "A labelled value was observed. Runtime presence does not establish hardcoding, transport exposure, or credential validity.",
                            f"Source: {origin}; label: {label}; length: {len(value)}; SHA-256: {digest}; value: [redacted]",
                            "credential_candidate"))

    for packet in data.get("tcp_packets", []):
        body = packet.get("body") or ""
        if not isinstance(body, str):
            continue
        origin = "network capture at " + str(packet.get("dest", "unknown endpoint"))
        credentials(body, origin)
        # Reading HTTP inside a TLS hook says nothing about on-wire encryption.
        head, separator, _ = body.replace("\r\n", "\n").partition("\n\n")
        response = bool(re.match(r"^HTTP/1\.[01] [1-5][0-9]{2}(?: |\n)", head))
        if not response or not separator:
            continue
        for line in head.split("\n")[1:]:
            name, colon, value = line.partition(":")
            if not colon or name.lower() != "set-cookie":
                continue
            parts = [p.strip() for p in value.split(";")]
            cookie_name = parts[0].partition("=")[0]
            if not re.search(r"sess|auth|token|jwt|(?:^|_)sid$", cookie_name, re.I):
                continue
            flags = {part.partition("=")[0].lower() for part in parts[1:]}
            missing = [flag for flag in ("secure", "httponly") if flag not in flags]
            if missing:
                add(observation("Cookie attributes require review",
                                "An authentication-like cookie name lacks attributes. Its authentication role, channel and application requirements remain unverified.",
                                f"{origin}; cookie name: {cookie_name}; missing attributes: {', '.join(missing)}; cookie value: [redacted]",
                                "cookie_configuration", "high"))

    for source in ("static_strings", "memory_strings"):
        for item in data.get(source, []):
            value = item.get("val", "") if isinstance(item, dict) else item
            if isinstance(value, str):
                credentials(value, "static strings" if source == "static_strings" else "memory strings")

    for event in data.get("crypto_events", []):
        if event.get("dpapi_local_machine") and event.get("op") == "protect":
            add(observation("Machine-scoped DPAPI protection observed",
                            "Machine scope was requested. Whether it is inappropriate depends on blob access permissions, additional entropy and the intended trust boundary.",
                            str(event.get("api", "CryptProtectData")) + ": LOCAL_MACHINE", "dpapi_scope", "high"))
        # Plaintext at a decrypt/unprotect boundary is expected and is not a flaw.

    # File access, failed DLL lookups, algorithm names, entropy, shell arguments,
    # database error text and serialization signatures cannot establish exploitability.
    return observations
