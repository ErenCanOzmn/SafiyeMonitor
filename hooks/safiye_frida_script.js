// Frida 17 compatibility: the global Module.findExportByName and
// Memory.readByteArray were removed in Frida 17. Restore them so the rest of
// this script works unchanged on both Frida 16 and 17.
if (typeof Module.findExportByName !== "function") {
    Module.findExportByName = function (moduleName, symbol) {
        try {
            if (!moduleName) {
                return (typeof Module.findGlobalExportByName === "function")
                    ? Module.findGlobalExportByName(symbol) : null;
            }
            var m = (typeof Process.findModuleByName === "function")
                ? Process.findModuleByName(moduleName) : null;
            if (!m) { try { m = Process.getModuleByName(moduleName); } catch (e) { m = null; } }
            if (!m) return null;
            if (typeof m.findExportByName === "function") return m.findExportByName(symbol);
            if (typeof m.getExportByName === "function") { try { return m.getExportByName(symbol); } catch (e) {} }
            return null;
        } catch (e) { return null; }
    };
}
if (typeof Memory.readByteArray !== "function") {
    Memory.readByteArray = function (ptr, len) {
        try { return ptr.readByteArray(len); } catch (e) { return null; }
    };
}

// Depth counter for winsock send calls. The AFD NT-layer hook
// (NtDeviceIoControlFile) fires for the same bytes that ws2_32 send/WSASend
// already captured, producing duplicates. While we are inside a ws2_32 send,
// this is > 0 so the AFD hook can skip the duplicate. Direct NtDeviceIoControlFile
// senders (that bypass ws2_32) still get captured because the depth stays 0.
var winsockSendDepth = 0;

var sendPtr = Module.findExportByName("ws2_32.dll", "send");
var WSASendPtr = Module.findExportByName("ws2_32.dll", "WSASend");
var recvPtr = Module.findExportByName("ws2_32.dll", "recv");
var WSARecvPtr = Module.findExportByName("ws2_32.dll", "WSARecv");
var connectPtr = Module.findExportByName("ws2_32.dll", "connect");

var socketMap = {};

// ── Destination resolution ────────────────────────────────────────────────
// socketMap is populated eagerly by the connect()/WSAConnect() hooks, but many
// apps reach the network through paths those hooks never see: IPv6 sockets,
// ConnectEx/AcceptEx (async winsock used by browsers, .NET, curl), or a socket
// that was already connected before we attached. For all of those we ask the
// OS directly with getpeername(), which returns the real remote address of any
// connected socket regardless of how the connection was made. The result is
// cached back into socketMap so we only pay the syscall once per socket.
var getpeernamePtr = Module.findExportByName("ws2_32.dll", "getpeername");
var getpeernameFn = getpeernamePtr
    ? new NativeFunction(getpeernamePtr, 'int', ['int', 'pointer', 'pointer'])
    : null;

function fmtIPv6(bytes) {
    // bytes: 16-element array of octets → compressed "[a:b::c]" form.
    var parts = [];
    for (var i = 0; i < 16; i += 2) {
        parts.push((((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF)).toString(16));
    }
    // Compress the longest run of zero groups into "::".
    var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    for (var j = 0; j < 8; j++) {
        if (parts[j] === "0") {
            if (curStart < 0) { curStart = j; curLen = 1; } else { curLen++; }
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else { curStart = -1; curLen = 0; }
    }
    if (bestLen > 1) {
        var head = parts.slice(0, bestStart).join(":");
        var tail = parts.slice(bestStart + bestLen).join(":");
        return "[" + head + "::" + tail + "]";
    }
    return "[" + parts.join(":") + "]";
}

// Parse a sockaddr (AF_INET / AF_INET6) at addrPtr into "ip:port" (or null).
function parseSockaddr(addrPtr) {
    try {
        var family = addrPtr.readU16();
        if (family === 2) {          // AF_INET (IPv4)
            var port = ((addrPtr.add(2).readU8() & 0xFF) << 8) | (addrPtr.add(3).readU8() & 0xFF);
            var ip = addrPtr.add(4).readU8() + "." + addrPtr.add(5).readU8() + "." +
                     addrPtr.add(6).readU8() + "." + addrPtr.add(7).readU8();
            return ip + ":" + port;
        }
        if (family === 23) {         // AF_INET6 (IPv6)
            var port6 = ((addrPtr.add(2).readU8() & 0xFF) << 8) | (addrPtr.add(3).readU8() & 0xFF);
            var b = [];
            for (var k = 0; k < 16; k++) b.push(addrPtr.add(8 + k).readU8() & 0xFF);
            return fmtIPv6(b) + ":" + port6;
        }
    } catch (e) { }
    return null;
}

// Return the best-known destination for a socket, querying getpeername() as a
// fallback and caching any success. Never caches "Unknown", so a socket that is
// not connected yet can still resolve on a later send/recv.
function resolveDest(socket) {
    var known = socketMap[socket];
    if (known && known !== "Unknown") return known;
    if (getpeernameFn === null || !socket) return known || "Unknown";
    try {
        var addrBuf = Memory.alloc(128);   // sockaddr_storage
        var lenBuf = Memory.alloc(4);
        lenBuf.writeInt(128);
        if (getpeernameFn(socket, addrBuf, lenBuf) === 0) {
            var d = parseSockaddr(addrBuf);
            if (d) { socketMap[socket] = d; return d; }
        }
    } catch (e) { }
    return known || "Unknown";
}

var intercept_mode = false;
var packetCounter = 0;

// Per-socket queue of injected recv bytes (Safiye cURL Mode response replay).
// When set, the next recv()/WSARecv() on that socket returns these bytes
// instead of reading from the network.
var pendingRecvBySocket = {};

// Per-socket capture flag for Forward Packet responses. After we forward an
// intercepted send on a socket, the next inbound bytes on that same socket are
// captured and shipped to the UI as the "Last Response" for that packet.
// socketId -> { pkgId: <number>, remaining: <bytesLeftToCapture or null> }
var captureRespBySocket = {};
var inRepeaterSend = false;

// ── FUNCTION FAKER ────────────────────────────────────────────────────────────
// Runtime return-value / trace hooks installed on demand via RPC (fakeradd). Lets
// an operator force any function's return value live (e.g. IsLicenseValid -> 1,
// IsDebuggerPresent -> 0) for license/auth/anti-debug bypass, or just trace calls.
var fakerRules = {};                       // ruleId -> { listener, module, symbol, offset, mode, value, hits, addr }
var _fakerRate = { sec: 0, count: 0 };

function _fakerAllowed() {                  // rate-limit only the UI notification, never the replace
    var now = Math.floor(Date.now() / 1000);
    if (now !== _fakerRate.sec) { _fakerRate.sec = now; _fakerRate.count = 0; }
    if (_fakerRate.count >= 100) return false;
    _fakerRate.count++;
    return true;
}

function _fakerModule(name) {
    try {
        if (typeof Process.findModuleByName === "function") return Process.findModuleByName(name);
        return Process.getModuleByName(name);
    } catch (e) { return null; }
}

function _resolveFakerTarget(moduleName, symbol, offset) {
    try {
        if (symbol) return Module.findExportByName(moduleName || null, symbol);
        if (offset) {
            var mod = _fakerModule(moduleName);
            if (mod) return mod.base.add(ptr(offset));
        }
    } catch (e) {}
    return null;
}

function emitResponseCapture(socketId, bytes) {
    try {
        var meta = captureRespBySocket[socketId];
        if (!meta) return;
        if (meta.isRepeater) {
            var hexStr = "";
            for (var i = 0; i < bytes.length; i++)
                hexStr += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
            send({
                type: "repeater_tcp_response",
                socket: socketId,
                body_hex: hexStr,
                size: bytes.length
            });
        } else {
            send({
                type: "intercept_response",
                id: meta.pkgId,
                socket: socketId,
                size: bytes.length
            }, bytes.buffer);
        }
    } catch (e) { console.log("[FRIDA] emitResponseCapture error: " + e); }
}

function queueInjectedRecv(socketId, hexStr) {
    if (typeof hexStr !== "string" || hexStr.length === 0) return;
    var clean = hexStr.replace(/\s+/g, "");
    var bytes = new Uint8Array(clean.length / 2);
    for (var i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
    }
    if (!pendingRecvBySocket[socketId]) pendingRecvBySocket[socketId] = [];
    // We push the full payload as a single chunk; the recv hook splits it
    // across multiple recv() calls if the client uses small buffers.
    pendingRecvBySocket[socketId].push(bytes);
    console.log("[FRIDA] Queued injected recv for socket=" + socketId + " (" + bytes.length + " bytes). Queue depth=" + pendingRecvBySocket[socketId].length);
}

function consumeInjectedRecv(socketId, maxLen) {
    var q = pendingRecvBySocket[socketId];
    if (!q || q.length === 0) return null;
    var chunk = q[0];
    if (chunk.length <= maxLen) {
        q.shift();
        if (q.length === 0) delete pendingRecvBySocket[socketId];
        return chunk;
    }
    // Split: deliver maxLen bytes now, leave the rest for the next recv()
    var head = chunk.subarray(0, maxLen);
    q[0] = chunk.subarray(maxLen);
    return head;
}

// Filter Frida's own injected-agent artifacts out of memory-dump results so the
// strings list reflects the target process, not the instrumentation.
function isFridaNoise(s) {
    return s.indexOf("frida") !== -1 ||
           s.indexOf("pipe:role=") !== -1 ||
           s.indexOf("GumScript") !== -1 ||
           s.indexOf("gum-js-loop") !== -1;
}

rpc.exports = {
    setintercept: function (state) {
        intercept_mode = state;
        console.log("[FRIDA] Intercept mode set to: " + state);
    },
    dumpstrings: function () {
        var results = [];
        var mainModule = Process.enumerateModules()[0];
        var ranges = Process.enumerateRanges({
            protection: 'r--',
            coalesce: true
        });

        ranges.forEach(function (range) {
            var scanSize = Math.min(range.size, 1024 * 1024 * 2); // Max 2MB per range
            try {
                var buf = Memory.readByteArray(range.base, scanSize);
                if (buf === null) return;
                var uint8 = new Uint8Array(buf);
                var str = "";
                for (var i = 0; i < uint8.length; i++) {
                    var c = uint8[i];
                    if (c >= 32 && c <= 126) {
                        str += String.fromCharCode(c);
                    } else {
                        if (str.length > 5 && !isFridaNoise(str)) {
                            results.push({
                                type: "ASCII",
                                addr: range.base.add(i - str.length).toString(),
                                val: str
                            });
                        }
                        str = "";
                    }
                    if (results.length > 1000) return;
                }
            } catch (e) { }
        });
        return results;
    },

    // Scan readable memory for credential-like material (Tier-2: memory credential
    // scan + post-logout cleanup). Values are masked and fingerprinted — never sent
    // raw over the message bus. The fingerprint (fp) lets the backend compare a
    // pre-logout scan against a post-logout scan: an fp present in BOTH means the
    // app failed to zero that secret on logout.
    scanmemorycreds: function () {
        var CRED_RES = [
            { cat: "private-key",       re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
            { cat: "jwt",               re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/ },
            { cat: "aws-access-key",    re: /\bAKIA[0-9A-Z]{16}\b/ },
            { cat: "connection-string", re: /(?:Data Source|Server|Initial Catalog)\s*=[^;]{1,80};[\s\S]{0,120}?(?:Password|Pwd)\s*=[^;]{1,80}/i },
            { cat: "password-assign",   re: /(?:password|passwd|pwd|sifre|parola)\s*[=:]\s*[^\s"'<>&;]{3,80}/i },
            { cat: "bearer-token",      re: /(?:bearer\s+|api[_-]?key\s*[=:]\s*|access[_-]?token\s*[=:]\s*)[A-Za-z0-9._\-]{12,}/i },
            { cat: "basic-auth",        re: /Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}/i }
        ];
        function djb2(s) { var h = 5381; for (var i = 0; i < s.length; i++) { h = ((h << 5) + h + s.charCodeAt(i)) >>> 0; } return h.toString(16); }
        function maskv(s) { if (s.length <= 6) return s.charAt(0) + "****"; return s.substr(0, 4) + "****" + s.substr(s.length - 2); }

        var results = [];
        var GLOBAL_BUDGET = 256 * 1024 * 1024;  // scan at most 256MB total
        var TIME_BUDGET   = 8000;               // ms — bound the in-process thread freeze
        var WINDOW        = 4 * 1024 * 1024;     // 4MB read window (walk the WHOLE range, not just the head)
        var RUN_MAX       = 2048;                // cap one string run (avoid O(n^2) + pathological regex)
        var RESULT_MAX    = 500;
        var t0 = Date.now(), scanned = 0;
        function overBudget() { return results.length > RESULT_MAX || scanned >= GLOBAL_BUDGET || (Date.now() - t0) > TIME_BUDGET; }

        function testStr(s, addr, enc) {
            if (s.length < 6 || isFridaNoise(s)) return;
            for (var k = 0; k < CRED_RES.length; k++) {
                var m = CRED_RES[k].re.exec(s);
                if (m) {
                    var v = m[0];
                    results.push({ category: CRED_RES[k].cat, addr: addr, enc: enc,
                                   masked: maskv(v), fp: djb2(v), len: v.length });
                    return;
                }
            }
        }
        function scanChunk(u8, baseAddr) {
            var codes = [], start = -1, i;
            for (i = 0; i < u8.length; i++) {                       // ASCII runs
                var c = u8[i];
                if (c >= 32 && c <= 126) { if (start < 0) start = i; if (codes.length < RUN_MAX) codes.push(c); }
                else { if (codes.length > 6) testStr(String.fromCharCode.apply(null, codes), baseAddr.add(start).toString(), "ascii"); codes = []; start = -1; }
                if (results.length > RESULT_MAX) return;
            }
            if (codes.length > 6) testStr(String.fromCharCode.apply(null, codes), baseAddr.add(start).toString(), "ascii");
            var w = [], wstart = -1, j;
            for (j = 0; j + 1 < u8.length; j += 2) {                // UTF-16LE runs (Windows wide strings hold passwords)
                if (u8[j + 1] === 0 && u8[j] >= 32 && u8[j] <= 126) { if (wstart < 0) wstart = j; if (w.length < RUN_MAX) w.push(u8[j]); }
                else { if (w.length > 6) testStr(String.fromCharCode.apply(null, w), baseAddr.add(wstart).toString(), "utf16"); w = []; wstart = -1; }
                if (results.length > RESULT_MAX) return;
            }
            if (w.length > 6) testStr(String.fromCharCode.apply(null, w), baseAddr.add(wstart).toString(), "utf16");
        }

        var ranges = Process.enumerateRanges({ protection: 'r--', coalesce: true });  // includes rw- heap
        for (var r = 0; r < ranges.length && !overBudget(); r++) {
            var range = ranges[r], off = 0;
            while (off < range.size && !overBudget()) {
                var take = Math.min(WINDOW, range.size - off);
                try {
                    var buf = Memory.readByteArray(range.base.add(off), take);
                    if (buf !== null) scanChunk(new Uint8Array(buf), range.base.add(off));
                } catch (e) { }
                scanned += take; off += take;
            }
        }
        return { findings: results, scanned_bytes: scanned,
                 truncated: (scanned >= GLOBAL_BUDGET || (Date.now() - t0) > TIME_BUDGET) };
    },

    repeatersend: function(socketId, payload, isHex) {
        try {
            if (!sendPtr) return "error:send() not found";
            var sid = parseInt(socketId);
            var bytes;
            if (isHex) {
                var clean = (payload || "").replace(/[\s\n\r\t]/g, "");
                if (clean.length % 2 !== 0) clean = "0" + clean;
                if (clean.length === 0) return "error:empty hex payload";
                bytes = new Uint8Array(clean.length / 2);
                for (var i = 0; i < clean.length; i += 2)
                    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
            } else {
                var enc = [];
                for (var i = 0; i < payload.length; i++) {
                    var c = payload.charCodeAt(i);
                    if (c < 0x80) enc.push(c);
                    else if (c < 0x800) { enc.push((c >> 6) | 0xC0); enc.push((c & 0x3F) | 0x80); }
                    else { enc.push((c >> 12) | 0xE0); enc.push(((c >> 6) & 0x3F) | 0x80); enc.push((c & 0x3F) | 0x80); }
                }
                bytes = new Uint8Array(enc);
            }
            if (bytes.byteLength === 0) return "error:empty payload";
            var sendFn = new NativeFunction(sendPtr, 'int', ['int', 'pointer', 'int', 'int']);
            var buf = Memory.alloc(bytes.byteLength);
            buf.writeByteArray(Array.from(bytes));
            captureRespBySocket[sid] = { pkgId: -1, isRepeater: true };
            inRepeaterSend = true;
            try {
                var ret = sendFn(sid, buf, bytes.byteLength, 0);
            } finally {
                inRepeaterSend = false;
            }
            return "sent:" + bytes.byteLength + " ret=" + ret;
        } catch(e) {
            inRepeaterSend = false;
            return "error:" + e;
        }
    },

    // Install a faker hook. mode "return" forces retval to `value`; mode "trace"
    // only reports calls. Target is module!symbol (exported) or module+offset.
    fakeradd: function (ruleId, moduleName, symbol, offset, mode, value) {
        try {
            if (value === "true") value = "1";
            else if (value === "false") value = "0";
            if (fakerRules[ruleId]) { try { fakerRules[ruleId].listener.detach(); } catch (e) {} delete fakerRules[ruleId]; }
            var target = _resolveFakerTarget(moduleName, symbol, offset);
            if (!target || target.isNull()) return "error:target not found";
            var label = symbol || (moduleName + "+" + offset);
            var rule = { module: moduleName, symbol: symbol, offset: offset, mode: mode, value: value, hits: 0, addr: target.toString() };
            var listener = Interceptor.attach(target, {
                onEnter: function (args) {
                    this.a = [];
                    for (var i = 0; i < 4; i++) { try { this.a.push(args[i].toString()); } catch (e) { this.a.push("?"); } }
                    this.caller = _callerMod(this.returnAddress);
                },
                onLeave: function (retval) {
                    var orig = retval.toString();
                    var forced = orig;
                    if (mode === "return") {
                        try { retval.replace(ptr(value)); forced = ptr(value).toString(); } catch (e) {}
                    }
                    rule.hits++;
                    if (_fakerAllowed()) {
                        send({ type: "faker_hit", id: ruleId, label: label, module: moduleName, symbol: symbol,
                               args: this.a, orig_ret: orig, forced_ret: forced, mode: mode, caller: this.caller,
                               hits: rule.hits, _ts: _procTs() });
                    }
                }
            });
            rule.listener = listener;
            fakerRules[ruleId] = rule;
            return "ok:" + target.toString();
        } catch (e) { return "error:" + e; }
    },
    fakerremove: function (ruleId) {
        try {
            if (fakerRules[ruleId]) { try { fakerRules[ruleId].listener.detach(); } catch (e) {} delete fakerRules[ruleId]; return "ok"; }
            return "error:no such rule";
        } catch (e) { return "error:" + e; }
    },
    fakerlist: function () {
        var out = [];
        for (var k in fakerRules) {
            var r = fakerRules[k];
            out.push({ id: k, module: r.module, symbol: r.symbol, offset: r.offset, mode: r.mode, value: r.value, hits: r.hits, addr: r.addr });
        }
        return out;
    },
    fakersearch: function (moduleName, query, limit) {
        var out = [];
        try {
            var mod = _fakerModule(moduleName);
            if (!mod) return out;
            var q = (query || "").toLowerCase();
            var exps = mod.enumerateExports();
            for (var i = 0; i < exps.length && out.length < (limit || 100); i++) {
                if (!q || exps[i].name.toLowerCase().indexOf(q) !== -1) {
                    out.push({ name: exps[i].name, address: exps[i].address.toString() });
                }
            }
        } catch (e) {}
        return out;
    }
};

// Deserialization Magic Bytes Signatures
// TLS record framing: content type 0x14-0x17 (ChangeCipherSpec/Alert/Handshake/
// AppData) followed by version 0x03,0x00-0x04. Ciphertext is random bytes, so
// scanning it for magic bytes is the single biggest false-positive source —
// skip it outright.
function _looksLikeTls(u8) {
    return u8.length >= 3 && u8[0] >= 0x14 && u8[0] <= 0x17 &&
           u8[1] === 0x03 && u8[2] <= 0x04;
}

// Offset just past the first CRLFCRLF (HTTP header/body boundary), or -1.
function _httpBodyStart(u8) {
    var lim = Math.min(u8.length - 4, 4096);
    for (var i = 0; i <= lim; i++) {
        if (u8[i] === 0x0d && u8[i + 1] === 0x0a && u8[i + 2] === 0x0d && u8[i + 3] === 0x0a)
            return i + 4;
    }
    return -1;
}

function _isDigit(b) { return b >= 0x30 && b <= 0x39; }

// Return a serialization format name if a REAL serialized object begins exactly
// at position p — full, specific signatures instead of a 2-byte prefix at an
// arbitrary offset (which matches random data ~constantly).
function _deserAt(u8, p) {
    var n = u8.length;
    if (p < 0 || p + 2 > n) return null;
    // Java: STREAM_MAGIC 0xACED + STREAM_VERSION 0x0005
    if (p + 4 <= n && u8[p] === 0xAC && u8[p + 1] === 0xED && u8[p + 2] === 0x00 && u8[p + 3] === 0x05)
        return "Java Serialization";
    // .NET BinaryFormatter header: 00 01 00 00 00 FF FF FF FF
    if (p + 9 <= n && u8[p] === 0x00 && u8[p + 1] === 0x01 && u8[p + 2] === 0x00 &&
        u8[p + 3] === 0x00 && u8[p + 4] === 0x00 && u8[p + 5] === 0xFF && u8[p + 6] === 0xFF &&
        u8[p + 7] === 0xFF && u8[p + 8] === 0xFF)
        return ".NET BinaryFormatter";
    // Python pickle: PROTO opcode 0x80 + version 2/3/4, AND a STOP '.' (0x2E) as
    // the final byte of the payload — a real pickle always ends with STOP.
    if (u8[p] === 0x80 && (u8[p + 1] === 0x02 || u8[p + 1] === 0x03 || u8[p + 1] === 0x04) && u8[n - 1] === 0x2E)
        return "Python Pickle";
    // PHP serialized object: O:<len>:"   → 4F 3A <ascii digits> 3A 22
    if (u8[p] === 0x4F && u8[p + 1] === 0x3A) {
        var q = p + 2, d = 0;
        while (q < n && _isDigit(u8[q])) { q++; d++; }
        if (d > 0 && q + 1 < n && u8[q] === 0x3A && u8[q + 1] === 0x22)
            return "PHP Serialized Object";
    }
    return null;
}

function checkDeserialization(data, socket, dest, direction) {
    if (!data || data.byteLength < 4) return;
    var u8 = new Uint8Array(data);
    if (_looksLikeTls(u8)) return;   // encrypted record — nothing to scan here
    // Anchor only at meaningful positions: the payload start and the HTTP body
    // start (for a serialized blob POSTed inside an HTTP request).
    var positions = [0];
    var b = _httpBodyStart(u8);
    if (b > 0) positions.push(b);
    for (var pi = 0; pi < positions.length; pi++) {
        var fmt = _deserAt(u8, positions[pi]);
        if (fmt) {
            send({
                type: "alert",
                severity: "HIGH",
                title: "Insecure Deserialization Detected!",
                message: "Detected " + fmt + " payload at offset " + positions[pi] + " in " + direction + " traffic to " + dest,
                socket: socket
            });
            return;
        }
    }
}

function handleSend(socket, bufPtr, len, name) {
    if (inRepeaterSend) return "forward";
    var dest = resolveDest(socket);
    var bufData = Memory.readByteArray(bufPtr, len);

    checkDeserialization(bufData, socket, dest, "Outgoing (" + name + ")");

    if (intercept_mode) {
        packetCounter++;
        var currentId = packetCounter;
        
        // Convert to HEX for safe transport
        var uint8 = new Uint8Array(bufData);
        var hexStr = "";
        for (var i = 0; i < uint8.length; i++) {
            var h = uint8[i].toString(16);
            if (h.length === 1) h = "0" + h;
            hexStr += h;
        }

        send({
            type: "intercept_wait",
            id: currentId,
            socket: socket,
            dest: dest,
            size: len,
            direction: "Outgoing (" + name + ")",
            body_hex: hexStr // Send original HEX to UI
        }, bufData);

        var actionCode = "forward";
        var finalBuf = null;
        
        recv('action_' + currentId, function (msg) {
            actionCode = msg.action;
            console.log("[FRIDA] recv action_" + currentId + " action=" + msg.action + " modHexLen=" + (msg.modified_hex ? msg.modified_hex.length : 0) + " injHexLen=" + (msg.inject_recv_hex ? msg.inject_recv_hex.length : 0));
            if (msg.modified_hex && actionCode === 'forward') {
                var mHex = msg.modified_hex.replace(/\s+/g, '');
                var mBytes = new Uint8Array(mHex.length / 2);
                for (var i = 0; i < mHex.length; i += 2) {
                    mBytes[i / 2] = parseInt(mHex.substr(i, 2), 16);
                }
                finalBuf = mBytes.buffer;
                console.log("[FRIDA] Applying MODIFIED buffer for packet " + currentId + " (" + mBytes.length + " bytes)");
            }
            // Safiye cURL Mode: queue the synthetic HTTP response for replay into recv()
            if (msg.inject_recv_hex && (typeof msg.socket_id !== "undefined")) {
                queueInjectedRecv(msg.socket_id, msg.inject_recv_hex);
            }
        }).wait();

        if (actionCode === 'drop') return "drop";
        // Whether the user kept the original or modified the buffer, the next
        // bytes received on this socket belong to this packet's response — flag
        // the socket so recv()/WSARecv() can ship the inbound data to the UI.
        captureRespBySocket[socket] = { pkgId: currentId };
        console.log("[FRIDA] Capturing response on socket=" + socket + " for packet=" + currentId);
        if (finalBuf !== null) return finalBuf;
        console.log("[FRIDA] Forwarding ORIGINAL buffer for packet " + currentId);
        return "forward"; // TRULY bit-perfect: keep original buffer
    } else {
        send({
            type: "tcp_out",
            socket: socket,
            dest: dest,
            size: len,
            direction: "Outgoing (" + name + ")"
        }, bufData);
        return "forward";
    }
}

if (connectPtr !== null) {
    Interceptor.attach(connectPtr, {
        onEnter: function (args) {
            try {
                this.socket = args[0].toInt32();
                var namePtr = args[1];
                var namelen = args[2].toInt32();
                if (!namePtr.isNull() && namelen >= 16) {
                    var destInfo = parseSockaddr(namePtr);   // IPv4 + IPv6
                    if (destInfo) {
                        socketMap[this.socket] = destInfo;
                        this.destInfo = destInfo;
                    }
                }
            } catch (e) { }
        },
        onLeave: function (retval) {
            if (this.destInfo) {
                send({
                    type: "tcp_out",
                    socket: this.socket,
                    dest: this.destInfo,
                    size: 0,
                    direction: "Connection (connect)",
                    status: retval.toInt32() === 0 ? "SUCCESS" : "PENDING/ERROR"
                });
            }
        }
    });
}

// WSAConnect: the async connect path used by browsers, .NET and curl. Same
// sockaddr layout as connect(), so it feeds socketMap the same way; sockets
// connected via ConnectEx (no plain export) still resolve lazily through
// getpeername() in resolveDest().
var WSAConnectPtr = Module.findExportByName("ws2_32.dll", "WSAConnect");
if (WSAConnectPtr !== null) {
    Interceptor.attach(WSAConnectPtr, {
        onEnter: function (args) {
            try {
                this.socket = args[0].toInt32();
                var namePtr = args[1];
                var namelen = args[2].toInt32();
                if (!namePtr.isNull() && namelen >= 16) {
                    var destInfo = parseSockaddr(namePtr);
                    if (destInfo) {
                        socketMap[this.socket] = destInfo;
                        this.destInfo = destInfo;
                    }
                }
            } catch (e) { }
        },
        onLeave: function (retval) {
            if (this.destInfo) {
                send({
                    type: "tcp_out",
                    socket: this.socket,
                    dest: this.destInfo,
                    size: 0,
                    direction: "Connection (WSAConnect)",
                    status: retval.toInt32() === 0 ? "SUCCESS" : "PENDING/ERROR"
                });
            }
        }
    });
}

// Pin replacement allocations so Frida's JS GC can't reclaim them while the
// kernel is still reading from them (especially relevant for overlapped WSASend).
var pinnedSendBuffers = [];
function pinAndAlloc(byteSource) {
    var buf = Memory.alloc(byteSource.byteLength);
    buf.writeByteArray(byteSource);
    pinnedSendBuffers.push(buf);
    // Cap the pin list so memory doesn't grow unbounded over a long session
    if (pinnedSendBuffers.length > 256) pinnedSendBuffers.shift();
    return buf;
}

function hexPreview(p, n) {
    try {
        var show = Math.min(n, 64);
        var u8 = new Uint8Array(Memory.readByteArray(p, show));
        var s = "";
        for (var i = 0; i < u8.length; i++) s += (u8[i] < 16 ? "0" : "") + u8[i].toString(16);
        return s + (n > show ? "..." : "");
    } catch (e) { return "<read err: " + e + ">"; }
}

if (sendPtr !== null) {
    Interceptor.attach(sendPtr, {
        onEnter: function (args) {
            winsockSendDepth++;
            this.droppedLen = -1;
            this.replacedLen = -1;
            try {
                var socket = args[0].toInt32();
                var bufPtr = args[1];
                var len = args[2].toInt32();
                if (len <= 0) return;

                var res = handleSend(socket, bufPtr, len, "send");
                if (res === "drop") {
                    this.droppedLen = len;
                    args[2] = ptr(0);
                    console.log("[FRIDA send] DROP socket=" + socket + " origLen=" + len);
                } else if (res !== "forward") {
                    var newLen = res.byteLength;
                    var newBuf = pinAndAlloc(res);
                    args[1] = newBuf;
                    args[2] = ptr(newLen);
                    this.replacedLen = newLen;
                    console.log("[FRIDA send] REPLACE socket=" + socket + " origLen=" + len + " newLen=" + newLen);
                    console.log("[FRIDA send] orig hex: " + hexPreview(bufPtr, len));
                    console.log("[FRIDA send] new  hex: " + hexPreview(newBuf, newLen));
                }
            } catch (e) {
                console.log("[FRIDA send] onEnter ERROR: " + e + " stack=" + (e && e.stack));
            }
        },
        onLeave: function (retval) {
            if (winsockSendDepth > 0) winsockSendDepth--;
            try {
                if (this.droppedLen !== -1) {
                    retval.replace(this.droppedLen);
                } else if (this.replacedLen !== -1) {
                    var rv = retval.toInt32();
                    console.log("[FRIDA send] return after replace: kernelRet=" + rv + " requested=" + this.replacedLen);
                    // If the kernel reports a partial send count we leave it alone — the
                    // caller's loop will re-send the rest. The semantics match real send().
                }
            } catch (e) { console.log("[FRIDA send] onLeave ERROR: " + e); }
        }
    });
}

if (WSASendPtr !== null) {
    Interceptor.attach(WSASendPtr, {
        onEnter: function (args) {
            winsockSendDepth++;
            this.dropped = false;
            this.replaced = false;
            try {
                var socket = args[0].toInt32();
                var lpBuffers = args[1];
                var dwBufferCount = args[2].toInt32();
                var lpNumberOfBytesSent = args[3];
                var lpOverlapped = args[7] ? args[7] : ptr(0);
                var offset = (Process.pointerSize === 8) ? 16 : 8;

                for (var i = 0; i < dwBufferCount; i++) {
                    var lenPtr = lpBuffers.add(i * offset);
                    var bufLength = lenPtr.readU32();
                    var bufPtrPtr = (Process.pointerSize === 8) ? lenPtr.add(8) : lenPtr.add(4);
                    var bufPtr = bufPtrPtr.readPointer();
                    if (bufLength <= 0) continue;

                    var res = handleSend(socket, bufPtr, bufLength, "WSASend");
                    if (res === "drop") {
                        this.dropped = true;
                        lenPtr.writeU32(0);
                        console.log("[FRIDA WSASend] DROP socket=" + socket + " bufIdx=" + i + " origLen=" + bufLength);
                    } else if (res !== "forward") {
                        var newLen = res.byteLength;
                        var newBuf = pinAndAlloc(res);
                        bufPtrPtr.writePointer(newBuf);
                        lenPtr.writeU32(newLen);
                        this.replaced = true;
                        console.log("[FRIDA WSASend] REPLACE socket=" + socket + " bufIdx=" + i + " origLen=" + bufLength + " newLen=" + newLen);
                        console.log("[FRIDA WSASend] orig hex: " + hexPreview(bufPtr, bufLength));
                        console.log("[FRIDA WSASend] new  hex: " + hexPreview(newBuf, newLen));
                    }
                }
            } catch (e) {
                console.log("[FRIDA WSASend] onEnter ERROR: " + e + " stack=" + (e && e.stack));
            }
        },
        onLeave: function (retval) {
            if (winsockSendDepth > 0) winsockSendDepth--;
            try {
                if (this.dropped) {
                    retval.replace(0);
                } else if (this.replaced) {
                    var rv = retval.toInt32();
                    console.log("[FRIDA WSASend] return after replace: rv=" + rv);
                }
            } catch (e) { console.log("[FRIDA WSASend] onLeave ERROR: " + e); }
        }
    });
}

// === Safiye cURL Mode: recv() injection ===
// When a synthetic HTTP response has been queued for a socket (because the user
// sent the request via cURL Forward), the next recv() on that socket will return
// our bytes instead of reading from the network.
if (recvPtr !== null) {
    Interceptor.attach(recvPtr, {
        onEnter: function (args) {
            this.injectedBuf = null;
            try {
                this.socket = args[0].toInt32();
                this.userBuf = args[1];
                this.maxLen = args[2].toInt32();
                if (this.maxLen > 0 && pendingRecvBySocket[this.socket]) {
                    var chunk = consumeInjectedRecv(this.socket, this.maxLen);
                    if (chunk !== null) {
                        this.injectedBuf = chunk;
                        // Force the kernel call to be a no-op so it returns immediately.
                        args[2] = ptr(0);
                        console.log("[FRIDA] recv inject: socket=" + this.socket + " writing " + chunk.length + " bytes (max=" + this.maxLen + ")");
                    }
                }
            } catch (e) { console.log("[FRIDA] recv onEnter error: " + e); }
        },
        onLeave: function (retval) {
            try {
                if (this.injectedBuf !== null) {
                    this.userBuf.writeByteArray(this.injectedBuf);
                    retval.replace(this.injectedBuf.length);
                    return;
                }
                var n = retval.toInt32();
                if (n <= 0) return;
                var bufData = Memory.readByteArray(this.userBuf, n);
                if (captureRespBySocket[this.socket]) {
                    emitResponseCapture(this.socket, new Uint8Array(bufData));
                    delete captureRespBySocket[this.socket];
                    console.log("[FRIDA] recv captured response: socket=" + this.socket + " bytes=" + n);
                }
                send({
                    type: "tcp_in",
                    socket: this.socket,
                    dest: resolveDest(this.socket),
                    size: n,
                    direction: "Incoming (recv)"
                }, bufData);
            } catch (e) { console.log("[FRIDA] recv onLeave error: " + e); }
        }
    });
}

if (WSARecvPtr !== null) {
    Interceptor.attach(WSARecvPtr, {
        onEnter: function (args) {
            this.injected = false;
            this.savedLengths = null;
            this.captureForPkg = null;
            try {
                this.socket = args[0].toInt32();
                this.lpBuffers = args[1];
                this.dwBufferCount = args[2].toInt32();
                this.lpNumberOfBytesRecvd = args[3];
                var lpOverlapped = args[5];

                // Stash capture context so onLeave can read what the kernel actually wrote
                if (captureRespBySocket[this.socket]) {
                    this.captureForPkg = captureRespBySocket[this.socket].pkgId;
                }

                if (!pendingRecvBySocket[this.socket]) return;

                // SKIP overlapped/async WSARecv — those use completion ports / events
                // which we cannot synthesize safely. Pretending sync completion on an
                // overlapped call is what crashes the client. Let the real call go
                // through (it will time out / fail) so the client's IO state stays sane.
                if (!lpOverlapped.isNull()) {
                    console.log("[FRIDA] WSARecv inject SKIPPED for socket=" + this.socket + " (overlapped mode, lpOverlapped=" + lpOverlapped + ")");
                    return;
                }

                // Sync WSARecv path: gather capacities, write our payload across the
                // WSABUF segments, force the kernel to read 0 bytes, then in onLeave
                // restore lengths and write lpNumberOfBytesRecvd AFTER the kernel
                // has had a chance to overwrite it.
                var capacities = [];
                var totalCap = 0;
                var offset = (Process.pointerSize === 8) ? 16 : 8;
                this.savedLengths = [];
                for (var i = 0; i < this.dwBufferCount; i++) {
                    var lenPtr = this.lpBuffers.add(i * offset);
                    var bufLen = lenPtr.readU32();
                    capacities.push(bufLen);
                    this.savedLengths.push({ ptr: lenPtr, val: bufLen });
                    totalCap += bufLen;
                }
                if (totalCap === 0) return;

                var chunk = consumeInjectedRecv(this.socket, totalCap);
                if (chunk === null) return;

                var written = 0;
                for (var j = 0; j < this.dwBufferCount && written < chunk.length; j++) {
                    var segLenPtr = this.lpBuffers.add(j * offset);
                    var segCap = capacities[j];
                    var segPtrPtr = (Process.pointerSize === 8) ? segLenPtr.add(8) : segLenPtr.add(4);
                    var segPtr = segPtrPtr.readPointer();
                    var take = Math.min(segCap, chunk.length - written);
                    if (take > 0) {
                        segPtr.writeByteArray(chunk.subarray(written, written + take));
                        written += take;
                    }
                    // Force the kernel WSARecv call to read 0 bytes into this segment
                    segLenPtr.writeU32(0);
                }
                this.injectedWritten = written;
                this.injected = true;
                console.log("[FRIDA] WSARecv inject (sync): socket=" + this.socket + " writing " + written + " bytes");
            } catch (e) { console.log("[FRIDA] WSARecv onEnter error: " + e); }
        },
        onLeave: function (retval) {
            try {
                if (this.injected) {
                    // Restore original buffer lengths so caller's view of capacity is intact
                    if (this.savedLengths) {
                        for (var k = 0; k < this.savedLengths.length; k++) {
                            this.savedLengths[k].ptr.writeU32(this.savedLengths[k].val);
                        }
                    }
                    // Write bytes-received AFTER the kernel returns (it would have
                    // clobbered any earlier write with the real (0) byte count).
                    if (!this.lpNumberOfBytesRecvd.isNull()) {
                        this.lpNumberOfBytesRecvd.writeU32(this.injectedWritten);
                    }
                    retval.replace(0);
                    return;
                }

                // Real WSARecv path — capture only on sync completion (retval==0).
                // Overlapped/IOCP calls return SOCKET_ERROR with WSA_IO_PENDING;
                // bytes aren't ready here, so we skip them.
                if (retval.toInt32() === 0) {
                    var bytesRead = 0;
                    try { bytesRead = this.lpNumberOfBytesRecvd.isNull() ? 0 : this.lpNumberOfBytesRecvd.readU32(); } catch (e) {}
                    if (bytesRead > 0) {
                        var collected = new Uint8Array(bytesRead);
                        var poff = 0;
                        var offset = (Process.pointerSize === 8) ? 16 : 8;
                        for (var bi = 0; bi < this.dwBufferCount && poff < bytesRead; bi++) {
                            var lp = this.lpBuffers.add(bi * offset);
                            var capL = lp.readU32();
                            var dataPtrPtr = (Process.pointerSize === 8) ? lp.add(8) : lp.add(4);
                            var dataPtr = dataPtrPtr.readPointer();
                            var take = Math.min(capL, bytesRead - poff);
                            if (take > 0) {
                                var slice = new Uint8Array(Memory.readByteArray(dataPtr, take));
                                collected.set(slice, poff);
                                poff += take;
                            }
                        }
                        if (this.captureForPkg !== null) {
                            emitResponseCapture(this.socket, collected);
                            delete captureRespBySocket[this.socket];
                            console.log("[FRIDA] WSARecv captured response: socket=" + this.socket + " bytes=" + bytesRead);
                        }
                        send({
                            type: "tcp_in",
                            socket: this.socket,
                            dest: resolveDest(this.socket),
                            size: bytesRead,
                            direction: "Incoming (WSARecv)"
                        }, collected.buffer);
                    }
                }
            } catch (e) { console.log("[FRIDA] WSARecv onLeave error: " + e); }
        }
    });
}

// DLL HIJACKING DETECTOR
var dllAPIs = ["LoadLibraryW", "LoadLibraryExW", "LoadLibraryA", "LoadLibraryExA"];
dllAPIs.forEach(function (api) {
    var ptr = Module.findExportByName("kernel32.dll", api);
    if (ptr) {
        Interceptor.attach(ptr, {
            onEnter: function (args) { this.dllName = (api.endsWith('W')) ? args[0].readUtf16String() : args[0].readAnsiString(); },
            onLeave: function (retval) {
                var isFailed = retval.isNull();
                send({ type: "dll_monitor", dllName: this.dllName, status: isFailed ? "NAME NOT FOUND" : "SUCCESS", api: api, isFailed: isFailed });
                // Re-install traffic/crypto hooks the instant a relevant DLL loads late,
                // so we hook the export before the app first calls it (many TLS/crypto
                // DLLs — secur32, crypt32, bcrypt — load lazily on first use).
                if (!isFailed && this.dllName) {
                    var ln = this.dllName.toLowerCase();
                    if (ln.indexOf("ssl") !== -1) { try { hookSSL(); } catch (e) {} }
                    if (ln.indexOf("secur32") !== -1 || ln.indexOf("sspicli") !== -1 || ln.indexOf("schannel") !== -1) { try { hookSChannel(); } catch (e) {} }
                    if (ln.indexOf("crypt32") !== -1 || ln.indexOf("bcrypt") !== -1 || ln.indexOf("ncrypt") !== -1 || ln.indexOf("advapi32") !== -1) { try { hookCrypto(); } catch (e) {} }
                }
            }
        });
    }
});

// CREATEFILEW
var createFileWPtr = Module.findExportByName("kernel32.dll", "CreateFileW");
if (createFileWPtr) {
    Interceptor.attach(createFileWPtr, {
        onEnter: function (args) { this.fileName = args[0].readUtf16String(); },
        onLeave: function (retval) {
            if (!this.fileName) return;
            var lower = this.fileName.toLowerCase();
            var isSensitive = (lower.endsWith(".config") || lower.endsWith(".json") || lower.endsWith(".ini") || lower.endsWith(".db") || lower.endsWith(".sqlite") || lower.endsWith(".log"));
            if (isSensitive || lower.endsWith(".dll")) {
                var isFailed = retval.toInt32() === -1;
                send({ type: (lower.endsWith(".dll") ? "dll_monitor" : "registry_file_monitor"), target: this.fileName, dllName: this.fileName, status: isFailed ? "NAME NOT FOUND" : "SUCCESS", api: "CreateFileW", isFailed: isFailed });
            }
        }
    });
}

// REGISTRY MONITOR
var hKeyMap = {
    "0x80000000": "HKCR",
    "0x80000001": "HKCU",
    "0x80000002": "HKLM",
    "0x80000003": "HKU",
    "0x80000005": "HKCC",
    "0xffffffff80000000": "HKCR",
    "0xffffffff80000001": "HKCU",
    "0xffffffff80000002": "HKLM",
    "0xffffffff80000003": "HKU",
    "0xffffffff80000005": "HKCC"
};

function getHKeyPath(hKey) {
    var keyStr = hKey.toString();
    return hKeyMap[keyStr] || "HKEY(" + keyStr + ")";
}

function hookReg(module, func, isWide) {
    var p = Module.findExportByName(module, func);
    if (!p) return;

    Interceptor.attach(p, {
        onEnter: function (args) {
            this.inHook = true;

            if (func.includes("OpenKey") || func.includes("CreateKey")) {
                this.type = "create";
                this.hKeyBase = args[0];
                try {
                    this.subKey = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                } catch (e) { this.subKey = ""; }
                
                if (func.includes("CreateKeyEx")) this.phkResult = args[7];
                else if (func.includes("OpenKeyEx")) this.phkResult = args[4];
                else this.phkResult = args[2];
            } else if (func.includes("SetValueEx")) {
                this.type = "set";
                this.hKey = args[0];
                try {
                    this.valueName = isWide ? args[1].readUtf16String() : args[1].readAnsiString();
                } catch (e) { this.valueName = ""; }
                
                var type = args[3].toInt32();
                var dataPtr = args[4];
                var dataLen = args[5].toInt32();
                this.dataStr = "[Complex Data]";
                
                try {
                    if (!dataPtr.isNull() && dataLen > 0) {
                        if (type === 1 || type === 2) this.dataStr = isWide ? dataPtr.readUtf16String() : dataPtr.readAnsiString();
                        else if (type === 4) this.dataStr = dataPtr.readU32().toString();
                    }
                } catch (e) {}
            }
        },
        onLeave: function (retval) {
            if (!this.inHook) return;
            var res = retval.toInt32();
            
            if (this.type === "create" && res === 0 && !this.phkResult.isNull()) {
                try {
                    var newHKey = this.phkResult.readPointer();
                    if (newHKey.isNull()) return;
                    var fullPath = getHKeyPath(this.hKeyBase) + "\\" + (this.subKey || "");
                    hKeyMap[newHKey.toString()] = fullPath;
                    
                    var lower = fullPath.toLowerCase();
                    if (lower.includes("software") && !lower.includes("microsoft\\windows")) {
                        send({ type: "registry_file_monitor", target: fullPath, status: "SUCCESS", api: func, isFailed: false });
                    }
                } catch (e) {}
            } else if (this.type === "set") {
                var fullPath = getHKeyPath(this.hKey) + " -> " + (this.valueName || "(Default)");
                var lower = fullPath.toLowerCase();
                if (lower.includes("software") && !lower.includes("microsoft\\windows")) {
                    send({ 
                        type: "registry_file_monitor", 
                        target: fullPath + " = " + this.dataStr, 
                        status: res === 0 ? "SUCCESS" : "ERROR", 
                        api: func, 
                        isFailed: res !== 0 
                    });
                }
            }
        }
    });
}

// Only hook KernelBase if available, otherwise fallback to advapi32
var preferredModule = Module.findExportByName("KernelBase.dll", "RegOpenKeyExW") ? "KernelBase.dll" : "advapi32.dll";

[preferredModule].forEach(function (m) {
    ["RegOpenKeyExW", "RegOpenKeyExA", "RegCreateKeyExW", "RegCreateKeyExA", "RegSetValueExW", "RegSetValueExA", "RegOpenKeyW", "RegOpenKeyA", "RegCreateKeyW", "RegCreateKeyA"].forEach(function (f) {
        hookReg(m, f, f.endsWith('W'));
    });
});

// NT LAYER REGISTRY (Deep Monitor)
var ntSetValueKey = Module.findExportByName("ntdll.dll", "NtSetValueKey");
if (ntSetValueKey) {
    Interceptor.attach(ntSetValueKey, {
        onEnter: function (args) {
            this.hKey = args[0];
            var valName = "Unknown";
            try {
                var pUnicodeStr = args[1];
                if (!pUnicodeStr.isNull()) {
                    var len = pUnicodeStr.readU16();
                    var buffer = pUnicodeStr.add(Process.pointerSize).readPointer();
                    if (!buffer.isNull() && len > 0) {
                        valName = buffer.readUtf16String(len / 2);
                    }
                }
            } catch(e) {}
            send({ type: "registry_file_monitor", target: getHKeyPath(this.hKey) + " (NT) -> " + valName, status: "CALL", api: "NtSetValueKey", isFailed: false });
        }
    });
}

// NT API (AFD_SEND)
var ntIo = Module.findExportByName("ntdll.dll", "NtDeviceIoControlFile");
if (ntIo) {
    Interceptor.attach(ntIo, {
        onEnter: function (args) {
            // Skip if this AFD send originates from a ws2_32 send/WSASend we already
            // captured one frame up the stack — otherwise every packet is duplicated.
            if (winsockSendDepth > 0) return;
            var code = args[5].toInt32();
            if (code === 0x1201F || code === 0x12023) {
                var bufInfo = args[6];
                if (!bufInfo.isNull()) {
                    var bufferArrayPtr = bufInfo.readPointer();
                    var count = bufInfo.add(Process.pointerSize).readU32();
                    for (var i = 0; i < count; i++) {
                        var bufLen = bufferArrayPtr.add(i * Process.pointerSize * 2).readU32();
                        var bufPtr = bufferArrayPtr.add(i * Process.pointerSize * 2 + Process.pointerSize).readPointer();
                        if (bufLen > 0 && !bufPtr.isNull()) {
                            send({ type: "tcp_out", socket: args[0].toInt32(), dest: "AFD.SYS (NT Layer)", size: bufLen, direction: "Outgoing (AFD_SEND)" }, Memory.readByteArray(bufPtr, bufLen));
                        }
                    }
                }
            }
        }
    });
}

// OPENSSL
var sslMods = ["libssl-3.dll", "ssleay32.dll", "libssl32.dll"];
function hookSSL() {
    sslMods.forEach(function (m) {
        var w = Module.findExportByName(m, "SSL_write");
        var r = Module.findExportByName(m, "SSL_read");
        if (w) Interceptor.attach(w, { onEnter: function (args) { var len = args[2].toInt32(); if (len > 0) send({ type: "tcp_out", socket: 0, conn: "ssl:" + args[0].toString(), dest: "OpenSSL (" + m + ")", size: len, direction: "Outgoing (SSL_write)" }, Memory.readByteArray(args[1], len)); } });
        if (r) Interceptor.attach(r, { onLeave: function (retval) { var len = retval.toInt32(); if (len > 0) send({ type: "tcp_in", socket: 0, conn: this.ssl, dest: "OpenSSL (" + m + ")", size: len, direction: "Incoming (SSL_read)" }, Memory.readByteArray(this.bufPtr, len)); }, onEnter: function (args) { this.bufPtr = args[1]; this.ssl = "ssl:" + args[0].toString(); } });
    });
}
hookSSL();
setInterval(hookSSL, 5000);

// ── CHILD PROCESS MONITOR ────────────────────────────────────────────────────
// Hooks CreateProcessW/A and ShellExecuteW/ExW to capture every child process
// the target spawns. elevated=true when the verb is "runas".

function _procTs() {
    var d = new Date();
    return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function _callerMod(retAddr) {
    try {
        var m = Process.findModuleByAddress(retAddr);
        return m ? m.name : "unknown";
    } catch (e) { return "unknown"; }
}

function _emitSpawn(api, exe, cmdline, verb, elevated, caller) {
    send({
        type:       "process_spawn",
        api:        api,
        exe:        exe  || "",
        args:       cmdline || "",
        verb:       verb || null,
        elevated:   elevated || false,
        caller_mod: caller  || "unknown",
        _ts:        _procTs()
    });
}

(function () {
    var p = Module.findExportByName("kernel32.dll", "CreateProcessW");
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                var app = args[0].isNull() ? "" : args[0].readUtf16String();
                var cmd = args[1].isNull() ? "" : args[1].readUtf16String();
                this._exe    = app || (cmd ? cmd.split(" ")[0] : "");
                this._args   = cmd;
                this._caller = _callerMod(this.returnAddress);
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0)
                _emitSpawn("CreateProcessW", this._exe, this._args, null, false, this._caller);
        }
    });
})();

(function () {
    var p = Module.findExportByName("kernel32.dll", "CreateProcessA");
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                var app = args[0].isNull() ? "" : args[0].readAnsiString();
                var cmd = args[1].isNull() ? "" : args[1].readAnsiString();
                this._exe    = app || (cmd ? cmd.split(" ")[0] : "");
                this._args   = cmd;
                this._caller = _callerMod(this.returnAddress);
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0)
                _emitSpawn("CreateProcessA", this._exe, this._args, null, false, this._caller);
        }
    });
})();

(function () {
    var p = Module.findExportByName("shell32.dll", "ShellExecuteW");
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                this._verb   = args[1].isNull() ? "" : args[1].readUtf16String();
                this._file   = args[2].isNull() ? "" : args[2].readUtf16String();
                this._params = args[3].isNull() ? "" : args[3].readUtf16String();
                this._caller = _callerMod(this.returnAddress);
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (retval.toInt32() > 32) {
                var elevated = (this._verb || "").toLowerCase() === "runas";
                _emitSpawn("ShellExecuteW", this._file, this._params, this._verb, elevated, this._caller);
            }
        }
    });
})();

(function () {
    var p = Module.findExportByName("shell32.dll", "ShellExecuteExW");
    if (!p) return;
    var PS = Process.pointerSize;
    // SHELLEXECUTEINFOW: cbSize(4)+fMask(4)+hwnd(PS) = 8+PS before lpVerb
    var OFF_VERB   = 8 + PS;
    var OFF_FILE   = 8 + PS * 2;
    var OFF_PARAMS = 8 + PS * 3;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                var info = args[0];
                if (info.isNull()) return;
                var pV = info.add(OFF_VERB).readPointer();
                var pF = info.add(OFF_FILE).readPointer();
                var pP = info.add(OFF_PARAMS).readPointer();
                this._verb   = pV.isNull() ? "" : pV.readUtf16String();
                this._file   = pF.isNull() ? "" : pF.readUtf16String();
                this._params = pP.isNull() ? "" : pP.readUtf16String();
                this._caller = _callerMod(this.returnAddress);
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (retval.toInt32() !== 0) {
                var elevated = (this._verb || "").toLowerCase() === "runas";
                _emitSpawn("ShellExecuteExW", this._file, this._params, this._verb, elevated, this._caller);
            }
        }
    });
})();

// ── WINDOWS CRYPTO / DPAPI MONITOR ────────────────────────────────────────────
// Captures application-layer plaintext BEFORE it is encrypted (and secrets AFTER
// they are decrypted) by hooking the Windows crypto stack: DPAPI (crypt32),
// CNG/BCrypt (bcrypt.dll) and legacy CryptoAPI (advapi32). This reveals data that
// never travels the wire in cleartext — passwords, tokens, keys — regardless of
// TLS. Emits "crypto_event" messages that ride the same body/body_hex pipeline as
// tcp_out. DATA_BLOB is { DWORD cbData; BYTE* pbData; }; pbData sits at offset
// Process.pointerSize because of struct alignment (4 on x86, 8 on x64).

var CRYPTPROTECT_LOCAL_MACHINE = 0x4;
var CRYPTO_MAX = 65536;                 // cap bytes shipped per event
var CRYPTO_MAX_PER_SEC = 200;           // flood guard (schannel TLS runs through BCrypt)
var _cryptoHooked = {};                 // export-pointer string -> true (dedup guard)
var _cryptoRate = { sec: 0, count: 0, dropped: 0 };

function _cryptoAllowed() {
    var now = Math.floor(Date.now() / 1000);
    if (now !== _cryptoRate.sec) {
        if (_cryptoRate.dropped > 0)
            console.log("[FRIDA crypto] rate-limited, dropped " + _cryptoRate.dropped + " events last second");
        _cryptoRate.sec = now; _cryptoRate.count = 0; _cryptoRate.dropped = 0;
    }
    if (_cryptoRate.count >= CRYPTO_MAX_PER_SEC) { _cryptoRate.dropped++; return false; }
    _cryptoRate.count++;
    return true;
}

function _readBlob(blobPtr) {
    try {
        if (!blobPtr || blobPtr.isNull()) return null;
        var cb = blobPtr.readU32();
        if (cb <= 0) return null;
        var pb = blobPtr.add(Process.pointerSize).readPointer();
        if (pb.isNull()) return null;
        return { len: cb, buf: Memory.readByteArray(pb, Math.min(cb, CRYPTO_MAX)) };
    } catch (e) { return null; }
}

function _readRaw(p, len) {
    try {
        if (!p || p.isNull() || len <= 0) return null;
        return Memory.readByteArray(p, Math.min(len, CRYPTO_MAX));
    } catch (e) { return null; }
}

function _emitCrypto(api, op, buf, len, extra) {
    if (!_cryptoAllowed()) return;
    try {
        var payload = { type: "crypto_event", api: api, op: op, size: len, _ts: _procTs() };
        if (extra) { for (var k in extra) payload[k] = extra[k]; }
        if (buf) send(payload, buf); else send(payload);
    } catch (e) { console.log("[FRIDA crypto] emit error: " + e); }
}

function _attachCryptoOnce(mod, name, callbacks) {
    var p = Module.findExportByName(mod, name);
    if (!p) return;
    var key = p.toString();
    if (_cryptoHooked[key]) return;
    try {
        Interceptor.attach(p, callbacks);
        _cryptoHooked[key] = true;
    } catch (e) { console.log("[FRIDA crypto] attach " + name + " error: " + e); }
}

function hookCrypto() {
    // DPAPI: CryptProtectData(pDataIn,szDescr,pEntropy,pRes,pPrompt,dwFlags,pDataOut)
    _attachCryptoOnce("crypt32.dll", "CryptProtectData", {
        onEnter: function (args) {
            var blob = _readBlob(args[0]);
            if (!blob) return;
            var flags = 0; try { flags = args[5].toInt32(); } catch (e) {}
            var hasEntropy = false; try { hasEntropy = !args[2].isNull(); } catch (e) {}
            _emitCrypto("CryptProtectData", "protect", blob.buf, blob.len, {
                dpapi_local_machine: (flags & CRYPTPROTECT_LOCAL_MACHINE) !== 0,
                dpapi_entropy: hasEntropy
            });
        }
    });
    // DPAPI: CryptUnprotectData(pDataIn,ppszDescr,pEntropy,pRes,pPrompt,dwFlags,pDataOut)
    _attachCryptoOnce("crypt32.dll", "CryptUnprotectData", {
        onEnter: function (args) {
            this.pDataOut = args[6];
            try { this.hasEntropy = !args[2].isNull(); } catch (e) { this.hasEntropy = false; }
        },
        onLeave: function (retval) {
            if (retval.isNull() || retval.toInt32() === 0) return;   // BOOL FALSE
            var blob = _readBlob(this.pDataOut);
            if (blob) _emitCrypto("CryptUnprotectData", "unprotect", blob.buf, blob.len, { dpapi_entropy: this.hasEntropy });
        }
    });
    // DPAPI in-memory: CryptProtectMemory(pData,cbData,dwFlags) — plaintext in place on entry
    _attachCryptoOnce("crypt32.dll", "CryptProtectMemory", {
        onEnter: function (args) {
            var len = 0; try { len = args[1].toInt32(); } catch (e) {}
            var buf = _readRaw(args[0], len);
            if (buf) _emitCrypto("CryptProtectMemory", "protect", buf, len, null);
        }
    });
    // CryptUnprotectMemory(pData,cbData,dwFlags) — plaintext in place on leave
    _attachCryptoOnce("crypt32.dll", "CryptUnprotectMemory", {
        onEnter: function (args) { this.p = args[0]; try { this.len = args[1].toInt32(); } catch (e) { this.len = 0; } },
        onLeave: function (retval) {
            if (retval.isNull() || retval.toInt32() === 0) return;
            var buf = _readRaw(this.p, this.len);
            if (buf) _emitCrypto("CryptUnprotectMemory", "unprotect", buf, this.len, null);
        }
    });

    // CNG/BCrypt: BCryptEncrypt(hKey,pbInput,cbInput,pPad,pbIV,cbIV,pbOutput,cbOutput,pcbResult,dwFlags)
    _attachCryptoOnce("bcrypt.dll", "BCryptEncrypt", {
        onEnter: function (args) {
            try { if (args[6].isNull()) return; } catch (e) { return; }   // pbOutput NULL = size query, skip
            var len = 0; try { len = args[2].toInt32(); } catch (e) {}
            if (len <= 0) return;
            var buf = _readRaw(args[1], len);       // plaintext input
            if (buf) _emitCrypto("BCryptEncrypt", "encrypt", buf, len, null);
        }
    });
    // BCryptDecrypt(...): recovered plaintext lands in pbOutput, length *pcbResult
    _attachCryptoOnce("bcrypt.dll", "BCryptDecrypt", {
        onEnter: function (args) { this.pbOutput = args[6]; this.pcbResult = args[8]; },
        onLeave: function (retval) {
            try {
                if (retval.toInt32() !== 0) return;   // NTSTATUS != STATUS_SUCCESS
                if (!this.pbOutput || this.pbOutput.isNull() || this.pcbResult.isNull()) return;
                var len = this.pcbResult.readU32();
                var buf = _readRaw(this.pbOutput, len);
                if (buf) _emitCrypto("BCryptDecrypt", "decrypt", buf, len, null);
            } catch (e) {}
        }
    });

    // Legacy CryptoAPI: CryptEncrypt(hKey,hHash,Final,dwFlags,pbData,pdwDataLen,dwBufLen)
    // pbData holds plaintext on entry; *pdwDataLen is its length.
    var encMod = Module.findExportByName("advapi32.dll", "CryptEncrypt") ? "advapi32.dll" : "crypt32.dll";
    _attachCryptoOnce(encMod, "CryptEncrypt", {
        onEnter: function (args) {
            try {
                if (args[4].isNull() || args[5].isNull()) return;    // size query
                var len = args[5].readU32();
                var buf = _readRaw(args[4], len);
                if (buf) _emitCrypto("CryptEncrypt", "encrypt", buf, len, null);
            } catch (e) {}
        }
    });
    // CryptDecrypt(hKey,hHash,Final,dwFlags,pbData,pdwDataLen): decrypted plaintext in pbData on leave
    var decMod = Module.findExportByName("advapi32.dll", "CryptDecrypt") ? "advapi32.dll" : "crypt32.dll";
    _attachCryptoOnce(decMod, "CryptDecrypt", {
        onEnter: function (args) { this.pbData = args[4]; this.pLen = args[5]; },
        onLeave: function (retval) {
            try {
                if (retval.isNull() || retval.toInt32() === 0) return;
                if (this.pbData.isNull() || this.pLen.isNull()) return;
                var len = this.pLen.readU32();
                var buf = _readRaw(this.pbData, len);
                if (buf) _emitCrypto("CryptDecrypt", "decrypt", buf, len, null);
            } catch (e) {}
        }
    });
}

hookCrypto();
// bcrypt/crypt32/advapi32 can load after startup; re-scan with a dedup guard so we
// never double-attach the same export (the guard is what makes this interval safe).
setInterval(hookCrypto, 3000);

// ── SCHANNEL (SSPI) PLAINTEXT ─────────────────────────────────────────────────
// Native Windows TLS goes through secur32/sspicli EncryptMessage/DecryptMessage —
// used by .NET SslStream, WinHTTP, LDAPS, SQL TDS and any raw SChannel consumer,
// none of which touch OpenSSL. This is the biggest remaining plaintext blind spot.
// SChannel encrypts/decrypts IN PLACE inside a SecBufferDesc: on EncryptMessage
// entry the SECBUFFER_DATA buffer holds outbound plaintext; on DecryptMessage
// leave it holds the inbound plaintext. We read that one buffer and ship it
// through the existing tcp_out/tcp_in pipeline (History tab + rule scan), so no
// backend/UI change is needed. Cert pinning is already neutralized by ssl_unpin.js.
//
// SecBufferDesc { ULONG ulVersion; ULONG cBuffers; PSecBuffer pBuffers@+8 }
// SecBuffer     { ULONG cbBuffer@0; ULONG BufferType@4; void* pvBuffer@+8 }
// sizeof(SecBuffer) = 8 + Process.pointerSize (12 x86 / 16 x64). SECBUFFER_DATA = 1.

var SECBUFFER_DATA = 1;
var SECBUFFER_ATTRMASK = 0xF0000000;   // READONLY etc. live in the high nibble

function _readSecBufferData(pDesc) {
    try {
        if (!pDesc || pDesc.isNull()) return null;
        var cBuffers = pDesc.add(4).readU32();
        if (cBuffers <= 0 || cBuffers > 16) return null;
        var pBuffers = pDesc.add(8).readPointer();
        if (pBuffers.isNull()) return null;
        var stride = 8 + Process.pointerSize;
        for (var i = 0; i < cBuffers; i++) {
            var sb = pBuffers.add(i * stride);
            var cbBuffer = sb.readU32();
            var bufType = sb.add(4).readU32() & ~SECBUFFER_ATTRMASK;
            if (bufType === SECBUFFER_DATA && cbBuffer > 0) {
                var pv = sb.add(8).readPointer();
                if (!pv.isNull())
                    return { len: cbBuffer, buf: Memory.readByteArray(pv, Math.min(cbBuffer, CRYPTO_MAX)) };
            }
        }
    } catch (e) {}
    return null;
}

// A TLS connection has socket=0 at the crypto layer, so the UI cannot pair a
// request with its response by socket there. The SSPI context handle (phContext,
// a SecHandle = {dwLower, dwUpper}) is stable for the life of one TLS connection,
// so we ship it as `conn` and the UI correlates plaintext req/resp by it.
function _ctxId(phContext) {
    try {
        if (phContext && !phContext.isNull()) {
            var lo = phContext.readPointer();
            var hi = phContext.add(Process.pointerSize).readPointer();
            return "sc:" + lo.toString() + ":" + hi.toString();
        }
    } catch (e) {}
    return "sc:0";
}

function hookSChannel() {
    ["secur32.dll", "sspicli.dll"].forEach(function (mod) {
        // EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo) — plaintext on ENTRY
        _attachCryptoOnce(mod, "EncryptMessage", {
            onEnter: function (args) {
                var d = _readSecBufferData(args[2]);
                if (d && d.buf)
                    send({ type: "tcp_out", socket: 0, conn: _ctxId(args[0]), dest: "SChannel (" + mod + ")", size: d.len, direction: "Outgoing (EncryptMessage)" }, d.buf);
            }
        });
        // DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP) — plaintext on LEAVE
        _attachCryptoOnce(mod, "DecryptMessage", {
            onEnter: function (args) { this.pMsg = args[1]; this.conn = _ctxId(args[0]); },
            onLeave: function (retval) {
                try {
                    if (retval.toInt32() !== 0) return;   // SEC_E_OK == 0 (data decrypted)
                    var d = _readSecBufferData(this.pMsg);
                    if (d && d.buf)
                        send({ type: "tcp_in", socket: 0, conn: this.conn, dest: "SChannel (" + mod + ")", size: d.len, direction: "Incoming (DecryptMessage)" }, d.buf);
                } catch (e) {}
            }
        });
    });
}

hookSChannel();
// Short interval + the LoadLibrary re-trigger above catch secur32/sspicli when .NET
// or WinHTTP loads TLS lazily after our script is already running.
setInterval(hookSChannel, 1000);

console.log("[*] Safiye Frida Script loaded.");
