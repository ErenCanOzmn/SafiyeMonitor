var sendPtr = Module.findExportByName("ws2_32.dll", "send");
var WSASendPtr = Module.findExportByName("ws2_32.dll", "WSASend");
var recvPtr = Module.findExportByName("ws2_32.dll", "recv");
var WSARecvPtr = Module.findExportByName("ws2_32.dll", "WSARecv");
var connectPtr = Module.findExportByName("ws2_32.dll", "connect");

var socketMap = {};
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

function emitResponseCapture(socketId, bytes) {
    try {
        var meta = captureRespBySocket[socketId];
        if (!meta) return;
        send({
            type: "intercept_response",
            id: meta.pkgId,
            socket: socketId,
            size: bytes.length
        }, bytes.buffer);
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
                        if (str.length > 5) {
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
    }
};

// Deserialization Magic Bytes Signatures
var MAGIC_BYTES = {
    "Java Serialization": [0xAC, 0xED],
    "Python Pickle (v2+)": [0x80, 0x02],
    "Python Pickle (v3+)": [0x80, 0x03],
    "Python Pickle (v4+)": [0x80, 0x04],
    ".NET BinaryFormatter": [0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
    "PHP Serialized Object": [0x4F, 0x3A] // "O:"
};

function checkDeserialization(data, socket, dest, direction) {
    if (!data || data.byteLength < 2) return;
    var uint8 = new Uint8Array(data);
    for (var name in MAGIC_BYTES) {
        var signature = MAGIC_BYTES[name];
        if (uint8.length < signature.length) continue;
        var match = true;
        for (var i = 0; i < signature.length; i++) {
            if (uint8[i] !== signature[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            send({
                type: "alert",
                severity: "HIGH",
                title: "Insecure Deserialization Detected!",
                message: "Detected " + name + " signature in " + direction + " traffic to " + dest,
                socket: socket
            });
            break;
        }
    }
}

function handleSend(socket, bufPtr, len, name) {
    var dest = socketMap[socket] || "Unknown";
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
                    var family = namePtr.readU16();
                    if (family === 2) {
                        var port = ((namePtr.add(2).readU8() & 0xFF) << 8) | (namePtr.add(3).readU8() & 0xFF);
                        var ip = namePtr.add(4).readU8() + "." + namePtr.add(5).readU8() + "." + namePtr.add(6).readU8() + "." + namePtr.add(7).readU8();
                        var destInfo = ip + ":" + port;
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
                // Real recv just returned. If this socket is flagged for response
                // capture (because we forwarded an intercepted send on it), grab
                // the bytes and ship them to the UI.
                if (captureRespBySocket[this.socket]) {
                    var n = retval.toInt32();
                    if (n > 0) {
                        var data = Memory.readByteArray(this.userBuf, n);
                        emitResponseCapture(this.socket, new Uint8Array(data));
                        // One-shot capture: consume the flag now so subsequent recvs
                        // (e.g. follow-up requests on a keep-alive socket) don't get
                        // spuriously attributed to this packet.
                        delete captureRespBySocket[this.socket];
                        console.log("[FRIDA] recv captured response: socket=" + this.socket + " bytes=" + n);
                    }
                }
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

                // Real WSARecv path — capture the response for the UI if this socket
                // was flagged. Note: for overlapped calls the bytes may not be ready
                // yet (lpNumberOfBytesRecvd is filled by the IOCP/event later); we
                // capture only when retval==0 AND lpNumberOfBytesRecvd > 0.
                if (this.captureForPkg !== null && retval.toInt32() === 0) {
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
                        emitResponseCapture(this.socket, collected);
                        delete captureRespBySocket[this.socket];
                        console.log("[FRIDA] WSARecv captured response: socket=" + this.socket + " bytes=" + bytesRead);
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
        if (w) Interceptor.attach(w, { onEnter: function (args) { var len = args[2].toInt32(); if (len > 0) send({ type: "tcp_out", socket: 0, dest: "OpenSSL (" + m + ")", size: len, direction: "Outgoing (SSL_write)" }, Memory.readByteArray(args[1], len)); } });
        if (r) Interceptor.attach(r, { onLeave: function (retval) { var len = retval.toInt32(); if (len > 0) send({ type: "tcp_out", socket: 0, dest: "OpenSSL (" + m + ")", size: len, direction: "Incoming (SSL_read)" }, Memory.readByteArray(this.bufPtr, len)); }, onEnter: function (args) { this.bufPtr = args[1]; } });
    });
}
hookSSL();
setInterval(hookSSL, 5000);

// SQL MONITOR — ODBC + SQLite hooks
// ─────────────────────────────────────────────────────────────────────────────
var _hookedSqlPtrs = {};

function _sqlSend(api, driver, query, status) {
    if (!query || query.length < 3) return;
    send({ type: "sql_monitor", api: api, driver: driver, query: query, status: status });
}

function _attachSql(dll, fn, encoding, sqlArgIndex) {
    var key = dll + "::" + fn;
    if (_hookedSqlPtrs[key]) return;
    var ptr = Module.findExportByName(dll, fn);
    if (!ptr) return;
    _hookedSqlPtrs[key] = true;
    Interceptor.attach(ptr, {
        onEnter: function (args) {
            try {
                var raw = args[sqlArgIndex];
                if (raw.isNull()) return;
                this._sql = (encoding === "utf16") ? raw.readUtf16String() : raw.readUtf8String();
                this._fn  = fn;
                this._dll = dll;
            } catch (_) {}
        },
        onLeave: function (retval) {
            if (this._sql) _sqlSend(this._fn, this._dll, this._sql, retval.toInt32() === 0 ? "SUCCESS" : "ERROR");
        }
    });
}

function hookODBC() {
    // odbc32.dll — covers SQL Server, MySQL, PostgreSQL, Oracle via ODBC drivers
    [
        ["odbc32.dll",    "SQLExecDirectW", "utf16", 1],
        ["odbc32.dll",    "SQLExecDirectA", "ansi",  1],
        ["odbc32.dll",    "SQLPrepareW",    "utf16", 1],
        ["odbc32.dll",    "SQLPrepareA",    "ansi",  1],
        // SQL Server Native Client variants
        ["sqlsrv32.dll",  "SQLExecDirectW", "utf16", 1],
        ["sqlsrv32.dll",  "SQLExecDirectA", "ansi",  1],
        ["SQLNCLI11.dll", "SQLExecDirectW", "utf16", 1],
        ["msodbcsql17.dll","SQLExecDirectW","utf16", 1],
        ["msodbcsql18.dll","SQLExecDirectW","utf16", 1],
    ].forEach(function (spec) { _attachSql(spec[0], spec[1], spec[2], spec[3]); });
}

function hookSQLite() {
    // sqlite3_exec(db, sql, callback, arg, errmsg) — sql at index 1
    // sqlite3_prepare_v2(db, sql, nByte, ppStmt, pzTail) — sql at index 1
    // sqlite3_prepare16_v2 — same but UTF-16
    var sqliteMods = ["sqlite3.dll", "sqlite3_x64.dll", "winsqlite3.dll"];
    sqliteMods.forEach(function (mod) {
        _attachSql(mod, "sqlite3_exec",         "ansi",  1);
        _attachSql(mod, "sqlite3_prepare_v2",   "ansi",  1);
        _attachSql(mod, "sqlite3_prepare16_v2", "utf16", 1);
    });

    // Also scan every loaded module for sqlite3 exports (handles static linking)
    Process.enumerateModules().forEach(function (mod) {
        var e = mod.enumerateExports().filter(function (x) { return x.name === "sqlite3_exec" || x.name === "sqlite3_prepare_v2"; });
        e.forEach(function (exp) {
            var key = mod.name + "::" + exp.name;
            if (_hookedSqlPtrs[key]) return;
            _hookedSqlPtrs[key] = true;
            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    try { this._sql = args[1].readUtf8String(); this._fn = exp.name; this._dll = mod.name; } catch (_) {}
                },
                onLeave: function (retval) {
                    if (this._sql) _sqlSend(this._fn, this._dll + " (static)", this._sql, retval.toInt32() === 0 ? "SUCCESS" : "ERROR");
                }
            });
        });
    });
}

// SQL MONITOR — SNI (System.Data.SqlClient / Microsoft.Data.SqlClient)
// SNIPacketSetData receives the plaintext TDS buffer BEFORE TLS encryption.
// Signature: SNIPacketSetData(SNIPacket*, BYTE* buf, DWORD len, ...)
// TDS layout: [8-byte header][ALL_HEADERS (4-byte totalLen + headers)][UTF-16LE SQL]
function hookSNI() {
    var sniDll;
    try { sniDll = Process.getModuleByName("sni.dll"); } catch(e) { return; }

    var fnAddr;
    try { fnAddr = sniDll.getExportByName("SNIPacketSetData"); } catch(e) { return; }
    if (!fnAddr) return;

    var key = "sni.dll::SNIPacketSetData";
    if (_hookedSqlPtrs[key]) return;
    _hookedSqlPtrs[key] = true;

    Interceptor.attach(fnAddr, {
        onEnter: function(args) {
            try {
                var buf = args[1];
                var len = args[2].toInt32();
                if (len < 12 || buf.isNull()) return;

                // TDS byte 0 = packet type; 0x01 = SQL Batch
                var pktType = buf.readU8();
                if (pktType !== 0x01) return;

                // ALL_HEADERS: uint32 LE total length at offset 8
                var allHdrLen = buf.add(8).readU32();
                // Sanity: ALL_HEADERS is typically 22 bytes; cap at 512
                if (allHdrLen < 4 || allHdrLen > 512) return;

                var sqlOffset = 8 + allHdrLen;
                var sqlByteLen = len - sqlOffset;
                if (sqlByteLen < 4 || sqlOffset >= len) return;

                this._sql = buf.add(sqlOffset).readUtf16String(Math.floor(sqlByteLen / 2));
            } catch(_) {}
        },
        onLeave: function(retval) {
            if (this._sql && this._sql.length >= 3) {
                _sqlSend("SNIPacketSetData", "sni.dll", this._sql.trim(), "SUCCESS");
            }
        }
    });
}

hookODBC();
hookSQLite();
hookSNI();
setInterval(function () { hookODBC(); hookSQLite(); hookSNI(); }, 5000);

console.log("[*] Safiye Frida Script loaded.");
