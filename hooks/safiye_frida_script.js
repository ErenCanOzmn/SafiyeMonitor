var sendPtr = Module.findExportByName("ws2_32.dll", "send");
var WSASendPtr = Module.findExportByName("ws2_32.dll", "WSASend");
var connectPtr = Module.findExportByName("ws2_32.dll", "connect");

var socketMap = {};
var intercept_mode = false;
var packetCounter = 0;

rpc.exports = {
    setintercept: function (state) {
        intercept_mode = state;
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
        send({
            type: "intercept_wait",
            id: currentId,
            socket: socket,
            dest: dest,
            size: len,
            direction: "Outgoing (" + name + ")"
        }, bufData);

        var actionCode = "forward";
        var newBuf = null;
        recv('action_' + currentId, function (msg, data) {
            actionCode = msg.action;
            if (data !== null && data.byteLength > 0 && actionCode === 'forward') {
                newBuf = data;
            }
        }).wait();

        if (actionCode === 'drop') return "drop";
        if (newBuf !== null) return newBuf;
        return "forward";
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

if (sendPtr !== null) {
    Interceptor.attach(sendPtr, {
        onEnter: function (args) {
            this.droppedLen = -1;
            try {
                var socket = args[0].toInt32();
                var bufPtr = args[1];
                var len = args[2].toInt32();
                if (len > 0) {
                    var res = handleSend(socket, bufPtr, len, "send");
                    if (res === "drop") {
                        this.droppedLen = len;
                        args[2] = ptr(0);
                    } else if (res !== "forward") {
                        var newBuf = Memory.alloc(res.byteLength);
                        newBuf.writeByteArray(res);
                        args[1] = newBuf;
                        args[2] = ptr(res.byteLength);
                    }
                }
            } catch (e) { }
        },
        onLeave: function (retval) {
            if (this.droppedLen !== -1) retval.replace(this.droppedLen);
        }
    });
}

if (WSASendPtr !== null) {
    Interceptor.attach(WSASendPtr, {
        onEnter: function (args) {
            this.dropped = false;
            try {
                var socket = args[0].toInt32();
                var lpBuffers = args[1];
                var dwBufferCount = args[2].toInt32();
                for (var i = 0; i < dwBufferCount; i++) {
                    var offset = (Process.pointerSize === 8) ? 16 : 8;
                    var lenPtr = lpBuffers.add(i * offset);
                    var bufLength = lenPtr.readU32();
                    var bufPtrPtr = (Process.pointerSize === 8) ? lenPtr.add(8) : lenPtr.add(4);
                    var bufPtr = bufPtrPtr.readPointer();
                    if (bufLength > 0) {
                        var res = handleSend(socket, bufPtr, bufLength, "WSASend");
                        if (res === "drop") {
                            this.dropped = true;
                            lenPtr.writeU32(0);
                        } else if (res !== "forward") {
                            var newBuf = Memory.alloc(res.byteLength);
                            newBuf.writeByteArray(res);
                            bufPtrPtr.writePointer(newBuf);
                            lenPtr.writeU32(res.byteLength);
                        }
                    }
                }
            } catch (e) { }
        },
        onLeave: function (retval) {
            if (this.dropped) retval.replace(0);
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
function hookReg(module, func, isWide, isSetValue) {
    var p = Module.findExportByName(module, func);
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) { try { this.keyName = isWide ? args[1].readUtf16String() : args[1].readAnsiString(); } catch (e) { this.keyName = "Unknown Key"; } },
        onLeave: function (retval) {
            var res = retval.toInt32();
            if (this.keyName && (res === 0 || isSetValue)) {
                var lower = this.keyName.toLowerCase();
                if (lower.includes("software") && !lower.includes("microsoft\\windows")) {
                    send({ type: "registry_file_monitor", target: this.keyName, status: res === 0 ? "SUCCESS" : "ERROR", api: func, isFailed: res !== 0 });
                }
            }
        }
    });
}

["advapi32.dll", "KernelBase.dll"].forEach(function (m) {
    ["RegOpenKeyW", "RegOpenKeyA", "RegCreateKeyW", "RegCreateKeyA", "RegSetValueExW", "RegSetValueExA"].forEach(function (f) {
        hookReg(m, f, f.endsWith('W'), f.includes('SetValue'));
    });
});

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

// NAMED PIPES REFRESH (Handled via RPC in real app, but this script covers hooks)
console.log("[*] Safiye Frida Script loaded in English mode.");
