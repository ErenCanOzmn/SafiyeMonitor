var sendPtr = Module.findExportByName("ws2_32.dll", "send");
var WSASendPtr = Module.findExportByName("ws2_32.dll", "WSASend");
var connectPtr = Module.findExportByName("ws2_32.dll", "connect");

var socketMap = {};
var intercept_mode = false;
var packetCounter = 0;

rpc.exports = {
    setintercept: function (state) {
        intercept_mode = state;
    }
};

function handleSend(socket, bufPtr, len, name) {
    var dest = socketMap[socket] || "PHP Target (Unknown)";
    var bufData = Memory.readByteArray(bufPtr, len);

    if (intercept_mode) {
        packetCounter++;
        var currentId = packetCounter;
        send({
            type: "intercept_wait",
            id: currentId,
            socket: socket,
            dest: dest,
            size: len,
            direction: "Outgoing PHP (" + name + ")"
        }, bufData);

        var actionCode = "forward";
        var newBuf = null;

        recv('action_' + currentId, function (msg, data) {
            actionCode = msg.action;
            if (data !== null && data.byteLength > 0 && actionCode === 'forward') {
                newBuf = data;
            }
        }).wait();

        if (actionCode === 'drop') {
            return "drop";
        } else if (newBuf !== null) {
            return newBuf;
        }
        return "forward";
    } else {
        send({
            type: "tcp_out",
            socket: socket,
            dest: dest,
            size: len,
            direction: "Outgoing PHP (" + name + ")"
        }, bufData);
        return "forward";
    }
}

if (connectPtr !== null) {
    Interceptor.attach(connectPtr, {
        onEnter: function (args) {
            try {
                var socket = args[0].toInt32();
                var namePtr = args[1];
                var namelen = args[2].toInt32();

                if (!namePtr.isNull() && namelen >= 16) {
                    var family = namePtr.readU16();
                    if (family === 2) { // AF_INET (IPv4)
                        var port = ((namePtr.add(2).readU8() & 0xFF) << 8) | (namePtr.add(3).readU8() & 0xFF);
                        var ip = namePtr.add(4).readU8() + "." +
                            namePtr.add(5).readU8() + "." +
                            namePtr.add(6).readU8() + "." +
                            namePtr.add(7).readU8();

                        socketMap[socket] = ip + ":" + port;
                    }
                }
            } catch (e) { }
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
