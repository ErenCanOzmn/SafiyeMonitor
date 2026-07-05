# Writing Frida Scripts for Safiye

Safiye loads one or more Frida scripts into the target process at spawn time. Each script is a standard Frida JavaScript agent running inside the process. This document explains how to write scripts that integrate cleanly with Safiye's UI and message pipeline.


## How Safiye loads your script

When you click Start Spawn, Safiye reads each script file you listed, creates a separate Frida script object per file, and loads them all into the same process session. The first script in the list is treated as the primary script and is the only one that may export RPC functions. All scripts share a single message callback, so any script can send data to the UI using the `send()` function.


## Sending data to the UI

Use the built-in Frida `send(payload, data)` function. The payload must be a plain object with a `type` field. Safiye routes messages by type.

```javascript
send({
    type: "tcp_out",
    socket: 0,
    dest: "api.example.com:443",
    size: body.length,
    direction: "Outgoing (MyHook)"
}, body);
```

The optional second argument is a raw `ArrayBuffer` or `NativePointer`-derived byte array. Safiye attaches it to the message as `body` (UTF-8 text) and `body_hex` (uppercase hex string), which the History tab displays in its detail panel.


## Message types Safiye understands

**tcp_out** and **tcp_in**
Appear as rows in the History tab. Required fields: `type`, `socket`, `dest`, `size`, `direction`. Attach raw bytes as the second argument to `send()` if you want the detail panel to show content.

**dll_monitor**
Appears in the DLL & Modules tab. Required fields: `type`, `api`, `status`, `dllName`. Optional: `isFailed` (boolean).

**registry_file_monitor**
Appears in the Registry tab when `api` contains "Reg", otherwise in a file events buffer. Required fields: `type`, `api`, `status`, `target`. Optional: `isFailed`.

**console_output**
Appends text to the System Output Log panel at the bottom of the UI. Required fields: `type`, `text`. Text is appended as-is; include a newline if you want line separation.

**bridge_log**
Appends a line to the Bridge Log panel inside the Bridge tab. Required fields: `type`, `text`. Optional: `isError` (boolean, renders the line in red).

**alert**
Triggers an immediate vulnerability report entry. Required fields: `type`, `title`, `message`, `socket`.

Any message type not in this list is still delivered to the browser over WebSocket; the UI silently ignores unknown types unless you add a handler for them in `app.js`.


## Minimal script template

```javascript
"use strict";

// Replace this with the function you want to hook.
var targetPtr = Module.findExportByName("example.dll", "ExampleFunction");

if (targetPtr) {
    Interceptor.attach(targetPtr, {
        onEnter: function (args) {
            // args[0], args[1], ... are NativePointer objects.
            // Read arguments here and store on `this` to use in onLeave.
            this.firstArg = args[0].toInt32();
        },
        onLeave: function (retval) {
            var body = Memory.allocUtf8String("captured something");
            send({
                type: "tcp_out",
                socket: 0,
                dest: "ExampleFunction",
                size: 16,
                direction: "Outgoing (ExampleFunction)"
            });
        }
    });
}
```


## Reading memory safely

Always wrap memory reads in try/catch. If the pointer is invalid or the process frees the buffer before your hook reads it, Frida throws a memory access error that will crash the script.

```javascript
function safeReadUtf8(ptr, maxLen) {
    try {
        if (!ptr || ptr.isNull()) return "";
        return Memory.readUtf8String(ptr, maxLen || 512) || "";
    } catch (e) {
        return "";
    }
}
```


## Hooking functions that load after startup

Some DLLs are loaded at runtime via `LoadLibrary`. Use a polling interval to wait for the module to appear, then attach your hooks.

```javascript
var _hooked = false;

function tryHook() {
    if (_hooked) return;
    var p = Module.findExportByName("lateDll.dll", "TargetFunction");
    if (!p) return;
    Interceptor.attach(p, { onEnter: function (args) { /* ... */ } });
    _hooked = true;
}

tryHook();
setInterval(tryHook, 2000);
```


## RPC exports (primary script only)

If your script is the first one in the list, you can export functions that the Safiye backend can call synchronously. Safiye itself uses this for `setintercept`, `dumpstrings`, and `repeatersend`. You can add your own exports alongside them or create a separate primary script that re-exports them.

```javascript
rpc.exports = {
    ping: function () {
        return "pong";
    },
    setconfig: function (value) {
        // Update hook behaviour at runtime.
    }
};
```

Call an RPC export from the Python backend with:

```python
result = state.frida_script.exports_sync.ping()
```


## Compatibility with Frida 16 and 17

Frida 16.x renamed several APIs. The main script shipped with Safiye includes a compatibility shim at the top. If you target both versions, copy the shim into your script:

```javascript
if (typeof Interceptor.flush === "undefined") {
    Interceptor.flush = function () {};
}
```

Check the Frida changelog if you use `Process.enumerateModules()`, `Module.enumerateExports()`, or `Stalker` — these had signature changes between major versions.


## Tips

- Keep each script focused on one concern. Use the multi-script feature to compose independent hooks rather than growing one large file.
- Use `send()` sparingly in tight loops. Every call crosses the process boundary and serializes through a queue. Batch data or rate-limit if you are hooking a high-frequency function.
- Name your hook with a recognizable `direction` string. It appears verbatim in the History tab direction column and makes filtering easier.
- Test the script standalone with `frida -l yourscript.js -f target.exe` before loading it through Safiye to isolate syntax errors from integration issues.
