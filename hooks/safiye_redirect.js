// ============================================================
// safiye_redirect.js  —  HTTP/HTTPS Proxy Redirect
// Routes app traffic through Safiye Bridge → Burp Suite
//
// Usage in Safiye (3 scripts):
//   Script 1: hooks\safiye_frida_script.js
//   Script 2: hooks\safiye_ssl_unpin.js
//   Script 3: hooks\safiye_redirect.js        ← this file
//
// Then: Start Bridge in Safiye UI (sidebar), open Burp on 8080.
//
// Strategies (all active simultaneously):
//   1. WinHTTP  — WinHttpOpen proxy override     (most thick-client apps)
//   2. WinInet  — InternetOpenW proxy override   (legacy apps, IE-based)
//   3. Python   — getenv + GetEnvironmentVariableW injection
//                 (requests / httpx / aiohttp / urllib3)
//   4. curl     — CURLOPT_PROXY injection via curl_easy_setopt
// ============================================================

"use strict";

var BRIDGE = "127.0.0.1:8081";       // Safiye Bridge
var BRIDGE_HTTP = "http://" + BRIDGE; // for env vars (requests/httpx expect scheme)

function _log(msg) {
    send({ type: "console_output", text: "[REDIRECT] " + msg + "\n" });
}

// ── 1. WinHTTP — force proxy on every session ────────────────────────────────
// WinHttpOpen(agent, dwAccessType, pwszProxyName, pwszProxyBypass, dwFlags)
// We set dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY (3) and inject the
// bridge address. WinHTTP then sends all requests as proxy requests to the bridge.
//
// Apps using WinHTTP: most modern Windows thick-client apps, .NET HttpClient
// on older Windows, games with WinHTTP backend, Office 365 clients, etc.

(function () {
    var p = Module.findExportByName("winhttp.dll", "WinHttpOpen");
    if (!p) return;

    var _WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;
    var _proxyName   = Memory.allocUtf16String(BRIDGE);
    var _proxyBypass = Memory.allocUtf16String("<local>");

    Interceptor.attach(p, {
        onEnter: function (args) {
            args[1] = ptr(_WINHTTP_ACCESS_TYPE_NAMED_PROXY);
            args[2] = _proxyName;
            args[3] = _proxyBypass;
        }
    });
    _log("WinHTTP proxy → " + BRIDGE);
})();

// ── 2. WinInet — same for older apps (IE-based, WINHTTP wrapper users) ───────
// InternetOpenW(agent, dwAccessType, pwszProxy, pwszProxyBypass, dwFlags)

(function () {
    var p = Module.findExportByName("wininet.dll", "InternetOpenW");
    if (!p) return;

    var _INTERNET_OPEN_TYPE_PROXY = 3;
    var _proxyName   = Memory.allocUtf16String(BRIDGE);
    var _proxyBypass = Memory.allocUtf16String("<local>");

    Interceptor.attach(p, {
        onEnter: function (args) {
            args[1] = ptr(_INTERNET_OPEN_TYPE_PROXY);
            args[2] = _proxyName;
            args[3] = _proxyBypass;
        }
    });
    _log("WinInet proxy → " + BRIDGE);
})();

// ── 3a. getenv (msvcrt / ucrtbase) — for Python and other C-runtime apps ─────
// Python requests/httpx/aiohttp check HTTP_PROXY, HTTPS_PROXY, ALL_PROXY.
// Hooking getenv intercepts these lookups and returns our bridge address.
// Also disables PYTHONHTTPSVERIFY so Python's ssl module doesn't reject Burp cert.
// Note: ssl_unpin.js already hooks OpenSSL — this is the fallback for Python's ssl.

var _envValA = Memory.allocUtf8String(BRIDGE_HTTP);
var _verifyOff = Memory.allocUtf8String("0");

function _hookGetenvA(mod) {
    var p = Module.findExportByName(mod, "getenv");
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try { this._n = Memory.readUtf8String(args[0]).toUpperCase(); } catch (e) {}
        },
        onLeave: function (retval) {
            var n = this._n;
            if (!n) return;
            if (n === "HTTP_PROXY" || n === "HTTPS_PROXY" || n === "ALL_PROXY") {
                retval.replace(_envValA);
            } else if (n === "PYTHONHTTPSVERIFY") {
                retval.replace(_verifyOff);
            }
        }
    });
    _log("getenv hooked in " + mod);
}

["ucrtbase.dll", "msvcrt.dll"].forEach(function (m) {
    try { _hookGetenvA(m); } catch (e) {}
});

// ── 3b. GetEnvironmentVariableW — Windows-level env var (Python os.environ) ──
// Python also uses this Win32 API for os.environ reads, especially on startup.

(function () {
    var p = Module.findExportByName("kernel32.dll", "GetEnvironmentVariableW");
    if (!p) return;

    Interceptor.attach(p, {
        onEnter: function (args) {
            try {
                this._n   = Memory.readUtf16String(args[0]).toUpperCase();
                this._buf = args[1];
                this._cap = args[2].toInt32(); // buffer capacity in WCHARs
            } catch (e) {}
        },
        onLeave: function (retval) {
            var n = this._n;
            if (!n) return;

            var val = null;
            if (n === "HTTP_PROXY" || n === "HTTPS_PROXY" || n === "ALL_PROXY") {
                val = BRIDGE_HTTP;
            } else if (n === "PYTHONHTTPSVERIFY") {
                val = "0";
            }

            if (!val) return;
            if (!this._buf || this._buf.isNull()) return;
            if (this._cap <= val.length) return; // buffer too small — don't overflow

            // Write UTF-16LE string into the caller's buffer
            for (var i = 0; i < val.length; i++) {
                this._buf.add(i * 2).writeU16(val.charCodeAt(i));
            }
            this._buf.add(val.length * 2).writeU16(0); // null terminator
            retval.replace(ptr(val.length));
        }
    });
    _log("GetEnvironmentVariableW hooked (kernel32)");
})();

// ── 4. libcurl — CURLOPT_PROXY injection ─────────────────────────────────────
// Apps using libcurl (curl.dll / libcurl.dll) can be redirected by hooking
// curl_easy_setopt and injecting CURLOPT_PROXY + CURLOPT_SSL_VERIFYPEER=0.
// Also hook curl_easy_perform to ensure options are set before each request.

(function () {
    var _curlLibs = ["libcurl.dll", "libcurl-4.dll", "curl.dll", "libcurl-x64.dll"];
    var _CURLOPT_PROXY         = 10004;
    var _CURLOPT_SSL_VERIFYPEER = 64;
    var _CURLOPT_SSL_VERIFYHOST = 81;
    var _CURLOPT_PROXYTYPE     = 101; // CURLPROXY_HTTP = 0

    var _proxyVal = Memory.allocUtf8String(BRIDGE);
    var _setoptFn = null;

    function _hookCurl(mod) {
        var pSetopt   = Module.findExportByName(mod, "curl_easy_setopt");
        var pPerform  = Module.findExportByName(mod, "curl_easy_perform");
        if (!pSetopt || !pPerform) return;

        if (!_setoptFn)
            _setoptFn = new NativeFunction(pSetopt, 'int', ['pointer', 'int', 'pointer']);

        Interceptor.attach(pPerform, {
            onEnter: function (args) {
                var easy = args[0];
                try {
                    _setoptFn(easy, _CURLOPT_PROXY,          _proxyVal);
                    _setoptFn(easy, _CURLOPT_SSL_VERIFYPEER, ptr(0));
                    _setoptFn(easy, _CURLOPT_SSL_VERIFYHOST, ptr(0));
                } catch (e) {}
            }
        });
        _log("curl_easy_perform hooked in " + mod + " → proxy " + BRIDGE);
    }

    _curlLibs.forEach(function (m) { try { _hookCurl(m); } catch (e) {} });
    setInterval(function () {
        _curlLibs.forEach(function (m) { try { _hookCurl(m); } catch (e) {} });
    }, 5000);
})();

_log("Redirect script loaded. Bridge: " + BRIDGE);
