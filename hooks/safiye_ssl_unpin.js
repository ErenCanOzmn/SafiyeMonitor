// ============================================================
// safiye_ssl_unpin.js  —  SSL/TLS Certificate Pinning Bypass
// Safiye Monitor | load as 2nd script alongside safiye_frida_script.js
//
// Covers:
//   1. CryptoAPI / SChannel  (crypt32.dll)   — WinHTTP, WinInet, .NET, LDAPS
//   2. WinHTTP               (winhttp.dll)   — HTTPS bypass + plaintext capture
//   3. WinInet               (wininet.dll)   — HTTPS bypass + plaintext capture
//   4. OpenSSL / BoringSSL   (libssl*.dll)   — Electron, games, custom clients
//
// Workflow:
//   Option A (proxy MITM):
//     Run Burp/mitmproxy, set system proxy. This script makes the app trust
//     any cert, so Burp's self-signed cert is accepted. Safiye captures
//     raw traffic; Burp shows decrypted HTTP.
//
//   Option B (no proxy):
//     WinHTTP/WinInet hooks below capture plaintext directly in Safiye
//     History tab, tagged as "WinHTTP (HTTPS)" or "WinInet (HTTPS)".
//     OpenSSL plaintext capture is already handled by safiye_frida_script.js.
//
// Custom pinning (hardcoded cert hash/pubkey):
//   If the app still rejects after this script, it has application-level
//   pinning. Reverse the binary to find the comparison function and hook it
//   (see commented section at the bottom).
// ============================================================

"use strict";

function _log(msg) {
    send({ type: "console_output", text: "[SSL-UNPIN] " + msg + "\n" });
}

// ── 1. CryptoAPI — CertVerifyCertificateChainPolicy ──────────────────────────
//
// The single most effective hook on Windows. Called by SChannel (and therefore
// WinHTTP, WinInet, .NET HttpClient, LDAPS) to validate the cert chain policy.
//
// Structure: CERT_CHAIN_POLICY_STATUS
//   offset 0 : cbSize  (DWORD)
//   offset 4 : dwError (DWORD)  ← set this to 0 = CERT_E_OK
//   offset 8 : lChainIndex
//   offset 12: lElementIndex
//
// Return value is BOOL; leaving it TRUE and zeroing dwError = full bypass.

(function () {
    var p = Module.findExportByName("crypt32.dll", "CertVerifyCertificateChainPolicy");
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) { this.pStatus = args[3]; },
        onLeave: function (retval) {
            try {
                if (!this.pStatus.isNull())
                    this.pStatus.add(4).writeU32(0); // dwError = 0
            } catch (e) {}
        }
    });
    _log("hooked CertVerifyCertificateChainPolicy — SChannel/WinHTTP/.NET bypass active");
})();

// ── 2. CryptoAPI — CertVerifyRevocation ──────────────────────────────────────
// Some apps explicitly check revocation status. Return TRUE (no revocation).

(function () {
    var p = Module.findExportByName("crypt32.dll", "CertVerifyRevocation");
    if (!p) return;
    Interceptor.replace(p, new NativeCallback(
        function (dwEncodingType, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, pRevStatus) {
            // Write CRYPT_E_NO_REVOCATION_CHECK to pRevStatus.dwError so the
            // caller knows we couldn't check (not that it's revoked).
            try {
                if (!pRevStatus.isNull()) pRevStatus.add(4).writeU32(0x80092012);
            } catch (e) {}
            return 1; // TRUE = "processed, check pRevStatus for details"
        },
        'int', ['uint32','uint32','uint32','pointer','uint32','pointer','pointer']
    ));
    _log("hooked CertVerifyRevocation");
})();

// ── 3. WinHTTP — SSL bypass + plaintext traffic capture ──────────────────────
//
// WinHttpSendRequest: inject WINHTTP_OPTION_SECURITY_FLAGS (31) = 0x3300 to
// disable hostname, expiry, and CA-chain errors before the TLS handshake.
//
// WinHttpReadData / WinHttpWriteData: capture decrypted body bytes and emit
// them as tcp_in / tcp_out so they appear in Safiye's History tab.

(function () {
    var pSetOpt  = Module.findExportByName("winhttp.dll", "WinHttpSetOption");
    var pSend    = Module.findExportByName("winhttp.dll", "WinHttpSendRequest");
    var pRead    = Module.findExportByName("winhttp.dll", "WinHttpReadData");
    var pWrite   = Module.findExportByName("winhttp.dll", "WinHttpWriteData");

    if (!pSetOpt) return;
    var _setOpt = new NativeFunction(pSetOpt, 'int', ['pointer','uint32','pointer','uint32']);

    // WinHttpSendRequest(hReq, headers, hLen, body, bodyLen, totalLen, ctx)
    if (pSend) {
        Interceptor.attach(pSend, {
            onEnter: function (args) {
                try {
                    // Inject security flags to skip cert errors
                    var buf = Memory.alloc(4);
                    buf.writeU32(0x3300); // SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
                    _setOpt(args[0], 31, buf, 4);
                } catch (e) {}
                try {
                    // Capture inline body (optional data)
                    var bodyLen = args[4].toInt32();
                    if (bodyLen > 0 && !args[3].isNull())
                        send({ type: "tcp_out", socket: 0,
                               dest: "WinHTTP (HTTPS)", size: bodyLen,
                               direction: "Outgoing (WinHttpSendRequest)" },
                             Memory.readByteArray(args[3], bodyLen));
                } catch (e) {}
            }
        });
    }

    // WinHttpWriteData(hReq, buffer, bytesToWrite, pBytesWritten)
    if (pWrite) {
        Interceptor.attach(pWrite, {
            onEnter: function (args) {
                try {
                    var n = args[2].toInt32();
                    if (n > 0)
                        send({ type: "tcp_out", socket: 0,
                               dest: "WinHTTP (HTTPS)", size: n,
                               direction: "Outgoing (WinHttpWriteData)" },
                             Memory.readByteArray(args[1], n));
                } catch (e) {}
            }
        });
    }

    // WinHttpReadData(hReq, buffer, bytesToRead, pBytesRead)
    if (pRead) {
        Interceptor.attach(pRead, {
            onEnter: function (args) {
                this.buf   = args[1];
                this.pRead = args[3];
            },
            onLeave: function (retval) {
                try {
                    if (!retval.toInt32() || this.pRead.isNull()) return;
                    var n = this.pRead.readU32();
                    if (n > 0)
                        send({ type: "tcp_in", socket: 0,
                               dest: "WinHTTP (HTTPS)", size: n,
                               direction: "Incoming (WinHttpReadData)" },
                             Memory.readByteArray(this.buf, n));
                } catch (e) {}
            }
        });
    }

    _log("hooked WinHTTP (SSL bypass + plaintext capture)");
})();

// ── 4. WinInet — SSL bypass + plaintext traffic capture ──────────────────────
//
// Same approach as WinHTTP. InternetSetOptionW option 31 = INTERNET_OPTION_SECURITY_FLAGS.
// HttpSendRequestW for outgoing body, InternetReadFile for incoming response.

(function () {
    var pSetOpt  = Module.findExportByName("wininet.dll", "InternetSetOptionW");
    var pSend    = Module.findExportByName("wininet.dll", "HttpSendRequestW");
    var pRead    = Module.findExportByName("wininet.dll", "InternetReadFile");

    if (!pSetOpt) return;
    var _setOpt = new NativeFunction(pSetOpt, 'int', ['pointer','uint32','pointer','uint32']);

    // HttpSendRequestW(hReq, headers, hLen, body, bodyLen)
    if (pSend) {
        Interceptor.attach(pSend, {
            onEnter: function (args) {
                try {
                    var buf = Memory.alloc(4);
                    buf.writeU32(0x3300);
                    _setOpt(args[0], 31, buf, 4);
                } catch (e) {}
                try {
                    var bodyLen = args[4].toInt32();
                    if (bodyLen > 0 && !args[3].isNull())
                        send({ type: "tcp_out", socket: 0,
                               dest: "WinInet (HTTPS)", size: bodyLen,
                               direction: "Outgoing (HttpSendRequestW)" },
                             Memory.readByteArray(args[3], bodyLen));
                } catch (e) {}
            }
        });
    }

    // InternetReadFile(hFile, buffer, bytesToRead, pBytesRead)
    if (pRead) {
        Interceptor.attach(pRead, {
            onEnter: function (args) {
                this.buf   = args[1];
                this.pRead = args[3];
            },
            onLeave: function (retval) {
                try {
                    if (!retval.toInt32() || this.pRead.isNull()) return;
                    var n = this.pRead.readU32();
                    if (n > 0)
                        send({ type: "tcp_in", socket: 0,
                               dest: "WinInet (HTTPS)", size: n,
                               direction: "Incoming (InternetReadFile)" },
                             Memory.readByteArray(this.buf, n));
                } catch (e) {}
            }
        });
    }

    _log("hooked WinInet (SSL bypass + plaintext capture)");
})();

// ── 5. OpenSSL / BoringSSL — verification bypass ─────────────────────────────
//
// For apps that bundle their own SSL library (Electron, Python apps, games,
// custom clients). Traffic capture (SSL_write / SSL_read) is already handled
// by safiye_frida_script.js — here we only bypass certificate verification.
//
// SSL_CTX_set_verify / SSL_set_verify : set mode = SSL_VERIFY_NONE (0)
// SSL_get_verify_result               : return 0 = X509_V_OK (always valid)
// X509_verify_cert                    : return 1 = success (skip chain build)

var _SSL_LIBS = [
    "libssl-3.dll", "libssl-3-x64.dll",
    "ssleay32.dll", "libssl32.dll", "libssl.dll", "ssl.dll",
    "boringssl.dll"
];

function _hookOpenSSL(mod) {
    var hit = false;

    var p1 = Module.findExportByName(mod, "SSL_CTX_set_verify");
    if (p1) {
        Interceptor.attach(p1, {
            onEnter: function (args) { args[1] = ptr(0); args[2] = ptr(0); }
        });
        hit = true;
    }

    var p2 = Module.findExportByName(mod, "SSL_set_verify");
    if (p2) {
        Interceptor.attach(p2, {
            onEnter: function (args) { args[1] = ptr(0); args[2] = ptr(0); }
        });
    }

    var p3 = Module.findExportByName(mod, "SSL_get_verify_result");
    if (p3) {
        Interceptor.replace(p3, new NativeCallback(
            function () { return 0; }, 'long', ['pointer']
        ));
        hit = true;
    }

    var p4 = Module.findExportByName(mod, "X509_verify_cert");
    if (p4) {
        Interceptor.replace(p4, new NativeCallback(
            function () { return 1; }, 'int', ['pointer']
        ));
        hit = true;
    }

    if (hit) _log("hooked OpenSSL/BoringSSL in " + mod);
}

_SSL_LIBS.forEach(function (m) { try { _hookOpenSSL(m); } catch (e) {} });

// Re-run every 5 seconds to catch DLLs loaded after startup
setInterval(function () {
    _SSL_LIBS.forEach(function (m) { try { _hookOpenSSL(m); } catch (e) {} });
}, 5000);

// ── 6. Application-level / Custom Pinning (manual) ───────────────────────────
//
// If the app still rejects connections after this script, it has hardcoded
// certificate hashes or public keys in application code. Steps to bypass:
//
//   1. In Safiye's Strings tab: search for "sha256/" or base64-looking 44-char
//      strings — these are often pinned public key hashes (HPKP style).
//
//   2. Attach a debugger or use Frida's Stalker to trace execution around the
//      TLS handshake and find where the custom comparison occurs.
//
//   3. Hook the comparison. Common patterns:
//
//      Example A — memcmp-based pin check:
//
//        var _mc = Module.findExportByName(null, "memcmp");
//        if (_mc) {
//            Interceptor.attach(_mc, {
//                onLeave: function(retval) {
//                    // If comparing exactly 32 bytes (SHA-256) return equal
//                    if (this._size === 32) retval.replace(0);
//                }
//            });
//            // Store size from onEnter: this._size = args[2].toInt32();
//        }
//
//      Example B — return value patch on a custom verify function:
//
//        var _customVerify = <address from reverse engineering>;
//        Interceptor.replace(ptr(_customVerify), new NativeCallback(
//            function() { return 1; }, 'int', []
//        ));
//
// ── .NET / Java thick clients ─────────────────────────────────────────────────
//
//   .NET HttpClient / HttpWebRequest:
//     CertVerifyCertificateChainPolicy (hook 1 above) covers most cases.
//     If not, the app sets ServicePointManager.ServerCertificateValidationCallback
//     to a custom delegate — requires CLR introspection or a .NET-specific
//     Frida module to override the managed callback.
//
//   Java (Swing/JavaFX apps):
//     The JVM uses its own TrustManager. Bypass requires hooking
//     javax.net.ssl.X509TrustManager.checkServerTrusted via JNI exports or
//     using frida-java-bridge if available.

_log("SSL/TLS unpin script loaded and active.");
