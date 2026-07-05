"""
Safiye Burp Bridge — async HTTP/HTTPS transparent proxy

Flow:
  App → [Frida redirect OR proxy setting] → Bridge (default :8081)
      → Burp Suite (:8080)                → Real Server

HTTPS: Bridge tunnels via CONNECT; Burp does TLS MITM (+ ssl_unpin.js makes app trust Burp cert).
HTTP : Bridge forwards full proxy request to Burp.

Events emitted to packet_queue as {"type": "bridge_req", ...} — appear in History tab.
"""

import asyncio
from datetime import datetime, timezone

_BUF = 65536


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]


class SafiyeBridge:
    def __init__(self, bridge_port: int, burp_host: str, burp_port: int, on_event):
        self.bridge_port = bridge_port
        self.burp_host   = burp_host
        self.burp_port   = burp_port
        self._on_event   = on_event   # callable(dict) — puts msg on packet_queue
        self._server     = None
        self.running     = False
        self._seq        = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", self.bridge_port
        )
        self.running = True
        self._log(f"Bridge listening on 127.0.0.1:{self.bridge_port} → Burp {self.burp_host}:{self.burp_port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.running = False
        self._log("Bridge stopped.")

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _log(self, text: str, is_error: bool = False):
        self._on_event({"type": "bridge_log", "text": text, "isError": is_error})

    def _emit_req(self, msg: dict):
        msg["_ts"] = _ts()
        self._on_event(msg)

    async def _open_burp(self):
        return await asyncio.wait_for(
            asyncio.open_connection(self.burp_host, self.burp_port),
            timeout=5.0
        )

    # ── Connection handler ─────────────────────────────────────────────────────

    async def _handle(self, cr: asyncio.StreamReader, cw: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(cr.read(_BUF), timeout=10.0)
        except Exception:
            try: cw.close()
            except: pass
            return

        if not head:
            try: cw.close()
            except: pass
            return

        first = head.split(b"\r\n")[0].decode("utf-8", errors="replace")
        parts = first.split()
        method = parts[0].upper() if parts else "?"

        # Open connection to Burp
        try:
            br, bw = await self._open_burp()
        except Exception as e:
            self._log(f"Cannot reach Burp {self.burp_host}:{self.burp_port} — {e}", is_error=True)
            try:
                cw.write(b"HTTP/1.1 502 Burp Unreachable\r\nContent-Length: 26\r\n\r\nBurp Suite is not running.")
                await cw.drain()
                cw.close()
            except: pass
            return

        self._seq += 1
        seq = self._seq

        if method == "CONNECT":
            # HTTPS — build tunnel: App ↔ Bridge ↔ Burp (Burp handles TLS MITM)
            target = parts[1] if len(parts) > 1 else "?"
            self._emit_req({
                "type":      "bridge_req",
                "method":    "CONNECT",
                "direction": "Outgoing (Bridge→Burp CONNECT)",
                "dest":      target,
                "size":      len(head),
                "body":      head.decode("utf-8", errors="replace"),
                "body_hex":  head.hex().upper(),
                "proto":     "HTTPS",
                "req_id":    seq,
            })
            await self._do_connect(cr, cw, br, bw, head)
        else:
            # Plain HTTP proxy request
            host = "?"
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    host = line[5:].strip().decode("utf-8", errors="replace")
                    break
            # Extract path from first request line for the log
            url = parts[1] if len(parts) > 1 else "?"
            self._emit_req({
                "type":      "bridge_req",
                "method":    method,
                "direction": "Outgoing (Bridge→Burp)",
                "dest":      host,
                "url":       url,
                "size":      len(head),
                "body":      head.decode("utf-8", errors="replace"),
                "body_hex":  head.hex().upper(),
                "proto":     "HTTP",
                "req_id":    seq,
            })
            await self._do_http(cr, cw, br, bw, head)

    async def _do_connect(self, cr, cw, br, bw, head):
        # Forward CONNECT to Burp, relay its 200 response, then tunnel
        bw.write(head)
        await bw.drain()
        try:
            resp = await asyncio.wait_for(br.read(_BUF), timeout=10.0)
        except Exception:
            try: cw.close(); bw.close()
            except: pass
            return
        try:
            cw.write(resp)
            await cw.drain()
        except:
            try: bw.close()
            except: pass
            return
        if b"200" not in resp[:32]:
            try: cw.close(); bw.close()
            except: pass
            return
        await _pipe_both(cr, cw, br, bw)

    async def _do_http(self, cr, cw, br, bw, head):
        # Forward request + bidirectional tunnel for response (and keep-alive)
        bw.write(head)
        await bw.drain()
        await _pipe_both(cr, cw, br, bw)


async def _pipe_both(cr, cw, br, bw):
    """Bidirectional transparent pipe until either side closes."""
    async def _one(r, w):
        try:
            while True:
                data = await r.read(_BUF)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except Exception:
            pass
        finally:
            try: w.close()
            except: pass

    await asyncio.gather(_one(cr, bw), _one(br, cw), return_exceptions=True)
