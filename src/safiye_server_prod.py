import asyncio
import threading
import queue
import json
import logging
import os
import frida
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pydantic import BaseModel
from typing import Optional
from contextlib import asynccontextmanager

# [GOLDEN RULE] Configure explicit logging to both file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("safiye_debug.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SafiyeServer")

# Global state
class State:
    frida_session = None
    frida_script = None
    frida_device = None
    on_device_output_cb = None
    intercept_mode = False
    connected_clients = set()
    packet_queue = queue.Queue()
    is_hooking = False

state = State()

async def broadcast_message(message: dict):
    """Send JSON message to all connected real-time clients."""
    disconnected = set()
    # DEBUG: Log outgoing critical messages
    if message.get("type") in ["memory_dump", "static_strings", "status"]:
        logger.info(f"[OUTGOING WS] Type: {message.get('type')}, Data Length: {len(message.get('data', [])) if isinstance(message.get('data'), list) else 'N/A'}")
    
    for client in state.connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.add(client)
    for c in disconnected:
        state.connected_clients.remove(c)

async def queue_processor():
    """Async task to pull from thread-safe queue and broadcast to WebSockets."""
    while True:
        try:
            while not state.packet_queue.empty():
                item = state.packet_queue.get_nowait()
                await broadcast_message(item)
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Queue processor error: {e}")
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start the queue processor
    asyncio.create_task(queue_processor())
    yield
    # Shutdown
    pass

app = FastAPI(title="Safiye Web UI", lifespan=lifespan)

# Mount static files and templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

class HookRequest(BaseModel):
    target_exe: str
    target_script: str
    target_args: Optional[str] = ""

def frida_on_message(message, data):
    """Callback from Frida JavaScript."""
    if message.get("type") == "send":
        payload = message.get("payload")
        if data:
            payload["body_hex"] = data.hex().upper()
            payload["body"] = data.decode("utf-8", errors="replace")
        state.packet_queue.put(payload)
    elif message.get("type") == "error":
        logger.error(f"[FRIDA ERROR] {message}")
        state.packet_queue.put({"type": "error", "message": str(message)})

def frida_worker_thread(target_exe: str, target_script: str, args: str):
    try:
        device = frida.get_local_device()
        with open(target_script, "r", encoding="utf-8", errors="ignore") as f:
            js_code = f.read()
        spawn_args = [target_exe]
        if args: spawn_args.extend(args.split())
        pid = device.spawn(spawn_args)
        session = device.attach(pid)
        script = session.create_script(js_code)
        script.on("message", frida_on_message)
        script.load()
        state.frida_session = session
        state.frida_script = script
        state.is_hooking = True
        device.resume(pid)
        state.packet_queue.put({"type": "status", "message": "Hook Active!"})
    except Exception as e:
        logger.exception("Frida spawn error")
        state.packet_queue.put({"type": "status", "message": f"Error: {e}"})
        state.is_hooking = False

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/status")
async def get_status():
    return {"is_hooking": state.is_hooking}

@app.get("/api/browse_file")
async def browse_file():
    import tkinter as tk
    from tkinter import filedialog
    def open_dialog():
        root = tk.Tk(); root.withdraw(); root.attributes("-topmost", True)
        path = filedialog.askopenfilename()
        root.destroy(); return path
    p = await asyncio.to_thread(open_dialog)
    return {"path": p or ""}

@app.post("/api/start_hook")
async def start_hook(req: HookRequest):
    if state.is_hooking: return {"status": "error"}
    threading.Thread(target=frida_worker_thread, args=(req.target_exe, req.target_script, req.target_args), daemon=True).start()
    return {"status": "ok"}

@app.post("/api/stop_hook")
async def stop_hook():
    try:
        if state.frida_script: state.frida_script.unload()
        if state.frida_session: state.frida_session.detach()
    except: pass
    state.is_hooking = False
    state.frida_script = None
    await broadcast_message({"type": "status", "message": "Hook Stopped."})
    return {"status": "ok"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.connected_clients.add(websocket)
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await websocket.receive_text()
            cmd = json.loads(data)
            action = cmd.get("action")
            
            if action == "dump_memory":
                if state.frida_script:
                    def do_dump():
                        try:
                            res = state.frida_script.exports_sync.dumpstrings()
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "memory_dump", "data": res}), loop)
                        except Exception as e: logger.error(f"Dump error: {e}")
                    threading.Thread(target=do_dump, daemon=True).start()
            
            elif action == "get_static_strings":
                path = cmd.get("path")
                if path and os.path.exists(path):
                    def do_static():
                        try:
                            import re
                            with open(path, "rb") as f: content = f.read()
                            strs = re.findall(rb"[ -~]{5,}", content)
                            res = [{"type": "Static", "val": s.decode('ascii', errors='ignore')} for s in strs]
                            asyncio.run_coroutine_threadsafe(broadcast_message({"type": "static_strings", "data": res}), loop)
                        except Exception as e: logger.error(f"Static error: {e}")
                    threading.Thread(target=do_static, daemon=True).start()

            elif action == "toggle_intercept":
                state.intercept_mode = cmd.get("value", False)
                if state.frida_script: state.frida_script.exports_sync.setintercept(state.intercept_mode)
            
            elif action == "submit_action":
                if state.frida_script:
                    state.frida_script.post({"type": f"action_{cmd.get('id')}", "action": cmd.get("decision"), "modified_data": cmd.get("modified_data")})
            
            elif action == "repeater_send":
                sid = str(cmd.get("socket", ""))
                payload = str(cmd.get("data", ""))
                if sid == "HTTP":
                    import requests as _req
                    try:
                        # Simple HTTP repeater fallback
                        lines = payload.split('\n'); first = lines[0].split(' ')
                        method = first[0]; path = first[1] if len(first)>1 else '/'
                        host = ""; 
                        for l in lines: 
                            if l.lower().startswith("host:"): host = l.split(":")[1].strip()
                        if host:
                            r = _req.request(method, f"http://{host}{path}", timeout=5)
                            await websocket.send_json({"type": "repeater_response", "data": r.text})
                    except Exception as e: await websocket.send_json({"type": "repeater_response", "data": str(e)})
                elif state.frida_script:
                    try:
                        res = state.frida_script.exports_sync.repeatersend(sid, payload)
                        await websocket.send_json({"type": "repeater_response", "data": res})
                    except Exception as e: await websocket.send_json({"type": "repeater_response", "data": str(e)})

    except WebSocketDisconnect:
        state.connected_clients.remove(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
