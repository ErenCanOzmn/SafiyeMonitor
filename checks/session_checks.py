"""Offline regression checks: no instrumentation, external traffic or live server."""
import ast
import asyncio
import copy
import json
import logging
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import session_format as fmt


def fixture():
    finding = {"title": "Example observation", "severity": "INFO", "evidence": "sample",
               "ui_review_status": "In review", "source": "rule"}
    return fmt.build_session(
        [{"type": "tcp_out", "dest": "example.test:443", "body": "Merhaba 🐈" * 2000,
          "body_hex": "73616d706c65", "captured_at": "2026-09-23T12:00:00+00:00"},
         {"type": "crypto_event", "body": "example"}],
        {"static_strings": {"type": "static_strings", "data": [{"val": "example"}, "plain string"]}},
        [finding], {"rule": [dict(finding)]}, {"target_name": "Example.exe", "target_pid": 1234},
        {"dropped_events": 7})


class FormatChecks(unittest.TestCase):
    def test_roundtrip_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Türkçe.json"
            original = fixture()
            fmt.write_session(path, original)
            self.assertEqual(fmt.read_session(path), original)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                fmt.write_session(path, original)
            self.assertEqual(path.read_bytes(), before)
            changed = copy.deepcopy(original)
            changed["metadata"]["target_name"] = "Updated.exe"
            fmt.write_session(path, changed, overwrite=True)
            self.assertEqual(fmt.read_session(path)["metadata"]["target_name"], "Updated.exe")
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["Türkçe.json"])

    def test_v1_and_derived_data(self):
        old = {"version": 1, "session_events": [{"type": "tcp_in", "_ts": "12:34:56"}],
               "session_snapshot": {}, "vuln_findings": []}
        result = fmt.normalize_session(old)
        self.assertEqual(result["version"], 2)
        self.assertIsNone(result["coverage"]["dropped_events"])
        self.assertIsNone(result["analysis"]["timeline"]["first_utc"])
        result["analysis"] = {"record_count": -1}
        self.assertEqual(fmt.normalize_session(result)["analysis"]["record_count"], 1)

    def test_lossless_unicode_chunks(self):
        data = fixture()
        page = fmt.record_page(data, "tcp_out", preview_chars=128)
        self.assertTrue(page["records"][0]["truncated"])
        self.assertTrue(page["records"][0]["omitted_fields"])
        self.assertEqual(page["records"][0]["context"]["dest"], "example.test:443")
        offset, chunks = 0, []
        while offset is not None:
            part = fmt.record_chunk(data, "/session_events/0", offset, 113)
            chunks.append(part["text"])
            offset = part["next_offset"]
        self.assertEqual(json.loads("".join(chunks)), data["session_events"][0])

    def test_page_coverage_and_budget(self):
        data = fixture()
        data["session_events"] = [{"type": "tcp_out", "body": "x" * 10000} for _ in range(120)]
        data.pop("capture_sha256")
        data = fmt.normalize_session(data)
        offset, refs = 0, []
        while offset is not None:
            page = fmt.record_page(data, "tcp_out", offset, 100, 8000)
            self.assertLessEqual(sum(len(r["json_preview"]) for r in page["records"]), 48000)
            refs.extend(r["ref"] for r in page["records"])
            offset = page["next_offset"]
        self.assertEqual(len(set(refs)), 120)
        self.assertIsNone(fmt.record_page(data, offset=999)["next_offset"])

    def test_invalid_shapes_and_integrity(self):
        bad_values = [[], {"version": 3}, {"version": True},
                      {"version": 1, "session_events": {}, "session_snapshot": {}},
                      {"version": 1, "session_events": [{"type": "status"}], "session_snapshot": {}},
                      {"version": 1, "session_events": [{"type": []}], "session_snapshot": {}}]
        for bad in bad_values:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fmt.normalize_session(bad)
        damaged = fixture()
        damaged["session_events"][0]["body"] = "changed"
        with self.assertRaisesRegex(ValueError, "checksum"):
            fmt.normalize_session(damaged)
        bad = fixture()
        bad["vuln_sources"]["rule"][0]["severity"] = []
        with self.assertRaises(ValueError):
            fmt.normalize_session(bad)

    def test_input_independence_and_snapshot_identity(self):
        original = fixture()
        saved = fmt.normalize_session(original)
        original["vuln_findings"][0]["title"] = "changed"
        self.assertNotEqual(saved["vuln_findings"], original["vuln_findings"])
        self.assertNotEqual(fmt.snapshot_id(saved), fmt.snapshot_id(original))
        saved["saved_at"] = "new export time"
        self.assertEqual(fmt.snapshot_id(saved), fmt.snapshot_id(fixture()))

    def test_bounds(self):
        for kwargs in ({"offset": -1}, {"limit": 101}, {"limit": True}, {"preview_chars": 1}, {"collection": "unknown"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                fmt.record_page(fixture(), **kwargs)
        with self.assertRaises(ValueError):
            fmt.record_chunk(fixture(), "/missing")


def isolated_server():
    """Compile just persistence functions, avoiding the server's startup side effects."""
    source = ROOT / "src" / "safiye_server_prod.py"
    tree = ast.parse(source.read_text(encoding="utf-8-sig"))
    names = {"_vuln_dedupe_key", "_rebuild_vuln", "_session_archive", "import_session",
             "export_session", "session_analysis", "new_session", "finding_review", "broadcast_message", "_now_ts", "_set_vuln_source"}
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    for node in nodes:
        node.decorator_list = []
    state = SimpleNamespace(session_events=[], session_snapshot={}, last_vuln_analysis=[], vuln_sources={},
                            archive_metadata=None, archive_coverage=None, dropped_events=0, analysis_session=None,
                            ui_target_name="Example.exe", ui_target_pid=1234, ui_started_at=1,
                            is_hooking=False, bridge=None, pending_analysis_data=None, memcred_before_fps=None,
                            connected_clients=set(), review_observations=[])
    import time
    from fastapi.responses import JSONResponse
    from capture_review import observation
    namespace = dict(state=state, json=json, copy=copy, time=time, datetime=datetime, timezone=timezone,
                     Request=object, JSONResponse=JSONResponse, logger=logging.getLogger("offline-checks"),
                     build_session=fmt.build_session, normalize_session=fmt.normalize_session,
                     session_summary=fmt.summary, record_page=fmt.record_page, record_chunk=fmt.record_chunk,
                     snapshot_id=fmt.snapshot_id, MAX_FILE_BYTES=fmt.MAX_FILE_BYTES,
                     _VULN_SOURCE_ORDER=["ai", "rule", "import"], _SEV_ORDER={"INFO": 4},
                     _REPLAY_STREAM=fmt.STREAM_TYPES, _REPLAY_SNAPSHOT=fmt.SNAPSHOT_TYPES)
    namespace["observation"] = observation
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(source), "exec"), namespace)
    return namespace


class Request:
    def __init__(self, data):
        self.data = data

    async def json(self):
        return self.data

    async def body(self):
        return json.dumps(self.data).encode("utf-8")


class ServerChecks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 10
        self.api = isolated_server()
        self.state = self.api["state"]

    async def test_restore_sources_reviews_metadata(self):
        archive = fixture()
        archive["vuln_sources"]["rule"][0]["ui_review_status"] = "Unreviewed"
        result = await self.api["import_session"](Request(archive))
        self.assertEqual(result["status"], "ok")
        exported = await self.api["export_session"]()
        self.assertEqual(exported["session_events"], archive["session_events"])
        self.assertEqual(exported["metadata"], archive["metadata"])
        self.assertEqual(exported["coverage"]["dropped_events"], 7)
        self.assertEqual(exported["vuln_sources"]["rule"][0]["ui_review_status"], "In review")

    async def test_invalid_import_is_nonmutating(self):
        self.state.session_events = [{"type": "tcp_in", "body": "keep"}]
        for data in ({"version": 99}, {**fixture(), "vuln_findings": [{"title": []}]}):
            with self.assertLogs("offline-checks", level="ERROR"):
                response = await self.api["import_session"](Request(data))
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.state.session_events, [{"type": "tcp_in", "body": "keep"}])

    async def test_active_import_is_rejected(self):
        self.state.is_hooking = True
        response = await self.api["import_session"](Request(fixture()))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.state.session_events, [])

    async def test_pinned_snapshot_survives_new_events(self):
        self.state.session_events = [{"type": "tcp_in", "body": "first"}]
        summary = await self.api["session_analysis"](Request({"action": "summary"}))
        self.state.session_events.append({"type": "tcp_in", "body": "second"})
        page = await self.api["session_analysis"](Request({"action": "records", "snapshot_id": summary["snapshot_id"]}))
        self.assertEqual(page["total"], 1)
        await self.api["session_analysis"](Request({"action": "summary"}))
        response = await self.api["session_analysis"](Request({"action": "records", "snapshot_id": summary["snapshot_id"]}))
        self.assertEqual(response.status_code, 400)

    async def test_retention_and_reset(self):
        self.state.session_events = [{"type": "tcp_out"} for _ in range(3000)]
        await self.api["broadcast_message"]({"type": "tcp_in", "body": "sample"})
        self.assertEqual(len(self.state.session_events), 3000)
        self.assertEqual(self.state.dropped_events, 1)
        self.assertIn("captured_at", self.state.session_events[-1])
        await self.api["new_session"]()
        self.assertEqual(self.state.dropped_events, 0)
        self.assertIsNone(self.state.ui_target_name)

    async def test_review_sync(self):
        await self.api["import_session"](Request(fixture()))
        result = await self.api["finding_review"](Request({"title": "Example observation", "evidence": "sample", "ui_review_status": "Confirmed"}))
        self.assertEqual(result["status"], "ok")
        self.assertEqual((await self.api["export_session"]())["vuln_findings"][0]["ui_review_status"], "Confirmed")


class MCPChecks(unittest.IsolatedAsyncioTestCase):
    async def test_save_load_tools(self):
        import mcp_server as mcp
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "capture.json")
            with patch.object(mcp, "_get", return_value=fixture()) as get:
                saved = json.loads((await mcp.handle_call_tool("save_session", {"path": path}))[0].text)
                self.assertEqual(saved["path"], path)
                get.assert_called_once_with("/api/export_session", timeout=60)
            with patch.object(mcp, "_post", return_value={"status": "ok"}) as post:
                loaded = json.loads((await mcp.handle_call_tool("load_session", {"path": path}))[0].text)
                self.assertEqual(loaded["status"], "ok")
                self.assertEqual(post.call_args.args[0], "/api/import_session")
                self.assertEqual(post.call_args.args[1]["version"], 2)

    async def test_tools_and_offline_reads(self):
        asyncio.get_running_loop().slow_callback_duration = 10
        import mcp_server as mcp
        names = {t.name for t in await mcp.handle_list_tools()}
        self.assertTrue({"save_session", "load_session", "get_session_summary", "get_session_records", "get_session_record"} <= names)
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "capture.json")
            fmt.write_session(path, fixture())
            with patch.object(mcp, "_post", side_effect=AssertionError("offline read used server")):
                result = await mcp.handle_call_tool("get_session_summary", {"file_path": path})
                summary = json.loads(result[0].text)
                result = await mcp.handle_call_tool("get_session_records", {"file_path": path, "snapshot_id": summary["snapshot_id"], "limit": 1})
                self.assertEqual(len(json.loads(result[0].text)["records"]), 1)
                result = await mcp.handle_call_tool("get_session_records", {"file_path": path, "snapshot_id": "stale"})
                self.assertEqual(json.loads(result[0].text)["status"], "error")


if __name__ == "__main__":
    unittest.main(verbosity=2)
