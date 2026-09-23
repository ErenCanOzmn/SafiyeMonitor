"""Synthetic offline cases for extraction precision and the confirmation gate."""
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from artifact_scan import scan_blob, text_candidates, safe_url
from capture_review import analyze_capture
from session_checks import isolated_server, Request


class InventoryChecks(unittest.TestCase):
    def test_structured_credentials_and_masking(self):
        text = '''{"username":"alice_lab","password":"Fixture!9x"}
User ID=sql_lab;Password="Another!9x";
<password>Xml!9x</password>
<add key="client_secret" value="Setting!9x" />'''
        items = scan_blob(text.encode())["findings"]
        self.assertEqual({f["category"] for f in items}, {"username", "password", "token"})
        for value in ("alice_lab", "Fixture!9x", "Another!9x", "Xml!9x", "Setting!9x"):
            self.assertIn(hashlib.sha256(value.encode()).hexdigest(), {f["sha256"] for f in items})
            self.assertNotIn(value, json.dumps(items))
        self.assertTrue(all(f["severity"] == "INFO" and f["validation_status"] == "needs_review" for f in items))

    def test_turkish_utf8_and_wide_offsets(self):
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                text = 'kullanıcı_adı="çağrı_lab";şifre="Örnek!9x"'
                blob = b"\x00\x00\x00" + text.encode(encoding) + b"\x00\x00\x00"
                items = scan_blob(blob, reveal=True)["findings"]
                password = next(f for f in items if f.get("value") == "Örnek!9x")
                self.assertEqual(password["offset"], blob.index("Örnek!9x".encode(encoding)))
                self.assertEqual(password["enc"], encoding)
                self.assertTrue(any(f.get("value") == "çağrı_lab" for f in items))

    def test_endpoints_and_ip_validation(self):
        text = 'https://example.test/api?q=abc http://[2001:db8::1]:8080/ 10.2.3.4 999.2.3.4 version=1.2.3.4'
        items = scan_blob(text.encode())["findings"]
        ips = {f["masked"] for f in items if f["category"] == "ip"}
        self.assertIn("10.2.3.4", ips)
        self.assertIn("2001:db8::1", ips)
        self.assertNotIn("999.2.3.4", ips)
        self.assertNotIn("1.2.3.4", ips)
        self.assertTrue(all(f["validation_status"] == "inventory" for f in items))

    def test_url_userinfo_and_query_redaction(self):
        value = "postgresql://alice_lab:Fixture%219x@example.test/db?token=Query!9x#Fragment!9x"
        result = scan_blob(value.encode())
        rendered = json.dumps(result)
        for secret in ("alice_lab", "Fixture", "Query!9x", "Fragment!9x"):
            self.assertNotIn(secret, rendered)
        self.assertTrue(any(f["category"] == "password" for f in result["findings"]))
        self.assertIsNone(safe_url("http://999.2.3.4/path"))

    def test_noise_and_placeholders(self):
        text = '''password=changeme secret=${SECRET} username="your_username"
PasswordBox System.Security.Cryptography.MD5 0123456789abcdef0123456789abcdef
token="DEMO_ONLY_NOT_A_REAL_PASSWORD" api_key="xxxxxxxx"
password="${PASSWORD}" password=getPassword() username="username"'''
        # your_username is also a placeholder, never a useful identity.
        self.assertEqual(scan_blob(text.encode())["findings"], [])

    def test_multiple_values_deduplication_and_late_strings(self):
        text = "x" * 9000 + '\x00password="One!9x";password="Two!9x";password="One!9x"'
        result = scan_blob(text.encode(), reveal=True)
        self.assertEqual({f["value"] for f in result["findings"]}, {"One!9x", "Two!9x"})
        self.assertEqual(next(f for f in result["findings"] if f["value"] == "One!9x")["occurrences"], 2)

    def test_caps_are_explicit(self):
        result = scan_blob(b'password="One!9x";password="Two!9x"', max_items=1)
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["results_truncated"])
        self.assertEqual(list(text_candidates("password=" + "x" * 5000)), [])

    def test_long_run_does_not_create_truncated_duplicate(self):
        secret = "Long!9x" * 200
        text = "z" * 65000 + ';password="' + secret + '"'
        result = scan_blob(text.encode(), reveal=True)
        self.assertEqual([f["value"] for f in result["findings"]], [secret])

    def test_endpoint_volume_does_not_hide_later_credential(self):
        blob = b"http://one.test/\x00http://two.test/\x00password=Fixture!9x"
        result = scan_blob(blob, max_items=2)
        self.assertTrue(result["results_truncated"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(any(f["category"] == "password" for f in result["findings"]))


@unittest.skipUnless(os.name == "nt", "Windows reflection helper")
class ManagedChecks(unittest.TestCase):
    def test_metadata_literals_without_executing_static_constructor(self):
        with tempfile.TemporaryDirectory() as directory:
            assembly = str(Path(directory) / "InventoryFixture.dll")
            env = dict(os.environ, SAFIYE_CHECK_SOURCE=str(ROOT / "checks" / "ManagedInventoryFixture.cs"), SAFIYE_CHECK_OUTPUT=assembly)
            compile_result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                             "Add-Type -Path $env:SAFIYE_CHECK_SOURCE -OutputAssembly $env:SAFIYE_CHECK_OUTPUT"],
                                            env=env, capture_output=True, timeout=30)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr.decode(errors="replace"))
            command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                       str(ROOT / "src" / "helpers" / "managed_secret_scan.ps1"), "-AssemblyPath", assembly]
            result = subprocess.run(command, capture_output=True, timeout=30)
            data = json.loads(result.stdout.decode("utf-8-sig"))
            self.assertIsNone(data["error"])
            findings = {f["member"]: f for f in data["findings"]}
            self.assertIn("Username", findings)
            self.assertIn("Password", findings)
            self.assertNotIn("PlaceholderSecret", findings)
            self.assertEqual(findings["Password"]["value_origin"], "metadata_literal")
            self.assertEqual(findings["RuntimePassword"]["value_origin"], "name_only")
            self.assertEqual(findings["Password"]["masked_value"], "[redacted]")
            self.assertTrue(all(f["severity"] == "INFO" for f in findings.values()))


class RulePrecisionChecks(unittest.TestCase):
    def test_normal_runtime_patterns_do_not_claim_vulnerabilities(self):
        data = {"tcp_packets": [{"direction": "Outgoing (SSL_write)", "dest": "example.test:8443",
                                  "body": "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}],
                "dll_events": [{"dllName": "C:\\Users\\example\\AppData\\thing.dll", "isFailed": True, "status": "NAME NOT FOUND"}],
                "registry_events": [{"api": "RegQueryValueExW", "target": "HKCU\\CurrentVersion\\Run", "status": "SUCCESS"}],
                "file_events": [{"api": "CreateFileW", "target": "C:\\Windows\\System32\\example.dll"}],
                "static_strings": [{"val": "MD5"}, {"val": "0123456789abcdef0123456789abcdef"}, {"val": "-----BEGIN PRIVATE KEY-----"}]}
        self.assertEqual(analyze_capture(data), [])

    def test_crypto_plaintext_is_expected(self):
        self.assertEqual(analyze_capture({"crypto_events": [{"op": "decrypt", "body": "password=Fixture!9x"}]}), [])

    def test_runtime_credential_is_not_hardcoding(self):
        result = analyze_capture({"memory_strings": [{"val": 'password="Fixture!9x"'}]})
        self.assertEqual(len(result), 1)
        self.assertNotIn("hardcoded", result[0]["title"].lower())
        self.assertNotIn("Fixture!9x", json.dumps(result))
        self.assertEqual(result[0]["validation_status"], "needs_review")

    def test_cookie_flag_parsing_and_header_boundary(self):
        complete = "HTTP/1.1 200 OK\r\nSet-Cookie: session=Fixture!9x; Secure; HttpOnly\r\n\r\n"
        self.assertEqual(analyze_capture({"tcp_packets": [{"body": complete}]}), [])
        fake_flags = "HTTP/1.1 200 OK\r\nSet-Cookie: session=securehttponly\r\n\r\n"
        result = analyze_capture({"tcp_packets": [{"body": fake_flags}]})
        self.assertEqual(len(result), 1)
        self.assertIn("secure, httponly", result[0]["evidence"])
        documentation = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSet-Cookie: session=value"
        self.assertEqual(analyze_capture({"tcp_packets": [{"body": documentation}]}), [])


class GateChecks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 10
        self.api = isolated_server()
        self.state = self.api["state"]
        self.item = {"title": "Example candidate", "evidence": "Recorded condition", "severity": "HIGH"}

    async def test_scanner_cannot_self_confirm(self):
        result = self.api["_set_vuln_source"]("ai", [{**self.item, "ui_review_status": "Confirmed", "validation_status": "confirmed", "confidence": "high"}])
        self.assertEqual(result, [])
        self.assertEqual(len(self.state.review_observations), 1)
        self.assertEqual(self.state.review_observations[0]["validation_status"], "needs_review")

    async def test_review_promotes_and_rescan_preserves_only_same_evidence(self):
        self.api["_set_vuln_source"]("rule", [self.item])
        result = await self.api["finding_review"](Request({**self.item, "ui_review_status": "Confirmed"}))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(self.state.last_vuln_analysis), 1)
        self.assertEqual(self.state.review_observations, [])
        self.api["_set_vuln_source"]("rule", [self.item])
        self.assertEqual(len(self.state.last_vuln_analysis), 1)
        self.api["_set_vuln_source"]("rule", [{**self.item, "evidence": "Different condition"}])
        self.assertEqual(self.state.last_vuln_analysis, [])

    async def test_runtime_alert_cannot_bypass_gate(self):
        await self.api["broadcast_message"]({"type": "vulnerability_report", "vulnerabilities": [{"title": "Signature matched"}]})
        self.assertEqual(self.state.last_vuln_analysis, [])
        self.assertEqual(len(self.state.review_observations), 1)

    async def test_observation_archive_roundtrip(self):
        self.api["_set_vuln_source"]("rule", [self.item])
        archive = await self.api["export_session"]()
        self.assertEqual(archive["vuln_findings"], [])
        self.assertEqual(len(archive["vuln_observations"]), 1)
        await self.api["new_session"]()
        await self.api["import_session"](Request(archive))
        self.assertEqual(self.state.last_vuln_analysis, [])
        self.assertEqual(len(self.state.review_observations), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
