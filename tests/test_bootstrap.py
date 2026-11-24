#!/usr/bin/env python3
"""Tests for bootstrap.py (stdlib unittest only)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bootstrap  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "minisign"
LICENSE_KEY = "IK-TEST-TEST-TEST-ABCD"


def _load_pub(path: Path) -> str:
    return path.read_text(encoding="utf-8").splitlines()[1].strip()


class TestMinisignVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not FIXTURES.is_dir():
            raise unittest.SkipTest("minisign fixtures missing")

    def test_valid_signature(self):
        data = (FIXTURES / "payload.bin").read_bytes()
        sig = (FIXTURES / "payload.bin.minisig").read_bytes()
        pub = _load_pub(FIXTURES / "test.pub")
        self.assertTrue(bootstrap.verify_signature(data, sig, pub))

    def test_tampered_payload(self):
        data = (FIXTURES / "tampered.bin").read_bytes()
        sig = (FIXTURES / "payload.bin.minisig").read_bytes()
        pub = _load_pub(FIXTURES / "test.pub")
        self.assertFalse(bootstrap.verify_signature(data, sig, pub))

    def test_other_key(self):
        data = (FIXTURES / "payload.bin").read_bytes()
        sig = (FIXTURES / "payload.bin.minisig").read_bytes()
        pub = _load_pub(FIXTURES / "other.pub")
        self.assertFalse(bootstrap.verify_signature(data, sig, pub))

    def test_trusted_comment_tampered(self):
        data = (FIXTURES / "payload.bin").read_bytes()
        lines = (FIXTURES / "payload.bin.minisig").read_text(encoding="utf-8").splitlines()
        lines[2] = "trusted comment: TAMPERED"
        sig = ("\n".join(lines) + "\n").encode("utf-8")
        pub = _load_pub(FIXTURES / "test.pub")
        self.assertFalse(bootstrap.verify_signature(data, sig, pub))

    def test_malformed_signature(self):
        data = (FIXTURES / "payload.bin").read_bytes()
        pub = _load_pub(FIXTURES / "test.pub")
        self.assertFalse(bootstrap.verify_signature(data, b"not-a-signature", pub))
        self.assertFalse(bootstrap.verify_signature(data, b"", pub))


class TestSha256(unittest.TestCase):
    def test_sha256_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pkg.tar.gz"
            path.write_bytes(b"hello")
            with self.assertRaises(bootstrap.VerificationError):
                bootstrap.check_sha256(path, hashlib.sha256(b"other").hexdigest())


class TestSafeUnpack(unittest.TestCase):
    def _make_tar(self, tmp: Path, members_builder) -> Path:
        tar_path = tmp / "pkg.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            members_builder(tf, tmp)
        return tar_path

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            dest = tmp_p / "dest"
            dest.mkdir()

            def build(tf, base):
                info = tarfile.TarInfo(name="intel-kit-0.1.0/../../evil.txt")
                data = b"x"
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            tar_path = self._make_tar(tmp_p, build)
            with self.assertRaises(bootstrap.VerificationError):
                bootstrap.safe_unpack(tar_path, dest, "0.1.0")

    def test_rejects_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            dest = tmp_p / "dest"
            dest.mkdir()

            def build(tf, base):
                info = tarfile.TarInfo(name="/etc/passwd")
                data = b"x"
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            tar_path = self._make_tar(tmp_p, build)
            with self.assertRaises(bootstrap.VerificationError):
                bootstrap.safe_unpack(tar_path, dest, "0.1.0")

    def test_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            dest = tmp_p / "dest"
            dest.mkdir()

            def build(tf, base):
                dir_info = tarfile.TarInfo(name="intel-kit-0.1.0")
                dir_info.type = tarfile.DIRTYPE
                dir_info.mode = 0o755
                tf.addfile(dir_info)
                link = tarfile.TarInfo(name="intel-kit-0.1.0/escape")
                link.type = tarfile.SYMTYPE
                link.linkname = "../../outside"
                tf.addfile(link)

            tar_path = self._make_tar(tmp_p, build)
            with self.assertRaises(bootstrap.VerificationError):
                bootstrap.safe_unpack(tar_path, dest, "0.1.0")


class TestErrorMapping(unittest.TestCase):
    def test_http_status_to_exit(self):
        self.assertEqual(bootstrap.exit_code_for_error(401, "invalid_key"), 2)
        self.assertEqual(bootstrap.exit_code_for_error(403, "revoked"), 2)
        self.assertEqual(bootstrap.exit_code_for_error(403, "device_limit"), 3)
        self.assertEqual(bootstrap.exit_code_for_error(429, "daily_cap"), 4)
        self.assertEqual(bootstrap.exit_code_for_error(0, "network"), 5)

    def test_chinese_messages(self):
        for code in ("invalid_key", "revoked", "device_limit", "daily_cap", "network", "verification"):
            msg = bootstrap.message_for_error(code)
            self.assertTrue(msg)
            self.assertRegex(msg, r"[\u4e00-\u9fff]")


class TestMaskKey(unittest.TestCase):
    def test_mask(self):
        masked = bootstrap.mask_key(LICENSE_KEY)
        self.assertNotIn("TEST", masked)
        self.assertTrue(masked.endswith("ABCD"))
        self.assertIn("****", masked)


class FakeAPIHandler(BaseHTTPRequestHandler):
    server_version = "FakeAPI/1.0"

    def log_message(self, fmt, *args):
        return

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "bad_request", "message": "坏请求"})
        if self.path != "/v1/activate":
            return self._json(404, {"error": "not_found", "message": "未找到"})
        key = body.get("license_key", "")
        mode = getattr(self.server, "activate_mode", "ok")
        if mode == "invalid":
            return self._json(401, {"error": "invalid_key", "message": "激活码无效"})
        if mode == "revoked":
            return self._json(403, {"error": "revoked", "message": "已吊销"})
        if mode == "device_limit":
            return self._json(403, {"error": "device_limit", "message": "设备上限"})
        if mode == "daily_cap":
            return self._json(429, {"error": "daily_cap", "message": "今日上限"})
        if key != LICENSE_KEY and mode == "ok":
            return self._json(401, {"error": "invalid_key", "message": "激活码无效"})
        pkg = self.server.package_bytes
        sha = hashlib.sha256(pkg).hexdigest()
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self._json(
            200,
            {
                "license_id": "lic_test",
                "version": "0.1.0",
                "schema_version": 1,
                "sha256": sha,
                "size": len(pkg),
                "package_url": f"{base}/v1/dl/0.1.0/package.tar.gz",
                "signature_url": f"{base}/v1/dl/0.1.0/package.tar.gz.minisig",
                "expires_at": "2099-01-01T00:00:00Z",
                "update_expires_at": "2099-12-31T00:00:00Z",
                "update_rights_expired": False,
            },
        )

    def do_GET(self):
        if self.path.startswith("/v1/dl/0.1.0/package.tar.gz.minisig"):
            data = self.server.sig_bytes
        elif self.path.startswith("/v1/dl/0.1.0/package.tar.gz"):
            data = self.server.package_bytes
        elif self.path.startswith("/v1/latest"):
            return self._json(
                200,
                {
                    "version": "0.1.0",
                    "schema_version": 1,
                    "sha256": "abc",
                    "size": 1,
                    "released_at": "2026-01-01T00:00:00Z",
                    "update_rights_expired": False,
                },
            )
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _build_package_bytes(version: str = "0.1.0") -> bytes:
    buf = io.BytesIO()
    root = f"intel-kit-{version}"
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        dir_info = tarfile.TarInfo(name=root)
        dir_info.type = tarfile.DIRTYPE
        dir_info.mode = 0o755
        tf.addfile(dir_info)
        for rel, content in [
            (f"{root}/VERSION", version.encode() + b"\n"),
            (f"{root}/manifest.json", json.dumps({"version": version, "schema_version": 1, "built_at": "t"}).encode()),
            (f"{root}/src/intelkit/__init__.py", b""),
            (f"{root}/src/intelkit/cli.py", b"def main():\n    print('ok')\n"),
        ]:
            info = tarfile.TarInfo(name=rel)
            info.size = len(content)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


class TestEndToEndInstall(unittest.TestCase):
    def setUp(self):
        self._httpd = HTTPServer(("127.0.0.1", 0), FakeAPIHandler)
        self._httpd.package_bytes = _build_package_bytes()
        self._httpd.sig_bytes = b"fake-sig"
        self._httpd.activate_mode = "ok"
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self.api = f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def tearDown(self):
        self._httpd.shutdown()
        self._httpd.server_close()

    def test_full_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            # pre-existing user files must stay untouched
            (home / "intel.yaml").write_text("keep: me\n", encoding="utf-8")
            (home / "state").mkdir()
            (home / "state" / "x").write_text("1", encoding="utf-8")

            with mock.patch.object(bootstrap, "verify_signature", return_value=True):
                code = bootstrap.run_install(
                    key=LICENSE_KEY,
                    home=home,
                    api_url=self.api,
                    skip_deps=True,
                )
            self.assertEqual(code, 0)
            version_dir = home / "app" / "0.1.0"
            self.assertTrue((version_dir / "src" / "intelkit" / "cli.py").is_file())
            current = home / "app" / "current"
            self.assertTrue(current.is_symlink() or (home / "app" / "current.txt").is_file())
            if current.is_symlink():
                self.assertEqual(current.resolve(), version_dir.resolve())
            lic = json.loads((home / "license.json").read_text(encoding="utf-8"))
            self.assertEqual(lic["license_id"], "lic_test")
            self.assertEqual(lic["version"], "0.1.0")
            self.assertNotIn("license_key", lic)
            self.assertNotIn(LICENSE_KEY, json.dumps(lic))
            env_path = home / ".env"
            self.assertTrue(env_path.is_file())
            self.assertEqual(stat.S_IMODE(env_path.stat().st_mode), 0o600)
            self.assertIn(f"INTEL_KIT_LICENSE_KEY={LICENSE_KEY}", env_path.read_text(encoding="utf-8"))
            self.assertEqual((home / "intel.yaml").read_text(encoding="utf-8"), "keep: me\n")
            self.assertTrue((home / "bin" / "intel").is_file() or (home / "bin" / "intel.cmd").is_file())

    def test_key_not_leaked_to_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            buf_out = io.StringIO()
            buf_err = io.StringIO()
            with mock.patch.object(bootstrap, "verify_signature", return_value=True):
                with mock.patch("sys.stdout", buf_out), mock.patch("sys.stderr", buf_err):
                    code = bootstrap.run_install(
                        key=LICENSE_KEY, home=home, api_url=self.api, skip_deps=True
                    )
            self.assertEqual(code, 0)
            combined = buf_out.getvalue() + buf_err.getvalue()
            self.assertNotIn(LICENSE_KEY, combined)
            self.assertNotIn("TEST-TEST-TEST", combined)

    def test_error_codes_from_api(self):
        cases = [
            ("invalid", 2),
            ("revoked", 2),
            ("device_limit", 3),
            ("daily_cap", 4),
        ]
        for mode, expected in cases:
            with self.subTest(mode=mode):
                self._httpd.activate_mode = mode
                with tempfile.TemporaryDirectory() as tmp:
                    home = Path(tmp) / "home"
                    home.mkdir()
                    code = bootstrap.run_install(
                        key=LICENSE_KEY, home=home, api_url=self.api, skip_deps=True
                    )
                    self.assertEqual(code, expected)

    def test_deps_failure_exits_7_no_current_switch(self):
        def boom_deps(home, version_dir):
            raise bootstrap.DepsError("venv failed")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            # Pre-existing current must not be replaced on deps failure
            app = home / "app"
            app.mkdir()
            old = app / "0.0.9"
            old.mkdir()
            (old / "VERSION").write_text("0.0.9\n", encoding="utf-8")
            bootstrap._atomic_point_current(app, old)

            buf_err = io.StringIO()
            with mock.patch.object(bootstrap, "verify_signature", return_value=True):
                with mock.patch("sys.stderr", buf_err):
                    code = bootstrap.run_install(
                        key=LICENSE_KEY,
                        home=home,
                        api_url=self.api,
                        install_deps_fn=boom_deps,
                    )
            self.assertEqual(code, 7)
            err = buf_err.getvalue()
            self.assertIn("venv", err)
            self.assertIn("pip", err)
            self.assertRegex(err, r"[\u4e00-\u9fff]")
            current = home / "app" / "current"
            if current.is_symlink():
                self.assertEqual(current.resolve(), old.resolve())
            else:
                txt = (home / "app" / "current.txt").read_text(encoding="utf-8").strip()
                self.assertEqual(Path(txt).resolve(), old.resolve())
            # New version unpacked but not switched
            self.assertTrue((home / "app" / "0.1.0").is_dir())


class TestLauncher(unittest.TestCase):
    def test_launcher_exports_intel_kit_home_and_venv_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "ik"
            home.mkdir()
            bootstrap.write_launcher(home)
            sh = home / "bin" / "intel"
            self.assertTrue(sh.is_file())
            text = sh.read_text(encoding="utf-8")
            self.assertIn("INTEL_KIT_HOME", text)
            self.assertIn("venv/bin/python", text)
            self.assertIn("PYTHONPATH", text)
            self.assertIn("app/current/src", text)
            self.assertIn("python3", text)  # fallback
            cmd = home / "bin" / "intel.cmd"
            # Always written on non-Windows too for content check? production writes
            # intel.cmd only on Windows. Check platform branch via mock.
            with mock.patch("bootstrap.platform.system", return_value="Windows"):
                bootstrap.write_launcher(home)
            cmd_text = (home / "bin" / "intel.cmd").read_text(encoding="utf-8")
            self.assertIn("INTEL_KIT_HOME", cmd_text)
            self.assertIn(r"venv\Scripts\python.exe", cmd_text)
            self.assertIn("PYTHONPATH", cmd_text)
            self.assertIn(r"app\current\src", cmd_text)


class TestSslContext(unittest.TestCase):
    def test_ssl_honours_ssl_cert_file(self):
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            ca = f.name
            f.write(b"-----BEGIN CERTIFICATE-----\nMIIBkTCB+wI=\n-----END CERTIFICATE-----\n")
        try:
            with mock.patch.dict(os.environ, {"SSL_CERT_FILE": ca}, clear=False):
                with mock.patch("ssl.create_default_context") as m:
                    m.return_value = mock.Mock()
                    bootstrap._ssl_context()
                    m.assert_called_once_with(cafile=ca)
        finally:
            os.unlink(ca)

    def test_ssl_uses_certifi_when_importable(self):
        fake_certifi = mock.Mock()
        fake_certifi.where.return_value = "/fake/cacert.pem"
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SSL_CERT_FILE", None)
            with mock.patch.dict(sys.modules, {"certifi": fake_certifi}):
                with mock.patch("ssl.create_default_context") as m:
                    m.return_value = mock.Mock()
                    bootstrap._ssl_context()
                    m.assert_called_once_with(cafile="/fake/cacert.pem")

    def test_certificate_error_prints_chinese_hint(self):
        import ssl
        import urllib.error

        exc = urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed"))
        buf_err = io.StringIO()
        with mock.patch("urllib.request.urlopen", side_effect=exc):
            with mock.patch("sys.stderr", buf_err):
                with self.assertRaises(bootstrap.APIError):
                    bootstrap._http_json("GET", "https://example.invalid/v1/x")
        err = buf_err.getvalue()
        self.assertRegex(err, r"[\u4e00-\u9fff]")
        self.assertTrue(
            "SSL_CERT_FILE" in err or "Install Certificates" in err or "证书" in err
        )


class TestEnvPermsAndUntouched(unittest.TestCase):
    def test_write_env_perms(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            bootstrap.ensure_home_dir(home)
            bootstrap.write_env_key(home, LICENSE_KEY)
            mode = stat.S_IMODE((home / ".env").stat().st_mode)
            self.assertEqual(mode, 0o600)
            # replace existing
            bootstrap.write_env_key(home, "IK-AAAA-BBBB-CCCC-DDDD")
            text = (home / ".env").read_text(encoding="utf-8")
            self.assertIn("IK-AAAA-BBBB-CCCC-DDDD", text)
            self.assertNotIn(LICENSE_KEY, text)


if __name__ == "__main__":
    unittest.main()
