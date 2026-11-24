#!/usr/bin/env python3
"""intel-kit public installer (stdlib only, Python 3.9+)."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

__version__ = "0.1.0"
CLIENT = f"bootstrap/{__version__}"
DEFAULT_API = "https://intel-kit-dl.runicscript7.workers.dev"
# Release public key (minisign base64 body only).
PUBKEY = "RWS5EBqsqD2Wxxb5n6/8HmrpgL8hXrSKuTK3nj/Ur2vSB7i6zYIL+giq"

EXIT_OK = 0
EXIT_INVALID = 2
EXIT_DEVICE_LIMIT = 3
EXIT_DAILY_CAP = 4
EXIT_NETWORK = 5
EXIT_VERIFY = 6
EXIT_DEPS = 7

_SSL_HINT = (
    "证书校验失败。macOS 可运行 Python 的 Install Certificates.command，"
    "或设置 SSL_CERT_FILE 指向 CA 证书包。"
)
_DEPS_HINT = "需要 python3 的 venv 和 pip，可联网安装依赖"


class VerificationError(Exception):
    """Package verification or safe-unpack failure."""


class DepsError(Exception):
    """Virtualenv creation or pip install failure."""


class APIError(Exception):
    def __init__(self, error: str, message: str, http_status: int = 0):
        super().__init__(message)
        self.error = error
        self.message = message
        self.http_status = http_status


# ---------------------------------------------------------------------------
# Ed25519 verify (RFC 8032) — verify only
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _modp_inv(_D * y * y + 1)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


def _edwards_add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % _P
    B = (Y1 + X1) * (Y2 + X2) % _P
    C = T1 * 2 * _D * T2 % _P
    Dd = Z1 * 2 * Z2 % _P
    E = B - A
    F = Dd - C
    G = Dd + C
    H = B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _edwards_double(P):
    return _edwards_add(P, P)


def _scalarmult(P, e: int):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_double(P)
        e >>= 1
    return Q


_By = 4 * _modp_inv(5) % _P
_Bx = _xrecover(_By)
_B = (_Bx % _P, _By % _P, 1, (_Bx * _By) % _P)


def _encodepoint(P) -> bytes:
    X, Y, Z, _T = P
    zi = _modp_inv(Z)
    x = X * zi % _P
    y = Y * zi % _P
    y |= (x & 1) << 255
    return y.to_bytes(32, "little")


def _decodepoint(s: bytes):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _P - x
    if (y * y - x * x - 1 - _D * x * x * y * y) % _P != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, x * y % _P)


def _ed25519_verify(pk: bytes, signature: bytes, message: bytes) -> bool:
    if len(pk) != 32 or len(signature) != 64:
        return False
    try:
        A = _decodepoint(pk)
        Rpt = _decodepoint(signature[:32])
    except ValueError:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + pk + message).digest(), "little") % _L
    sB = _scalarmult(_B, S)
    hA = _scalarmult(A, h)
    RhA = _edwards_add(Rpt, hA)
    return _encodepoint(_scalarmult(sB, 8)) == _encodepoint(_scalarmult(RhA, 8))


def _parse_pubkey(pubkey: str) -> tuple[bytes, bytes]:
    """Return (key_id[8], pk[32]) from minisign pubkey body or full file text."""
    text = pubkey.strip()
    if "\n" in text:
        lines = [ln for ln in text.splitlines() if ln.strip()]
        b64 = lines[-1].strip()
    else:
        b64 = text
    raw = base64.b64decode(b64)
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise VerificationError("公钥格式无效")
    return raw[2:10], raw[10:42]


def verify_signature(data: bytes, signature: bytes | str | Path, pubkey: Optional[str] = None) -> bool:
    """Verify minisign signature over data. pubkey defaults to PUBKEY."""
    if pubkey is None:
        pubkey = PUBKEY
    try:
        key_id, pk = _parse_pubkey(pubkey)
    except Exception:
        return False
    if isinstance(signature, (str, Path)):
        sig_text = Path(signature).read_text(encoding="utf-8")
    else:
        try:
            sig_text = signature.decode("utf-8")
        except UnicodeDecodeError:
            return False
    lines = sig_text.splitlines()
    if len(lines) < 4:
        return False
    try:
        sig_raw = base64.b64decode(lines[1].strip())
        global_sig = base64.b64decode(lines[3].strip())
    except Exception:
        return False
    if len(sig_raw) != 74 or len(global_sig) != 64:
        return False
    sig_alg = sig_raw[:2]
    if sig_raw[2:10] != key_id:
        return False
    sig = sig_raw[10:74]
    if sig_alg == b"ED":
        message = hashlib.blake2b(data, digest_size=64).digest()
    elif sig_alg == b"Ed":
        message = data
    else:
        return False
    if not _ed25519_verify(pk, sig, message):
        return False
    trusted = lines[2]
    prefix = "trusted comment: "
    if not trusted.startswith(prefix):
        return False
    tc = trusted[len(prefix) :].encode("utf-8")
    return _ed25519_verify(pk, global_sig, sig + tc)


# ---------------------------------------------------------------------------
# Device fingerprint
# ---------------------------------------------------------------------------

def _machine_id() -> str:
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            if m:
                return m.group(1)
        elif system == "Linux":
            for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                p = Path(path)
                if p.is_file():
                    return p.read_text(encoding="utf-8").strip()
        elif system == "Windows":
            import winreg  # type: ignore

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
            ) as key:
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                return str(val)
    except Exception:
        pass
    return str(uuid_getnode())


def uuid_getnode() -> int:
    import uuid

    return uuid.getnode()


def device_fingerprint() -> str:
    raw = "|".join(
        [
            "intel-kit",
            platform.system(),
            platform.machine(),
            _machine_id(),
            getpass.getuser(),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Errors / messaging
# ---------------------------------------------------------------------------

_ERROR_MESSAGES = {
    "invalid_key": "激活码无效。",
    "bad_request": "请求无效，请检查激活码格式。",
    "revoked": "激活码已吊销。",
    "device_limit": "已达设备数量上限，无法在此设备激活。",
    "device_not_activated": "此设备尚未激活。",
    "daily_cap": "今日下载次数已达上限，请明天再试。",
    "no_release": "没有可用的安装包版本。",
    "network": "网络错误，无法连接下载服务。",
    "verification": "软件包校验失败，已删除临时文件并中止安装。",
    "link_expired": "下载链接已过期，请重试。",
    "bad_signature": "下载签名无效。",
    "not_found": "服务返回未找到。",
}


def message_for_error(error: str) -> str:
    return _ERROR_MESSAGES.get(error, "安装失败，请稍后重试。")


def exit_code_for_error(http_status: int, error: str) -> int:
    if error in ("invalid_key", "revoked", "bad_request"):
        return EXIT_INVALID
    if error == "device_limit":
        return EXIT_DEVICE_LIMIT
    if error == "daily_cap":
        return EXIT_DAILY_CAP
    if error in ("network",) or http_status == 0:
        if error == "verification":
            return EXIT_VERIFY
        if error in ("invalid_key", "revoked", "bad_request"):
            return EXIT_INVALID
        if error == "device_limit":
            return EXIT_DEVICE_LIMIT
        if error == "daily_cap":
            return EXIT_DAILY_CAP
        if error == "verification":
            return EXIT_VERIFY
        return EXIT_NETWORK
    if http_status == 401:
        return EXIT_INVALID
    if http_status == 403:
        if error == "device_limit":
            return EXIT_DEVICE_LIMIT
        return EXIT_INVALID
    if http_status == 429:
        return EXIT_DAILY_CAP
    if error == "verification":
        return EXIT_VERIFY
    return EXIT_NETWORK


def mask_key(key: str) -> str:
    key = key.strip()
    parts = key.split("-")
    last = parts[-1] if parts else ""
    last4 = last[-4:] if len(last) >= 4 else last
    return f"IK-****-…-{last4}"


# ---------------------------------------------------------------------------
# HTTP helpers / SSL
# ---------------------------------------------------------------------------

def _ssl_context() -> ssl.SSLContext:
    """Build a verifying SSL context; honour SSL_CERT_FILE, prefer certifi."""
    cafile = os.environ.get("SSL_CERT_FILE")
    if cafile and Path(cafile).is_file():
        return ssl.create_default_context(cafile=cafile)
    try:
        import certifi  # optional; may be absent on bare stdlib installs

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _is_cert_error(exc: BaseException) -> bool:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    if isinstance(exc, ssl.SSLError):
        msg = str(exc).upper()
        return "CERTIFICATE" in msg or "CERT" in msg
    reason = getattr(exc, "reason", None)
    if isinstance(reason, BaseException):
        return _is_cert_error(reason)
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, BaseException):
        return _is_cert_error(cause)
    return False


def _print_ssl_hint_if_needed(exc: BaseException) -> None:
    if _is_cert_error(exc):
        print(_SSL_HINT, file=sys.stderr)


def _http_json(
    method: str,
    url: str,
    body: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: float = 60.0,
) -> tuple[int, Any]:
    data = None
    hdrs = {"Accept": "application/json", "User-Agent": CLIENT}
    if headers:
        hdrs.update(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            raw = resp.read()
            status = resp.getcode()
            if not raw:
                return status, {}
            return status, json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            payload = {"error": "network", "message": message_for_error("network")}
        if "error" not in payload:
            payload["error"] = "network"
        raise APIError(payload.get("error", "network"), payload.get("message") or message_for_error(payload.get("error", "network")), e.code) from e
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as e:
        _print_ssl_hint_if_needed(e)
        raise APIError("network", message_for_error("network"), 0) from e


def _download(url: str, dest: Path, expected_size: Optional[int] = None, timeout: float = 60.0) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": CLIENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
            data = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ssl.SSLError) as e:
        _print_ssl_hint_if_needed(e)
        raise APIError("network", message_for_error("network"), 0) from e
    if expected_size is not None and len(data) != expected_size:
        raise VerificationError(f"下载大小不符：期望 {expected_size}，实际 {len(data)}")
    dest.write_bytes(data)


# ---------------------------------------------------------------------------
# Home layout / unpack
# ---------------------------------------------------------------------------

def default_home() -> Path:
    env = os.environ.get("INTEL_KIT_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".intel-kit"


def ensure_home_dir(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass


def check_sha256(path: Path, expected_hex: str) -> None:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest().lower() != expected_hex.lower():
        raise VerificationError("sha256 不匹配")


def _is_within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_unpack(tar_path: Path, dest_parent: Path, version: str) -> Path:
    """Unpack package into dest_parent/<version>/ which contains intel-kit contents.

    Archive must have a single top directory intel-kit-<version>/.
    Files land in dest_parent/<version>/ (contents of that top dir).
    """
    expected_top = f"intel-kit-{version}"
    dest = dest_parent / version
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "r:*") as tf:
        members = tf.getmembers()
        if not members:
            raise VerificationError("安装包为空")
        tops = set()
        for m in members:
            name = m.name
            if name.startswith("/") or name.startswith("\\") or re.match(r"^[A-Za-z]:[\\/]", name):
                raise VerificationError("安装包含绝对路径")
            norm = name.replace("\\", "/")
            parts = [p for p in norm.split("/") if p not in ("", ".")]
            if any(p == ".." for p in parts):
                raise VerificationError("安装包含路径穿越")
            if not parts:
                continue
            tops.add(parts[0])
            if m.issym() or m.islnk():
                link = m.linkname or ""
                if link.startswith("/") or link.startswith("\\") or re.match(r"^[A-Za-z]:[\\/]", link):
                    raise VerificationError("符号链接指向包外")
                link_parts = [p for p in link.replace("\\", "/").split("/") if p not in ("", ".")]
                # Resolve relative to member's directory
                base_parts = parts[:-1]
                resolved = list(base_parts)
                for lp in link_parts:
                    if lp == "..":
                        if not resolved:
                            raise VerificationError("符号链接逃逸")
                        resolved.pop()
                    else:
                        resolved.append(lp)
                if not resolved or resolved[0] != expected_top:
                    raise VerificationError("符号链接逃逸")
            if m.isdev() or (hasattr(tarfile, "FIFOTYPE") and m.type == tarfile.FIFOTYPE):
                raise VerificationError("安装包含设备文件")
            # CHRTYPE/BLKTYPE
            if m.type in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                raise VerificationError("安装包含设备文件")

        if tops != {expected_top}:
            raise VerificationError(f"安装包顶层目录必须是 {expected_top}/")

        for m in members:
            norm = m.name.replace("\\", "/")
            parts = [p for p in norm.split("/") if p not in ("", ".")]
            if not parts:
                continue
            rel = "/".join(parts[1:])  # strip top dir
            if not rel:
                continue
            out = dest / rel
            if not _is_within(dest, out if not (m.isdir()) else out):
                raise VerificationError("解压路径越界")
            if m.isdir():
                out.mkdir(parents=True, exist_ok=True)
            elif m.issym():
                out.parent.mkdir(parents=True, exist_ok=True)
                if out.exists() or out.is_symlink():
                    out.unlink()
                os.symlink(m.linkname, out)
                if not _is_within(dest, out.resolve()):
                    out.unlink(missing_ok=True)
                    raise VerificationError("符号链接逃逸")
            elif m.isreg():
                out.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(m)
                if src is None:
                    raise VerificationError("无法读取包内文件")
                with out.open("wb") as f:
                    shutil.copyfileobj(src, f)
                mode = m.mode & 0o755
                if mode:
                    os.chmod(out, mode)
            else:
                raise VerificationError("不支持的归档条目类型")

    return dest


def _atomic_point_current(app_dir: Path, version_dir: Path) -> None:
    current = app_dir / "current"
    if platform.system() == "Windows":
        txt = app_dir / "current.txt"
        tmp = app_dir / "current.txt.tmp"
        tmp.write_text(str(version_dir.resolve()), encoding="utf-8")
        tmp.replace(txt)
        return
    tmp_link = app_dir / f".current.tmp.{os.getpid()}"
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    os.symlink(version_dir.resolve(), tmp_link)
    os.replace(tmp_link, current)


def write_launcher(home: Path) -> None:
    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    if platform.system() == "Windows":
        # intel.cmd — use current.txt if no symlink; prefer venv python
        cmd = home / "bin" / "intel.cmd"
        cmd.write_text(
            "@echo off\r\n"
            "setlocal\r\n"
            f'set "IK_HOME={home}"\r\n'
            'set "INTEL_KIT_HOME=%IK_HOME%"\r\n'
            'if exist "%IK_HOME%\\app\\current\\src" (\r\n'
            '  set "PP=%IK_HOME%\\app\\current\\src"\r\n'
            ") else (\r\n"
            '  set /p CUR=<"%IK_HOME%\\app\\current.txt"\r\n'
            '  set "PP=%CUR%\\src"\r\n'
            ")\r\n"
            'set "PYTHONPATH=%PP%"\r\n'
            'if exist "%IK_HOME%\\venv\\Scripts\\python.exe" (\r\n'
            '  set "PY=%IK_HOME%\\venv\\Scripts\\python.exe"\r\n'
            ") else (\r\n"
            '  set "PY=python3"\r\n'
            ")\r\n"
            '"%PY%" -m intelkit.cli %*\r\n',
            encoding="utf-8",
        )
    sh = home / "bin" / "intel"
    sh.write_text(
        "#!/bin/sh\n"
        f'HOME_IK="{home}"\n'
        'export INTEL_KIT_HOME="$HOME_IK"\n'
        'export PYTHONPATH="$HOME_IK/app/current/src"\n'
        'if [ -x "$HOME_IK/venv/bin/python" ]; then\n'
        '  PY="$HOME_IK/venv/bin/python"\n'
        "else\n"
        "  PY=python3\n"
        "fi\n"
        'exec "$PY" -m intelkit.cli "$@"\n',
        encoding="utf-8",
    )
    os.chmod(sh, 0o755)


def install_deps(home: Path, version_dir: Path) -> None:
    """Create/refresh <home>/venv and pip-install version_dir/requirements.txt."""
    venv_dir = home / "venv"
    req = version_dir / "requirements.txt"
    try:
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        raise DepsError(_DEPS_HINT) from e

    if platform.system() == "Windows":
        vpy = venv_dir / "Scripts" / "python.exe"
    else:
        vpy = venv_dir / "bin" / "python"
    if not vpy.is_file():
        raise DepsError(_DEPS_HINT)

    if not req.is_file():
        return

    try:
        subprocess.run(
            [str(vpy), "-m", "pip", "install", "-q", "-r", str(req)],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as e:
        raise DepsError(_DEPS_HINT) from e


def write_license_json(home: Path, license_id: str, version: str, update_expires_at: Any) -> None:
    payload = {
        "license_id": license_id,
        "version": version,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "update_expires_at": update_expires_at,
    }
    path = home / "license.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_env_key(home: Path, key: str) -> None:
    ensure_home_dir(home)
    env_path = home / ".env"
    lines: list[str] = []
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("INTEL_KIT_LICENSE_KEY="):
                continue
            lines.append(line)
    lines.append(f"INTEL_KIT_LICENSE_KEY={key}")
    text = "\n".join(lines) + "\n"
    # write then chmod 600
    fd = os.open(str(env_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(env_path, 0o600)


def installed_version(home: Path) -> Optional[str]:
    lic = home / "license.json"
    if lic.is_file():
        try:
            return json.loads(lic.read_text(encoding="utf-8")).get("version")
        except json.JSONDecodeError:
            pass
    ver_file = home / "app" / "current" / "VERSION"
    if ver_file.is_file():
        return ver_file.read_text(encoding="utf-8").strip()
    return None


# ---------------------------------------------------------------------------
# Install / check
# ---------------------------------------------------------------------------

def run_check(key: str, home: Path, api_url: str) -> int:
    fp = device_fingerprint()
    try:
        status, data = _http_json(
            "GET",
            f"{api_url.rstrip('/')}/v1/latest",
            headers={
                "X-License-Key": key,
                "X-Device-Fingerprint": fp,
            },
        )
    except APIError as e:
        print(e.message or message_for_error(e.error), file=sys.stderr)
        return exit_code_for_error(e.http_status, e.error)
    avail = data.get("version", "?")
    cur = installed_version(home) or "未安装"
    print(f"已安装版本：{cur}")
    print(f"可用版本：{avail}")
    return EXIT_OK


def run_install(
    key: str,
    home: Path,
    api_url: str,
    *,
    skip_deps: bool = False,
    install_deps_fn: Optional[Callable[[Path, Path], None]] = None,
) -> int:
    ensure_home_dir(home)
    fp = device_fingerprint()
    cur = installed_version(home)
    print(f"正在激活（{mask_key(key)}）…")
    try:
        _status, data = _http_json(
            "POST",
            f"{api_url.rstrip('/')}/v1/activate",
            body={
                "license_key": key,
                "device_fingerprint": fp,
                "client": CLIENT,
                "current_version": cur,
            },
        )
    except APIError as e:
        msg = e.message if e.message else message_for_error(e.error)
        # Prefer our mapped Chinese if server message empty; always print Chinese map when known
        if e.error in _ERROR_MESSAGES:
            msg = message_for_error(e.error)
        print(msg, file=sys.stderr)
        return exit_code_for_error(e.http_status, e.error)

    version = data["version"]
    sha256 = data["sha256"]
    size = int(data["size"])
    package_url = data["package_url"]
    signature_url = data["signature_url"]
    license_id = data["license_id"]
    update_expires_at = data.get("update_expires_at")

    deps_fn = install_deps_fn if install_deps_fn is not None else install_deps

    tmpdir = Path(tempfile.mkdtemp(prefix="intel-kit-dl-"))
    pkg_path = tmpdir / "package.tar.gz"
    sig_path = tmpdir / "package.tar.gz.minisig"
    try:
        print("正在下载安装包…")
        _download(package_url, pkg_path, expected_size=size)
        _download(signature_url, sig_path, expected_size=None)
        print("正在校验签名与哈希…")
        if not verify_signature(pkg_path.read_bytes(), sig_path.read_bytes()):
            raise VerificationError("签名校验失败")
        check_sha256(pkg_path, sha256)
        app_dir = home / "app"
        app_dir.mkdir(parents=True, exist_ok=True)
        print(f"正在解压到 {app_dir / version} …")
        version_dir = safe_unpack(pkg_path, app_dir, version)
        # Deps before switching current — install stays atomic
        if not skip_deps:
            print("正在创建虚拟环境并安装依赖…")
            try:
                deps_fn(home, version_dir)
            except DepsError:
                raise
            except Exception as e:
                raise DepsError(_DEPS_HINT) from e
        _atomic_point_current(app_dir, version_dir)
        write_launcher(home)
        write_license_json(home, license_id, version, update_expires_at)
        write_env_key(home, key)
    except DepsError:
        print(_DEPS_HINT, file=sys.stderr)
        return EXIT_DEPS
    except VerificationError as e:
        print(message_for_error("verification"), file=sys.stderr)
        print(str(e), file=sys.stderr)
        return EXIT_VERIFY
    except APIError as e:
        msg = message_for_error(e.error) if e.error in _ERROR_MESSAGES else (e.message or message_for_error("network"))
        print(msg, file=sys.stderr)
        return exit_code_for_error(e.http_status, e.error)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print("安装完成。下一步：按 SETUP.md 第 3 步开始问用户问题。")
    return EXIT_OK


def resolve_key(arg_key: Optional[str]) -> str:
    if arg_key:
        return arg_key.strip()
    env = os.environ.get("INTEL_KIT_LICENSE_KEY")
    if env:
        return env.strip()
    return getpass.getpass("请输入激活码：").strip()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="intel-kit 安装程序")
    parser.add_argument("--key", help="激活码")
    parser.add_argument("--home", type=Path, help="安装目录（默认 ~/.intel-kit）")
    parser.add_argument("--api", dest="api_url", help="API 基址")
    parser.add_argument("--check", action="store_true", help="仅检查版本")
    parser.add_argument(
        "--skip-deps",
        action="store_true",
        help="跳过 venv/pip 依赖安装（测试用）",
    )
    args = parser.parse_args(argv)

    home = (args.home or default_home()).expanduser()
    api_url = args.api_url or os.environ.get("INTEL_KIT_API") or DEFAULT_API
    try:
        key = resolve_key(args.key)
    except (EOFError, KeyboardInterrupt):
        print("已取消。", file=sys.stderr)
        return EXIT_INVALID
    if not key:
        print(message_for_error("invalid_key"), file=sys.stderr)
        return EXIT_INVALID

    if args.check:
        return run_check(key, home, api_url)
    return run_install(key, home, api_url, skip_deps=args.skip_deps)


if __name__ == "__main__":
    sys.exit(main())
