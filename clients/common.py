"""Small, Python 3.6-compatible primitives shared by both bridge endpoints."""
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

MAX_REQUEST = 32768
MAX_RESULT = 8 * 1024 * 1024
ID_RE = re.compile(r"^[0-9a-f]{32}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION = 1


class BridgeError(RuntimeError):
    pass


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def decoded(raw, limit=MAX_RESULT):
    if len(raw) > limit:
        raise BridgeError("PAYLOAD_TOO_LARGE")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BridgeError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(BridgeError("NONFINITE_JSON")))
    except (UnicodeError, ValueError):
        raise BridgeError("INVALID_JSON")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata_tool_ok(value):
    """MCP transport success alone is not vendor operation success."""
    if not isinstance(value, dict) or value.get("isError") is True:
        return False
    bodies = []
    structured = value.get("structuredContent")
    if isinstance(structured, dict):
        bodies.append(structured)
    for block in value.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            raw = block.get("text", "")
            if not isinstance(raw, str) or not raw.strip():
                continue
            try:
                bodies.append(decoded(raw.encode("utf-8")))
            except BridgeError:
                bodies.append(raw)
    return bool(bodies) and all(not isinstance(body, dict) or
                               (body.get("ok") is not False and not body.get("error"))
                               for body in bodies)


def metadata_readiness(result):
    calls = result.get("metadata_calls", {})
    required = ("xverif_ping", "xverif_tools", "xverif_debug_list_actions")
    failed = [name for name in required if not metadata_tool_ok(calls.get(name))]
    return {"mcp_connected": result.get("connected") is True,
            "ping_ok": metadata_tool_ok(calls.get("xverif_ping")),
            "action_catalog_ready": result.get("connected") is True and not failed,
            "failed_metadata_tools": failed,
            "waveform_queries_enabled": False}


def no_links(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise BridgeError("UNSAFE_PATH")
    for part in [path] + list(path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise BridgeError("LINK_NOT_ALLOWED")
    return path


def regular(path, limit=None, private=False):
    path = no_links(Path(path).absolute())
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise BridgeError("REGULAR_FILE_REQUIRED")
    if limit is not None and info.st_size > limit:
        raise BridgeError("FILE_TOO_LARGE")
    if private and os.name == "posix":
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise BridgeError("PRIVATE_FILE_PERMISSIONS")
    return path


def private_dir(path):
    path = no_links(Path(path).absolute())
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode):
        raise BridgeError("DIRECTORY_REQUIRED")
    if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise BridgeError("PRIVATE_DIRECTORY_PERMISSIONS")
    return path


def atomic_write(path, raw, mode=0o600):
    import tempfile
    path = no_links(Path(path).absolute())
    fd, name = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, str(path))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(argv, data=None, timeout=30, limit=MAX_RESULT, cwd=None, env=None):
    opts = {"creationflags": 0x08000000} if os.name == "nt" else {}
    try:
        result = subprocess.run([str(item) for item in argv], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, cwd=cwd, env=env, **opts)
    except subprocess.TimeoutExpired:
        raise BridgeError("PROCESS_TIMEOUT")
    if result.returncode:
        # Raw stderr can contain credentials, signal names, or vendor paths.
        raise BridgeError("PROCESS_FAILED_{}".format(result.returncode))
    if len(result.stdout) > limit or len(result.stderr) > MAX_RESULT:
        raise BridgeError("PROCESS_OUTPUT_TOO_LARGE")
    return result.stdout


def cms_encrypt(openssl, raw, certificate):
    regular(certificate, 65536)
    return run([openssl, "cms", "-encrypt", "-binary", "-aes256", "-outform", "DER", certificate],
               raw, limit=MAX_RESULT + 65536)


def cms_decrypt(openssl, raw, certificate, key):
    regular(certificate, 65536)
    regular(key, 65536, private=True)
    return run([openssl, "cms", "-decrypt", "-binary", "-inform", "DER",
                "-recip", certificate, "-inkey", key], raw)


def cms_sign(openssl, raw, certificate, key):
    regular(certificate, 65536)
    regular(key, 65536, private=True)
    return run([openssl, "cms", "-sign", "-binary", "-nodetach", "-nosmimecap",
                "-md", "sha256", "-outform", "DER", "-signer", certificate,
                "-inkey", key], raw)


def cms_verify(openssl, raw, certificate):
    regular(certificate, 65536)
    return run([openssl, "cms", "-verify", "-binary", "-inform", "DER",
                "-noverify", "-nointern", "-certfile", certificate], raw)


def validate_envelope(value, request_id, now=None):
    now = time.time() if now is None else now
    if not isinstance(value, dict) or value.get("version") != VERSION:
        raise BridgeError("BAD_VERSION")
    if not ID_RE.fullmatch(request_id) or value.get("request_id") != request_id:
        raise BridgeError("REQUEST_ID_MISMATCH")
    created, expires = value.get("created"), value.get("expires")
    if type(created) not in (int, float) or type(expires) not in (int, float):
        raise BridgeError("BAD_TIMESTAMP")
    if not (0 < expires - created <= 1800 and created <= now + 60 and now <= expires):
        raise BridgeError("REQUEST_EXPIRED")
    return value
