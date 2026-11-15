"""Bounded, authenticated messages for a user-enabled ETX session.

This module has no clipboard, networking, filesystem-policy or process-execution
side effects. OpenSSL supplies the cryptography; the wire format is our own.
"""
import base64
import hashlib
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

MAGIC = 'ETX_SESSION_V1\n'
MAGIC_CRLF = 'ETX_SESSION_V1\r\n'
MAX_WIRE = 786432
MAX_PLAIN = 524288
MAX_CHUNK = 262144
MAX_FILE = 16777216
MAX_SESSION = 28800
MAX_REQUEST_LIFE = 120
ID = re.compile(r'[0-9a-f]{32}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
OPS = frozenset(('hello', 'close', 'read_batch', 'read_begin', 'read_chunk', 'read_log', 'search',
    'upload_begin', 'upload_chunk', 'upload_status', 'commit', 'restore', 'receipt',
    'workers', 'submit_simmer', 'status', 'status_many', 'submit_task', 'task_result', 'release_selftests'))


class Rejected(Exception):
    """Only a fixed diagnostic code may cross the transport boundary."""
    def __init__(self, code):
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,63}', code):
            code = 'INTERNAL_ERROR'
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise Rejected(code)


def is_frame(value):
    return isinstance(value,str) and value.startswith((MAGIC,MAGIC_CRLF))


def normalize_frame(value):
    require(is_frame(value),'BAD_FRAME')
    # ETX normalises the outer LF to CRLF on the measured client route.
    # Never change the signed/encrypted payload or its declared digest.
    return MAGIC+value[len(MAGIC_CRLF):] if value.startswith(MAGIC_CRLF) else value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(',', ':')).encode('utf-8')
    except (ValueError, TypeError, UnicodeError):
        raise Rejected('BAD_JSON') from None


def _pairs(items):
    out = {}
    for key, value in items:
        require(key not in out, 'DUPLICATE_KEY')
        out[key] = value
    return out


def strict_json(data, limit=MAX_PLAIN):
    require(isinstance(data, bytes) and len(data) <= limit, 'MESSAGE_SIZE_LIMIT')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Rejected('BAD_JSON')))
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected('BAD_JSON') from None
    require(isinstance(value, dict), 'BAD_JSON')
    return value


def keys(value, names):
    require(isinstance(value, dict) and set(value) == set(names), 'BAD_FIELDS')


def identifier(value):
    require(isinstance(value, str) and ID.fullmatch(value), 'BAD_ID')
    return value


def sha(value):
    require(isinstance(value, str) and SHA.fullmatch(value), 'BAD_SHA256')
    return value


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, 'BAD_INTEGER')
    return value


def encode_bytes(data):
    return base64.b64encode(data).decode('ascii')


def decode_bytes(text, limit=MAX_CHUNK):
    require(isinstance(text, str) and len(text) <= ((limit + 2) // 3) * 4,
        'CHUNK_SIZE_LIMIT')
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, UnicodeError):
        raise Rejected('BAD_BASE64') from None
    require(len(data) <= limit, 'CHUNK_SIZE_LIMIT')
    return data


def request(session, operation, arguments, request_id=None, now=None):
    now = int(time.time() if now is None else now)
    return {'v': 1, 'session': identifier(session),
        'id': identifier(request_id or uuid.uuid4().hex), 'issued': now,
        'expires': now + MAX_REQUEST_LIFE, 'op': operation, 'args': arguments}


def validate_request(message, session, now=None):
    keys(message, ('v', 'session', 'id', 'issued', 'expires', 'op', 'args'))
    require(type(message['v']) is int and message['v'] == 1, 'BAD_VERSION')
    identifier(message['id'])
    identifier(message['session'])
    require(message['op'] in OPS and isinstance(message['args'], dict), 'BAD_OPERATION')
    now = int(time.time() if now is None else now)
    issued = integer(message['issued'], 0, 2**63 - 1)
    expires = integer(message['expires'], issued, issued + MAX_REQUEST_LIFE)
    require(issued <= now + 30 and now <= expires, 'REQUEST_EXPIRED')
    if message['op'] != 'hello':
        require(message['session'] == session, 'WRONG_SESSION')
    return message


def operation_digest(message):
    # A reconnected session may renew its transport expiry without creating a
    # second business operation. The stable ID remains bound to op + arguments.
    return digest(canonical({'op': message['op'], 'args': message['args']}))


class Crypto:
    def __init__(self, signer_cert, signer_key, trusted_cert, recipient_cert,
                 openssl='openssl'):
        self.signer_cert = str(signer_cert)
        self.signer_key = str(signer_key)
        self.trusted_cert = str(trusted_cert)
        self.recipient_cert = str(recipient_cert)
        self.openssl = str(openssl)
        self.elapsed_seconds = 0.0
        self.calls = 0

    def run(self, args, data=None):
        started = time.perf_counter()
        self.calls += 1
        try:
            reply = subprocess.run([self.openssl, *args], input=data,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=30, check=True)
            require(len(reply.stdout) <= MAX_WIRE, 'CRYPTO_SIZE_LIMIT')
            return reply.stdout
        except (OSError, subprocess.SubprocessError):
            raise Rejected('CRYPTO_FAILED') from None
        finally:
            self.elapsed_seconds += time.perf_counter() - started

    def fingerprint(self, cert):
        return digest(self.run(['x509', '-in', str(cert), '-outform', 'DER']))

    def seal(self, message, encrypted=True, advertise_cert=False):
        plain = canonical(message)
        require(len(plain) <= MAX_PLAIN, 'MESSAGE_SIZE_LIMIT')
        signed = self.run(['cms', '-sign', '-binary', '-nodetach', '-nocerts',
            '-md', 'sha256', '-signer', self.signer_cert, '-inkey', self.signer_key,
            '-outform', 'DER'], plain)
        data = self.run(['cms', '-encrypt', '-binary', '-aes256', '-outform', 'DER',
            '-recip', self.recipient_cert, '-keyopt', 'rsa_padding_mode:oaep',
            '-keyopt', 'rsa_oaep_md:sha256'], signed) if encrypted else signed
        cert = Path(self.signer_cert).read_bytes() if advertise_cert else b''
        require(len(cert) <= 8192, 'BAD_CERTIFICATE')
        frame = {'v': 1, 'encrypted': encrypted, 'bytes': len(data),
            'sha256': digest(data), 'certificate': encode_bytes(cert),
            'data': encode_bytes(data)}
        wire = MAGIC + canonical(frame).decode('ascii')
        require(len(wire.encode('ascii')) <= MAX_WIRE, 'MESSAGE_SIZE_LIMIT')
        return wire

    def open(self, wire, allow_signed_hello=False):
        require(isinstance(wire, str), 'BAD_FRAME')
        try:
            raw = wire.encode('ascii')
        except UnicodeError:
            raise Rejected('BAD_FRAME') from None
        require(len(raw) <= MAX_WIRE and is_frame(wire), 'BAD_FRAME')
        raw=normalize_frame(wire).encode('ascii')
        frame = strict_json(raw[len(MAGIC):], MAX_WIRE)
        keys(frame, ('v', 'encrypted', 'bytes', 'sha256', 'certificate', 'data'))
        require(type(frame['v']) is int and frame['v'] == 1 and
            type(frame['encrypted']) is bool, 'BAD_FRAME')
        data = decode_bytes(frame['data'], MAX_WIRE)
        require(frame['bytes'] == len(data) and frame['sha256'] == digest(data),
            'FRAME_HASH_MISMATCH')
        require(frame['encrypted'] or allow_signed_hello, 'ENCRYPTION_REQUIRED')
        signed = self.run(['cms', '-decrypt', '-binary', '-inform', 'DER',
            '-recip', self.signer_cert, '-inkey', self.signer_key], data) \
            if frame['encrypted'] else data
        plain = self.run(['cms', '-verify', '-binary', '-inform', 'DER',
            '-nointern', '-noverify', '-certfile', self.trusted_cert], signed)
        message = strict_json(plain)
        require(frame['encrypted'] or message.get('op') == 'hello',
            'ENCRYPTION_REQUIRED')
        return message


def advertised_certificate(wire):
    require(is_frame(wire) and len(wire) <= MAX_WIRE, 'BAD_FRAME')
    wire=normalize_frame(wire)
    frame = strict_json(wire[len(MAGIC):].encode('ascii'), MAX_WIRE)
    return decode_bytes(frame.get('certificate'), 8192)
