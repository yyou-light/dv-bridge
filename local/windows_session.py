"""Bounded Windows client for the canonical ETX session protocol.

Only native clipboard APIs are used. No windows are focused and no keys are
sent. Each invocation restores its owned plain-text clipboard lease and exits.
"""
import argparse
import contextlib
import ctypes
from ctypes import wintypes
import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'etx'))
from session_protocol import (Crypto, Rejected, require, request, strict_json,
    canonical, advertised_certificate, sha, MAX_WIRE, MAGIC,is_frame,normalize_frame)
from session_files import atomic_json

INTERRUPTION_RETRY_DELAY = 30
INTERRUPTION_WAIT_LIMIT = 300
INTERRUPTION_READ_ERRORS = frozenset(('CLIPBOARD_NOT_PLAIN_TEXT', 'CLIPBOARD_SIZE_LIMIT'))


def clipboard_text(data):
    # GlobalSize can include allocation padding after the aligned terminator.
    # Do not decode uninitialised bytes beyond the actual Unicode string.
    end=next((i for i in range(0,len(data)-1,2) if data[i:i+2]==b'\x00\x00'),None)
    require(end is not None,'CLIPBOARD_ENCODING_REJECTED')
    try:
        return data[:end].decode('utf-16-le')
    except UnicodeError:
        raise Rejected('CLIPBOARD_ENCODING_REJECTED') from None


def same_clipboard_text(left,right):
    if is_frame(left) and is_frame(right):
        return normalize_frame(left)==normalize_frame(right)
    return left==right


class Clipboard:
    def __init__(self):
        require(os.name=='nt','WINDOWS_REQUIRED')
        self.user=ctypes.WinDLL('user32',use_last_error=True)
        self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        self.user.OpenClipboard.argtypes=[ctypes.c_void_p]
        self.user.GetClipboardData.argtypes=[ctypes.c_uint]
        self.user.GetClipboardData.restype=ctypes.c_void_p
        self.user.SetClipboardData.argtypes=[ctypes.c_uint,ctypes.c_void_p]
        self.user.SetClipboardData.restype=ctypes.c_void_p
        self.user.GetClipboardSequenceNumber.restype=ctypes.c_uint
        self.user.GetClipboardFormatNameW.argtypes=[ctypes.c_uint,ctypes.c_wchar_p,ctypes.c_int]
        self.user.CreateWindowExW.argtypes=[ctypes.c_uint,ctypes.c_wchar_p,
            ctypes.c_wchar_p,ctypes.c_uint,ctypes.c_int,ctypes.c_int,ctypes.c_int,
            ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p]
        self.user.CreateWindowExW.restype=ctypes.c_void_p
        self.user.DestroyWindow.argtypes=[ctypes.c_void_p]
        self.user.PeekMessageW.argtypes=[ctypes.POINTER(wintypes.MSG),ctypes.c_void_p,
            ctypes.c_uint,ctypes.c_uint,ctypes.c_uint]
        self.user.TranslateMessage.argtypes=[ctypes.POINTER(wintypes.MSG)]
        self.user.DispatchMessageW.argtypes=[ctypes.POINTER(wintypes.MSG)]
        self.user.DispatchMessageW.restype=ctypes.c_ssize_t
        self.kernel.GlobalAlloc.argtypes=[ctypes.c_uint,ctypes.c_size_t]
        self.kernel.GlobalAlloc.restype=ctypes.c_void_p
        self.kernel.GlobalLock.argtypes=[ctypes.c_void_p]
        self.kernel.GlobalLock.restype=ctypes.c_void_p
        self.kernel.GlobalUnlock.argtypes=[ctypes.c_void_p]
        self.kernel.GlobalSize.argtypes=[ctypes.c_void_p]
        self.kernel.GlobalSize.restype=ctypes.c_size_t
        self.kernel.GlobalFree.argtypes=[ctypes.c_void_p]
        # A message-only owner satisfies SetClipboardData without showing,
        # activating or controlling any application window.
        self.owner=self.user.CreateWindowExW(0,'STATIC','ETX session clipboard owner',
            0,0,0,0,0,ctypes.c_void_p(-3),None,None,None)
        require(bool(self.owner),'CLIPBOARD_OWNER_FAILED')

    def close(self):
        if self.owner:
            self.pump()
            self.user.DestroyWindow(self.owner)
            self.owner=None

    def pump(self):
        # Service only this process's message queue. The protocol owner is a
        # message-only window; no other application is focused or controlled.
        message=wintypes.MSG()
        while self.user.PeekMessageW(ctypes.byref(message),None,0,0,1):
            self.user.TranslateMessage(ctypes.byref(message))
            self.user.DispatchMessageW(ctypes.byref(message))

    @contextlib.contextmanager
    def opened(self):
        self.pump()
        deadline=time.monotonic()+10
        while not self.user.OpenClipboard(self.owner):
            if time.monotonic()>=deadline:
                raise Rejected('CLIPBOARD_OPEN_BUSY')
            time.sleep(0.02)
        try:
            yield
        finally:
            self.user.CloseClipboard()
            self.pump()

    def _read(self):
        if self.user.CountClipboardFormats()==0:
            return None
        require(self.user.IsClipboardFormatAvailable(13),'CLIPBOARD_NOT_PLAIN_TEXT')
        handle=self.user.GetClipboardData(13)
        require(bool(handle),'CLIPBOARD_READ_FAILED')
        size=self.kernel.GlobalSize(handle)
        require(2<=size<=2*(MAX_WIRE+2),'CLIPBOARD_SIZE_LIMIT')
        pointer=self.kernel.GlobalLock(handle)
        require(bool(pointer),'CLIPBOARD_READ_FAILED')
        try:
            data=ctypes.string_at(pointer,size)
            return clipboard_text(data)
        finally:
            self.kernel.GlobalUnlock(handle)

    def read(self):
        with self.opened():
            return self._read()

    def sequence(self):
        # Observation only: do not open the clipboard or read user contents
        # while yielding it to the user after an interrupted exchange.
        self.pump()
        return self.user.GetClipboardSequenceNumber()

    def snapshot(self):
        with self.opened():
            text=self._read()
            formats=[]
            number=0
            total=0
            while True:
                number=self.user.EnumClipboardFormats(number)
                if not number:
                    break
                # Registered formats use byte-copyable global memory; preserve
                # bounded opaque OLE metadata as well as RTF/HTML text formats.
                # Standard GDI and private handle formats remain unsupported.
                allowed=number in (1,7,13,16) or 0xc000<=number<=0xffff
                format_name=None
                if number>=0xc000:
                    name=ctypes.create_unicode_buffer(256)
                    self.user.GetClipboardFormatNameW(number,name,256)
                    format_name=name.value
                if not allowed:
                    self.unsupported_format={'id':number,'name':format_name}
                require(allowed,'CLIPBOARD_FORMAT_NOT_RESTORABLE')
                handle=self.user.GetClipboardData(number)
                require(bool(handle),'CLIPBOARD_READ_FAILED')
                size=self.kernel.GlobalSize(handle)
                total+=size
                require(0<size and total<=4*1024*1024,'CLIPBOARD_SIZE_LIMIT')
                pointer=self.kernel.GlobalLock(handle)
                require(bool(pointer),'CLIPBOARD_READ_FAILED')
                try:
                    formats.append((number,ctypes.string_at(pointer,size)))
                finally:
                    self.kernel.GlobalUnlock(handle)
            return {'text':text,'formats':formats,
                'sequence':self.user.GetClipboardSequenceNumber()}

    def put(self,number,raw):
        memory=self.kernel.GlobalAlloc(0x0002,len(raw))
        require(bool(memory),'CLIPBOARD_WRITE_FAILED')
        transferred=False
        try:
            pointer=self.kernel.GlobalLock(memory)
            require(bool(pointer),'CLIPBOARD_WRITE_FAILED')
            try:
                ctypes.memmove(pointer,raw,len(raw))
            finally:
                self.kernel.GlobalUnlock(memory)
            require(bool(self.user.SetClipboardData(number,memory)),'CLIPBOARD_WRITE_FAILED')
            transferred=True
        finally:
            if not transferred:
                self.kernel.GlobalFree(memory)

    def restore(self,snapshot,expected):
        with self.opened():
            require(same_clipboard_text(self._read(),expected),'CLIPBOARD_USER_CHANGED')
            require(self.user.EmptyClipboard(),'CLIPBOARD_WRITE_FAILED')
            for number,raw in snapshot['formats']:
                self.put(number,raw)

    def write(self,text,expected=None,compare=False,expected_sequence=None):
        with self.opened():
            if compare:
                require(same_clipboard_text(self._read(),expected),'CLIPBOARD_USER_CHANGED')
            if expected_sequence is not None:
                require(self.user.GetClipboardSequenceNumber()==expected_sequence,
                    'CLIPBOARD_USER_CHANGED')
            require(self.user.EmptyClipboard(),'CLIPBOARD_WRITE_FAILED')
            if text is None:
                return
            if is_frame(text):
                # Windows text clipboard formats specify CRLF line endings.
                # The peer canonicalizes only this unsigned outer header.
                text=normalize_frame(text).replace(MAGIC,'ETX_SESSION_V1\r\n',1)
            self.put(13,(text+'\x00').encode('utf-16-le'))
            if text.isascii():
                # ETX can request ANSI/OEM text while forwarding PRIMARY.
                # Materialize these formats instead of relying on delayed
                # synthesis by a clipboard owner that exits after each RPC.
                raw=(text+'\x00').encode('ascii')
                self.put(1,raw)
                self.put(7,raw)
                self.put(16,(0x409).to_bytes(4,'little'))


@contextlib.contextmanager
def packet_mutex():
    require(os.name=='nt','WINDOWS_REQUIRED')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_bool,ctypes.c_wchar_p]
    kernel.CreateMutexW.restype=ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint]
    kernel.ReleaseMutex.argtypes=[ctypes.c_void_p]
    kernel.CloseHandle.argtypes=[ctypes.c_void_p]
    handle=kernel.CreateMutexW(None,False,'Local\\ETX_X11_WindowsPacket')
    require(bool(handle),'CLIPBOARD_MUTEX_FAILED')
    acquired=False
    try:
        require(kernel.WaitForSingleObject(handle,0) in (0,0x80),'CLIPBOARD_BUSY')
        acquired=True
        yield
    finally:
        if acquired:
            kernel.ReleaseMutex(handle)
        kernel.CloseHandle(handle)


class Client:
    def __init__(self,config,clipboard,now=time.time,sleep=time.sleep,monotonic=None):
        self.config=config
        self.rpc_metrics=[]
        self.clipboard=clipboard
        self.now=now
        self.sleep=sleep
        self.monotonic=monotonic or (time.monotonic if now is time.time else now)
        self.timeout=config.get('rpc_timeout_seconds',30)
        require(type(self.timeout) is int and 1<=self.timeout<=60,'BAD_RPC_TIMEOUT')
        self.session=None
        self.session_expires=0
        self.crypto=Crypto(config['signer_cert'],config['signer_key'],
            config['server_cert'],config['server_cert'],config.get('openssl','openssl'))
        connection=config.get('connection_state')
        if connection and Path(connection).exists() and Path(config['server_cert']).exists():
            value=strict_json(Path(connection).read_bytes())
            if value.get('fingerprint')==self.crypto.fingerprint(config['server_cert']):
                self.session=value.get('session')
                self.session_expires=value.get('expires',0)

    def verify_protocol_baseline(self,text,pairing_fingerprint):
        """Recognize our authenticated protocol residue without consuming it."""
        temporary=None
        try:
            checker=self.crypto
            if pairing_fingerprint is not None:
                certificate=advertised_certificate(text)
                require(bool(certificate),'PEER_CERTIFICATE_REQUIRED')
                fd,name=tempfile.mkstemp(prefix='.peer-',dir=str(Path(self.config['server_cert']).parent))
                temporary=Path(name)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(certificate)
                require(self.crypto.fingerprint(temporary)==sha(pairing_fingerprint),
                    'PEER_FINGERPRINT_MISMATCH')
                checker=Crypto(self.config['signer_cert'],self.config['signer_key'],
                    temporary,temporary,self.config.get('openssl','openssl'))
            reply=checker.open(text)
            require(reply.get('v')==1 and 'id' in reply and 'session' in reply and
                type(reply.get('expires')) is int,'RESPONSE_MISMATCH')
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)

    def exchange(self,message,pairing_fingerprint=None):
        started = time.perf_counter()
        crypto_before = getattr(self.crypto, 'elapsed_seconds', 0.0)
        self.phase_metrics = {'seal_seconds': 0.0, 'verify_seconds': 0.0,
            'response_wait_seconds': 0.0, 'clipboard_restore_seconds': 0.0}
        try:
            return self._exchange_with_retry(message, pairing_fingerprint)
        finally:
            self.rpc_metrics.append({'id': message['id'], 'op': message['op'],
                'seconds': round(time.perf_counter() - started, 6),
                'crypto_seconds': round(getattr(self.crypto, 'elapsed_seconds', 0.0) - crypto_before, 6),
                **{k: round(v, 6) for k, v in self.phase_metrics.items()}})

    def measured(self, name, operation, *args, **kwargs):
        started = time.perf_counter()
        try:
            return operation(*args, **kwargs)
        finally:
            self.phase_metrics[name] += time.perf_counter() - started

    def _exchange_with_retry(self,message,pairing_fingerprint=None):
        self.interruption_count=0
        self.interruption_retries=0
        self.interruption_wait_expired=False
        self.current_request_id=message['id']
        resume_sequence=None
        wait_deadline=None
        while True:
            try:
                return self._exchange_once(message,pairing_fingerprint,resume_sequence)
            except Rejected as exc:
                interrupted=(exc.code=='CLIPBOARD_USER_CHANGED' or
                    self.attempt_sent and exc.code in INTERRUPTION_READ_ERRORS)
                # Legacy/test adapters without sequence observation retain
                # their fail-stop behavior; never poll ordinary user text.
                if message['op']=='close' or not interrupted or not hasattr(self.clipboard,'sequence'):
                    raise
                self.interruption_count+=1
                if wait_deadline is None:
                    wait_deadline=self.monotonic()+INTERRUPTION_WAIT_LIMIT
                resume_sequence=self._wait_after_interruption(wait_deadline)
                self.interruption_retries+=1
                # Renew only the transport timestamps. Business identity,
                # operation, arguments and transaction IDs remain unchanged.
                message=request(message['session'],message['op'],message['args'],
                    message['id'],now=self.now())

    def _wait_after_interruption(self,deadline):
        sequence=self.clipboard.sequence()
        quiet_until=self.monotonic()+INTERRUPTION_RETRY_DELAY
        while True:
            current=self.clipboard.sequence()
            now=self.monotonic()
            if current!=sequence:
                sequence=current
                quiet_until=now+INTERRUPTION_RETRY_DELAY
            if now>=deadline:
                self.interruption_wait_expired=True
                raise Rejected('CLIPBOARD_USER_BUSY')
            if now>=quiet_until:
                return sequence
            self.sleep(min(0.1,quiet_until-now,deadline-now))

    def _exchange_once(self,message,pairing_fingerprint=None,resume_sequence=None):
        self.attempt_sent=False
        self.clipboard_restored=False
        self.protocol_baseline_recovered=False
        pairing=pairing_fingerprint is not None
        wire=self.measured('seal_seconds',self.crypto.seal,message,encrypted=message['op']!='hello')
        saved=self.clipboard.snapshot() if hasattr(self.clipboard,'snapshot') else None
        if resume_sequence is not None:
            require(self.clipboard.sequence()==resume_sequence,'CLIPBOARD_USER_CHANGED')
        baseline=saved['text'] if saved is not None else self.clipboard.read()
        restore_baseline=baseline
        if is_frame(baseline):
            # A previous failed call or legacy handoff may have restored an
            # authenticated reply instead of ordinary user data. Never clear
            # arbitrary text or an unverified protocol-looking clipboard.
            self.verify_protocol_baseline(baseline,pairing_fingerprint)
            restore_baseline=None
            self.protocol_baseline_recovered=True
            if saved is not None:
                saved=dict(saved,text=None,formats=[])
        if saved is not None:
            self.clipboard.write(wire,expected=baseline,compare=True,
                expected_sequence=saved['sequence'])
        else:
            self.clipboard.write(wire,expected=baseline,compare=True)
        self.attempt_sent=True
        last_owned=wire
        completed=False
        deadline=self.monotonic()+self.timeout
        sent=self.monotonic()
        response_started=time.perf_counter()
        verify_before=self.phase_metrics['verify_seconds']
        try:
            while self.monotonic()<deadline:
                text=self.clipboard.read()
                if text!=wire and not (is_frame(text) and normalize_frame(text)==wire):
                    require(is_frame(text),'CLIPBOARD_USER_CHANGED')
                    checker=self.crypto
                    temporary=None
                    try:
                        if pairing:
                            cert=advertised_certificate(text)
                            require(bool(cert),'PEER_CERTIFICATE_REQUIRED')
                            fd,name=tempfile.mkstemp(prefix='.peer-',dir=str(Path(self.config['server_cert']).parent))
                            temporary=Path(name)
                            with os.fdopen(fd,'wb') as stream:
                                stream.write(cert)
                            require(self.crypto.fingerprint(temporary)==sha(pairing_fingerprint),
                                'PEER_FINGERPRINT_MISMATCH')
                            checker=Crypto(self.config['signer_cert'],self.config['signer_key'],
                                temporary,temporary,self.config.get('openssl','openssl'))
                        response=self.measured('verify_seconds',checker.open,text)
                        self.response_checks={
                            'version_matches':response.get('v')==1,
                            'id_matches':response.get('id')==message['id'],
                            'session_matches':response.get('session')==message['session'],
                            'expires_is_integer':type(response.get('expires')) is int,
                            'peer_expiry_delta_seconds':round(response['expires']-self.now(),3)
                                if type(response.get('expires')) is int else None}
                        require(response.get('v')==1 and type(response.get('expires')) is int,
                            'RESPONSE_MISMATCH')
                        # ETX may finish synchronizing a previous authenticated
                        # reply after this request was written. Keep this same
                        # request identity and do not accept the unrelated reply.
                        last_owned=text
                        if response.get('id')!=message['id'] or response.get('session')!=message['session']:
                            self.clipboard.write(wire,expected=text,compare=True)
                            last_owned=wire
                            sent=self.monotonic()
                            self.sleep(0.1)
                            continue
                        require(response['expires']>=self.now(),'RESPONSE_MISMATCH')
                        if pairing:
                            os.replace(temporary,self.config['server_cert'])
                            temporary=None
                        require(response.get('ok') is True,response.get('error','BAD_RESPONSE'))
                        completed=True
                        return response['result']
                    finally:
                        if temporary:
                            temporary.unlink(missing_ok=True)
                if self.monotonic()-sent>=5:
                    self.clipboard.write(wire,expected=text,compare=True)
                    sent=self.monotonic()
                self.sleep(0.1)
            raise Rejected('RPC_TIMEOUT_QUERY_SAME_ID')
        finally:
            self.phase_metrics['response_wait_seconds'] += max(0, time.perf_counter()-response_started-(self.phase_metrics['verify_seconds']-verify_before))
            restore_started=time.perf_counter()
            try:
                if saved is not None:
                    self.clipboard.restore(saved,last_owned)
                else:
                    self.clipboard.write(restore_baseline,expected=last_owned,compare=True)
                self.clipboard_restored=True
            except Rejected as exc:
                # Preserve a user's new clipboard contents rather than replacing it.
                # A copy during reply verification also needs a quiet period
                # before the next chunk. Same-ID retry recovers this result.
                if completed and message['op']!='close' and (exc.code=='CLIPBOARD_USER_CHANGED' or
                        exc.code in INTERRUPTION_READ_ERRORS):
                    raise
            finally:
                self.phase_metrics['clipboard_restore_seconds'] += time.perf_counter()-restore_started

    def hello(self,fingerprint=None):
        value=self.exchange(request(uuid.uuid4().hex,'hello',{},now=self.now()),fingerprint)
        self.session=value['session']
        self.session_expires=value['expires']
        if self.config.get('connection_state'):
            atomic_json(Path(self.config['connection_state']),{'session':self.session,
                'expires':self.session_expires,'fingerprint':self.crypto.fingerprint(self.config['server_cert'])})
        return value

    def call(self,operation,arguments,operation_id=None):
        if self.session is None or self.session_expires<=self.now():
            self.hello()
        operation_id=operation_id or uuid.uuid4().hex
        for attempt in range(2):
            try:
                return self.exchange(request(self.session,operation,arguments,
                    operation_id,now=self.now()))
            except Rejected as exc:
                if exc.code not in ('WRONG_SESSION','SESSION_EXPIRED') or attempt or operation=='close':
                    raise
                self.hello()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('pair','rpc','read-files'))
    parser.add_argument('--config',required=True)
    parser.add_argument('--fingerprint')
    parser.add_argument('--request-file')
    parser.add_argument('--response-file',required=True)
    parser.add_argument('--launcher-start-ms',type=int)
    args=parser.parse_args()
    started=time.perf_counter()
    launcher_seconds=max(0, time.time()-args.launcher_start_ms/1000) if args.launcher_start_ms else None
    board=None
    client=None
    phase='load_config'
    try:
        config=strict_json(Path(args.config).read_bytes())
        require(type(config.get('version')) is int and config['version']==1,
            'BAD_CONFIG_VERSION')
        phase='clipboard_init'
        board=Clipboard()
        phase='client_init'
        client=Client(config,board)
        phase='packet_mutex'
        with packet_mutex():
            phase='exchange'
            if args.operation=='pair':
                result=client.hello(sha(args.fingerprint))
            elif args.operation=='read-files':
                from windows_read_files import read_files
                result=read_files(client,strict_json(Path(args.request_file).read_bytes()),Path(args.response_file).parent)
            else:
                spec=strict_json(Path(args.request_file).read_bytes())
                require(set(spec)=={'id','op','args'},'BAD_FIELDS')
                result=client.call(spec['op'],spec['args'],spec['id'])
        atomic_json(Path(args.response_file),{'ok':True,'result':result,
            'clipboard_restored':client.clipboard_restored,
            'protocol_baseline_recovered':client.protocol_baseline_recovered,
            'interruption_count':client.interruption_count,
            'interruption_retries':client.interruption_retries,
            'timings':{'launcher_to_python_seconds':launcher_seconds,
                'python_seconds':round(time.perf_counter()-started,6),
                'crypto_seconds':round(client.crypto.elapsed_seconds,6),
                'rpc':client.rpc_metrics}})
        print(json.dumps({'ok':True,'response_file':args.response_file}))
        return 0
    except Rejected as exc:
        diagnostic={'ok':False,'error':exc.code,'phase':phase}
        if client is not None:
            diagnostic['clipboard_restored']=getattr(client,'clipboard_restored',False)
            diagnostic['protocol_baseline_recovered']=getattr(client,'protocol_baseline_recovered',False)
            diagnostic['request_id']=getattr(client,'current_request_id',None)
            diagnostic['interruption_count']=getattr(client,'interruption_count',0)
            diagnostic['interruption_retries']=getattr(client,'interruption_retries',0)
            diagnostic['interruption_wait_expired']=getattr(client,'interruption_wait_expired',False)
            diagnostic['timings']={'python_seconds':round(time.perf_counter()-started,6),'rpc':client.rpc_metrics}
            if exc.code=='RESPONSE_MISMATCH':
                diagnostic['response_checks']=getattr(client,'response_checks',None)
        if exc.code=='CLIPBOARD_FORMAT_NOT_RESTORABLE' and board is not None:
            diagnostic['clipboard_format']=getattr(board,'unsupported_format',None)
        atomic_json(Path(args.response_file),diagnostic)
        print(json.dumps({'ok':False,'error':exc.code}))
        return 1
    finally:
        if board:
            board.close()


if __name__=='__main__':
    raise SystemExit(main())
