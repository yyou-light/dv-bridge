"""Bounded Windows client for the canonical ETX session protocol.

Only native clipboard APIs are used. No windows are focused and no keys are
sent. Each invocation restores its owned clipboard lease and exits.
"""
import argparse
import contextlib
import ctypes
from ctypes import wintypes
import json
import multiprocessing
import threading
import os
import stat
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'etx'))
from session_protocol import (Crypto, Rejected, require, request, strict_json,
    canonical, advertised_certificate, sha, digest, MAX_WIRE, MAGIC,is_frame,normalize_frame)
from session_files import atomic_json

INTERRUPTION_RETRY_DELAY = 30
INTERRUPTION_WAIT_LIMIT = 300
INTERRUPTION_READ_ERRORS = frozenset(('CLIPBOARD_NOT_PLAIN_TEXT', 'CLIPBOARD_SIZE_LIMIT'))
BITMAP_BUFFERS = (8, 17)  # CF_DIB and CF_DIBV5 carry the pixels in global memory.
BITMAP_HANDLES = (2, 9)   # CF_BITMAP and CF_PALETTE can be supplied from the DIB.
MAX_BITMAP_SNAPSHOT = 64 * 1024 * 1024
MAX_OTHER_SNAPSHOT = 4 * 1024 * 1024


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
        self.user.GetClipboardOwner.restype=ctypes.c_void_p
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
        # Any competing clipboard access wins immediately, including paste.
        if not self.user.OpenClipboard(self.owner):
            raise Rejected('CLIPBOARD_USER_CHANGED')
        try:
            yield
        finally:
            self.user.CloseClipboard()
            self.pump()

    def _read(self, *, allow_no_text=False):
        if self.user.CountClipboardFormats()==0:
            return None
        if not self.user.IsClipboardFormatAvailable(13):
            if allow_no_text:
                return None
            formats=[];number=0
            while len(formats)<64:
                number=self.user.EnumClipboardFormats(number)
                if not number:break
                name=ctypes.create_unicode_buffer(256)
                if number>=0xc000:self.user.GetClipboardFormatNameW(number,name,256)
                formats.append({'id':number,'name':name.value or None})
            self.unsupported_format={'unicode_available':False,'formats':formats}
            raise Rejected('CLIPBOARD_NOT_PLAIN_TEXT')
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

    def read_state(self):
        with self.opened():
            return {'text':self._read(),'sequence':self.user.GetClipboardSequenceNumber()}

    def read(self):
        return self.read_state()['text']

    def sequence(self):
        # Observation only: do not open the clipboard or read user contents
        # while yielding it to the user after an interrupted exchange.
        self.pump()
        return self.user.GetClipboardSequenceNumber()

    def snapshot(self):
        with self.opened():
            has_bitmap=any(self.user.IsClipboardFormatAvailable(number) for number in BITMAP_BUFFERS)
            text=self._read(allow_no_text=has_bitmap)
            formats=[]
            number=0
            bitmap_bytes=other_bytes=0
            while True:
                number=self.user.EnumClipboardFormats(number)
                if not number:
                    break
                if has_bitmap and number in BITMAP_HANDLES:
                    # Windows can reconstruct these handles from the saved DIB.
                    continue
                # Registered formats use byte-copyable global memory; preserve
                # bounded opaque OLE metadata as well as RTF/HTML text formats.
                allowed=number in (1,7,13,16) or number in BITMAP_BUFFERS or 0xc000<=number<=0xffff
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
                require(size>0,'CLIPBOARD_SIZE_LIMIT')
                if number in BITMAP_BUFFERS:
                    bitmap_bytes+=size
                    require(bitmap_bytes<=MAX_BITMAP_SNAPSHOT,'CLIPBOARD_SIZE_LIMIT')
                else:
                    other_bytes+=size
                    require(other_bytes<=MAX_OTHER_SNAPSHOT,'CLIPBOARD_SIZE_LIMIT')
                pointer=self.kernel.GlobalLock(handle)
                require(bool(pointer),'CLIPBOARD_READ_FAILED')
                try:
                    formats.append((number,ctypes.string_at(pointer,size)))
                finally:
                    self.kernel.GlobalUnlock(handle)
            require(not has_bitmap or bitmap_bytes>0,'CLIPBOARD_FORMAT_NOT_RESTORABLE')
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

    def restore(self,snapshot,expected,expected_sequence=None):
        with self.opened():
            if expected_sequence is not None:
                require(self.user.GetClipboardSequenceNumber()==expected_sequence,'CLIPBOARD_USER_CHANGED')
            require(same_clipboard_text(self._read(),expected),'CLIPBOARD_USER_CHANGED')
            require(self.user.EmptyClipboard(),'CLIPBOARD_WRITE_FAILED')
            for number,raw in snapshot['formats']:
                self.put(number,raw)
            restored_sequence=self.user.GetClipboardSequenceNumber()
        # CloseClipboard can add synthesized formats and advance the sequence.
        # Use that sequence only while this helper still owns the clipboard.
        closed_sequence=self.user.GetClipboardSequenceNumber()
        return closed_sequence if self.user.GetClipboardOwner()==self.owner else restored_sequence

    def write(self,text,expected=None,compare=False,expected_sequence=None):
        with self.opened():
            if expected_sequence is not None:
                require(self.user.GetClipboardSequenceNumber()==expected_sequence,
                    'CLIPBOARD_USER_CHANGED')
            if compare:
                # A checked snapshot may have pixels but no protocol text.
                # Its sequence must still match under OpenClipboard.
                current=self._read(allow_no_text=expected is None and expected_sequence is not None)
                require(same_clipboard_text(current,expected),'CLIPBOARD_USER_CHANGED')
            require(self.user.EmptyClipboard(),'CLIPBOARD_WRITE_FAILED')
            if text is None:
                return self.user.GetClipboardSequenceNumber()
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
            return self.user.GetClipboardSequenceNumber()


CLIPBOARD_IO_TIMEOUT = 0.25
CLIPBOARD_RENDER_PROBE_INTERVAL = 1.0


def clipboard_station():
    user=ctypes.WinDLL('user32',use_last_error=True)
    user.GetProcessWindowStation.restype=ctypes.c_void_p
    user.GetUserObjectInformationW.argtypes=[ctypes.c_void_p,ctypes.c_int,
        ctypes.c_void_p,ctypes.c_uint,ctypes.POINTER(ctypes.c_uint)]
    name=ctypes.create_unicode_buffer(256);needed=ctypes.c_uint()
    require(bool(user.GetUserObjectInformationW(user.GetProcessWindowStation(),2,
        name,ctypes.sizeof(name),ctypes.byref(needed))),'CLIPBOARD_STATION_UNAVAILABLE')
    return name.value


def _leave_if_parent_exits(parent):
    # A stuck Win32 call releases the GIL. This thread still observes the
    # original parent's process handle, even while GetClipboardData blocks.
    parent.join()
    os._exit(73)


def _clipboard_worker(channel):
    parent = multiprocessing.parent_process()
    if parent is not None:
        threading.Thread(target=_leave_if_parent_exits,args=(parent,),daemon=True).start()
    board = None
    saved_snapshot = None
    try:
        board = Clipboard()
        channel.send({'ok':True,'value':{'station':clipboard_station()}})
        while True:
            if not channel.poll(0.02):
                board.pump()
                continue
            operation, args, kwargs = channel.recv()
            if operation == 'close':
                break
            require(operation in ('snapshot','read','read_state','write','restore'),'CLIPBOARD_IO_OPERATION_REJECTED')
            try:
                if operation == 'snapshot':
                    saved_snapshot = None
                    saved_snapshot = board.snapshot()
                    # Keep clipboard format bytes in the I/O helper's memory.
                    value = dict(saved_snapshot, formats=None)
                elif operation == 'restore' and args[0]['formats'] is None:
                    require(saved_snapshot is not None and args[0]['sequence']==saved_snapshot['sequence'],
                        'CLIPBOARD_SNAPSHOT_MISMATCH')
                    value = board.restore(saved_snapshot, *args[1:], **kwargs)
                    saved_snapshot = None
                else:
                    value = getattr(board,operation)(*args,**kwargs)
                channel.send({'ok':True,'value':value})
            except Rejected as exc:
                channel.send({'ok':False,'error':exc.code,
                    'format':getattr(board,'unsupported_format',None)})
    except Rejected as exc:
        channel.send({'ok':False,'error':exc.code})
    except (EOFError,BrokenPipeError,OSError):
        pass
    finally:
        if board is not None:
            board.close()
        channel.close()


class ClipboardProcess:
    """Bound Win32 clipboard I/O without ever killing an ETX/client process."""
    def __init__(self,timeout=CLIPBOARD_IO_TIMEOUT,worker_target=_clipboard_worker):
        require(os.name=='nt','WINDOWS_REQUIRED')
        self.timeout=timeout
        self.io_calls=0
        self.io_timeout=False
        self.last_operation='startup'
        self.closed=False
        self.user=ctypes.WinDLL('user32',use_last_error=True)
        self.user.GetClipboardSequenceNumber.restype=ctypes.c_uint
        context=multiprocessing.get_context('spawn')
        self.channel,child=context.Pipe()
        self.process=context.Process(target=worker_target,args=(child,),daemon=True)
        try:
            self.process.start()
            child.close()
            ready=self._receive(8.0)
            self.station=ready['station']
            require(self.station==clipboard_station(),'CLIPBOARD_STATION_MISMATCH')
        except BaseException:
            child.close()
            self.close()
            raise

    def _receive(self,timeout):
        if not self.channel.poll(timeout):
            self.io_timeout=True
            self.close(force=True)
            raise Rejected('CLIPBOARD_IO_TIMEOUT')
        try:
            reply=self.channel.recv()
        except (EOFError,BrokenPipeError,OSError):
            self.close()
            raise Rejected('CLIPBOARD_IO_PROCESS_EXITED') from None
        if not reply.get('ok'):
            if reply.get('format') is not None:
                self.unsupported_format=reply['format']
            raise Rejected(reply.get('error','CLIPBOARD_IO_FAILED'))
        return reply.get('value')

    def _call(self,operation,*args,**kwargs):
        require(not self.closed,'CLIPBOARD_IO_PROCESS_EXITED')
        self.last_operation=operation
        self.io_calls+=1
        try:
            self.channel.send((operation,args,kwargs))
        except (EOFError,BrokenPipeError,OSError):
            self.close()
            raise Rejected('CLIPBOARD_IO_PROCESS_EXITED') from None
        return self._receive(self.timeout)

    def snapshot(self):
        value=self._call('snapshot');self.last_read_sequence=value['sequence'];return value
    def read(self):
        value=self._call('read_state');self.last_read_sequence=value['sequence'];return value['text']
    def write(self,*args,**kwargs):
        self.last_write_sequence=self._call('write',*args,**kwargs)
    def restore(self,*args,**kwargs):
        self.last_write_sequence=self._call('restore',*args,**kwargs)
    def sequence(self):return self.user.GetClipboardSequenceNumber()

    def diagnostic(self):
        return {'worker_pid':self.process.pid,'station':getattr(self,'station',None),'calls':self.io_calls,
            'timeout':self.io_timeout,'last_operation':self.last_operation,
            'timeout_seconds':self.timeout}

    def close(self,force=False):
        if self.closed:return
        self.closed=True
        try:
            if self.process.pid is not None and self.process.is_alive():
                if not force:
                    try:
                        self.channel.send(('close',(),{}))
                        self.process.join(timeout=0.5)
                    except (EOFError,BrokenPipeError,OSError):
                        pass
                if self.process.is_alive():
                    # Fault containment only; never terminate the ETX client.
                    self.process.terminate()
                    self.process.join(timeout=2)
                    if self.process.is_alive():self.process.kill();self.process.join(timeout=2)
        finally:
            self.channel.close()


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


class SharedUserPriority:
    """No clipboard contents: only sequence and a shared user quiet deadline."""
    def __init__(self,path,now):
        self.path=Path(path) if path else None
        self.now=now
        self.state=None

    def load(self):
        if self.state is None and self.path is not None and (self.path.exists() or self.path.is_symlink()):
            info=self.path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_size<=4096,'USER_PRIORITY_STATE_REJECTED')
            value=strict_json(self.path.read_bytes())
            require(set(value)=={'version','sequence','until'} and value['version']==1 and
                type(value['sequence']) is int and 0<=value['sequence']<2**32 and
                type(value['until']) in (int,float) and 0<=value['until']<2**63,
                'USER_PRIORITY_STATE_REJECTED')
            self.state=value
        return self.state

    def save(self):
        if self.path is not None:atomic_json(self.path,self.state)

    def observe(self,sequence,force_user=False):
        previous=self.load()
        if previous is None:
            # First observation cannot establish when the user copied. Give
            # that existing content the same conservative thirty seconds.
            self.state={'version':1,'sequence':sequence,
                'until':self.now()+30 if self.path is not None or force_user else 0}
            self.save()
        elif force_user or sequence!=previous['sequence']:
            self.state=dict(previous,sequence=sequence,until=self.now()+30)
            self.save()
        return max(0,self.state['until']-self.now())

    def owned(self,sequence):
        if sequence is None:return
        previous=self.load()
        self.state={'version':1,'sequence':sequence,'until':previous['until'] if previous else 0}
        self.save()


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
        connection=config.get('connection_state')
        priority_path=Path(connection).with_name('clipboard-user-priority.json') if connection else None
        self.user_priority=SharedUserPriority(priority_path,self.now)
        self.user_priority_wait_seconds=0.0
        self.user_wait_deadline=None
        self.crypto=Crypto(config['signer_cert'],config['signer_key'],
            config['server_cert'],config['server_cert'],config.get('openssl','openssl'))
        connection=config.get('connection_state')
        if connection and Path(connection).exists() and Path(config['server_cert']).exists():
            value=strict_json(Path(connection).read_bytes())
            if value.get('fingerprint')==self.crypto.fingerprint(config['server_cert']):
                self.session=value.get('session')
                self.session_expires=value.get('expires',0)

    def protocol_frame_ledger(self):
        connection=self.config.get('connection_state')
        if not connection:return None,[]
        path=Path(connection).with_name('clipboard-protocol-hashes.json')
        hashes=[]
        if path.exists() or path.is_symlink():
            info=path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_size<=4096,
                'CLIPBOARD_RECOVERY_STATE_REJECTED')
            saved=strict_json(path.read_bytes())
            require(set(saved)=={'version','hashes'} and saved['version']==1 and
                type(saved['hashes']) is list and len(saved['hashes'])<=8,
                'CLIPBOARD_RECOVERY_STATE_REJECTED')
            hashes=[sha(value) for value in saved['hashes']]
        return path,hashes

    def remember_protocol_frame(self,text):
        # Only our newly generated encrypted/signed protocol frame is hashed.
        # Neither clipboard contents nor plaintext payloads enter this file.
        path,hashes=self.protocol_frame_ledger()
        if path is not None:
            value=digest(normalize_frame(text).encode('ascii'))
            atomic_json(path,{'version':1,'hashes':(hashes+[value])[-8:]})

    def verify_protocol_baseline(self,text,pairing_fingerprint):
        """Recognize our authenticated protocol residue without consuming it."""
        _,hashes=self.protocol_frame_ledger()
        if digest(normalize_frame(text).encode('ascii')) in hashes:
            return  # Exact frame generated locally before a previous I/O failure.
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
        self.response_reads=0
        self.phase_metrics = {'seal_seconds': 0.0, 'verify_seconds': 0.0,
            'response_wait_seconds': 0.0, 'clipboard_restore_seconds': 0.0}
        try:
            return self._exchange_with_retry(message, pairing_fingerprint)
        finally:
            self.rpc_metrics.append({'id': message['id'], 'op': message['op'],
                'seconds': round(time.perf_counter() - started, 6),
                'response_reads':self.response_reads,
                'crypto_seconds': round(getattr(self.crypto, 'elapsed_seconds', 0.0) - crypto_before, 6),
                **{k: round(v, 6) for k, v in self.phase_metrics.items()}})

    def measured(self, name, operation, *args, **kwargs):
        started = time.perf_counter()
        try:
            return operation(*args, **kwargs)
        finally:
            self.phase_metrics[name] += time.perf_counter() - started

    def _sequence_for(self,name):
        value=getattr(self.clipboard,name,None)
        return value if value is not None else self.clipboard.sequence() if hasattr(self.clipboard,'sequence') else None

    def _respect_user_priority(self,deadline=None):
        if not hasattr(self.clipboard,'sequence'):return None
        started=self.monotonic()
        try:
            while True:
                sequence=self.clipboard.sequence()
                remaining=self.user_priority.observe(sequence)
                if remaining<=0:return sequence
                if self.user_wait_deadline is None:
                    self.user_wait_deadline=self.monotonic()+INTERRUPTION_WAIT_LIMIT
                limit=deadline if deadline is not None else self.user_wait_deadline
                if self.monotonic()>=limit:
                    self.interruption_wait_expired=True
                    raise Rejected('CLIPBOARD_USER_BUSY')
                # Metadata only during user protection, including repeated copy.
                self.sleep(min(0.1,remaining,limit-self.monotonic()))
        finally:
            self.user_priority_wait_seconds+=self.monotonic()-started

    def _note_user(self):
        if hasattr(self.clipboard,'sequence'):
            self.user_priority.observe(self.clipboard.sequence(),force_user=True)

    def _owned(self,name):
        self.user_priority.owned(self._sequence_for(name))

    def _exchange_with_retry(self,message,pairing_fingerprint=None):
        self.interruption_count=0
        self.interruption_retries=0
        self.interruption_wait_expired=False
        self.user_priority_wait_seconds=0.0
        self.user_wait_deadline=None
        self.current_request_id=message['id']
        resume_sequence=None
        wait_deadline=None
        while True:
            try:
                return self._exchange_once(message,pairing_fingerprint,resume_sequence)
            except Rejected as exc:
                if exc.code=='CLIPBOARD_IO_TIMEOUT':
                    self._note_user()
                    raise Rejected('CLIPBOARD_USER_PRIORITY_YIELD') from None
                interrupted=(exc.code=='CLIPBOARD_USER_CHANGED' or
                    self.attempt_sent and exc.code in INTERRUPTION_READ_ERRORS)
                if interrupted:self._note_user()
                # Legacy/test adapters without sequence observation retain
                # their fail-stop behavior; never poll ordinary user text.
                if message['op']=='close' or not interrupted or not hasattr(self.clipboard,'sequence'):
                    raise
                self.interruption_count+=1
                if wait_deadline is None:
                    wait_deadline=self.user_wait_deadline or self.monotonic()+INTERRUPTION_WAIT_LIMIT
                    self.user_wait_deadline=wait_deadline
                resume_sequence=self._wait_after_interruption(wait_deadline)
                self.interruption_retries+=1
                # Renew only the transport timestamps. Business identity,
                # operation, arguments and transaction IDs remain unchanged.
                message=request(message['session'],message['op'],message['args'],
                    message['id'],now=self.now())

    def _wait_after_interruption(self,deadline):
        return self._respect_user_priority(deadline)

    def _exchange_once(self,message,pairing_fingerprint=None,resume_sequence=None):
        self.attempt_sent=False
        self.clipboard_restored=False
        self.protocol_baseline_recovered=False
        pairing=pairing_fingerprint is not None
        permitted_sequence=self._respect_user_priority()
        # Start the frame lifetime after the user has finished copying.
        message=request(message['session'],message['op'],message['args'],message['id'],now=self.now())
        wire=self.measured('seal_seconds',self.crypto.seal,message,encrypted=message['op']!='hello')
        if permitted_sequence is not None:
            require(self.clipboard.sequence()==permitted_sequence,'CLIPBOARD_USER_CHANGED')
        saved=self.clipboard.snapshot() if hasattr(self.clipboard,'snapshot') else None
        if saved is not None and permitted_sequence is not None:
            require(saved['sequence']==permitted_sequence,'CLIPBOARD_USER_CHANGED')
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
        self.remember_protocol_frame(wire)
        if saved is not None:
            self.clipboard.write(wire,expected=baseline,compare=True,
                expected_sequence=saved['sequence'])
        else:
            self.clipboard.write(wire,expected=baseline,compare=True)
        self.attempt_sent=True
        self._owned('last_write_sequence')
        last_owned=wire
        last_owned_sequence=self._sequence_for('last_write_sequence')
        completed=False
        yielded=False
        deadline=self.monotonic()+self.timeout
        sent=self.monotonic()
        response_started=time.perf_counter()
        verify_before=self.phase_metrics['verify_seconds']
        last_sequence=None
        last_probe=sent-CLIPBOARD_RENDER_PROBE_INTERVAL
        text=wire
        try:
            while self.monotonic()<deadline:
                sequence=self.clipboard.sequence() if hasattr(self.clipboard,'sequence') else None
                # Sequence checks never open the clipboard. Keep a one-second
                # rendering probe: delayed formats need not advance sequence
                # until GetClipboardData actually requests their rendering.
                if (sequence is None or last_sequence is None or sequence!=last_sequence or
                        self.monotonic()-last_probe>=CLIPBOARD_RENDER_PROBE_INTERVAL):
                    text=self.clipboard.read()
                    self.response_reads+=1
                    last_sequence=self._sequence_for('last_read_sequence') if sequence is not None else None
                    last_probe=self.monotonic()
                if (hasattr(self.clipboard,'last_read_sequence') and text==wire and
                        last_owned_sequence is not None and last_sequence!=last_owned_sequence):
                    raise Rejected('CLIPBOARD_USER_CHANGED')
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
                        # A valid but retired reply is not permission to reclaim
                        # the clipboard. Yield for the shared 30-second window.
                        require(isinstance(response.get('request_sha256'),str),
                            'PEER_REPLY_BINDING_REQUIRED')
                        require(response.get('id')==message['id'] and
                            response.get('session')==message['session'] and
                            response['request_sha256']==digest(normalize_frame(wire).encode('utf-8')),
                            'CLIPBOARD_USER_CHANGED')
                        last_owned=text
                        last_owned_sequence=self._sequence_for('last_read_sequence')
                        self.user_priority.owned(last_owned_sequence)
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
                # Keep the same owner while the peer fetches this frame.
                # Rewriting on a timer can repeatedly interrupt a slow INCR.
                # Timeout is returned to the caller; query/retry the same ID.
                self.sleep(0.1)
            raise Rejected('RPC_TIMEOUT_QUERY_SAME_ID')
        except Rejected as exc:
            if exc.code=='RPC_TIMEOUT_QUERY_SAME_ID':
                self._note_user()  # Give queued proxy work and user copy room.
            yielded=(exc.code=='CLIPBOARD_USER_CHANGED' or exc.code in INTERRUPTION_READ_ERRORS or exc.code=='CLIPBOARD_IO_TIMEOUT')
            raise
        finally:
            self.phase_metrics['response_wait_seconds'] += max(0, time.perf_counter()-response_started-(self.phase_metrics['verify_seconds']-verify_before))
            restore_started=time.perf_counter()
            try:
                if not yielded:
                    extra={'expected_sequence':last_owned_sequence} if hasattr(self.clipboard,'last_read_sequence') else {}
                    if saved is not None:
                        self.clipboard.restore(saved,last_owned,**extra)
                    else:
                        self.clipboard.write(restore_baseline,expected=last_owned,compare=True,**extra)
                    self._owned('last_write_sequence')
                    self.clipboard_restored=True
            except Rejected as exc:
                # Preserve a user's new clipboard contents rather than replacing it.
                # A copy during reply verification also needs a quiet period
                # before the next chunk. Same-ID retry recovers this result.
                if exc.code=='CLIPBOARD_USER_CHANGED' or exc.code in INTERRUPTION_READ_ERRORS:self._note_user()
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
        require(not Path(__file__).with_name('clipboard-paused.json').exists(),'CLIPBOARD_EMERGENCY_PAUSED')
        config=strict_json(Path(args.config).read_bytes())
        require(type(config.get('version')) is int and config['version']==1,
            'BAD_CONFIG_VERSION')
        phase='clipboard_init'
        board=ClipboardProcess()
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
            'clipboard_io':board.diagnostic(),
            'interruption_count':client.interruption_count,
            'user_priority_wait_seconds':round(client.user_priority_wait_seconds,6),
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
            if board is not None:diagnostic['clipboard_io']=board.diagnostic()
            diagnostic['protocol_baseline_recovered']=getattr(client,'protocol_baseline_recovered',False)
            diagnostic['request_id']=getattr(client,'current_request_id',None)
            diagnostic['request_sent']=getattr(client,'attempt_sent',False)
            diagnostic['interruption_count']=getattr(client,'interruption_count',0)
            diagnostic['user_priority_wait_seconds']=round(getattr(client,'user_priority_wait_seconds',0),6)
            diagnostic['interruption_retries']=getattr(client,'interruption_retries',0)
            diagnostic['interruption_wait_expired']=getattr(client,'interruption_wait_expired',False)
            diagnostic['timings']={'python_seconds':round(time.perf_counter()-started,6),'rpc':client.rpc_metrics}
            if exc.code=='RESPONSE_MISMATCH':
                diagnostic['response_checks']=getattr(client,'response_checks',None)
        if exc.code in ('CLIPBOARD_FORMAT_NOT_RESTORABLE','CLIPBOARD_NOT_PLAIN_TEXT') and board is not None:
            diagnostic['clipboard_format']=getattr(board,'unsupported_format',None)
        atomic_json(Path(args.response_file),diagnostic)
        print(json.dumps({'ok':False,'error':exc.code}))
        return 1
    finally:
        if board:
            board.close()


if __name__=='__main__':
    raise SystemExit(main())
