#!/usr/bin/env python3
"""Fixed ETX simulation queue and foreground Terminal worker (stdlib only)."""

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'etx'))
from site_config import site


ROOT = Path(site()["remote"]["queue_root"])
HOST = socket.gethostname().split(".")[0]
VERSION = 1
LEASE_SECONDS = 30
POLL_SECONDS = 2
HEARTBEAT_SECONDS = 8
START_SECONDS = 60
MAX_RUNTIME = 4 * 60 * 60
SAFE_TERMINAL = {"exited", "launch_failed", "not_started"}
TERMINAL = SAFE_TERMINAL | {"needs_review"}
ID = re.compile(r"[0-9a-f]{32}\Z")
ALIAS = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
SLOT = re.compile(r"work0[1-5]\Z")
MAX_COMMAND_BYTES = 8192
MAX_COMMAND_BOX = 24576
MAX_ACTIVE_WORKERS = 5
TERMINAL_COLOR = re.compile(rb"\x1b\[[0-9;]*m")
MAX_SUMMARY_LINE = 4096
SIMMER_VERDICTS = {(b"1", b"0", b"0", b"1"): "PASS", (b"0", b"0", b"1", b"1"): "FAILED"}


class Rejected(Exception):
    """Error with a fixed public code, safe for Actions logs."""


def checked_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Rejected("BAD_ID")
    return value


def checked_alias(value):
    if not isinstance(value, str) or not ALIAS.fullmatch(value):
        raise Rejected("BAD_ALIAS")
    return value


def checked_argv(value):
    if (not isinstance(value, list) or not 1 <= len(value) <= 128
            or any(not isinstance(arg, str) or "\x00" in arg for arg in value)
            or not value[0]):
        raise Rejected("BAD_COMMAND_ARGV")
    return value


def simmer_argv(case, seed, slot):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", case):
        raise Rejected("BAD_SIMMER_CASE")
    if not 0 <= seed <= 2147483647 or not SLOT.fullmatch(slot):
        raise Rejected("BAD_SIMMER_SEED_OR_SLOT")
    wrapper = (Path(__file__).with_name("fsdb_access.py").read_text(encoding="utf-8") + "\n" +
               Path(__file__).with_name("simmer_launch.py").read_text(encoding="utf-8"))
    wrapper = "import sys;sys.path.insert(0,"+repr(site()["remote"]["install_root"]+"/etx")+");\n"+wrapper
    return [site()["remote"]["python"], "-c", wrapper, case, str(seed), slot]


def checked_box(value):
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_COMMAND_BOX:
        raise Rejected("BAD_COMMAND_BOX")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        raise Rejected("BAD_COMMAND_BOX") from None


def openssl(args, data=None):
    try:
        return subprocess.run([site()['remote']['openssl'], *args], input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, check=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        raise Rejected("COMMAND_CRYPTO_FAILED") from None


def seal_command(request_id, worker_id, profile, argv, signer, signing_key, recipient):
    packet = json.dumps({"request_id": checked_id(request_id), "worker_id": checked_id(worker_id),
                         "profile": checked_alias(profile), "argv": checked_argv(argv)},
                        separators=(",", ":"), ensure_ascii=False).encode()
    if len(packet) > MAX_COMMAND_BYTES:
        raise Rejected("COMMAND_SIZE_LIMIT")
    signed = openssl(["cms", "-sign", "-binary", "-nodetach", "-nocerts", "-md", "sha256",
                      "-signer", str(signer), "-inkey", str(signing_key), "-outform", "DER"], packet)
    encrypted = openssl(["cms", "-encrypt", "-binary", "-aes256", "-outform", "DER",
                         "-recip", str(recipient), "-keyopt", "rsa_padding_mode:oaep",
                         "-keyopt", "rsa_oaep_md:sha256"], signed)
    box = base64.b64encode(encrypted).decode("ascii")
    checked_box(box)
    return box


def open_command(request, recipient, private_key, trusted_signer):
    encrypted = checked_box(request.get("command_box"))
    signed = openssl(["cms", "-decrypt", "-binary", "-inform", "DER", "-recip", str(recipient),
                      "-inkey", str(private_key)], encrypted)
    # Trust only the provisioned signer. Verify its signature even though it is self-signed.
    data = openssl(["cms", "-verify", "-binary", "-inform", "DER", "-nointern", "-noverify",
                    "-certfile", str(trusted_signer)], signed)
    if len(data) > MAX_COMMAND_BYTES:
        raise Rejected("COMMAND_SIZE_LIMIT")
    try:
        packet = json.loads(data)
    except (ValueError, UnicodeError):
        raise Rejected("BAD_COMMAND_PACKET") from None
    if (not isinstance(packet, dict) or set(packet) != {"request_id", "worker_id", "profile", "argv"}
            or any(packet[key] != request[key] for key in ("request_id", "worker_id", "profile"))):
        raise Rejected("COMMAND_TARGET_MISMATCH")
    return checked_argv(packet["argv"])


def private_directory(path, create=False):
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise Rejected("BAD_DIRECTORY")
    if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise Rejected("BAD_DIRECTORY_PERMISSIONS")


def read_json(path):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Rejected("BAD_STATE_FILE")
        if os.name == "posix" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
            raise Rejected("BAD_STATE_PERMISSIONS")
        data = stream.read(65537)
    if len(data) > 65536:
        raise Rejected("STATE_SIZE_LIMIT")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise Rejected("BAD_STATE_FORMAT")
    return value


def put_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":"), allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_profile(path):
    value = read_json(path)
    if not value or set(value) != {"profile", "cases", "timeout_seconds"}:
        raise Rejected("BAD_PROFILE")
    checked_alias(value["profile"])
    limit, cases = value["timeout_seconds"], value["cases"]
    if type(limit) is not int or not 1 <= limit <= MAX_RUNTIME:
        raise Rejected("BAD_TIMEOUT")
    if not isinstance(cases, dict) or not 1 <= len(cases) <= 64:
        raise Rejected("BAD_CASE_LIST")
    for case, argv in cases.items():
        checked_alias(case)
        if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
                or any(not isinstance(arg, str) or not arg or len(arg) > 4096 or "\x00" in arg for arg in argv)
                or "{" in argv[0] or "}" in argv[0]):
            raise Rejected("BAD_PROFILE_ARGV")
    return value


def profile_digest(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def lock_fd(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise Rejected("BAD_LOCK_FILE")
    return fd


@contextlib.contextmanager
def transaction(lock_root):
    import fcntl

    fd = lock_fd(lock_root / "sim-control.lock")
    deadline = time.monotonic() + 5
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Rejected("QUEUE_LOCK_BUSY")
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


@contextlib.contextmanager
def shared_access(lock_root):
    """Use the same writer turnstile and resource lock as Runner access.sh."""
    import fcntl

    turnstile = lock_fd(lock_root / "turnstile.lock")
    resource = None
    acquired = False
    try:
        try:
            fcntl.flock(turnstile, fcntl.LOCK_EX | fcntl.LOCK_NB)
            resource = lock_fd(lock_root / "resource.lock")
            fcntl.flock(resource, fcntl.LOCK_SH | fcntl.LOCK_NB)
            acquired = True
        except BlockingIOError:
            pass
        finally:
            os.close(turnstile)
        yield (resource,) if acquired else None
    finally:
        if resource is not None:
            # Keep the shared lock if a still-running owned child inherited it.
            os.close(resource)


@contextlib.contextmanager
def simulation_access(lock_root):
    """Allow different simulator slots to run alongside uploads; exclude xverif."""
    import fcntl

    fd = lock_fd(lock_root / "sim-xverif.lock")
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            yield None
        else:
            yield (fd,)
    finally:
        os.close(fd)


class Queue:
    def __init__(self, root, transact, now=time.time):
        self.root = root
        self.transact = transact
        self.now = now
        self.workers = root / "workers"
        self.jobs = root / "jobs"
        self.active = root / "active.json"

    def prepare(self):
        for path in (self.root, self.workers, self.jobs):
            private_directory(path, create=True)

    def job(self, request_id):
        path = self.jobs / checked_id(request_id)
        if path.exists() or path.is_symlink():
            private_directory(path)
        return path

    def heartbeat(self, worker_id, profile, busy):
        entry = {
            "version": VERSION, "id": worker_id, "profile": profile["profile"],
            "cases": sorted(profile["cases"]), "timeout_seconds": profile["timeout_seconds"],
            "profile_digest": profile_digest(profile), "busy": busy, "at": self.now(),
            "upload_independent": True,
        }
        if "command_certificate" in profile:
            entry["command_certificate"] = profile["command_certificate"]
        if profile.get("parallel") is True:
            entry["parallel"] = True
        put_json(self.workers / (checked_id(worker_id) + ".json"), entry)

    def available_workers(self):
        if not self.workers.exists():
            return []
        private_directory(self.workers)
        result = []
        for path in sorted(self.workers.glob("*.json")):
            if not ID.fullmatch(path.stem):
                continue
            item = read_json(path)
            if (item and item["version"] == VERSION and item["id"] == path.stem
                    and 0 <= self.now() - item["at"] < LEASE_SECONDS):
                result.append(item)
        return result

    def worker_online(self, worker_id):
        item = read_json(self.workers / (checked_id(worker_id) + ".json"))
        return item is not None and 0 <= self.now() - item["at"] < LEASE_SECONDS

    def snapshot(self, request_id):
        directory = self.job(request_id)
        request = read_json(directory / "request.json")
        if request is None:
            return {"request_id": request_id, "state": "unknown"}
        state = read_json(directory / "state.json") or {"state": "queued"}
        result = {"request_id": request_id, "worker_id": request["worker_id"], "state": state["state"]}
        if "exit_code" in state:
            result["exit_code"] = state["exit_code"]
        if "reason" in state:
            result["reason"] = state["reason"]
        if state["state"] == "exited" and state.get("simmer_result") in ("PASS", "FAILED"):
            result["simmer_result"] = state["simmer_result"]
        if state["state"] not in TERMINAL:
            result["lease_current"] = self.live(directory)
            if state["state"] != "queued" and not (result["lease_current"] and self.worker_online(request["worker_id"])):
                result["requires_review"] = True
        elif state["state"] == "needs_review":
            result["requires_review"] = True
        return result

    def live(self, directory):
        lease = read_json(directory / "lease.json")
        return lease is not None and self.now() < lease["until"]

    def refresh(self, directory):
        put_json(directory / "lease.json", {"until": self.now() + LEASE_SECONDS})

    def pending_request(self, request_id):
        current = self.snapshot(request_id)
        if current["state"] == "queued" and not current["lease_current"]:
            self.finish(self.job(request_id), "not_started", reason="lease_expired_before_claim")
            return False
        if current["state"] in SAFE_TERMINAL:
            return False
        if current["state"] not in {"queued", "starting", "running", "needs_review"}:
            raise Rejected("ACTIVE_SIMULATION_OR_REVIEW_REQUIRED")
        return True

    def current_workers(self, active):
        return {worker_id: request_id for worker_id, request_id in active["workers"].items()
                if self.pending_request(request_id)}

    def clear_slot(self, active):
        if not active:
            return
        if "workers" in active:
            if self.current_workers(active):
                raise Rejected("ACTIVE_SIMULATION_OR_REVIEW_REQUIRED")
            self.finish(self.job(active["request_id"]), "exited")
        elif self.pending_request(active["request_id"]):
            raise Rejected("ACTIVE_SIMULATION_OR_REVIEW_REQUIRED")
        self.active.unlink()

    def refresh_guard(self, guard, pending):
        if any(self.snapshot(request_id).get("requires_review") for request_id in pending.values()):
            state = "needs_review"
        else:
            state = "running" if pending else "exited"
        self.finish(guard, state)

    def reconcile_workers(self):
        with self.transact():
            active = read_json(self.active)
            if not active or "workers" not in active:
                return
            try:
                pending = self.current_workers(active)
            except Rejected:
                self.finish(self.job(active["request_id"]), "needs_review")
            else:
                self.refresh_guard(self.job(active["request_id"]), pending)

    def select_worker(self, workers, profile, case, worker_id, command_box):
        choices = [w for w in workers if w["profile"] == profile and case in w["cases"]
                   and not w["busy"] and (not worker_id or w["id"] == worker_id)
                   and ("command_certificate" in w) == (command_box is not None)]
        if not choices:
            raise Rejected("NO_MATCHING_IDLE_WORKER")
        choices = [w for w in choices if w.get("upload_independent") is True]
        if not choices:
            raise Rejected("SIM_WORKER_RESTART_REQUIRED")
        if len({item["profile_digest"] for item in choices}) > 1:
            raise Rejected("AMBIGUOUS_PROFILE_SELECT_WORKER")
        return choices[0]

    def reserve(self, request_id, profile, case, seed, worker_id=None, command_box=None):
        checked_id(request_id)
        checked_alias(profile)
        checked_alias(case)
        if type(seed) is not int or not 1 <= seed <= 2147483647:
            raise Rejected("BAD_SEED")
        if worker_id:
            checked_id(worker_id)
        desired = {"profile": profile, "case": case, "seed": seed, "target_worker": worker_id}
        if command_box is not None:
            checked_box(command_box)
            if not worker_id or case != "run" or seed != 1:
                raise Rejected("COMMAND_TARGET_REQUIRED")
            desired["command_box"] = command_box
        with self.transact():
            directory = self.job(request_id)
            previous = read_json(directory / "request.json")
            if previous:
                if (any(previous.get(key) != value for key, value in desired.items())
                        or previous.get("command_box") != command_box):
                    raise Rejected("REQUEST_ID_CONFLICT")
                state = self.snapshot(request_id)
                if state["state"] == "queued" and not state["lease_current"]:
                    self.finish(directory, "not_started", reason="lease_expired_before_claim")
                return previous, False
            if directory.exists():
                raise Rejected("INCOMPLETE_REQUEST_NEEDS_REVIEW")
            selected = self.select_worker(self.available_workers(), profile, case, worker_id, command_box)
            readers = self.root / "readers" / profile
            if readers.is_dir() and any(readers.glob("*.json")):
                raise Rejected("WORKER_OUTPUT_IS_BEING_READ")
            active = read_json(self.active)
            guard = None
            if command_box is not None:
                if selected.get("parallel") is not True:
                    raise Rejected("PARALLEL_WORKER_RESTART_REQUIRED")
                if active and "workers" not in active:
                    self.clear_slot(active)
                    active = None
                pending = self.current_workers(active) if active else {}
                for pending_worker, pending_id in pending.items():
                    assigned = read_json(self.job(pending_id) / "request.json")
                    if assigned is None or pending_worker == worker_id or assigned["profile"] == profile:
                        raise Rejected("WORKER_ALREADY_ASSIGNED")
                if len(pending) >= MAX_ACTIVE_WORKERS:
                    raise Rejected("SIMULATION_CAPACITY_REACHED")
                guard_id = active["request_id"] if active else uuid.uuid4().hex
                guard = self.job(guard_id)
                if not active:
                    guard.mkdir(mode=0o700)
                pending[worker_id] = request_id
                reservation = {"request_id": guard_id, "workers": pending}
            else:
                self.clear_slot(active)
                reservation = {"request_id": request_id}
            request = dict(desired, version=VERSION, request_id=request_id, worker_id=selected["id"],
                           timeout_seconds=selected["timeout_seconds"], profile_digest=selected["profile_digest"])
            directory.mkdir(mode=0o700)
            put_json(directory / "request.json", request)
            # Commit the reservation before publishing a live lease to the worker.
            self.refresh(directory)
            if guard is not None:
                self.refresh_guard(guard, pending)
            put_json(self.active, reservation)
            return request, True

    def assigned_job(self, active, worker_id):
        if "workers" in active:
            request_id = active["workers"].get(worker_id)
        else:
            request_id = active["request_id"]
        return self.job(request_id) if request_id is not None else None

    def claim(self, worker_id, profile):
        with self.transact():
            active = read_json(self.active)
            if not active:
                return None
            directory = self.assigned_job(active, worker_id)
            if directory is None:
                return None
            request = read_json(directory / "request.json")
            if not request or request["worker_id"] != worker_id or read_json(directory / "state.json") is not None:
                return None
            if not self.live(directory):
                return None
            if (request["version"] != VERSION or request["profile"] != profile["profile"]
                    or request["case"] not in profile["cases"] or request["profile_digest"] != profile_digest(profile)):
                self.finish(directory, "not_started", reason="profile_changed")
                return None
            # An interrupted claim cannot be executed a second time.
            self.finish(directory, "starting")
            return request

    def finish(self, directory, state, **details):
        put_json(directory / "state.json", dict(details, state=state))

    def wait(self, request, stopping):
        request_id = request["request_id"]
        directory = self.job(request_id)
        start_deadline = time.monotonic() + START_SECONDS
        deadline = start_deadline + request["timeout_seconds"] + 15
        next_refresh = time.monotonic() + HEARTBEAT_SECONDS
        while True:
            with self.transact():
                result = self.snapshot(request_id)
                if result["state"] in TERMINAL:
                    return result
                now = time.monotonic()
                waiting_too_long = result["state"] == "queued" and now >= start_deadline
                if (stopping() or now >= deadline or waiting_too_long or not result["lease_current"]
                        or not self.worker_online(request["worker_id"])):
                    put_json(directory / "lease.json", {"until": 0})
                    if result["state"] == "queued":
                        self.finish(directory, "not_started", reason="runner_stopped_before_claim")
                        return self.snapshot(request_id)
                    break
                if now >= next_refresh:
                    self.refresh(directory)
                    next_refresh = now + HEARTBEAT_SECONDS
            time.sleep(POLL_SECONDS)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = self.snapshot(request_id)
            if result["state"] in TERMINAL:
                return result
            time.sleep(0.5)
        return dict(self.snapshot(request_id), requires_review=True)



def local_group_alive(process):
    if os.name != "posix":
        return process.poll() is None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    return True


def stop_local_group(process):
    # Only signal a group while the child we created is still its live leader.
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


class SimmerSummary:
    """Read only the single-case verdict in simmer's final Simulation Summary."""

    def __init__(self):
        self.partial = b""
        self.rows = None
        self.verdict = None
        self.drained = False

    def feed(self, data):
        *lines, self.partial = (self.partial + data).split(b"\n")
        self.partial = self.partial[:MAX_SUMMARY_LINE + 1]
        for line in lines:
            if len(line) > MAX_SUMMARY_LINE:
                self.rows = None
                continue
            line = TERMINAL_COLOR.sub(b"", line).strip()
            if line == b"%I:sim: Simulation Summary":
                self.rows = []
                self.verdict = None
            elif self.rows is not None:
                self.rows.append(line.split())
                if len(self.rows) == 3:
                    header, separator, counts = self.rows
                    self.rows = None
                    if header == [b"passed", b"skipped", b"failed", b"total"] and separator == [
                        b"------", b"-------", b"------", b"-----"
                    ]:
                        self.verdict = SIMMER_VERDICTS.get(tuple(counts))

    def forward(self, source, display):
        binary = getattr(display, "buffer", None)
        with source:
            while True:
                try:
                    data = source.read(65536)
                except OSError:
                    return
                if not data:
                    self.feed(b"\n")
                    self.drained = True
                    return
                self.feed(data)
                if display is not None:
                    try:
                        if binary is None:
                            display.write(data.decode("utf-8", errors="replace"))
                            display.flush()
                        else:
                            binary.write(data)
                            binary.flush()
                    except (OSError, ValueError):
                        display = None


def run_claim(queue, request, profile, working_directory, locks, stopping, command_keys=None):
    request_id = request["request_id"]
    directory = queue.job(request_id)
    output = directory / "output"
    output.mkdir(mode=0o700)
    seed = str(request["seed"])
    if command_keys is None:
        argv = [arg.replace("{seed}", seed).replace("{request_id}", request_id).replace("{output_dir}", str(output))
                for arg in profile["cases"][request["case"]]]
    else:
        try:
            argv = open_command(request, *command_keys)
        except Rejected:
            queue.finish(directory, "launch_failed", reason="command_rejected")
            return
    env = dict(os.environ, ETX_SIM_REQUEST_ID=request_id, ETX_SIM_OUTPUT_DIR=str(output), ETX_SIM_SEED=seed)
    process = None
    forwarding = None
    try:
        options = {"start_new_session": True, "pass_fds": locks} if os.name == "posix" else {}
        with queue.transact():
            if stopping() or not queue.live(directory):
                queue.finish(directory, "not_started", reason="lease_expired_before_launch")
                return
            process = subprocess.Popen(argv, cwd=working_directory, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0, **options)
            queue.finish(directory, "running", process_id=process.pid)
        summary = SimmerSummary()
        forwarding = threading.Thread(target=summary.forward, args=(process.stdout, sys.stdout), daemon=True)
        forwarding.start()
        deadline = time.monotonic() + request["timeout_seconds"]
        next_heartbeat = time.monotonic() + HEARTBEAT_SECONDS
        while process.poll() is None:
            now = time.monotonic()
            if now >= next_heartbeat:
                queue.heartbeat(request["worker_id"], profile, busy=True)
                next_heartbeat = now + HEARTBEAT_SECONDS
            if stopping() or not queue.live(directory) or now >= deadline:
                stop_local_group(process)
                queue.finish(directory, "needs_review", process_id=process.pid, reason="interrupted_or_timed_out")
                return
            time.sleep(min(0.5, POLL_SECONDS))
        if local_group_alive(process):
            queue.finish(directory, "needs_review", process_id=process.pid, reason="command_left_descendants")
            return
        if process.returncode < 0:
            queue.finish(directory, "needs_review", process_id=process.pid, exit_code=process.returncode,
                         reason="command_terminated_by_signal")
            return
        forwarding.join(timeout=2)
        if not summary.drained:
            queue.finish(directory, "needs_review", process_id=process.pid, reason="output_stream_incomplete")
            return
        details = {"exit_code": process.returncode}
        if summary.verdict is not None:
            details["simmer_result"] = summary.verdict
        queue.heartbeat(request["worker_id"], profile, busy=False)
        queue.finish(directory, "exited", **details)
    except OSError:
        if process is None:
            queue.heartbeat(request["worker_id"], profile, busy=False)
            queue.finish(directory, "launch_failed", reason="could_not_start_command")
            return
        raise
    finally:
        if process is not None and process.poll() is None:
            try:
                stop_local_group(process)
            finally:
                queue.finish(directory, "needs_review", process_id=process.pid, reason="cleanup_requires_confirmation")
        if forwarding is None and process is not None:
            process.stdout.close()


def worker_loop(queue, profile, access, stopping, worker_id=None, command_keys=None):
    worker_id = worker_id or uuid.uuid4().hex
    working_directory = Path.cwd()
    queue.prepare()
    print(f"ETX_SIM_WORKER={worker_id} profile={profile['profile']}", flush=True)
    try:
        while not stopping():
            queue.heartbeat(worker_id, profile, busy=False)
            active = read_json(queue.active)
            if active:
                directory = queue.assigned_job(active, worker_id)
                request = read_json(directory / "request.json") if directory is not None else None
                if request and request["worker_id"] == worker_id:
                    with access() as locks:
                        if locks is not None:
                            claimed = queue.claim(worker_id, profile)
                            if claimed:
                                queue.heartbeat(worker_id, profile, busy=True)
                                print(f"ETX_SIM_CLAIMED={claimed['request_id']}", flush=True)
                                run_claim(queue, claimed, profile, working_directory, locks, stopping, command_keys)
                                queue.reconcile_workers()
                                verdict = queue.snapshot(claimed["request_id"]).get("simmer_result")
                                if verdict is not None:
                                    print(f"ETX_SIM_RESULT={verdict}", flush=True)
            time.sleep(POLL_SECONDS)
    finally:
        (queue.workers / (worker_id + ".json")).unlink(missing_ok=True)


def command_worker(queue, slot, lock_root, access, stopping):
    import fcntl

    if not SLOT.fullmatch(slot):
        raise Rejected("BAD_WORKER_NUMBER")
    queue.prepare()
    slot_fd = lock_fd(lock_root / (slot + ".lock"))
    try:
        try:
            fcntl.flock(slot_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Rejected("WORKER_NUMBER_UNAVAILABLE") from None
        trusted_path = queue.root / "command-signer.pem"
        fd = os.open(trusted_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise Rejected("BAD_COMMAND_SIGNER")
            trusted = stream.read(8193)
        if not 1 <= len(trusted) <= 8192:
            raise Rejected("BAD_COMMAND_SIGNER")
        worker_id = uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix=".command-worker-", dir=queue.root) as temporary:
            directory = Path(temporary)
            certificate, key, signer = (directory / name for name in ("worker.pem", "worker-key.pem", "signer.pem"))
            signer.write_bytes(trusted)
            openssl(["x509", "-in", str(signer), "-noout"])
            openssl(["req", "-new", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30",
                     "-subj", "/CN=etx-worker-" + worker_id, "-keyout", str(key), "-out", str(certificate)])
            profile = {"profile": slot, "cases": {"run": []}, "timeout_seconds": MAX_RUNTIME,
                       "parallel": True, "command_certificate": base64.b64encode(certificate.read_bytes()).decode("ascii")}
            worker_loop(queue, profile, access, stopping, worker_id, (certificate, key, signer))
    finally:
        os.close(slot_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    terminal = modes.add_parser("worker")
    registration = terminal.add_mutually_exclusive_group(required=True)
    registration.add_argument("--profile-file", type=Path)
    registration.add_argument("--command-profile")
    seal = modes.add_parser("seal", help="Sign and encrypt a JSON argv array read from stdin")
    for name in ("request-id", "worker-id", "profile"):
        seal.add_argument("--" + name, required=True)
    for name in ("signer", "signing-key", "recipient"):
        seal.add_argument("--" + name, required=True, type=Path)
    seal.add_argument("--simmer-case")
    seal.add_argument("--simmer-seed", type=int, default=0)
    args = parser.parse_args()
    if args.mode == "seal":
        if args.simmer_case is not None:
            argv = simmer_argv(args.simmer_case, args.simmer_seed, args.profile)
        else:
            data = sys.stdin.buffer.read(MAX_COMMAND_BYTES + 1)
            if len(data) > MAX_COMMAND_BYTES:
                raise Rejected("COMMAND_SIZE_LIMIT")
            argv = json.loads(data)
        print(seal_command(args.request_id, args.worker_id, args.profile, argv,
                           args.signer, args.signing_key, args.recipient))
        return 0
    if os.name != "posix" or False:
        raise Rejected("FIXED_ETX_HOST_REQUIRED")
    import pwd

    if pwd.getpwuid(os.geteuid()).pw_name != site(required=True)["remote"]["user"]:
        raise Rejected("FIXED_ETX_USER_REQUIRED")
    os.umask(0o077)
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    lock_root = Path(site()["remote"]["lock_root"])
    private_directory(lock_root, create=True)
    queue = Queue(ROOT, lambda: transaction(lock_root))
    access = lambda: shared_access(lock_root)
    sim_access = lambda: simulation_access(lock_root)
    if args.mode == "worker":
        if args.command_profile is not None:
            command_worker(queue, args.command_profile, lock_root, sim_access, lambda: stopped)
        else:
            worker_loop(queue, load_profile(args.profile_file), sim_access, lambda: stopped)
        return 0

    raise Rejected("RUNNER_NOT_INCLUDED")



if __name__ == "__main__":
    try:
        sys.exit(main())
    except Rejected as error:
        print(f"ETX_SIM_ERROR={error}", file=sys.stderr)
        sys.exit(2)
    except Exception as error:
        print(f"ETX_SIM_ERROR={type(error).__name__}", file=sys.stderr)
        sys.exit(2)
