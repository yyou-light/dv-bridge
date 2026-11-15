"""LSF wrapper included in signed simmer requests built on the client."""

import errno
import json
import os
import pty
import pwd
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from site_config import site, native_output

if 'fsdb_access' not in globals():
    from fsdb_access import fsdb_access


SUBMISSION = re.compile(rb"^Job <([1-9][0-9]*)> is submitted to (?:default )?queue <[A-Za-z0-9_.-]+>\.\r*\n", re.MULTILINE)
STARTUP_LIMIT = 8192


def unverified():
    try:
        print("ETX_SIM_LSF_TERMINAL=UNVERIFIED", flush=True)
    finally:
        os.kill(os.getpid(), signal.SIGTERM)


def run_interactive(argv):
    master, terminal = pty.openpty()
    startup = b""
    job_id = None
    try:
        with subprocess.Popen(argv, stdin=terminal, stdout=terminal, stderr=terminal) as process:
            os.close(terminal)
            terminal = None
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:  # Linux PTYs report EIO after the slave closes.
                        unverified()
                    break
                if not data:
                    break
                try:
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                except OSError:
                    unverified()
                if job_id is None and len(startup) < STARTUP_LIMIT:
                    startup = (startup + data)[:STARTUP_LIMIT]
                    # Identify the LSF submission before the remote program starts writing.
                    header = startup.split(b"<<Starting on", 1)[0]
                    match = SUBMISSION.search(header)
                    if match:
                        job_id = match[1].decode("ascii")
            return process.wait(), job_id
    finally:
        if terminal is not None:
            os.close(terminal)
        os.close(master)


def main():
    request = os.environ["ETX_SIM_REQUEST_ID"]
    if not re.fullmatch(r"[0-9a-f]{32}", request):
        raise SystemExit("Bad simulation request ID")
    case, seed, slot = sys.argv[1:]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", case):
        raise SystemExit("Specify one exact case name.")
    if not re.fullmatch(r"[0-9]{1,10}", seed) or int(seed) > 2147483647:
        raise SystemExit("Specify a seed between 0 and 2147483647.")
    if not re.fullmatch(r"work(?:0[1-9]|[1-9][0-9])", slot):
        raise SystemExit("Specify one worker number.")
    owner = pwd.getpwuid(os.geteuid()).pw_name
    wave = Path(native_output(case,seed,slot))/site()['remote']['fsdb_name']
    with fsdb_access(wave, write=True):
        declaration = Path(os.environ['ETX_SIM_OUTPUT_DIR']) / 'fsdb-write.json'
        if declaration.exists():
            raise SystemExit('FSDB_WRITE_RECORD_ALREADY_EXISTS')
        temporary = declaration.with_suffix('.tmp')
        fd = os.open(str(temporary), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'request_id': request, 'fsdb': str(wave.resolve())}, stream)
        os.replace(temporary, declaration)
        return run_simulation(case, seed, slot, owner)


def run_simulation(case, seed, slot, owner):
    argv = ["bsub", "-I", "-q", site()["remote"]["lsf_queue"], "simmer", "-t", site()["remote"]["target"]+":"+case,
            "--waves", "--seed", seed, "--dir-suffix", slot]
    code, job_id = run_interactive(argv)

    fields = "jobid stat queue:128 user:128"
    deadline = time.monotonic() + 90
    while job_id is not None and time.monotonic() < deadline:
        try:
            reply = subprocess.run(["bjobs", "-a", "-u", owner, "-json", "-o", fields, job_id],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=10, check=True)
            records = json.loads(reply.stdout)["RECORDS"]
            row = {key.lower(): str(value).strip() for key, value in records[0].items()} if len(records) == 1 else {}
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
            row = {}
        if (row.get("jobid") == job_id and row.get("queue") == site()["remote"]["lsf_queue"] and row.get("user") == owner
                and row.get("stat") in ("DONE", "EXIT")):
            print("ETX_SIM_LSF_JOB_ID=" + job_id, flush=True)
            return 0 if row["stat"] == "DONE" and code == 0 else 1
        time.sleep(5)
    unverified()


if __name__ == "__main__":
    sys.exit(main())
