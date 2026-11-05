"""Where the experiment's processes run: a tester container (Docker) or an SSH host.

Every other module talks to machines only through the Host protocol below. Implementations:

* DockerHost  - the tester container of one AS of the generated topology (compose exec).
* SSHHost     - an SSH host of deployment.hosts, through hummbwtester's ssh_orchestration.
* LocalHost   - this machine; for unit tests and development.

Conventions shared by all of them
---------------------------------
* Commands are argv lists, quoted with shlex wherever a shell is unavoidable; nothing from the
  configuration is ever interpreted by a shell.
* The helper scripts (daemon start/stop, atomic writes) are bash and run as `bash -c <script> bash
  <args>`: the tester containers have bash but no `sh`, and no nc, grep or ps either, so scripts
  stick to bash builtins plus coreutils.
* ``run(env=...)`` is for non-secret values: on Docker they appear in the argv of the local
  `docker` client (`-e K=V`), on SSH in the remote argv (`env K=V ...`).
* Secrets (SCION_MARKETPLACE_JWT) go through ``start_daemon``: its ``env`` and ``env_from_files``
  travel on the stdin of the launcher script, which evaluates them inside the (root) shell on the
  host. They never appear in any argv. ``env_from_files`` is the preferred way: the secret then is
  read from a mode-600 file on the host (put there with ``put_text(..., mode="600")``) and the
  runner never even holds it after installing it.
* Logs and pidfiles of daemons are world-readable (umask 022); the directories are created.

Methods beyond the lead's first draft (documented in the protocol): ``start_daemon(env_from_files=)``,
``daemon_alive``, ``sciond_address``.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol


class Host(Protocol):
    """One machine or container. Commands are argv lists: never build shell strings from config."""

    name: str  # for logs and error messages, e.g. "tester_1-ff00_0_112" or "ufms"
    kind: str  # "docker" or "ssh"

    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = True,
        timeout: float | None = None,
        env: Mapping[str, str] | None = None,
        input: str | bytes | None = None,
        root: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run argv to completion on the host. stdout/stderr are captured as text.

        env is set for the command only. With root=True the command runs as root
        (a no-op in Docker, where the tester already is root; `sudo -n` over SSH).
        check=True raises HostError, carrying the command, exit status and stderr.
        A timeout raises HostError (status None).
        """
        ...

    def popen(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        stdout: int | None = subprocess.PIPE,
        stderr: int | None = subprocess.STDOUT,
        root: bool = False,
    ) -> subprocess.Popen[str]:
        """Start a long-running command whose output the runner streams (rsync progress, iperf3, ping).

        stdout is a text pipe by default; stdin is a pipe too (keep it open, closing it asks
        the remote command to stop). Terminating the returned Popen terminates the remote
        process too. Docker: `compose exec` does NOT forward signals, so the command runs
        under a guard that kills it on stdin EOF (verified live). SSH: `ssh -tt`, the hangup of
        the pty kills it; the pty turns "\\n" into "\\r\\n" in the output.
        """
        ...

    def start_daemon(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None,
        log_path: str,
        pid_path: str,
        root: bool = False,
        env_from_files: Mapping[str, str] | None = None,
    ) -> int:
        """Start argv detached on the host, stdout+stderr to log_path, its pid to pid_path. Returns the pid.

        The environment must not leak into argv or the process list of other users.
        Secrets such as SCION_MARKETPLACE_JWT arrive as env values the implementation passes
        through stdin or a root-only file, never on a command line.

        env_from_files maps a variable name to the path of a file on the host whose content
        (trailing newlines stripped by the shell) becomes the value, read inside the launcher
        shell with root=True privileges: the way to pass a secret without the runner holding it.
        The parent directories of log_path and pid_path are created. The returned pid is the
        pid of argv itself (the launcher execs it). Use daemon_alive to see if it survived.
        """
        ...

    def daemon_alive(self, pid_path: str, *, root: bool = False) -> bool:
        """True if the pid recorded in pid_path is a live (non-zombie) process."""
        ...

    def stop_daemon(self, pid_path: str, *, timeout: float = 5.0, root: bool = False) -> bool:
        """SIGTERM the pid in pid_path (then SIGKILL after timeout), remove the pidfile.

        Only ever signals the pid it recorded: never a pattern match. Returns False if nothing ran.
        """
        ...

    def put_file(self, local: Path, remote: str, mode: str = "644") -> None:
        """Copy a local file to remote, atomically (write remote.tmp-<random>, then mv). Creates the parent."""
        ...

    def put_text(self, text: str, remote: str, mode: str = "644") -> None:
        """Write text to remote, atomically. The text travels on stdin, never in argv. Creates the parent."""
        ...

    def get_file(self, remote: str, local: Path) -> None:
        ...

    def read_text(self, remote: str) -> str:
        ...

    def path_exists(self, remote: str) -> bool:
        ...

    def address(self) -> str:
        """The host's own address on the SCION underlay, as used in SCION_LOCAL_IA=<ia>,<address>.

        Queried every time, never cached (the Docker topology may be regenerated).
        """
        ...

    def sciond_address(self) -> str:
        """The SCION daemon address of this host for SCION_DAEMON_ADDRESS.

        Docker: the SCION_DAEMON environment variable of the tester container (e.g.
        `[fd00:f00d:cafe::7f00:14]:30255`), as scion-end2end.py reads it. SSH: the `sciond`
        field of the deployment host.
        """
        ...


class HostError(RuntimeError):
    """A command on a host failed; the message includes host, argv, status and stderr."""

    def __init__(self, host: str, argv: Sequence[str], status: int | None, stderr: str):
        self.host, self.argv, self.status, self.stderr = host, list(argv), status, stderr
        super().__init__(f"{host}: {' '.join(map(str, argv))} -> {status}: {stderr.strip()}")


# ---------------------------------------------------------------------------------------------
# The scripts. All bash; arguments arrive as $1.. so that nothing is ever interpolated.
# ---------------------------------------------------------------------------------------------

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MODE = re.compile(r"^[0-7]{3,4}$")

# $1 target, $2 mode; the content on stdin. Written to a temporary file next to the target.
_WRITE_SCRIPT = r"""set -e
umask 077
mkdir -p -- "$(dirname -- "$1")"
tmp="$1.tmp-$3"
trap 'rm -f -- "$tmp"' EXIT
cat > "$tmp"
chmod "$2" "$tmp"
mv -f -- "$tmp" "$1"
trap - EXIT
"""

# $1 temporary file (already copied in), $2 mode, $3 target.
_INSTALL_SCRIPT = r"""set -e
chmod "$2" "$1"
mv -f -- "$1" "$3"
"""

# $1 pidfile, $2 logfile, then argv. stdin: shell assignments (env and env_from_files).
# The pid file is written by the shell that then execs argv, so it holds argv's own pid.
_START_SCRIPT = r"""set -e
umask 022
pidfile=$1; logfile=$2; shift 2
set -a
eval "$(cat)"
set +a
mkdir -p -- "$(dirname -- "$pidfile")" "$(dirname -- "$logfile")"
rm -f -- "$pidfile"
setsid bash -c 'echo "$$" > "$1"; shift; exec "$@"' bash "$pidfile" "$@" >"$logfile" 2>&1 </dev/null &
i=0
while [ ! -s "$pidfile" ] && [ "$i" -lt 100 ]; do sleep 0.05; i=$((i+1)); done
[ -s "$pidfile" ] || { echo "daemon did not record its pid in $pidfile" >&2; exit 1; }
cat "$pidfile"
"""

# $1 pidfile. Exit 0 if the pid is alive and not a zombie.
_ALIVE_SCRIPT = r"""pid=$(cat -- "$1" 2>/dev/null) || exit 1
case "$pid" in ''|*[!0-9]*) exit 1;; esac
kill -0 "$pid" 2>/dev/null || exit 1
s=$(cat "/proc/$pid/stat" 2>/dev/null) || exit 1
s=${s##*) }
[ "${s:0:1}" != Z ]
"""

# $1 pidfile, $2 number of 0.1 s steps before SIGKILL. Exit 0 if a process was stopped, 1 if none ran.
_STOP_SCRIPT = r"""pidfile=$1; steps=$2
pid=$(cat -- "$pidfile" 2>/dev/null) || exit 1
case "$pid" in ''|*[!0-9]*) rm -f -- "$pidfile"; exit 1;; esac
alive() {
  kill -0 "$pid" 2>/dev/null || return 1
  local s; s=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
  s=${s##*) }
  [ "${s:0:1}" != Z ]
}
if ! alive; then rm -f -- "$pidfile"; exit 1; fi
kill -TERM "$pid" 2>/dev/null || true
i=0
while alive && [ "$i" -lt "$steps" ]; do sleep 0.1; i=$((i+1)); done
if alive; then kill -KILL "$pid" 2>/dev/null || true; sleep 0.2; fi
rm -f -- "$pidfile"
exit 0
"""

# Kill the command when the guard's stdin reaches EOF, i.e. when the local client goes away.
# (a background job gets /dev/null as stdin, so the real stdin is kept on fd 3 for the watcher)
_GUARD_SCRIPT = r"""exec 3<&0
"$@" </dev/null & c=$!
( read -r _ <&3 || true; kill "$c" 2>/dev/null ) & r=$!
wait "$c"; st=$?
kill "$r" 2>/dev/null
exit "$st"
"""


def _bash(script: str, *args: str) -> list[str]:
    return ["bash", "-c", script, "bash", *args]


def _check_env(env: Mapping[str, str] | None) -> dict[str, str]:
    out = dict(env or {})
    for key in out:
        if not _ENV_NAME.match(key):
            raise ValueError(f"invalid environment variable name {key!r}")
    return out


def _check_mode(mode: str) -> str:
    if not _MODE.match(mode):
        raise ValueError(f"invalid file mode {mode!r}")
    return mode


def start_script_input(env: Mapping[str, str] | None,
                       env_from_files: Mapping[str, str] | None) -> str:
    """The stdin of the launcher: one shell-quoted assignment per variable."""
    lines = [f"{k}={shlex.quote(v)}" for k, v in _check_env(env).items()]
    for k, path in _check_env(env_from_files).items():
        lines.append(f"{k}=$(cat -- {shlex.quote(path)})")
    return "\n".join(lines) + "\n"


class _ScriptHost:
    """Everything above the transport: subclasses provide _run_raw and _spawn_raw, put/get, address."""

    name: str
    kind: str

    # -- transport (subclasses) ------------------------------------------------------------
    def _run_raw(self, argv: Sequence[str], env: Mapping[str, str] | None, root: bool,
                 input: str | None, timeout: float | None) -> subprocess.CompletedProcess[str]:
        raise NotImplementedError

    def popen(self, argv, *, env=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
              root=False):
        raise NotImplementedError

    # -- the Host protocol on top ----------------------------------------------------------
    def run(self, argv, *, check=True, timeout=None, env=None, input=None, root=False):
        argv = [str(a) for a in argv]
        _check_env(env)
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        try:
            result = self._run_raw(argv, env, root, input, timeout)
        except subprocess.TimeoutExpired as e:
            raise HostError(self.name, argv, None, f"timed out after {timeout}s") from e
        if check and result.returncode != 0:
            raise HostError(self.name, argv, result.returncode, result.stderr or result.stdout)
        return result

    def _script(self, script: str, *args: str, input: str | None = None, root: bool = False,
                check: bool = True, timeout: float | None = 120) -> subprocess.CompletedProcess[str]:
        return self.run(_bash(script, *args), input=input, root=root, check=check, timeout=timeout)

    def start_daemon(self, argv, *, env, log_path, pid_path, root=False, env_from_files=None):
        argv = [str(a) for a in argv]
        stdin = start_script_input(env, env_from_files)
        result = self._script(_START_SCRIPT, pid_path, log_path, *argv, input=stdin, root=root,
                              check=False)
        if result.returncode != 0:
            # The command line is reported without the environment, which may hold secrets.
            raise HostError(self.name, ["start_daemon", *argv], result.returncode, result.stderr)
        try:
            return int(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise HostError(self.name, ["start_daemon", *argv], None,
                            f"no pid in {result.stdout!r}") from None

    def daemon_alive(self, pid_path, *, root=False):
        return self._script(_ALIVE_SCRIPT, pid_path, root=root, check=False).returncode == 0

    def stop_daemon(self, pid_path, *, timeout=5.0, root=False):
        steps = str(max(int(timeout * 10), 0))
        result = self._script(_STOP_SCRIPT, pid_path, steps, root=root, check=False,
                              timeout=timeout + 30)
        if result.returncode not in (0, 1):
            raise HostError(self.name, ["stop_daemon", pid_path], result.returncode, result.stderr)
        return result.returncode == 0

    def put_text(self, text, remote, mode="644"):
        self._script(_WRITE_SCRIPT, remote, _check_mode(mode), uuid.uuid4().hex[:8], input=text)

    def read_text(self, remote):
        return self.run(["cat", "--", remote]).stdout

    def path_exists(self, remote):
        result = self.run(["test", "-e", remote], check=False)
        if result.returncode not in (0, 1):
            raise HostError(self.name, ["test", "-e", remote], result.returncode, result.stderr)
        return result.returncode == 0

    def get_file(self, remote, local):
        """Binary safe: the content travels base64 encoded."""
        out = self.run(["base64", "--", remote]).stdout
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_bytes(base64.b64decode(out))


# ---------------------------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------------------------

def tester_service(isd_as: str) -> str:
    """Name of the Compose service running the tester of an AS: tester_1-ff00_0_112."""
    return "tester_" + isd_as.replace(":", "_")


def _drop_compose_noise(text: str) -> str:
    # `docker compose` prints e.g. `time="..." level=warning msg="... `version` is obsolete ..."`
    # on stderr of every call.
    return "".join(line for line in text.splitlines(keepends=True)
                   if not (line.startswith("time=") and "level=warning" in line))


class DockerHost(_ScriptHost):
    """The tester container of one AS of the generated Docker topology.

    Commands are `docker compose -f <scion_dir>/gen/scion-dc.yml exec -T tester_<ia> ...`. root is a
    no-op (the tester runs as root). Compose is the single source of the container identity: nothing
    is cached, so a regenerated topology is picked up.
    """

    kind = "docker"

    def __init__(self, scion_dir: Path, isd_as: str):
        self.scion_dir = Path(scion_dir)
        self.isd_as = isd_as
        self.service = tester_service(isd_as)
        self.name = self.service
        self.compose_file = self.scion_dir / "gen" / "scion-dc.yml"
        if not self.compose_file.is_file():
            raise HostError(self.name, ["docker", "compose"], None,
                            f"{self.compose_file} is missing; generate the topology first "
                            f"(cd {self.scion_dir} && ./scion.sh topology ... && ./scion.sh start)")

    def _compose(self, *args: str) -> list[str]:
        return ["docker", "compose", "-f", str(self.compose_file), *args]

    def _exec_argv(self, argv: Sequence[str], env: Mapping[str, str] | None) -> list[str]:
        env_args: list[str] = []
        for k, v in (env or {}).items():
            env_args += ["-e", f"{k}={v}"]
        return self._compose("exec", "-T", *env_args, self.service, *argv)

    def _run_raw(self, argv, env, root, input, timeout):
        result = subprocess.run(
            self._exec_argv(argv, env), capture_output=True, text=True, input=input,
            stdin=None if input is not None else subprocess.DEVNULL, timeout=timeout)
        return subprocess.CompletedProcess(result.args, result.returncode, result.stdout,
                                           _drop_compose_noise(result.stderr))

    def popen(self, argv, *, env=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
              root=False):
        _check_env(env)
        guarded = _bash(_GUARD_SCRIPT, *[str(a) for a in argv])
        return subprocess.Popen(self._exec_argv(guarded, env), stdin=subprocess.PIPE,
                                stdout=stdout, stderr=stderr, text=True)

    def put_file(self, local, remote, mode="644"):
        _check_mode(mode)
        tmp = f"{remote}.tmp-{uuid.uuid4().hex[:8]}"
        self.run(["mkdir", "-p", "--", os.path.dirname(remote) or "."])
        cp = subprocess.run(self._compose("cp", str(local), f"{self.service}:{tmp}"),
                            capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if cp.returncode != 0:
            raise HostError(self.name, ["compose", "cp", str(local), tmp], cp.returncode,
                            _drop_compose_noise(cp.stderr))
        try:
            self._script(_INSTALL_SCRIPT, tmp, mode, remote)
        except HostError:
            self.run(["rm", "-f", "--", tmp], check=False)
            raise

    def get_file(self, remote, local):
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        cp = subprocess.run(self._compose("cp", f"{self.service}:{remote}", str(local)),
                            capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if cp.returncode != 0:
            raise HostError(self.name, ["compose", "cp", remote, str(local)], cp.returncode,
                            _drop_compose_noise(cp.stderr))

    def address(self) -> str:
        """The host part of `scion address`, which is what the SCION bind would pick itself."""
        out = self.run(["scion", "address"]).stdout.strip()
        ia, _, ip = out.partition(",")
        if not ip or ia != self.isd_as:
            raise HostError(self.name, ["scion", "address"], 0,
                            f"reported {out!r}, which is not an address of {self.isd_as}")
        return ip

    def sciond_address(self) -> str:
        out = self.run(["printenv", "SCION_DAEMON"]).stdout.strip()
        if not out:
            raise HostError(self.name, ["printenv", "SCION_DAEMON"], 0, "empty")
        return out


# ---------------------------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------------------------

_SCION_DIR: Path | None = None


def configure(scion_dir: Path) -> None:
    """Tell this module where hummbwtester lives ($SCION). Needed once before the first SSHHost use,
    unless SSHHost is given scion_dir or an `orchestration` module."""
    global _SCION_DIR
    _SCION_DIR = Path(scion_dir)


def _load_orchestration(scion_dir: Path | None) -> Any:
    root = scion_dir or _SCION_DIR
    if root is None:
        raise HostError("ssh", [], None, "hosts.configure(scion_dir) was not called; "
                        "SSH hosts need hummbwtester ($SCION/tools/hummbwtester)")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        from tools.hummbwtester.scripts import ssh_orchestration  # type: ignore
    except ImportError as e:
        raise HostError("ssh", [], None,
                        f"cannot import hummbwtester from {root}: {e} (PyYAML is required)") from e
    return ssh_orchestration


class SSHHost(_ScriptHost):
    """An SSH host of deployment.hosts, wrapping hummbwtester's ssh_orchestration.SSHHost.

    * Commands go through `ssh_orchestration.ssh_command(host, command, check=False, ...)`, whose
      command is a string for the remote `sh -c`; it is built with shlex.join from the argv.
      root=True prefixes `sudo -n`; env becomes `env K=V` after it (so it works through sudo).
    * Files go in with `scp_to` to a temporary name beside the target, then chmod + mv.
    * The helper scripts need bash on the remote host.
    * popen: `ssh -tt` with `exec <command>`; terminating the local ssh hangs up the pty, which
      kills the remote command. Output carries "\\r\\n" line ends.
    * address(): `127.0.0.1` unless `address=` says otherwise (SCIERA hosts run the SCION
      endpoints on loopback, see experiment-sciera.json); sciond_address() is the `sciond` field.
    * Never kill or modify anything that is not ours: daemons are stopped by recorded pid only.
    """

    kind = "ssh"

    def __init__(self, ssh_host: Any, *, scion_dir: Path | None = None,
                 address: str = "127.0.0.1", orchestration: Any = None):
        self.host = ssh_host
        self.name = ssh_host.name
        self._address = address
        self._orch = orchestration or _load_orchestration(scion_dir)

    @property
    def run_dir(self) -> str:
        return self.host.run_dir

    @staticmethod
    def _command(argv: Sequence[str], env: Mapping[str, str] | None, root: bool) -> str:
        words: list[str] = []
        if root:
            words += ["sudo", "-n"]
        if env:
            words += ["env", *[f"{k}={v}" for k, v in env.items()]]
        return shlex.join([*words, *argv])

    def _run_raw(self, argv, env, root, input, timeout):
        kwargs: dict[str, Any] = {"capture_output": True, "timeout": timeout}
        if input is not None:
            kwargs["input"] = input
        return self._orch.ssh_command(self.host, self._command(argv, env, root), check=False,
                                      **kwargs)

    def popen(self, argv, *, env=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
              root=False):
        _check_env(env)
        command = "exec " + self._command([str(a) for a in argv], env, root)
        full = ["ssh", *self._orch.SSH_OPTIONS, "-tt", "--", self.host.alias,
                shlex.join(["sh", "-c", command])]
        return subprocess.Popen(full, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                text=True)

    def put_file(self, local, remote, mode="644"):
        _check_mode(mode)
        self.run(["mkdir", "-p", "--", os.path.dirname(remote) or "."])
        tmp = f"{remote}.tmp-{uuid.uuid4().hex[:8]}"
        try:
            self._orch.scp_to(self.host, Path(local), tmp)
            self._script(_INSTALL_SCRIPT, tmp, mode, remote)
        except subprocess.CalledProcessError as e:
            self.run(["rm", "-f", "--", tmp], check=False)
            raise HostError(self.name, ["scp", str(local), tmp], e.returncode, "scp failed") from e
        except HostError:
            self.run(["rm", "-f", "--", tmp], check=False)
            raise

    def address(self) -> str:
        return self._address

    def sciond_address(self) -> str:
        return self.host.sciond


# ---------------------------------------------------------------------------------------------
# Local (tests, development)
# ---------------------------------------------------------------------------------------------

class LocalHost(_ScriptHost):
    """This machine. root=True means `sudo -n` unless already root. Same protocol, same scripts."""

    kind = "local"

    def __init__(self, name: str = "local", *, address: str = "127.0.0.1", sciond: str = ""):
        self.name = name
        self._address = address
        self._sciond = sciond

    @staticmethod
    def _prefix(env: Mapping[str, str] | None, root: bool) -> list[str]:
        words: list[str] = []
        if root and os.geteuid() != 0:
            words += ["sudo", "-n"]
        if env:
            words += ["env", *[f"{k}={v}" for k, v in env.items()]]
        return words

    def _run_raw(self, argv, env, root, input, timeout):
        return subprocess.run([*self._prefix(env, root), *argv], capture_output=True, text=True,
                              input=input, timeout=timeout,
                              stdin=None if input is not None else subprocess.DEVNULL)

    def popen(self, argv, *, env=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
              root=False):
        _check_env(env)
        return subprocess.Popen([*self._prefix(env, root), *[str(a) for a in argv]],
                                stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, text=True)

    def put_file(self, local, remote, mode="644"):
        _check_mode(mode)
        target = Path(remote)
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(f"{target.name}.tmp-{uuid.uuid4().hex[:8]}")
        try:
            shutil.copyfile(local, tmp)
            os.chmod(tmp, int(mode, 8))
            os.replace(tmp, target)
        finally:
            if tmp.exists():
                tmp.unlink()

    def address(self) -> str:
        return self._address

    def sciond_address(self) -> str:
        return self._sciond
