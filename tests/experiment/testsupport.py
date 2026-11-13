"""The SCION checkout whose hummbwtester modules the tests import.

$SCION_DIR if set, else the directory of the SCION Go module that go.mod pins (`go list -m`), so
the tests run against the hummbwtester version this repository is built with. Every test module
resolves the same directory: infra.load_hummbwtester allows one checkout per process.

A test that needs hummbwtester and cannot load it fails with the reason; it is not skipped, since
a skip would hide exactly the version skew between wgexp and hummbwtester the tests should catch.
"""

from __future__ import annotations

import functools
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCION_MODULE = "github.com/scionproto/scion"


@functools.cache
def scion_dir() -> Path:
    """$SCION_DIR, or the directory of the pinned SCION Go module."""
    env = os.environ.get("SCION_DIR")
    if env:
        return Path(env).resolve()
    try:
        out = subprocess.run(["go", "list", "-m", "-f", "{{.Dir}}", SCION_MODULE], cwd=REPO,
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as err:
        detail = getattr(err, "stderr", "") or err
        raise RuntimeError(f"cannot find the SCION checkout for hummbwtester: $SCION_DIR is not "
                           f"set and `go list -m {SCION_MODULE}` failed: {detail}") from err
    if not out:
        raise RuntimeError(f"`go list -m {SCION_MODULE}` gave no directory; run `go mod download` "
                           "or set $SCION_DIR")
    return Path(out).resolve()


def hummbwtester() -> SimpleNamespace:
    """hummbwtester's modules (orchestration, remote, ssh_setup), loaded by infra."""
    import infra  # here, so that importing this module stays cheap
    try:
        return infra.load_hummbwtester(scion_dir())
    except infra.InfraError as err:
        raise RuntimeError(f"cannot load hummbwtester from {scion_dir()}: {err}") from err
