import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="windows")


def ps(cmd):
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True, check=False
    )
    return (r.stdout + r.stderr).strip()


def test_diag():
    q = "(Get-CimInstance Win32_Service -Filter \"Name='BITS'\").StartMode"
    out = ["start0=" + ps(q)]
    out.append("start-after-cim=" + ps(q))
    ps("Get-BitsTransfer -AllUsers | Out-Null")
    out.append("after-getbits=" + ps(q))
    ps("Get-Service | Out-Null; Get-ScheduledTask | Out-Null")
    out.append("after-getsvc-tasks=" + ps(q))
    assert shutil is not None
    pytest.fail(" ; ".join(out))
