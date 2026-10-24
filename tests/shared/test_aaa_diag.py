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
    q = "(Get-CimInstance Win32_Service -Filter \"Name='BITS'\").StartMode + '/' + (Get-Service BITS).Status"
    out = ["start0=" + ps(q)]
    ps("Start-Service BITS")
    out.append("started=" + ps(q))
    ps("Get-BitsTransfer -AllUsers | Out-Null")
    out.append("after-getbits-running=" + ps(q))
    ps("Stop-Service BITS; Set-Service BITS -StartupType Manual")
    out.append("reset=" + ps(q))
    ps("bitsadmin /list /allusers | Out-Null")
    out.append("after-bitsadmin=" + ps(q))
    pytest.fail(" ; ".join(out))
