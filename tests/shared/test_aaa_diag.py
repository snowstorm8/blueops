import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="windows")


def test_diag():
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         "windows/audit/Invoke-WindowsAudit.ps1", "-Json", "-Quiet"],
        capture_output=True, text=True, check=False,
    )
    d = json.loads(r.stdout)
    want = {"AUT-WINLOGON-001": 3, "PER-BOOT-001": 3, "PER-NETSH-001": 3, "PER-PORTMON-001": 3,
            "FW-RULE-002": 5, "FS-SCRIPT-001": 8, "PRC-PATH-001": 3, "FS-RECENT-001": 5,
            "TSK-SYSTEM-001": 3, "NET-ESTAB-002": 2}
    rows = []
    for f in d["findings"]:
        if f["id"] in want:
            for e in f.get("evidence", [])[: want[f["id"]]]:
                rows.append(f["id"] + " " + json.dumps(e)[:230])
    errs = []
    pytest.fail("ROWS\n" + "\n".join(rows) + "\nERRS\n" + "\n".join(errs) + f"\nexit={r.returncode}")
