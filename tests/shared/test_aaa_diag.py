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
    rows = [f"{f['id']}|{f['severity']}|{f.get('confidence')}|n={len(f.get('evidence', []))}"
            for f in d["findings"] if f["severity"] != "info"]
    errs = [f"{e['code']}|{e.get('material')}" for e in d["errors"]]
    pytest.fail("ROWS\n" + "\n".join(rows) + "\nERRS\n" + "\n".join(errs) + f"\nexit={r.returncode}")
