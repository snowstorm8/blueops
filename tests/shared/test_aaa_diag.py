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
    rows = [f"{f['id']}|{f['severity']}|n={len(f.get('evidence', []))}"
            for f in d["findings"] if f["severity"] in ("high", "medium")]
    for f in d["findings"]:
        if f["id"] in ("FS-SCRIPT-001", "FS-RECENT-001", "PRC-PATH-001", "TSK-SYSTEM-001"):
            for e in f.get("evidence", [])[:6]:
                rows.append(f["id"] + " " + json.dumps(e)[:200])
    errs = [e["code"] for e in d["errors"]]
    pytest.fail("ROWS\n" + "\n".join(rows) + "\nERRS " + ",".join(errs))
