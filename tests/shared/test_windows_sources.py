"""Static guards for the Windows collectors, runnable on every platform (no PowerShell needed).

They pin the hardening that Pester cannot check on a Linux box: tools are resolved from System32
(never through PATH), the fixture hooks are read only in the gated helpers, and the manifest has
the same shape as the Linux one. Pester (tests/windows) covers the runtime behaviour on CI.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ROOT / "windows"
COMMON = (WINDOWS / "lib" / "Common.ps1").read_text(encoding="utf-8")


def _scripts() -> list[Path]:
    return sorted(WINDOWS.rglob("*.ps1"))


def test_native_executables_are_never_resolved_through_path() -> None:
    """`& netstat.exe` searches PATH: a writable entry could substitute the tool and the audit
    would report what the planted program says. Calls must use Get-BoSystemToolPath."""
    offenders = []
    for path in _scripts():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("#", 1)[0]
            if re.search(r"&\s+[A-Za-z0-9_.-]+\.exe\b", code):
                offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, "\n".join(offenders)


def test_the_three_known_native_calls_use_the_system32_resolver() -> None:
    for script, exe in (
        ("audit/Get-NetworkAudit.ps1", "netstat.exe"),
        ("audit/Get-SecurityConfigAudit.ps1", "auditpol.exe"),
        ("audit/Get-ScheduledTaskAudit.ps1", "schtasks.exe"),
        ("audit/Get-SecurityConfigAudit.ps1", "net.exe"),
    ):
        text = (WINDOWS / script).read_text(encoding="utf-8")
        assert f"Get-BoSystemToolPath '{exe}'" in text, script


def _function_of(lines: list[str], index: int) -> str:
    for i in range(index, -1, -1):
        m = re.match(r"function\s+(\S+)", lines[i])
        if m:
            return m.group(1)
    return ""


def test_fixture_hooks_are_read_only_in_the_gated_helpers() -> None:
    """Every read of BO_FIXTURE_DIR / BO_FORCE_MISSING sits in a function that is itself behind
    Test-BoFixtureMode / Test-BoTestMode, or is the check that records ignored hooks."""
    lines = COMMON.splitlines()
    allowed = {
        "BO_FIXTURE_DIR": {
            "Test-BoFixtureMode",
            "Initialize-BoRun",
            "Get-BoFixtureJson",
            "Get-BoData",
            "Resolve-BoFsPath",
        },
        "BO_FORCE_MISSING": {"Get-BoForcedMissing", "Initialize-BoRun"},
    }
    for n, line in enumerate(lines):
        code = line.split("#", 1)[0]
        for var, funcs in allowed.items():
            if f"$env:{var}" in code:
                assert _function_of(lines, n) in funcs, f"line {n + 1}: {line.strip()}"
    for script in _scripts():
        if script.name == "Common.ps1":
            continue
        text = script.read_text(encoding="utf-8")
        assert "$env:BO_FIXTURE_DIR" not in text and "$env:BO_FORCE_MISSING" not in text, script


def test_fixture_mode_requires_test_mode() -> None:
    m = re.search(r"function Test-BoFixtureMode \{(.*?)\n\}", COMMON, re.S)
    assert m and "Test-BoTestMode" in m.group(1)
    t = re.search(r"function Test-BoTestMode \{(.*?)\n\}", COMMON, re.S)
    assert t and "BO_TEST_MODE -eq '1'" in t.group(1)
    assert "TEST_HOOKS_IGNORED" in COMMON


def test_manifest_has_the_same_shape_as_the_linux_one() -> None:
    m = re.search(r"function Write-BoRunManifest \{(.*?)\n\}\n", COMMON, re.S)
    assert m
    body = m.group(1)
    for key in (
        "schema_version",
        "kind",
        "hash_algorithm",
        "complete",
        "tool",
        "run",
        "host",
        "files",
        "collector",
    ):
        assert re.search(rf"\b{key}\s*=", body), key
    assert "'run-manifest'" in body and "'sha256'" in body
    linux = (ROOT / "linux/lib/common.sh").read_text(encoding="utf-8")
    for key in ('"kind":"run-manifest"', '"hash_algorithm":"sha256"', '"collector":['):
        assert key in linux


def test_run_directory_is_never_reused_and_text_escapes_are_injective() -> None:
    m = re.search(r"function Write-BoRunDirectory \{(.*?)\n\}\n", COMMON, re.S)
    assert m and re.search(r"while \(\[System\.IO\.Directory\]::Exists\(\$dir\)", m.group(1))
    s = re.search(r"function ConvertTo-BoSafeString \{(.*?)\n\}\n", COMMON, re.S)
    assert s
    code = "\n".join(line.split("#", 1)[0] for line in s.group(1).splitlines())
    assert "'?'" not in code  # the lossy substitution is gone
    assert "u005c" in code  # literal backslash-u text is escaped first


_STATE_CHANGING = re.compile(
    r"\b(?:Set-Content|Out-File|Add-Content|Copy-Item|Move-Item|Remove-Item|New-Item|Start-Process"
    r"|Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression|Invoke-CimMethod|Invoke-WmiMethod"
    r"|Stop-Service|Start-Service|Set-Service|Set-ItemProperty|Remove-ItemProperty"
    r"|Set-Acl|Restart-Computer|Stop-Process)\b"
    r"|\.Delete\(|IO\.File\]::(?:Write|Delete|Move|Copy|Append)|IO\.Directory\]::(?:Create|Delete|Move)"
    r"|SetUnixFileMode|\biex\b"
)


def test_collectors_change_nothing_except_their_own_output_directory() -> None:
    """Read-only by default: outside the two run-directory writers there is no call that creates,
    changes, deletes or executes anything (pattern strings inside quotes are data, not calls)."""
    allowed = {"Write-BoRunDirectory", "Write-BoRunManifest"}
    offenders = []
    for path in _scripts():
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            code = re.sub(r"'(?:[^']|'')*'", "''", line.split("#", 1)[0])
            code = re.sub(r'"(?:[^"`]|`.)*"', '""', code)
            if _STATE_CHANGING.search(code) and _function_of(lines, n) not in allowed:
                offenders.append(f"{path.relative_to(ROOT)}:{n + 1}: {line.strip()}")
    assert not offenders, "\n".join(offenders)


_REGISTRY_WRITES = re.compile(
    r"\b(?:New-ItemProperty|Set-ItemProperty|Remove-ItemProperty|Rename-ItemProperty"
    r"|Clear-ItemProperty|Set-Item|Add-Type|Import-Module|Register-\w*Task|Set-\w*Policy)\b"
    r"|\.(?:SetValue|DeleteValue|DeleteSubKey\w*|CreateSubKey)\("
    r"|OpenSubKey\([^)]*,\s*(?:\$true|1|\[bool\]1)\)"
    r"|Registry\]::SetValue|\bRegSetValue\w*|\bRegDeleteValue\w*|\bRegCreateKey\w*"
    r"|\breg(?:\.exe)?\s+(?:add|delete|import|copy|save|restore|load|unload)\b"
    r"|\b(?:secedit|auditpol|lgpo|gpupdate)(?:\.exe)?\b[^\n]*\s/(?:set|configure|import|restore|clear)\b"
)


def test_no_collector_can_write_the_registry() -> None:
    """The Lsa-key question: nothing under windows/ may write, create or delete a registry value,
    define P/Invoke code, or call a policy-changing tool. Quoted text (remediation advice, pattern
    strings) is data and is ignored, as in the broader read-only guard above."""
    offenders = []
    for path in _scripts():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            code = re.sub(r"'(?:[^']|'')*'", "''", line.split("#", 1)[0])
            code = re.sub(r'"(?:[^"`]|`.)*"', '""', code)
            if _REGISTRY_WRITES.search(code):
                offenders.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not offenders, "\n".join(offenders)


def test_the_guard_recognises_registry_writes() -> None:
    for bad in (
        "Set-ItemProperty -Path $p -Name RunAsPPL -Value 1",
        "$k.SetValue('a', 1)",
        "$h.OpenSubKey($sub, $true)",
        "reg add HKLM\\X /v a",
        "[Microsoft.Win32.Registry]::SetValue($p, 'a', 1)",
        "Add-Type -MemberDefinition $code -Name X",
        "secedit /configure /db x.sdb",
    ):
        assert _REGISTRY_WRITES.search(bad), bad
    for good in (
        "$k = $hive.OpenSubKey($sub)",
        "$v = $k.GetValue($n, $null, $opts)",
        "auditpol /get /category:*",
        "Get-ItemProperty -LiteralPath $p",
    ):
        assert not _REGISTRY_WRITES.search(good), good


def test_state_snapshot_script_is_read_only_and_withholds_values() -> None:
    """The snapshot runs before and after every live audit; it must not itself touch state, and the
    only key whose data may be printed is Lsa (Winlogon holds credential-bearing values)."""
    text = (ROOT / "tests" / "shared" / "windows-state-snapshot.ps1").read_text(encoding="utf-8")
    code = "\n".join(
        re.sub(r"'(?:[^']|'')*'", "''", ln.split("#", 1)[0]) for ln in text.splitlines()
    )
    assert not re.search(r"\b(?:Set|New|Remove|Clear|Rename|Start|Stop|Restart)-\w+", code)
    assert not re.search(r"OpenSubKey\([^)]*,", text)  # no writable-handle overload
    assert "$dataKeys = @('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa')" in text
    assert "Winlogon" not in text.split("$dataKeys", 1)[1].split("\n", 1)[0]
    assert "$sensitiveName" in text
    assert text.isascii()
