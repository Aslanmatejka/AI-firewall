# Troubleshooting

Symptom → cause → fix. Read top to bottom for your issue.

---

## Service & dashboard

### “Service Offline” / dashboard won’t load / connection refused

**Cause:** Python service is not running.

**Fix:**

1. Open PowerShell in the project folder.
2. Run `.\scripts\start.ps1`.
3. Wait for `Dashboard: http://127.0.0.1:9470`.
4. Refresh the browser.

**Still broken?** Check if something else uses port 9470:

```powershell
Get-NetTCPConnection -LocalPort 9470 -ErrorAction SilentlyContinue
```

Kill the old process or change `dashboard_port` in config.

---

### Dashboard loads but nothing updates

**Cause:** Browser cache or service stuck.

**Fix:**

1. Hard refresh: `Ctrl+Shift+R`.
2. Restart service: `Ctrl+C` in PowerShell, then `.\scripts\start.ps1`.
3. Check PowerShell window for red error lines.

---

### WPF app says “Service Offline” but web works

**Cause:** Desktop app started before service, or wrong port.

**Fix:** Start `.\scripts\start.ps1` first, then `.\scripts\launch-dashboard.ps1`.

---

## Approvals

### Pending requests never appear

**Checklist:**

1. Is policy set to **ask** (not allow) for that resource?
2. Is an AI process actually running? (Check **AI Processes** page.)
3. Is `approval_ui` set to `dashboard` in config? (Not `desktop` only with no dialog.)
4. For network: is there active traffic to an AI domain?

**Test the approval pipeline:**

```powershell
python scripts\test-live-approval.py
```

Should print `LIVE APPROVAL TEST PASSED`.

---

### Clicked Allow but access still blocked

**Cause:** Separate policy layer still blocking (e.g. global network block while you allowed one request).

**Fix:** Check **Settings** global policies and **App Rules**. One-time Allow grants last **24 hours** for that specific resource pattern only.

---

## Network blocking

### “Block Domain” does nothing

**Cause:** Not running as Administrator.

**Fix:** Close service, open PowerShell **as Administrator**, run `.\scripts\start.ps1` again.

**Verify:** AI Firewall tries WFP first (`wfp_enabled`), then `netsh`. Both need admin for persistent OS rules.

---

### Block works but comes back after reboot

**Cause:** Firewall rules may not persist if created in a non-admin session, or service not installed as Windows Service.

**Fix:** Use `.\scripts\install-service.ps1` as admin for always-on enforcement.

---

## File protection

### Files not triggering alerts

**Cause:** File guard watches **changes** while AI is running; enforcer scans **open handles**.

**Checklist:**

1. AI process must be detected (see **AI Processes**).
2. Path must be under a **protected folder**.
3. Policy must be **ask** or **block** (not allow).

**Stronger blocking:** Install kernel minifilter (see [NEXT.md](NEXT.md) — requires WDK + signing).

---

## Clipboard

### Log says “Clipboard listener unavailable — using poll mode”

**Cause:** Windows blocked `AddClipboardFormatListener` in that session, or pywin32/ctypes init failed.

**Impact:** Clipboard still monitored every ~1 second in poll mode. Slightly slower, still works.

**Fix (optional):** Run as normal user (not Remote Desktop nested session). Restart service after Windows update.

---

## Mic / camera

### Mic blocking not detected

**Cause:** `pycaw` not installed or no active audio session.

**Fix:**

```powershell
pip install pycaw
```

Restart service. Speak/use mic while AI app is running to trigger detection.

---

## Python / install errors

### `python` is not recognized

**Fix:** Reinstall Python from python.org. Enable **“Add Python to PATH”**. Restart PowerShell.

---

### `pip install` fails

**Fix:**

```powershell
python -m pip install --upgrade pip
python -m pip install -r python\requirements.txt
```

---

### Service starts then immediately exits

**Fix:**

1. Run with debug logging:
   ```powershell
   cd python
   python -m aishield --log-level DEBUG
   ```
2. Read the last error line.
3. Common cause: invalid JSON in config — validate at jsonlint.com.

---

## Windows Service (install-service.ps1)

### Service “AiShield” won’t start

**Fix:**

```powershell
# As Administrator
Get-EventLog -LogName Application -Source AiShield -Newest 10
```

Ensure Python is on the system PATH for the service account, or reinstall with `install-service.ps1`.

---

## Tests failing (developers)

```powershell
cd python
python -m unittest discover -s tests -v
```

All 12 tests should pass. If resolver tests fail on Windows, ensure no stale `%APPDATA%\AiShield\permissions.db` from manual testing.

---

## Still stuck?

1. Delete `%APPDATA%\AiShield\permissions.db` (resets audit/grants — policies in config remain).
2. Re-run `.\scripts\install.ps1`.
3. Open an issue with: Windows version, Python version, exact error text, and whether you run as admin.

---

## Quick diagnostic script

Run with service up:

```powershell
# Service reachable?
Invoke-WebRequest http://127.0.0.1:9470/api/status -UseBasicParsing | Select-Object StatusCode

# Live approval test
python scripts\test-live-approval.py
```

Both should succeed.
