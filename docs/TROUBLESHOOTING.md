# Troubleshooting

Symptom → cause → fix. Read top to bottom for your issue.

---

## Service & dashboard

### Sign-in page instead of the dashboard

**Cause:** The sign-in link expired or was already used, or AI Firewall restarted.

**Fix:** Run `.\scripts\open-dashboard.ps1`.

---

### “Service offline” / dashboard won’t load / connection refused

**Cause:** Python service is not running.

**Fix:**

1. Open PowerShell in the project folder.
2. Run `.\scripts\start.ps1`.
3. Wait for `AI Firewall is running`. Your browser opens the dashboard.

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

### Desktop app says “Service offline” but web works

**Cause:** The two aren't using the same Windows account.

**Fix:** Run `.\scripts\start.ps1` and `.\scripts\launch-dashboard.ps1` as the same user, either both as administrator or neither. If something still looks wrong, check `%LOCALAPPDATA%\AiShield\dashboard.log`.

---

## Approvals

### Pending requests never appear

**Checklist:**

1. Is policy set to **ask** (not allow) for that resource?
2. Is an AI process actually running? (Check **AI Processes** page.)
3. Is `approval_ui` set to `dashboard` in config? (Not `desktop` only with no dialog.)
4. Network requests won't appear: network detection isn't working yet.

---

### Clicked Allow but access still blocked

**Cause:** Separate policy layer still blocking (e.g. global network block while you allowed one request).

**Fix:** Check **Settings** global policies and **App Rules**. One-time Allow grants last **24 hours** for that specific resource pattern only.

---

## Network

### The Network page stays empty, or blocking gives an error

**Cause:** Network detection and blocking aren't working yet.

Blocking is switched off on purpose. It worked by blocking a domain's IP address, and many unrelated sites can share that address. If an older version left rules behind, [Installation](INSTALLATION.md#if-you-used-an-older-version) shows how to remove them.

---

## File protection

### Files not triggering alerts

**Cause:** File guard watches **changes** while AI is running; enforcer scans **open handles**.

**Checklist:**

1. AI process must be detected (see **AI Processes**).
2. Path must be under a **protected folder**.
3. Policy must be **ask** or **block** (not allow).

**Limits:** file protection responds after a file is opened. It can't stop the open itself.

---

## Clipboard

### Log says “Clipboard listener unavailable — using poll mode”

**Cause:** Windows blocked `AddClipboardFormatListener` in that session, or pywin32/ctypes init failed.

**Impact:** Clipboard still monitored every ~1 second in poll mode. Slightly slower, still works.

**Fix (optional):** Run as normal user (not Remote Desktop nested session). Restart service after Windows update.

---

## Mic / camera

### Mic or camera use not detected

**Cause:** AI Firewall relies on Windows' own record of which desktop apps use these devices. It can't see Microsoft Store apps, or apps it doesn't recognize as AI.

Denying access or setting a block policy is recorded, but doesn't stop the app in this version.

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

## Tests failing (developers)

```powershell
cd python
python -m unittest discover -s tests -v
```

All tests should pass. If resolver tests fail on Windows, ensure no stale `%APPDATA%\AiShield\permissions.db` from manual testing.

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
Invoke-RestMethod http://127.0.0.1:9470/api/health
```

It should show `ok: True`.
