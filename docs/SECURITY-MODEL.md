# Security model

What AI Firewall's protected service defends against, how, what CI proves on every change, and what it can't do. This covers the C# service installed by the MSI. The older Python engine has no protection against software running as you.

## Who it defends against

| Attacker | Defended? |
|----------|-----------|
| An AI app or other program running as you, without admin rights | **Yes.** This is the main threat. |
| Another standard user on the same PC | **Yes.** |
| A program with administrator rights | **No.** Administrators can stop or remove any Windows program that doesn't have a kernel driver. AI Firewall makes this visible in the Windows event log but can't prevent it. |
| Code running in the Windows kernel | **No.** |

If you sign in as an administrator, set User Account Control to **Always notify**. At the default level, some programs can quietly gain admin rights.

## What stops a program running as you

| It might try to | Why it can't |
|---|---|
| Stop, reconfigure or delete the service | Only SYSTEM and administrators may control it. |
| Kill or inject into the service | It runs as SYSTEM, which ordinary programs can't open. |
| Read or change policy and logs | `%ProgramData%\AiShield` is open only to SYSTEM and administrators. |
| Replace AI Firewall's files | They're in Program Files. The service refuses to trust its own app if the folder becomes writable. |
| Approve its own request or relax a policy | That needs your answer on the secure prompt, not just the desktop app. |
| Read, click or cover the secure prompt | It runs as SYSTEM on a separate desktop, like a UAC prompt. Programs on your normal desktop can't reach it. **Allow** only works after two seconds. |
| Pretend to be the desktop app | The service checks the real program path Windows reports. A copy elsewhere, even with the same name, gets nothing. |
| Pretend to be the service | The app checks the pipe belongs to the service Windows started. |
| Grab the pipe's name first | The name is random each start and published where only administrators can write. |
| Flood the pipe | Unknown programs get a few small connections. The desktop app has its own budget. |
| Flood the audit log or the prompt | Detections are recorded once per app every 10 minutes, at most 30 a minute. After a refusal, each new prompt waits twice as long, up to a minute. |
| Plant a folder or link where the service keeps data | The service only adopts a folder that's already locked down. Anything else is moved aside under an unguessable name. |
| Use the installer to get SYSTEM | Maintenance runs without any window, uses full paths for system tools, and never deletes or changes anything an ordinary user can. |

## Damage control if the service is attacked

- **Fewer privileges.** It keeps only the privileges it uses. Debug, backup, restore, take-ownership and driver-loading are removed.
- **Fewer injection routes.** The service and prompt refuse DLLs from network shares or low-integrity files. They block legacy injection routes and load only system fonts. Their DLL searches skip PATH and the current folder.
- **The prompt can't start programs.**
- **Faults restart it.** A critical failure exits with an error, so Windows restarts it.

## Proven in CI

Each change installs the service on a fresh Windows machine and attacks it from a non-admin account (`scripts/ci/service-integration.ps1`, `scripts/ci/installer-integration.ps1`, `csharp/AiShield.TamperProbe`). That covers every row above, including:

- the junction and folder squats
- the 300-connection flood
- holding the old pipe name across a restart
- a killed service and a killed desktop app
- install, upgrade, downgrade and uninstall

## Known limits

- **Detection is easy to dodge.** A renamed program isn't recognized. Browsers, WSL and Docker aren't seen at all. Detection triggers no enforcement yet. Fixing this means detecting traffic to AI services whatever the program, and identifying apps by their code signature rather than their file name. That's planned for M4 and M5.
- **The desktop app can be driven by any program running as you.** That's why loosening anything needs the secure prompt. It also means such a program can read status, stop AI apps in your session, and close the desktop app for an hour.
- **Files aren't signed yet.** Windows SmartScreen warns about the installer, and the service trusts its app by location rather than signature. Code signing is planned for M7.
- **No protected-process status.** Windows only grants antimalware protection to vendors in the Microsoft Virus Initiative, which requires a Microsoft-signed early-launch driver.
- **Leftovers are left in place.** A folder someone planted before install, and the desktop app's small error log in your profile, stay after uninstall. Deleting them as SYSTEM would be unsafe.
