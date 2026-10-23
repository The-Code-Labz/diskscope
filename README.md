# DiskScope

A Windows Terminal storage analyzer and cleanup tool. Single PowerShell file, zero dependencies — no Python, no npm, no installs.

## Run

```powershell
powershell -File DiskScope.ps1            # pick a drive, browse
powershell -File DiskScope.ps1 C:\        # jump straight to a path
powershell -File DiskScope.ps1 -Advisor   # jump straight to cleanup advisor
```

Works in Windows Terminal, conhost, and PowerShell 5.1+ / PowerShell 7+. Runs on any drive (C:, D:, external USB).

## What it does

**Drive picker** — all fixed drives with used/free space, arrow-key select.

**Folder browser** — per-folder sizes sorted largest-first, usage bars color-coded by share, drill in with Enter, back out with Backspace. Loose files are aggregated so a folder full of small files still shows its real cost.

**Largest files** — press `L` on any folder: recursive top-50 file hunt with live progress. On Windows, reveal any file in Explorer with `O`.

**Cleanup advisor** — press `C`: a curated list of known reclaimable locations with live measured sizes, risk labels, and one-key cleaning:

| Target | Risk |
|---|---|
| User temp files | Safe |
| Windows temp files | Safe (admin) |
| Windows Update download cache | Safe (admin) |
| Recycle Bin | Safe |
| Delivery Optimization cache | Safe (admin) |
| Crash dumps / Windows error reports | Safe |
| Thumbnail cache | Safe |
| Windows logs | Moderate (admin) |
| Hibernation file (`hiberfil.sys`) | Moderate (admin) |
| Component Store cleanup (DISM) | Safe (admin) |
| Windows.old | via Disk Cleanup |
| Chrome / Edge caches | Safe |
| npm / pip caches | Safe |
| Docker Desktop WSL data | Manual |

Every clean action shows its size first, requires typing `YES`, and reports exactly how much was reclaimed. Locked/in-use files are skipped, not fatal.

## Keys

```
[Up/Down] navigate   [Enter] open/details   [Bksp] up
[L] largest files    [C] cleanup advisor    [R] rescan   [Q] quit / stop scan
```

## Notes

- First scan of a whole drive takes a while on HDDs (progress shown, `Q` stops early and shows partial results). Results are cached; `R` forces a rescan.
- Access-denied folders are counted and skipped, never fatal.
- Reparse points/junctions are never followed, so no double-counting or loops.
- Admin-only actions are blocked (not failed) when the terminal isn't elevated.
