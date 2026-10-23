#Requires -Version 5.1
<#
.DESCRIPTION
  DiskScope - Windows Terminal storage analyzer and cleanup tool.
  Analyzes any drive, shows where space is going, and reclaims it.
  Zero dependencies. Run: powershell -File DiskScope.ps1
#>
[CmdletBinding()]
param(
  [string]$StartPath,
  [switch]$Advisor
)

$ErrorActionPreference = 'Stop'
$script:ListingCache = @{}
$script:ScanErrors = 0
$script:CancelScan = $false
$script:Headless = $false
$script:IsWin = ($env:OS -eq 'Windows_NT')
$script:ESC = [char]27
$script:BAR_FULL = [char]0x2588   # full block
$script:BAR_EMPTY = [char]0x2591  # light shade

# ---------- console setup ----------
function Initialize-Console {
  try {
    if ([Console]::WindowWidth -le 0) { $script:Headless = $true; return }
  } catch {
    $script:Headless = $true
    return
  }
  try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
  if ($script:IsWin) {
    # enable ANSI/VT processing on Windows 10+ conhost / Windows Terminal
    try {
      $sig = @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetStdHandle(int nStdHandle);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool GetConsoleMode(System.IntPtr hConsoleHandle, out uint lpMode);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern bool SetConsoleMode(System.IntPtr hConsoleHandle, uint dwMode);
'@
      $k32 = Add-Type -MemberDefinition $sig -Name 'K32' -Namespace 'DiskScope' -PassThru
      $h = $k32::GetStdHandle(-11)
      $m = [uint32]0
      [void]$k32::GetConsoleMode($h, [ref]$m)
      [void]$k32::SetConsoleMode($h, ($m -bor 4))
    } catch {}
  }
}

function Test-Admin {
  if (-not $script:IsWin) { return $false }
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

# ---------- formatting ----------
function Format-Size {
  param([long]$Bytes)
  if ($Bytes -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
  if ($Bytes -ge 1GB) { return '{0:N2} GB' -f ($Bytes / 1GB) }
  if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
  if ($Bytes -ge 1KB) { return '{0:N0} KB' -f ($Bytes / 1KB) }
  return "$Bytes B"
}

function Get-Bar {
  param([double]$Pct, [int]$Width = 20)
  $fill = [Math]::Min($Width, [int][Math]::Round($Width * ($Pct / 100.0)))
  $bar = ([string]$script:BAR_FULL) * $fill + ([string]$script:BAR_EMPTY) * ($Width - $fill)
  if ($Pct -ge 25) { $color = '91' } elseif ($Pct -ge 10) { $color = '93' } else { $color = '92' }
  return "$($script:ESC)[${color}m$bar$($script:ESC)[0m"
}

function Write-ScanProgress {
  param([string]$Message)
  if ($script:Headless) { return }
  try {
    $w = [Console]::WindowWidth - 1
    if ($w -lt 1) { return }
    if ($Message.Length -gt $w) { $Message = $Message.Substring(0, $w) }
    [Console]::Write("`r" + $Message.PadRight($w))
  } catch {}
}

function Clear-ScanProgress {
  if ($script:Headless) { return }
  try {
    $w = [Console]::WindowWidth - 1
    if ($w -lt 1) { return }
    [Console]::Write("`r" + (' ' * $w) + "`r")
  } catch {}
}

function Test-CancelKey {
  if ($script:Headless) { return }
  try {
    if ([Console]::KeyAvailable) {
      $k = [Console]::ReadKey($true)
      if ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') {
        $script:CancelScan = $true
      }
    }
  } catch {}
}

# ---------- scanning ----------
function Get-DirectorySize {
  param([string]$Path)
  $total = [long]0
  $stack = New-Object 'System.Collections.Generic.Stack[string]'
  $stack.Push($Path)
  while ($stack.Count -gt 0) {
    if ($script:CancelScan) { break }
    Test-CancelKey
    $dir = $stack.Pop()
    $di = $null
    try { $di = [System.IO.DirectoryInfo]::new($dir) } catch { $script:ScanErrors++; continue }
    try {
      foreach ($f in $di.EnumerateFiles()) {
        try { $total += $f.Length } catch {}
      }
    } catch { $script:ScanErrors++ }
    try {
      foreach ($d in $di.EnumerateDirectories()) {
        try {
          if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
          $stack.Push($d.FullName)
        } catch {}
      }
    } catch { $script:ScanErrors++ }
  }
  return $total
}

function Get-ChildListing {
  param([string]$Path, [switch]$Force)
  if (-not $Force -and $script:ListingCache.ContainsKey($Path)) {
    return $script:ListingCache[$Path]
  }
  $script:CancelScan = $false
  $script:ScanErrors = 0
  $items = New-Object 'System.Collections.Generic.List[object]'
  $di = [System.IO.DirectoryInfo]::new($Path)
  $dirs = @()
  try { $dirs = @($di.EnumerateDirectories()) } catch { $script:ScanErrors++ }
  $i = 0
  $partial = $false
  foreach ($d in $dirs) {
    if ($script:CancelScan) { $partial = $true; break }
    try {
      if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
    } catch { continue }
    $i++
    $sz = Get-DirectorySize -Path $d.FullName
    Clear-ScanProgress
    Write-ScanProgress ("Scanning " + $d.Name + "  ($i of " + $dirs.Count + " dirs)  " + (Format-Size $sz) + "  [Q stops scan]")
    $items.Add([pscustomobject]@{ Name = $d.Name; FullName = $d.FullName; IsDir = $true; Size = $sz })
  }
  $files = @()
  try { $files = @($di.EnumerateFiles()) } catch { $script:ScanErrors++ }
  $fileCount = 0; $fileBytes = [long]0
  foreach ($f in $files) {
    try {
      $fileCount++
      $fileBytes += $f.Length
    } catch {}
  }
  Clear-ScanProgress
  $sorted = @($items | Sort-Object -Property Size -Descending)
  $result = [pscustomobject]@{
    Items = $sorted
    LooseFileCount = $fileCount
    LooseFileBytes = $fileBytes
    Partial = $partial
    Errors = $script:ScanErrors
  }
  if (-not $partial) { $script:ListingCache[$Path] = $result }
  return $result
}

function Get-LargestFiles {
  param([string]$Path, [int]$Top = 50)
  $script:CancelScan = $false
  $script:ScanErrors = 0
  $topList = New-Object 'System.Collections.Generic.List[object]'
  $stack = New-Object 'System.Collections.Generic.Stack[string]'
  $stack.Push($Path)
  $count = 0
  while ($stack.Count -gt 0) {
    if ($script:CancelScan) { break }
    Test-CancelKey
    $dir = $stack.Pop()
    $di = $null
    try { $di = [System.IO.DirectoryInfo]::new($dir) } catch { $script:ScanErrors++; continue }
    try {
      foreach ($f in $di.EnumerateFiles()) {
        $count++
        if (($count % 2000) -eq 0) {
          Write-ScanProgress ("Scanning files... $count examined  [Q stops]")
        }
        $len = 0
        try { $len = $f.Length } catch { continue }
        if ($topList.Count -ge $Top) {
          $min = ($topList | Measure-Object -Property Size -Minimum).Minimum
          if ($len -le $min) { continue }
          $topList.Remove(($topList | Sort-Object Size | Select-Object -First 1)) | Out-Null
        }
        $topList.Add([pscustomobject]@{ Name = $f.Name; FullName = $f.FullName; Size = $len })
      }
    } catch { $script:ScanErrors++ }
    try {
      foreach ($d in $di.EnumerateDirectories()) {
        try {
          if ($d.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
          $stack.Push($d.FullName)
        } catch {}
      }
    } catch { $script:ScanErrors++ }
  }
  Clear-ScanProgress
  return @($topList | Sort-Object -Property Size -Descending | Select-Object -First $Top)
}

# ---------- cleanup advisor ----------
function Get-CleanupTargets {
  $t = @()
  $add = {
    param($Name, $Paths, $Risk, $Desc, $Action, $AdminNeeded)
    $script:tmp_targets += [pscustomobject]@{
      Name = $Name; Paths = $Paths; Risk = $Risk; Desc = $Desc
      Action = $Action; Admin = $AdminNeeded
    }
  }
  $script:tmp_targets = @()
  if ($script:IsWin) {
    & $add 'User temp files' @($env:TEMP) 'Safe' `
      'Per-user temp files. Apps recreate what they need. Files in use are skipped.' 'delete' $false
    & $add 'Windows temp files' @('C:\Windows\Temp') 'Safe (admin)' `
      'System-wide temp files. Requires elevation; files in use are skipped.' 'delete' $true
    & $add 'Windows Update download cache' @('C:\Windows\SoftwareDistribution\Download') 'Safe (admin)' `
      'Leftover update payloads. Services are stopped, cache cleared, services restarted.' 'wu' $true
    & $add 'Recycle Bin' @() 'Safe' `
      'Empties the Recycle Bin on all drives.' 'recyclebin' $false
    & $add 'Delivery Optimization cache' @('C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache') 'Safe (admin)' `
      'Windows Update peer-to-peer download cache. Regenerated automatically.' 'delete' $true
    & $add 'Crash dumps' @('C:\Windows\MEMORY.DMP', 'C:\Windows\Minidump') 'Safe (admin)' `
      'Kernel and minidump files from past crashes. Only useful for debugging a BSOD.' 'delete' $true
    & $add 'Windows error reports' @('C:\ProgramData\Microsoft\Windows\WER', "$env:LOCALAPPDATA\Microsoft\Windows\WER") 'Safe' `
      'Queued Windows Error Reporting data.' 'delete' $false
    & $add 'Thumbnail cache' @("$env:LOCALAPPDATA\Microsoft\Windows\Explorer") 'Safe' `
      'Explorer thumbnail databases (thumbcache_*.db). Regenerated on demand.' 'thumbcache' $false
    & $add 'Windows logs' @('C:\Windows\Logs') 'Moderate (admin)' `
      'Setup and servicing logs. Useful only when troubleshooting update failures.' 'delete' $true
    & $add 'Hibernation file (hiberfil.sys)' @('C:\hiberfil.sys') 'Moderate (admin)' `
      'Disables hibernation and deletes hiberfil.sys. Fast Startup will also be disabled.' 'hibernate' $true
    & $add 'Component Store cleanup (WinSxS)' @() 'Safe (admin)' `
      'Runs DISM StartComponentCleanup to remove superseded update components. Can take several minutes.' 'dism' $true
    & $add 'Windows.old' @('C:\Windows.old') 'Moderate (admin)' `
      'Previous Windows installation. Deleted via Disk Cleanup; manual delete requires taking ownership.' 'manual_cleanmgr' $true
    & $add 'Chrome cache' @("$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache", "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache") 'Safe' `
      'Chrome disk caches. Close Chrome first for best results; locked files are skipped.' 'delete' $false
    & $add 'Edge cache' @("$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache", "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache") 'Safe' `
      'Edge disk caches. Close Edge first for best results; locked files are skipped.' 'delete' $false
    & $add 'npm cache' @("$env:LOCALAPPDATA\npm-cache") 'Safe' `
      'Node package manager download cache. Repopulates on next install.' 'delete' $false
    & $add 'pip cache' @("$env:LOCALAPPDATA\pip\cache") 'Safe' `
      'Python pip download cache. Repopulates on next install.' 'delete' $false
    & $add 'Docker Desktop data (WSL VHDX)' @("$env:LOCALAPPDATA\Docker\wsl") 'Manual' `
      'Docker images/containers live here. Prune with: docker system prune. Delete only if Docker is removed.' 'manual' $false
  } else {
    & $add 'Temp directory' @('/tmp') 'Safe' 'Temp files.' 'delete' $false
  }
  return $script:tmp_targets
}

function Remove-PathContents {
  param([string]$Path)
  $freedBefore = 0
  if (Test-Path -LiteralPath $Path) { $freedBefore = Get-DirectorySize -Path $Path }
  if ((Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).PSIsContainer) {
    Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | ForEach-Object {
      try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {}
    }
  } else {
    try { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue } catch {}
  }
  $after = 0
  if (Test-Path -LiteralPath $Path) { $after = Get-DirectorySize -Path $Path }
  return ($freedBefore - $after)
}

function Invoke-CleanupAction {
  param($Target)
  $freed = [long]0
  switch ($Target.Action) {
    'delete' {
      foreach ($p in $Target.Paths) {
        if (Test-Path -LiteralPath $p) { $freed += Remove-PathContents -Path $p }
      }
    }
    'thumbcache' {
      $dir = $Target.Paths[0]
      if (Test-Path -LiteralPath $dir) {
        $freed = Get-DirectorySize -Path $dir
        Get-ChildItem -LiteralPath $dir -Force -Filter 'thumbcache_*.db' -ErrorAction SilentlyContinue | ForEach-Object {
          try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
        }
        Get-ChildItem -LiteralPath $dir -Force -Filter 'iconcache_*.db' -ErrorAction SilentlyContinue | ForEach-Object {
          try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
        }
        $freed -= Get-DirectorySize -Path $dir
      }
    }
    'recyclebin' {
      try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch {}
    }
    'wu' {
      try { Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue } catch {}
      try { Stop-Service -Name bits -Force -ErrorAction SilentlyContinue } catch {}
      $p = $Target.Paths[0]
      if (Test-Path -LiteralPath $p) { $freed += Remove-PathContents -Path $p }
      try { Start-Service -Name wuauserv -ErrorAction SilentlyContinue } catch {}
      try { Start-Service -Name bits -ErrorAction SilentlyContinue } catch {}
    }
    'hibernate' {
      if (Test-Path -LiteralPath 'C:\hiberfil.sys') {
        $freed = (Get-Item -LiteralPath 'C:\hiberfil.sys' -Force).Length
      }
      try { & powercfg.exe /h off 2>$null | Out-Null } catch {}
    }
    'dism' {
      Write-Host ''
      Write-Host '  Running DISM component cleanup (can take several minutes)...'
      try { & Dism.exe /online /Cleanup-Image /StartComponentCleanup } catch { Write-Host "  DISM failed: $_" }
    }
    'manual_cleanmgr' {
      Write-Host ''
      Write-Host '  Windows.old should be removed with Disk Cleanup:'
      Write-Host '    cleanmgr /sageset:1  then  cleanmgr /sagerun:1'
      Write-Host '  (select "Previous Windows installation(s)")'
    }
    'manual' {
      Write-Host ''
      Write-Host "  Manual step required: $($Target.Desc)"
    }
  }
  return $freed
}

function Get-TargetSize {
  param($Target)
  $total = [long]0
  foreach ($p in $Target.Paths) {
    if (Test-Path -LiteralPath $p) {
      $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
      if ($item -and -not $item.PSIsContainer) { $total += $item.Length }
      else { $total += Get-DirectorySize -Path $p }
    }
  }
  return $total
}

# ---------- UI ----------
function Write-Line {
  param([string]$Text = '', [string]$Color = '0')
  if ($Color -eq '0') { [Console]::WriteLine($Text) }
  else { [Console]::WriteLine("$($script:ESC)[${Color}m$Text$($script:ESC)[0m") }
}

function Show-DrivePicker {
  $drives = @()
  if ($script:IsWin) {
    $drives = @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and $_.DriveType -eq 'Fixed' })
  } else {
    $drives = @([System.IO.DriveInfo]::new('/'))
  }
  if ($drives.Count -eq 1) { return $drives[0].RootDirectory.FullName }
  $sel = 0
  while ($true) {
    Clear-Host
    Write-Line '  DiskScope - select a drive' '96'
    Write-Line ''
    for ($i = 0; $i -lt $drives.Count; $i++) {
      $d = $drives[$i]
      $used = $d.TotalSize - $d.AvailableFreeSpace
      $pct = [Math]::Round(100.0 * $used / [Math]::Max(1, $d.TotalSize), 1)
      $line = ('  {0}  {1} used of {2} ({3}%)  {4} free' -f $d.Name, (Format-Size $used), (Format-Size $d.TotalSize), $pct, (Format-Size $d.AvailableFreeSpace))
      if ($i -eq $sel) { Write-Line ("> " + $line) '97;44' } else { Write-Line ('  ' + $line) }
    }
    Write-Line ''
    Write-Line '  [Up/Down] select  [Enter] open  [Q] quit' '90'
    $k = [Console]::ReadKey($true)
    if ($k.Key -eq 'UpArrow') { $sel = ($sel - 1 + $drives.Count) % $drives.Count }
    elseif ($k.Key -eq 'DownArrow') { $sel = ($sel + 1) % $drives.Count }
    elseif ($k.Key -eq 'Enter') { return $drives[$sel].RootDirectory.FullName }
    elseif ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') { return $null }
  }
}

function Show-Browser {
  param([string]$Path)
  $listing = Get-ChildListing -Path $Path
  $sel = 0
  while ($true) {
    $total = [long](($listing.Items | Measure-Object -Property Size -Sum).Sum + $listing.LooseFileBytes)
    Clear-Host
    $driveInfo = ''
    try {
      $root = [System.IO.Path]::GetPathRoot($Path)
      $di = [System.IO.DriveInfo]::new($root)
      if ($di.IsReady) {
        $driveInfo = ('   drive {0}  {1} free of {2}' -f $di.Name, (Format-Size $di.AvailableFreeSpace), (Format-Size $di.TotalSize))
      }
    } catch {}
    Write-Line ('  ' + $Path) '96'
    Write-Line ('  total: ' + (Format-Size $total) + $driveInfo) '90'
    if ($listing.Partial) { Write-Line '  (scan stopped early - press R to rescan)' '93' }
    if ($listing.Errors -gt 0) { Write-Line ('  (' + $listing.Errors + ' access-denied items skipped)') '90' }
    Write-Line ''
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($it in $listing.Items) { $rows.Add($it) }
    if ($listing.LooseFileCount -gt 0) {
      $rows.Add([pscustomobject]@{ Name = ('<files in this folder: ' + $listing.LooseFileCount + '>'); FullName = ''; IsDir = $false; Size = $listing.LooseFileBytes })
    }
    $pageSize = 18
    try { $pageSize = [Math]::Max(5, [Console]::WindowHeight - 9) } catch {}
    $offset = [Math]::Max(0, [Math]::Min($sel - [int]($pageSize / 2), [Math]::Max(0, $rows.Count - $pageSize)))
    $end = [Math]::Min($rows.Count - 1, $offset + $pageSize - 1)
    for ($i = $offset; $i -le $end; $i++) {
      $r = $rows[$i]
      $pct = 0.0
      if ($total -gt 0) { $pct = 100.0 * $r.Size / $total }
      $bar = Get-Bar -Pct $pct
      $sz = (Format-Size $r.Size).PadLeft(10)
      $pcts = (('{0:N1}%' -f $pct)).PadLeft(7)
      $name = $r.Name
      $maxName = 40
      try { $maxName = [Math]::Max(10, [Console]::WindowWidth - 55) } catch {}
      if ($name.Length -gt $maxName) { $name = $name.Substring(0, $maxName - 3) + '...' }
      $icon = ' '
      if ($r.IsDir) { $icon = 'D' } else { $icon = 'f' }
      $line = "  $icon $sz $pcts $bar $name"
      if ($i -eq $sel) { Write-Line (">" + $line.Substring(1)) '97;44' } else { [Console]::WriteLine($line) }
    }
    Write-Line ''
    Write-Line '  [Enter] open  [Bksp] up  [L] largest files  [C] cleanup advisor  [R] rescan  [Q] quit' '90'
    $k = [Console]::ReadKey($true)
    if ($k.Key -eq 'UpArrow') { if ($sel -gt 0) { $sel-- } }
    elseif ($k.Key -eq 'DownArrow') { if ($sel -lt ($rows.Count - 1)) { $sel++ } }
    elseif ($k.Key -eq 'Enter') {
      if ($rows.Count -gt 0 -and $rows[$sel].IsDir -and $rows[$sel].FullName) {
        Show-Browser -Path $rows[$sel].FullName
        $listing = Get-ChildListing -Path $Path
        $sel = 0
      }
    }
    elseif ($k.Key -eq 'Backspace') {
      $parent = [System.IO.Path]::GetDirectoryName($Path.TrimEnd('\', '/'))
      if ($parent) {
        Show-Browser -Path $parent
        return
      }
    }
    elseif ($k.KeyChar -eq 'l' -or $k.KeyChar -eq 'L') { Show-LargestFiles -Path $Path }
    elseif ($k.KeyChar -eq 'c' -or $k.KeyChar -eq 'C') { Show-CleanupAdvisor }
    elseif ($k.KeyChar -eq 'r' -or $k.KeyChar -eq 'R') {
      $script:ListingCache.Remove($Path) | Out-Null
      $listing = Get-ChildListing -Path $Path -Force
      $sel = 0
    }
    elseif ($k.KeyChar -eq 'q' -or $k.KeyChar -eq 'Q' -or $k.Key -eq 'Escape') { return }
  }
}

function Show-LargestFiles {
  param([string]$Path)
  $files = Get-LargestFiles -Path $Path -Top 50
  while ($true) {
    Clear-Host
    Write-Line ('  Largest files under ' + $Path) '96'
    Write-Line ''
    $shown = 0
    foreach ($f in $files) {
      $shown++
      $rel = $f.FullName
      $maxLen = 60
      try { $maxLen = [Math]::Max(20, [Console]::WindowWidth - 16) } catch {}
      if ($rel.Length -gt $maxLen) { $rel = '...' + $rel.Substring($rel.Length - $maxLen + 3) }
      Write-Line (('  {0,3}. {1}  {2}' -f $shown, (Format-Size $f.Size).PadLeft(10), $rel))
    }
    if ($shown -eq 0) { Write-Line '  (no files found, or scan was stopped)' '90' }
    Write-Line ''
    Write-Line '  [O] open folder of # (Windows)  [B] back' '90'
    $k = [Console]::ReadKey($true)
    if ($k.KeyChar -eq 'b' -or $k.KeyChar -eq 'B' -or $k.Key -eq 'Escape' -or $k.Key -eq 'Backspace') { return }
    if ($k.KeyChar -eq 'o' -or $k.KeyChar -eq 'O') {
      Write-Host ''
      Write-Host -NoNewline '  File number to reveal: '
      $n = Read-Host
      $idx = 0
      if ([int]::TryParse($n, [ref]$idx) -and $idx -ge 1 -and $idx -le $files.Count) {
        $target = $files[$idx - 1]
        if ($script:IsWin) { try { Start-Process explorer.exe -ArgumentList ('/select,"' + $target.FullName + '"') } catch {} }
        else { Write-Host ('  ' + $target.FullName) }
      }
    }
  }
}

function Show-CleanupAdvisor {
  $targets = Get-CleanupTargets
  $sizes = @{}
  Write-Host ''
  foreach ($t in $targets) {
    Write-ScanProgress ('Measuring ' + $t.Name + '...')
    $sizes[$t.Name] = Get-TargetSize -Target $t
  }
  Clear-ScanProgress
  $sel = 0
  while ($true) {
    Clear-Host
    $totalReclaim = [long]0
    foreach ($t in $targets) { $totalReclaim += $sizes[$t.Name] }
    Write-Line '  Cleanup Advisor' '96'
    Write-Line ('  Potential reclaimable space: ' + (Format-Size $totalReclaim)) '92'
    Write-Line ''
    for ($i = 0; $i -lt $targets.Count; $i++) {
      $t = $targets[$i]
      $sz = (Format-Size $sizes[$t.Name]).PadLeft(10)
      $risk = $t.Risk
      $riskColor = '92'
      if ($risk -like 'Moderate*') { $riskColor = '93' }
      if ($risk -like 'Manual*') { $riskColor = '94' }
      $line = "  $sz  $($t.Name)"
      $suffix = "   [$risk]"
      if ($i -eq $sel) {
        Write-Line (">" + $line.Substring(1) + $suffix) '97;44'
      } else {
        [Console]::Write($line)
        [Console]::WriteLine("$($script:ESC)[${riskColor}m$suffix$($script:ESC)[0m")
      }
    }
    Write-Line ''
    Write-Line '  [Up/Down] select  [Enter] details/clean  [B] back' '90'
    $k = [Console]::ReadKey($true)
    if ($k.Key -eq 'UpArrow') { $sel = ($sel - 1 + $targets.Count) % $targets.Count }
    elseif ($k.Key -eq 'DownArrow') { $sel = ($sel + 1) % $targets.Count }
    elseif ($k.Key -eq 'Enter') {
      Show-CleanupDetail -Target $targets[$sel] -Sizes $sizes
    }
    elseif ($k.KeyChar -eq 'b' -or $k.KeyChar -eq 'B' -or $k.Key -eq 'Escape' -or $k.Key -eq 'Backspace') { return }
  }
}

function Show-CleanupDetail {
  param($Target, $Sizes)
  while ($true) {
    Clear-Host
    Write-Line ('  ' + $Target.Name) '96'
    Write-Line ''
    Write-Line ('  Size now:  ' + (Format-Size $Sizes[$Target.Name]))
    Write-Line ('  Risk:      ' + $Target.Risk)
    if ($Target.Admin -and -not (Test-Admin)) {
      Write-Line '  NOTE: this action needs an elevated (Run as Administrator) terminal.' '93'
    }
    Write-Line ''
    Write-Line ('  ' + $Target.Desc)
    Write-Line ''
    foreach ($p in $Target.Paths) {
      $exists = Test-Path -LiteralPath $p
      $mark = '  (missing)'
      if ($exists) { $mark = '' }
      Write-Line ('    ' + $p + $mark) '90'
    }
    Write-Line ''
    $canClean = ($Target.Action -in @('delete', 'thumbcache', 'recyclebin', 'wu', 'hibernate', 'dism'))
    if ($canClean) {
      Write-Line '  [D] clean now  [B] back' '90'
    } else {
      Write-Line '  [I] show instructions  [B] back' '90'
    }
    $k = [Console]::ReadKey($true)
    if ($k.KeyChar -eq 'b' -or $k.KeyChar -eq 'B' -or $k.Key -eq 'Escape' -or $k.Key -eq 'Backspace') { return }
    if (($k.KeyChar -eq 'd' -or $k.KeyChar -eq 'D') -and $canClean) {
      if ($Target.Admin -and -not (Test-Admin)) {
        Write-Host ''
        Write-Host '  Blocked: not running as Administrator.'
        Start-Sleep -Seconds 2
        continue
      }
      Write-Host ''
      Write-Host -NoNewline ('  Type YES to clean "' + $Target.Name + '": ')
      $confirm = Read-Host
      if ($confirm -eq 'YES') {
        Write-Host '  Cleaning...'
        $freed = Invoke-CleanupAction -Target $Target
        if ($freed -gt 0) { Write-Host ('  Reclaimed: ' + (Format-Size $freed)) }
        else { Write-Host '  Done.' }
        $Sizes[$Target.Name] = Get-TargetSize -Target $Target
        Write-Host '  Press any key.'
        [void][Console]::ReadKey($true)
      }
    }
    if ($k.KeyChar -eq 'i' -or $k.KeyChar -eq 'I') {
      Write-Host ''
      [void](Invoke-CleanupAction -Target $Target)
      Write-Host '  Press any key.'
      [void][Console]::ReadKey($true)
    }
  }
}

# ---------- entry ----------
function Start-DiskScope {
  Initialize-Console
  if ($script:Headless) {
    Write-Host 'DiskScope needs an interactive terminal.'
    return
  }
  if ($Advisor) { Show-CleanupAdvisor; return }
  $path = $StartPath
  if (-not $path) {
    $path = Show-DrivePicker
    if (-not $path) { return }
  }
  Show-Browser -Path $path
}

# only start the UI when executed directly, not when dot-sourced (enables tests)
if ($MyInvocation.InvocationName -ne '.') {
  Start-DiskScope
}
