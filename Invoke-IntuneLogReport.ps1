<#
.SYNOPSIS
    Parses Intune Management Extension (IME) logs and produces a self-contained,
    interactive HTML report that highlights errors, warnings, and known issue
    patterns in plain English.

.DESCRIPTION
    Walks the Intune log folder (default C:\ProgramData\Microsoft\IntuneManagementExtension\Logs),
    parses the CMTrace-format entries, classifies them by severity, groups
    repeating errors/warnings, matches them against an Intune-specific
    knowledge base, and writes a single HTML file you can open in any browser.

    The HTML is fully self-contained (no external CDNs) so it will open on
    locked-down corporate machines.

.PARAMETER LogPath
    Folder containing the Intune logs. Defaults to the standard IME location.

.PARAMETER Hours
    Time window (in hours) of log entries to include. Default: 24.
    Ignored if -AllTime is used.

.PARAMETER AllTime
    Include every entry in every log file, with no time filter.

.PARAMETER IncludeOld
    Also parse rotated logs in the 'old' subfolder.

.PARAMETER Recurse
    Parse every .log file recursively, including company subfolders (e.g. Ashurst).

.PARAMETER DiagPath
    Folder containing the MDM diagnostic report (MDMDiagReport.html), produced by
    Settings > Accounts > Access work or school > Info > Create report, or by
    MdmDiagnosticsTool.exe. Default: C:\Users\Public\Documents\MDMDiagnostics
    Pass an empty string to skip MDM diagnostics analysis.

.PARAMETER OutputPath
    Where to write the HTML report. Default: %TEMP%\IntuneLogReport_<timestamp>.html

.PARAMETER DoNotOpen
    Skip auto-opening the report in the default browser.

.EXAMPLE
    .\Invoke-IntuneLogReport.ps1
    Run with defaults — last 24 hours of the standard log folder, opens the report.

.EXAMPLE
    .\Invoke-IntuneLogReport.ps1 -Hours 72 -IncludeOld
    Last 3 days, including rotated logs.

.EXAMPLE
    .\Invoke-IntuneLogReport.ps1 -AllTime -OutputPath C:\Temp\Intune.html
    All entries, custom output location.

.NOTES
    Author : Generated for Fergus (Azure architect workflow)
    Format : CMTrace / SCCM-style log entries
#>

[CmdletBinding()]
param(
    [string]$LogPath = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs',
    [int]$Hours = 24,
    [switch]$AllTime,
    [switch]$IncludeOld,
    [switch]$Recurse,
    [string]$DiagPath = 'C:\Users\Public\Documents\MDMDiagnostics',
    [string]$OutputPath,
    [switch]$DoNotOpen
)

#region ------------------------------ Setup -----------------------------------

$ErrorActionPreference = 'Stop'
$script:ScriptStart = Get-Date

if (-not (Test-Path -LiteralPath $LogPath)) {
    throw "Log path not found: $LogPath"
}

if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $OutputPath = Join-Path -Path $env:TEMP -ChildPath "IntuneLogReport_$stamp.html"
}

# Resolve to full path so we can open it later
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

Write-Host "Intune Log Report" -ForegroundColor Cyan
Write-Host ("Log folder : {0}" -f $LogPath)
Write-Host ("Output     : {0}" -f $OutputPath)
if ($AllTime) {
    Write-Host "Window     : ALL ENTRIES"
} else {
    Write-Host ("Window     : Last {0} hours" -f $Hours)
}
Write-Host ""

#endregion

#region ------------------------- Knowledge base -------------------------------
# Patterns are matched in order. First match wins. Use simple regex.
# Severity overrides what the log file declared (useful when MSFT mis-tags
# benign chatter as 'error').

$KnowledgeBase = @(
    @{
        Pattern    = '\[Win32App\] Found native machine from WoW64 process'
        Title      = 'WoW64 architecture detection (informational)'
        Meaning    = 'IME is running as a 32-bit process on a 64-bit OS and is reporting the native architecture. This is normal and harmless - Microsoft tags it as an error in the logs but it has no functional impact.'
        Suggestion = 'No action required. Safe to ignore.'
        Override   = 'Info'
    },
    @{
        Pattern    = '\[StatusService\] Unable to create Win32AppResult since intent is unknown'
        Title      = 'Status service: app intent unknown'
        Meaning    = 'IME tried to record the result of a Win32 app deployment but could not determine whether it was Required, Available, or Uninstall. Common during the first sync cycle for a new assignment, or after the assignment was changed in the portal.'
        Suggestion = 'Usually transient. If it persists, check the assignment in Intune (Apps > the app > Properties > Assignments) and force a sync from Company Portal.'
        Override   = 'Warning'
    },
    @{
        Pattern    = '\[StatusService\] EnforcementStateMessage is unknown'
        Title      = 'Status service: enforcement state unknown'
        Meaning    = 'IME could not translate an installation enforcement state code into a known message. Typically appears alongside the "intent is unknown" entry above.'
        Suggestion = 'Usually transient. Force a Company Portal sync. If it persists, check assignments and intent for the affected apps.'
        Override   = 'Warning'
    },
    @{
        Pattern    = 'CheckProductCodeExists fails with product code .* errorCode = 87'
        Title      = 'MSI ProductCode lookup: ERROR_INVALID_PARAMETER (87)'
        Meaning    = 'IME asked the Windows Installer whether an MSI ProductCode is installed and got Win32 error 87 (invalid parameter). Almost always means the GUID does not match anything on the device - the app is simply not installed. Logged as an error but is functional.'
        Suggestion = 'Confirm the ProductCode in your Win32 app''s detection rule matches the MSI you packaged. If it does, ignore - this is just IME''s clumsy way of saying "not installed".'
        Override   = 'Info'
    },
    @{
        Pattern    = '\[StatusService\] AppKey for user .* not found in the StatusServiceReports registry'
        Title      = 'Status service: AppKey not yet registered'
        Meaning    = 'IME tried to read a status report for a user/app combination that has not been written yet. Normal on first contact with a new app or after status reports have been cleaned up.'
        Suggestion = 'No action required. If it persists across many syncs and the app never reports, check the app actually targets this user/device.'
        Override   = 'Info'
    },
    @{
        Pattern    = '\[StatusService\] For user .* the Highest version is -1\. Returning null'
        Title      = 'Status service: no recorded version for app'
        Meaning    = 'No version has been reported for this user/app yet. Companion to the "AppKey not found" message - same root cause.'
        Suggestion = 'No action required. Will resolve as soon as the app reports a status.'
        Override   = 'Info'
    },
    @{
        Pattern    = '\[Flighting\d*\] CheckEnabledFlights:'
        Title      = 'Feature-flag check (informational)'
        Meaning    = 'IME is reading its internal feature flags from the registry. This is mis-tagged as an error in the source code; it is purely diagnostic.'
        Suggestion = 'No action required. Safe to ignore.'
        Override   = 'Info'
    },
    @{
        Pattern    = '\[StatusService\] Unable to authenticate user'
        Title      = 'Status service: user authentication failure'
        Meaning    = 'IME failed to authenticate the signed-in user when trying to write status reports. This is a real problem - it can prevent user-targeted apps and policies from reporting state correctly.'
        Suggestion = 'Sign the user out and back in. If it persists: dsregcmd /status to confirm AAD-joined / Hybrid state, check the user has a valid Intune licence, and restart the IntuneManagementExtension service.'
        Override   = 'Error'
    },
    @{
        Pattern    = '\[StatusService\] Unable to instantiate a Status Service class because the sidecar agent is unable to get UserId'
        Title      = 'Status service: cannot resolve UserId'
        Meaning    = 'The sidecar agent could not map the active session to a UserId. Usually appears at startup before a user has signed in, or briefly during fast-user-switching.'
        Suggestion = 'Ignore if it appears once at boot. If it repeats while a user is signed in, restart the IntuneManagementExtension service.'
        Override   = 'Warning'
    },
    @{
        Pattern    = 'Not registering the new Channel URI as the previous channel is yet to expire'
        Title      = 'WNS push channel still valid'
        Meaning    = 'IME asked Windows Push Notification Services for a new channel but the existing one has not expired, so reuse it. Mis-tagged as an error.'
        Suggestion = 'No action required. Safe to ignore.'
        Override   = 'Info'
    },
    @{
        Pattern    = 'Failed to parse appResultCreatedTimeUTC'
        Title      = 'Empty timestamp in app result (informational)'
        Meaning    = 'IME tried to parse a timestamp from a Win32AppResult that hadn''t been populated yet. Almost always benign - happens before the first install attempt completes for an app.'
        Suggestion = 'No action required.'
        Override   = 'Info'
    },
    @{
        Pattern    = 'Failed to parse downloadStartTimeUTC'
        Title      = 'Empty download timestamp (informational)'
        Meaning    = 'Same as above but for the download-start timestamp.'
        Suggestion = 'No action required.'
        Override   = 'Info'
    },
    @{
        Pattern    = 'co-mgt features is not available'
        Title      = 'Co-management features unavailable'
        Meaning    = 'Configuration Manager (SCCM) co-management is not configured on this device. Logged as a warning; expected on a pure Intune-only device.'
        Suggestion = 'Ignore unless you actually expect this device to be co-managed with SCCM.'
        Override   = 'Info'
    },
    @{
        Pattern    = '0x87D1041C'
        Title      = 'App detection rule failed (0x87D1041C)'
        Meaning    = 'The Win32 app detection rule did not detect the app after install. Common causes: detection script returns nothing, file/registry detection points to wrong path, or the install actually failed.'
        Suggestion = 'Open the app in Intune > Apps > Win32, check Detection Rules. For script detection, run the script manually as SYSTEM (psexec -i -s) and ensure it writes output to STDOUT for "installed".'
    },
    @{
        Pattern    = '0x87D30065'
        Title      = 'App not detected after install (0x87D30065)'
        Meaning    = 'IME ran the install command, the install command returned 0 (looked successful), but when IME re-ran the detection rule afterwards it still reported "not installed". Either the install silently failed, or the detection rule does not match what the install actually deploys.'
        Suggestion = 'Check the install command actually completes by running it manually as SYSTEM. Then manually validate the detection rule (file/registry/script) reflects what the installer deploys. For winget-style installs, ensure the app id matches exactly (case-sensitive in some contexts).'
    },
    @{
        Pattern    = '0x80070643'
        Title      = 'Fatal MSI install error (0x80070643 / 1603)'
        Meaning    = 'Windows Installer fatal error during install. Most common Win32App failure code. Reasons range from missing prerequisites, locked files, AV interference, broken custom actions, to existing partial installs.'
        Suggestion = 'Re-run the MSI manually with full logging: msiexec /i package.msi /l*v C:\Temp\msi.log. Read from the bottom up - find the first "return value 3" and look at the action that ran just before it. For winget-wrapped installs, ensure the install command runs in System context.'
    },
    @{
        Pattern    = '0x80070641'
        Title      = 'Windows Installer service failure (0x80070641)'
        Meaning    = 'The Windows Installer service is not available. Either it is disabled, stuck, or another install is holding it.'
        Suggestion = 'Restart the "Windows Installer" service. Look for stuck msiexec.exe processes. If repeated, run sfc /scannow.'
    },
    @{
        Pattern    = '0x80070001'
        Title      = 'Generic function failure (0x80070001)'
        Meaning    = 'ERROR_INVALID_FUNCTION. Most often appears as a transient error during content info requests or pre-install checks. Usually clears on retry.'
        Suggestion = 'If transient (clears within a sync or two), ignore. If repeated for the same app, raise with Microsoft - the app payload or Intune service-side state may be corrupted.'
    },
    @{
        Pattern    = '0x87D1FDE8'
        Title      = 'Sync session conflict (0x87D1FDE8)'
        Meaning    = 'A second sync started while the first was still running. Usually transient.'
        Suggestion = 'Wait for the next sync cycle. If repeated, check whether multiple sync triggers (Company Portal + Settings + scheduled task) are firing at once.'
    },
    @{
        Pattern    = '0x80073CF9'
        Title      = 'AppX install failure (0x80073CF9)'
        Meaning    = 'A modern (MSIX/AppX) app failed to install. Common causes: dependency missing, signature trust, or the package is already in a bad state on the device.'
        Suggestion = 'Get-AppxPackage -AllUsers | Where Name -like "<app>" to inspect. Try Add-AppxPackage manually to surface the real error. Confirm dependencies (e.g. VCLibs, .NET Native) are present.'
    },
    @{
        Pattern    = '0x80070005'
        Title      = 'Access denied (0x80070005)'
        Meaning    = 'Win32 ACCESS_DENIED. IME or a deployed payload tried to write/read somewhere it doesn''t have rights to.'
        Suggestion = 'Check NTFS perms on the target path and whether the install context (System vs User) matches the resource you''re touching.'
    },
    @{
        Pattern    = '0x80070002'
        Title      = 'File not found (0x80070002)'
        Meaning    = 'Win32 ERROR_FILE_NOT_FOUND. Usually a detection rule pointing at a non-existent path, or a missing dependency in the install command.'
        Suggestion = 'Verify the file path in your detection rule. For install errors, capture process output by wrapping the install command with cmd.exe /c "<cmd>" > C:\Windows\Temp\install.log 2>&1.'
    },
    @{
        Pattern    = '0x80004005'
        Title      = 'Generic E_FAIL (0x80004005)'
        Meaning    = 'Generic catch-all failure. Almost any subsystem can return this. Look at the surrounding log lines for the actual cause.'
        Suggestion = 'Look at the entries immediately before and after this one for context - they almost always reveal the real error.'
    },
    @{
        Pattern    = '\bexit code: 1603\b|\bexit code 1603\b'
        Title      = 'MSI fatal error during installation (1603)'
        Meaning    = 'Windows Installer fatal error. Almost always means the MSI itself failed - not Intune. Causes range from missing prereqs, locked files, AV interference, to broken custom actions.'
        Suggestion = 'Re-run the MSI manually with full logging: msiexec /i package.msi /l*v C:\Temp\msi.log. Read the log from the bottom up - find the first "return value 3" and look at the action that ran just before it.'
    },
    @{
        Pattern    = '\bexit code: 1618\b|\bexit code 1618\b'
        Title      = 'Another install in progress (1618)'
        Meaning    = 'Windows Installer is busy - another MSI install was running when IME tried to start one.'
        Suggestion = 'Transient. Will be retried on the next sync. If it persists, look for stuck msiexec.exe processes.'
        Override   = 'Warning'
    },
    @{
        Pattern    = '\bexit code: 1641\b|\bexit code: 3010\b'
        Title      = 'Soft reboot required'
        Meaning    = '1641 = installer triggered a reboot. 3010 = installer wants a reboot but didn''t take it. The install itself succeeded.'
        Suggestion = 'No action required if the app is configured to allow restart. Otherwise prompt the user.'
        Override   = 'Info'
    },
    @{
        Pattern    = 'hash mismatch|content hash.*does not match'
        Title      = 'Content download hash mismatch'
        Meaning    = 'IME downloaded the app payload but its hash didn''t match the hash recorded in the Intune service. Either content was corrupted in transit or the package on the back end is out of sync.'
        Suggestion = 'Clear C:\Windows\IMECache\<appId> and the corresponding folder under C:\ProgramData\Microsoft\IntuneManagementExtension\Content, then trigger a sync. If still failing, re-upload the .intunewin in the portal.'
    },
    @{
        Pattern    = 'ESP.*timeout|EnrollmentStatusTracking.*timeout|Out of grace period'
        Title      = 'Enrollment Status Page (ESP) timeout'
        Meaning    = 'A device hit the ESP timeout - apps or policies took longer than the configured grace period.'
        Suggestion = 'Review which apps/scripts are tracked by ESP. Increase the timeout in the ESP profile, or remove slow apps from the tracked list. Check apps for unattended-friendly install switches.'
    },
    @{
        Pattern    = '401 \(Unauthorized\)|HTTP/1\.1 401|HTTP 401'
        Title      = 'HTTP 401 - token rejected'
        Meaning    = 'IME called a Microsoft service and the token was rejected. Most often a clock-skew issue or an expired/revoked device certificate.'
        Suggestion = 'Check w32tm /query /status for time sync. Run dsregcmd /status to confirm the device cert is healthy. If clearly broken, leave/rejoin Intune.'
    },
    @{
        Pattern    = '403 \(Forbidden\)|HTTP/1\.1 403|HTTP 403'
        Title      = 'HTTP 403 - access denied by service'
        Meaning    = 'The token was valid but the service refused the call. Often a Conditional Access block, a licensing issue, or a region/tenant policy.'
        Suggestion = 'Check Conditional Access sign-in logs in Entra for the device account, confirm the user has the right Intune licence, and that the device meets compliance.'
    },
    @{
        Pattern    = '5\d\d \(Internal Server Error\)|HTTP/1\.1 5\d\d|HTTP 5\d\d'
        Title      = 'HTTP 5xx - Microsoft service error'
        Meaning    = 'The Intune backend returned a server error. Usually transient.'
        Suggestion = 'Check the Microsoft 365 / Intune status page. If localised to your tenant, raise a support ticket with the correlation IDs from the surrounding lines.'
        Override   = 'Warning'
    },
    @{
        Pattern    = 'PowerShell script .* exit code [^0]'
        Title      = 'Remediation / detection script non-zero exit'
        Meaning    = 'A Win32 detection script or a Proactive Remediation script returned a non-zero exit code. For detection scripts, this is how IME decides "not installed". For remediations, it means the remediation failed.'
        Suggestion = 'Open the script and run it locally as SYSTEM (psexec -i -s powershell.exe) to reproduce. Make sure detection scripts emit STDOUT only when the app IS installed and exit 0.'
    },
    @{
        Pattern    = 'PolicyAgent.*Forbidden|MDM Result.*404'
        Title      = 'MDM policy push rejected'
        Meaning    = 'The CSP/MDM stack rejected an incoming policy. Common with mistyped OMA-URIs or unsupported settings on the SKU.'
        Suggestion = 'Review the configuration profile in Intune. Cross-check the OMA-URI against the official CSP reference and confirm the SKU supports it (e.g. some settings are Enterprise-only).'
    }
)

function Get-KnowledgeMatch {
    param([string]$Message)
    foreach ($k in $KnowledgeBase) {
        if ($Message -match $k.Pattern) {
            return $k
        }
    }
    return $null
}

#endregion

#region ------------------------- File discovery -------------------------------

if ($Recurse) {
    $files = @(Get-ChildItem -LiteralPath $LogPath -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue)
} else {
    $rootFiles = @(Get-ChildItem -LiteralPath $LogPath -Filter '*.log' -File -ErrorAction SilentlyContinue)
    $oldFiles = @()
    if ($IncludeOld) {
        $oldFolder = Join-Path $LogPath 'old'
        if (Test-Path -LiteralPath $oldFolder) {
            $oldFiles = @(Get-ChildItem -LiteralPath $oldFolder -Filter '*.log' -File -ErrorAction SilentlyContinue)
        }
    }
    $files = @($rootFiles) + @($oldFiles)
}

if (-not $files -or $files.Count -eq 0) {
    throw "No .log files found under $LogPath"
}

Write-Host ("Found {0} log file(s)." -f $files.Count) -ForegroundColor Green

#endregion

#region ----------------------------- Parser -----------------------------------

# CMTrace regex. Multi-line message support via single-line option.
$entryRegex = [regex]::new(
    '<!\[LOG\[(?<message>.*?)\]LOG\]!><time="(?<time>[^"]+)" date="(?<date>[^"]+)" component="(?<component>[^"]*)" context="(?<context>[^"]*)" type="(?<type>[^"]+)" thread="(?<thread>[^"]+)" file="(?<file>[^"]*)">',
    [System.Text.RegularExpressions.RegexOptions]::Singleline
)

# Plain-timestamped log line, e.g. "2026-04-27 18:43:17 - Install-LanguageFODs v4.0"
$plainRegex = [regex]::new(
    '^(?<dt>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*-\s*(?<msg>.*)$',
    [System.Text.RegularExpressions.RegexOptions]::Multiline
)

$cutoff = if ($AllTime) { [datetime]::MinValue } else { (Get-Date).AddHours(-1 * [math]::Abs($Hours)) }

$entries = New-Object System.Collections.Generic.List[object]
$fileStats = New-Object System.Collections.Generic.List[object]

# Infer severity from a free-text message
function Get-InferredSeverity {
    param([string]$Message)
    if ($Message -match '(?i)\b(error|fail(ed|ure)?|exception|fatal|critical|cannot |could not |unable to|denied|refused|timeout|timed out)\b') {
        return 'Error'
    }
    if ($Message -match '(?i)\b(warn(ing)?|deprecated|skipped|retry|retrying|fall(ing)? back)\b') {
        return 'Warning'
    }
    return 'Info'
}

# Detect file format by sniffing the first few KB
function Get-LogFormat {
    param([string]$Content)
    $head = if ($Content.Length -gt 4096) { $Content.Substring(0, 4096) } else { $Content }
    if ($head -match '<!\[LOG\[') { return 'CMTrace' }
    if ($head -match 'Windows PowerShell transcript start') { return 'PSTranscript' }
    if ($head -match '^\s*\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\s*-\s') { return 'Plain' }
    return 'Unknown'
}

foreach ($file in $files) {
    Write-Host ("  Parsing {0} ({1:N0} KB)..." -f $file.Name, ($file.Length / 1KB))
    $content = $null
    try {
        $content = [System.IO.File]::ReadAllText($file.FullName)
    } catch {
        Write-Warning ("    Could not read {0}: {1}" -f $file.Name, $_.Exception.Message)
        continue
    }

    $format = Get-LogFormat -Content $content
    $fileTotal = 0
    $fileKept  = 0

    # ----- CMTrace -----
    if ($format -eq 'CMTrace') {
        $rxMatches = $entryRegex.Matches($content)
        $fileTotal = $rxMatches.Count

        foreach ($m in $rxMatches) {
        $dateStr = $m.Groups['date'].Value     # e.g. 4-27-2026  (M-D-YYYY)
        $timeStr = $m.Groups['time'].Value     # e.g. 18:42:25.5560401

        # Trim sub-second precision past 7 digits
        $timeClean = $timeStr
        if ($timeClean -match '^(\d{2}:\d{2}:\d{2})\.(\d+)$') {
            $frac = $Matches[2]
            if ($frac.Length -gt 7) { $frac = $frac.Substring(0, 7) }
            $timeClean = '{0}.{1}' -f $Matches[1], $frac
        }

        $dt = $null
        $combined = "$dateStr $timeClean"
        $formats = @(
            'M-d-yyyy HH:mm:ss.fffffff',
            'M-d-yyyy HH:mm:ss.ffffff',
            'M-d-yyyy HH:mm:ss.fffff',
            'M-d-yyyy HH:mm:ss.ffff',
            'M-d-yyyy HH:mm:ss.fff',
            'M-d-yyyy HH:mm:ss.ff',
            'M-d-yyyy HH:mm:ss.f',
            'M-d-yyyy HH:mm:ss'
        )
        foreach ($f in $formats) {
            try {
                $dt = [datetime]::ParseExact($combined, $f, [System.Globalization.CultureInfo]::InvariantCulture)
                break
            } catch { }
        }
        if (-not $dt) {
            try { $dt = [datetime]::Parse($combined, [System.Globalization.CultureInfo]::InvariantCulture) } catch { $dt = $null }
        }
        if (-not $dt) { continue }

        if ($dt -lt $cutoff) { continue }

        $rawType = $m.Groups['type'].Value
        $sev = switch ($rawType) {
            '1' { 'Info' }
            '2' { 'Warning' }
            '3' { 'Error' }
            default { 'Info' }
        }

        $message = $m.Groups['message'].Value.Trim()

        $kb = Get-KnowledgeMatch -Message $message
        if ($kb -and $kb.Override) { $sev = $kb.Override }

            $entries.Add([pscustomobject]@{
                Timestamp = $dt
                Severity  = $sev
                Component = $m.Groups['component'].Value
                Thread    = $m.Groups['thread'].Value
                Message   = $message
                File      = $file.Name
                KbTitle   = if ($kb) { $kb.Title }      else { $null }
                KbMeaning = if ($kb) { $kb.Meaning }    else { $null }
                KbAdvice  = if ($kb) { $kb.Suggestion } else { $null }
            })
            $fileKept++
        }
    }
    # ----- Plain timestamped (e.g. Install-LanguageFODs_de-DE.log) -----
    elseif ($format -eq 'Plain') {
        $component = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $plainMatches = $plainRegex.Matches($content)
        $fileTotal = $plainMatches.Count
        foreach ($pm in $plainMatches) {
            $dt = $null
            try { $dt = [datetime]::ParseExact($pm.Groups['dt'].Value, 'yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
            if (-not $dt) { continue }
            if ($dt -lt $cutoff) { continue }
            $message = $pm.Groups['msg'].Value.Trim()
            if (-not $message) { continue }
            $sev = Get-InferredSeverity -Message $message
            $kb = Get-KnowledgeMatch -Message $message
            if ($kb -and $kb.Override) { $sev = $kb.Override }
            $entries.Add([pscustomobject]@{
                Timestamp = $dt
                Severity  = $sev
                Component = $component
                Thread    = ''
                Message   = $message
                File      = $file.Name
                KbTitle   = if ($kb) { $kb.Title }      else { $null }
                KbMeaning = if ($kb) { $kb.Meaning }    else { $null }
                KbAdvice  = if ($kb) { $kb.Suggestion } else { $null }
            })
            $fileKept++
        }
    }
    # ----- PowerShell transcript (detection / remediation script output) -----
    elseif ($format -eq 'PSTranscript') {
        $component = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        # Pull the Start time stamp - format: yyyyMMddHHmmss
        $startDt = $file.LastWriteTime
        if ($content -match 'Start time:\s*(\d{14})') {
            try { $startDt = [datetime]::ParseExact($Matches[1], 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
        }
        # Extract the body between the second '**********************' (after metadata) and the 'Windows PowerShell transcript end' line.
        $bodyText = $content
        $startIdx = $content.IndexOf('Transcript started, output file is')
        if ($startIdx -ge 0) {
            $afterStart = $content.IndexOf("`n", $startIdx)
            if ($afterStart -ge 0) { $bodyText = $content.Substring($afterStart + 1) }
        }
        $endIdx = $bodyText.IndexOf('Windows PowerShell transcript end')
        if ($endIdx -ge 0) { $bodyText = $bodyText.Substring(0, $endIdx) }

        $bodyLines = $bodyText -split "`r?`n" | Where-Object {
            $_ -and $_.Trim() -and ($_ -notmatch '^\*{3,}\s*$')
        }
        $fileTotal = $bodyLines.Count

        if ($startDt -lt $cutoff) {
            # Skip whole transcript if it's outside the window
            $fileStats.Add([pscustomobject]@{
                Name = $file.Name; Folder = (Split-Path -Parent $file.FullName)
                SizeKB = [math]::Round($file.Length / 1KB, 1); Total = $fileTotal; Kept = 0
            })
            continue
        }

        $lineIdx = 0
        foreach ($ln in $bodyLines) {
            $lineIdx++
            $message = $ln.Trim()
            $sev = Get-InferredSeverity -Message $message
            # Common detection-script convention: "<App> not detected" usually means "not installed" - inform, not error.
            if ($message -match '(?i)\bnot detected\b' -and $message -notmatch '(?i)\b(error|exception|fail)\b') {
                $sev = 'Info'
            }
            $kb = Get-KnowledgeMatch -Message $message
            if ($kb -and $kb.Override) { $sev = $kb.Override }
            $entries.Add([pscustomobject]@{
                Timestamp = $startDt.AddMilliseconds($lineIdx)
                Severity  = $sev
                Component = $component
                Thread    = ''
                Message   = $message
                File      = $file.Name
                KbTitle   = if ($kb) { $kb.Title }      else { $null }
                KbMeaning = if ($kb) { $kb.Meaning }    else { $null }
                KbAdvice  = if ($kb) { $kb.Suggestion } else { $null }
            })
            $fileKept++
        }
    }
    # ----- Unknown format: best-effort line-by-line, no timestamp -----
    else {
        $component = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        $stamp = $file.LastWriteTime
        if ($stamp -lt $cutoff) {
            $fileStats.Add([pscustomobject]@{
                Name = $file.Name; Folder = (Split-Path -Parent $file.FullName)
                SizeKB = [math]::Round($file.Length / 1KB, 1); Total = 0; Kept = 0
            })
            continue
        }
        $lines = $content -split "`r?`n" | Where-Object { $_ -and $_.Trim() }
        $fileTotal = $lines.Count
        $i = 0
        foreach ($ln in $lines) {
            $i++
            $message = $ln.Trim()
            $sev = Get-InferredSeverity -Message $message
            $kb = Get-KnowledgeMatch -Message $message
            if ($kb -and $kb.Override) { $sev = $kb.Override }
            $entries.Add([pscustomobject]@{
                Timestamp = $stamp.AddMilliseconds(-1 * ($lines.Count - $i))
                Severity  = $sev
                Component = $component
                Thread    = ''
                Message   = $message
                File      = $file.Name
                KbTitle   = if ($kb) { $kb.Title }      else { $null }
                KbMeaning = if ($kb) { $kb.Meaning }    else { $null }
                KbAdvice  = if ($kb) { $kb.Suggestion } else { $null }
            })
            $fileKept++
        }
    }

    $fileStats.Add([pscustomobject]@{
        Name    = $file.Name
        Folder  = (Split-Path -Parent $file.FullName)
        SizeKB  = [math]::Round($file.Length / 1KB, 1)
        Total   = $fileTotal
        Kept    = $fileKept
    })
}

Write-Host ("Parsed {0:N0} entries within window." -f $entries.Count) -ForegroundColor Green
if ($entries.Count -eq 0) {
    Write-Warning "No entries fell within the time window. Try a wider -Hours value or -AllTime."
}

#endregion

#region ----------------- Win32App outcome extraction --------------------------
# IME embeds per-app install state and error code as JSON inside the
# [Win32App][ReportingManager] and [Win32App] content info request messages.
# Pull them out so we can show app-level outcomes in the report.

$IntentMap = @{ 0 = 'Not targeted'; 1 = 'Available'; 3 = 'Required'; 4 = 'Uninstall' }
$StateMap = @{
    1000 = 'Already compliant'
    2000 = 'Pending'
    2009 = 'In progress'
    5000 = 'Install succeeded'
    5001 = 'Install failed'
    5003 = 'Not detected after install'
}
$AppErrorMap = @{
    -2147023293 = 'Fatal MSI install error (1603). Installer ran and failed.'
    -2147024891 = 'Access denied. Install or detection lacks permission.'
    -2147024894 = 'File not found. Detection rule path or installer file missing.'
    -2147024809 = 'Invalid parameter.'
    -2016345060 = 'Detection rule did not match (app reported as not installed).'
    -2016214939 = 'App not detected after install. Install ran successfully but detection rule still says "not installed".'
    -2147467259 = 'Generic E_FAIL. Look at surrounding entries for the real cause.'
    -2147024769 = 'Procedure not found in DLL.'
    -2147024873 = 'CRC / data integrity error.'
    -2147024864 = 'File in use.'
    -2147467260 = 'E_ABORT - Operation aborted.'
    -2147023174 = 'RPC server unavailable.'
    -2016214952 = 'Content download failure.'
    -2016214953 = 'Hash mismatch on downloaded content.'
    1           = 'Generic invalid function.'
    -2147024896 = '(operation completed/no error in some contexts).'
}

function Get-AppErrorMeaning {
    param($Code)
    if ($null -eq $Code -or $Code -eq 0) { return $null }
    if ($AppErrorMap.ContainsKey([int]$Code)) { return $AppErrorMap[[int]$Code] }
    $hex = '0x{0:X8}' -f ([int]$Code -band 0xFFFFFFFF)
    return "$hex - (no plain-English mapping yet, search Microsoft docs for this code)"
}

# Build app inventory by scanning entries for embedded JSON
$appInventory = @{}
$cirNameRx     = [regex]::new('"ApplicationId":"(?<id>[0-9a-f-]{36})","ApplicationVersion":"(?<ver>[^"]*)","ApplicationName":"(?<name>[^"]+)"', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$cirIntentRx   = [regex]::new('"ApplicationId":"(?<id>[0-9a-f-]{36})"[^}]*?"Intent":"(?<intent>\d+)"', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$cirErrCodeRx  = [regex]::new('"ApplicationId":"(?<id>[0-9a-f-]{36})"[^}]*?"ErrorCode":"(?<err>-?\d+)"', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$idNameRx      = [regex]::new('\(\s*id\s*=\s*(?<id>[0-9a-f-]{36})[, ]\s*name\s*=?\s*(?<name>[^,)]+?)\s*\)', [System.Text.RegularExpressions.RegexOptions]::Singleline)
$reportRx      = [regex]::new('(?:ReportingState:|based on report:)\s*\{', [System.Text.RegularExpressions.RegexOptions]::Singleline)

function Get-Or-NewApp {
    param($Map, [string]$Id, [datetime]$Ts)
    if (-not $Map.ContainsKey($Id)) {
        $Map[$Id] = [ordered]@{
            Id = $Id; Name = $null; Version = $null; Intent = $null
            State = $null; ErrorCode = $null; ErrorHistory = New-Object System.Collections.Generic.List[int]
            FirstSeen = $Ts; LastSeen = $Ts
        }
    }
    if ($Ts -gt $Map[$Id].LastSeen)  { $Map[$Id].LastSeen  = $Ts }
    if ($Ts -lt $Map[$Id].FirstSeen) { $Map[$Id].FirstSeen = $Ts }
    return $Map[$Id]
}

function Get-JsonObjectAt {
    param([string]$Text, [int]$StartBrace)
    $depth = 0
    for ($i = $StartBrace; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($c -eq '{') { $depth++ }
        elseif ($c -eq '}') {
            $depth--
            if ($depth -eq 0) {
                $sub = $Text.Substring($StartBrace, $i - $StartBrace + 1)
                try { return ($sub | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
            }
        }
    }
    return $null
}

foreach ($e in $entries) {
    if ($e.Component -ne 'AppWorkload' -and $e.Component -ne 'IntuneManagementExtension') { continue }
    $msg = $e.Message
    if ($msg.Length -lt 40) { continue }

    foreach ($m in $cirNameRx.Matches($msg)) {
        $a = Get-Or-NewApp -Map $appInventory -Id $m.Groups['id'].Value -Ts $e.Timestamp
        $a.Name    = $m.Groups['name'].Value
        $a.Version = $m.Groups['ver'].Value
    }
    foreach ($m in $cirIntentRx.Matches($msg)) {
        $a = Get-Or-NewApp -Map $appInventory -Id $m.Groups['id'].Value -Ts $e.Timestamp
        if ($null -eq $a.Intent) { $a.Intent = [int]$m.Groups['intent'].Value }
    }
    foreach ($m in $cirErrCodeRx.Matches($msg)) {
        $code = [int]$m.Groups['err'].Value
        if ($code -ne 0) {
            $a = Get-Or-NewApp -Map $appInventory -Id $m.Groups['id'].Value -Ts $e.Timestamp
            $a.ErrorHistory.Add($code) | Out-Null
        }
    }
    foreach ($m in $idNameRx.Matches($msg)) {
        $a = Get-Or-NewApp -Map $appInventory -Id $m.Groups['id'].Value -Ts $e.Timestamp
        if (-not $a.Name) { $a.Name = $m.Groups['name'].Value.Trim() }
    }
    $rs = $reportRx.Match($msg)
    if ($rs.Success) {
        # Locate brace start (the literal '{' that follows the marker)
        $braceIdx = $msg.IndexOf('{', $rs.Index)
        if ($braceIdx -ge 0) {
            $obj = Get-JsonObjectAt -Text $msg -StartBrace $braceIdx
            if ($obj -and $obj.ApplicationId) {
                $a = Get-Or-NewApp -Map $appInventory -Id $obj.ApplicationId -Ts $e.Timestamp
                if ($null -ne $obj.Intent)               { $a.Intent    = [int]$obj.Intent }
                if ($null -ne $obj.EnforcementState)     { $a.State     = [int]$obj.EnforcementState }
                if ($null -ne $obj.EnforcementErrorCode) { $a.ErrorCode = [int]$obj.EnforcementErrorCode }
            }
        }
    }
}

# Build per-app summary objects (sorted: failures first, then by name)
$appSummary = @(
    foreach ($aid in $appInventory.Keys) {
        $a = $appInventory[$aid]
        $intentName = if ($null -ne $a.Intent) { $IntentMap[[int]$a.Intent] } else { $null }
        if (-not $intentName) { $intentName = '(unknown)' }
        $stateName  = if ($null -ne $a.State) { $StateMap[[int]$a.State] } else { 'Not yet reported' }
        $errMeaning = Get-AppErrorMeaning -Code $a.ErrorCode
        $histDescr = @()
        foreach ($c in $a.ErrorHistory) { $histDescr += (Get-AppErrorMeaning -Code $c) }
        $histDescr = ($histDescr | Select-Object -Unique) -join '; '

        # Severity classification
        $sev = 'Info'
        if ($a.State -in 5001, 5003) {
            $sev = 'Error'
        } elseif ($a.State -eq 5000 -and ($a.ErrorCode -or $a.ErrorHistory.Count -gt 0)) {
            # Eventually succeeded but had error(s) on the way
            $sev = 'Warning'
        } elseif (-not $a.State -and $intentName -in 'Required','Uninstall') {
            $sev = 'Warning'  # never reported a state for a required app within the window
        } elseif ($a.ErrorHistory.Count -gt 0) {
            $sev = 'Warning'
        }

        # Skip "NotTargeted" apps that have never reported anything interesting
        if ($intentName -eq 'Not targeted' -and -not $a.State -and -not $a.ErrorCode -and $a.ErrorHistory.Count -eq 0) { continue }

        [pscustomobject]@{
            Id        = $a.Id
            Name      = if ($a.Name) { $a.Name } else { '(unnamed app)' }
            Version   = $a.Version
            Intent    = $intentName
            State     = $stateName
            StateCode = $a.State
            ErrorCode = if ($null -ne $a.ErrorCode) { '0x{0:X8}' -f ([int]$a.ErrorCode -band 0xFFFFFFFF) } else { $null }
            ErrorMeaning = $errMeaning
            ErrorHistory = $histDescr
            FirstSeen = $a.FirstSeen
            LastSeen  = $a.LastSeen
            Severity  = $sev
        }
    }
)
$severityRank = @{ 'Error' = 0; 'Warning' = 1; 'Info' = 2 }
$appSummary = @($appSummary | Sort-Object @{ Expression = { $severityRank[$_.Severity] }; Ascending = $true }, Name)

# Synthesize a high-level entry for each problem app so it surfaces in the entries table & timeline
foreach ($app in $appSummary) {
    if ($app.Severity -eq 'Info') { continue }
    $synthMsg = "[App outcome] {0} ({1}, intent={2}) - {3}{4}{5}" -f `
        $app.Name, $app.Id, $app.Intent, $app.State,
        $(if ($app.ErrorCode) { ". ErrorCode $($app.ErrorCode): $($app.ErrorMeaning)" } else { '' }),
        $(if ($app.ErrorHistory) { ". History: $($app.ErrorHistory)" } else { '' })
    $kb = Get-KnowledgeMatch -Message $synthMsg
    $entries.Add([pscustomobject]@{
        Timestamp = $app.LastSeen
        Severity  = $app.Severity
        Component = 'AppOutcome'
        Thread    = ''
        Message   = $synthMsg
        File      = '(synthesized)'
        KbTitle   = if ($kb) { $kb.Title }   else { 'Win32 app outcome summary' }
        KbMeaning = if ($kb) { $kb.Meaning } else {
            switch ($app.Severity) {
                'Error'   { 'This Win32 app reported a failed install state for the targeted user/device within the analysed window.' }
                'Warning' { 'This Win32 app eventually reached a non-failed state but had errors during the process - worth checking the install command and detection rule.' }
                default   { 'Win32 app outcome summary.' }
            }
        }
        KbAdvice  = if ($kb) { $kb.Suggestion } else {
            'Open the app in Intune Admin Centre > Apps > Windows. Review Install command, detection rule, and any required dependencies/supersedence. Re-run the install command manually under SYSTEM context to capture the real failure.'
        }
    }) | Out-Null
}

#endregion


#region ----------------- MDM Diagnostic Report ingestion ----------------------
# Parses MDMDiagReport.html (output of MdmDiagnosticsTool.exe) and extracts
# device info, connection state, certificates, managed apps and LAPS settings.
# Surfaces sync failures, expiring certificates and warnings as synthesized
# entries so they appear in the timeline and entries table.

function ConvertFrom-HtmlSnippet {
    param([string]$Html)
    if (-not $Html) { return '' }
    # Strip tags
    $t = [regex]::Replace($Html, '<[^>]+>', '')
    # Decode common entities
    $t = $t -replace '&nbsp;', ' '
    $t = $t -replace '&amp;', '&'
    $t = $t -replace '&lt;', '<'
    $t = $t -replace '&gt;', '>'
    $t = $t -replace '&quot;', '"'
    $t = $t -replace '&#39;', "'"
    $t = $t -replace '&apos;', "'"
    return ($t -replace '\s+', ' ').Trim()
}

function Get-MdmDiagInfo {
    param([string]$DiagFolder)

    $result = [ordered]@{
        Found             = $false
        FilePath          = $null
        Generated         = $null
        Device            = [ordered]@{}
        Connection        = [ordered]@{}
        SyncFailed        = $false
        Account           = [ordered]@{}
        Certificates      = @()
        CertExpiringSoon  = @()
        ConfigSourceCount = 0
        ManagedPolicyCount= 0
        ManagedApps       = @()
        LapsSettings      = @()
        BlockedGpoCount   = 0
        UnmanagedPolicyCount = 0
        Warnings          = New-Object System.Collections.Generic.List[string]
    }

    if (-not $DiagFolder) { return $result }
    if (-not (Test-Path -LiteralPath $DiagFolder)) {
        Write-Host ("MDM diagnostics folder not found: {0} (skipping)" -f $DiagFolder) -ForegroundColor DarkYellow
        return $result
    }

    # Find the most recent MDMDiagReport.html in the folder (or any *.html)
    $diagFile = Get-ChildItem -LiteralPath $DiagFolder -Filter 'MDMDiagReport*.html' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $diagFile) {
        $diagFile = Get-ChildItem -LiteralPath $DiagFolder -Filter '*.html' -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }
    if (-not $diagFile) {
        Write-Host ("No MDMDiagReport.html in {0} (skipping)" -f $DiagFolder) -ForegroundColor DarkYellow
        return $result
    }

    Write-Host ("Parsing MDM diagnostic report: {0}" -f $diagFile.Name) -ForegroundColor Cyan
    $result.Found = $true
    $result.FilePath = $diagFile.FullName

    $content = [System.IO.File]::ReadAllText($diagFile.FullName)

    # Generated timestamp from header
    $hm = [regex]::Match($content, '<div class="TextBody"[^>]*>\s*(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*[AP]M)')
    if ($hm.Success) { $result.Generated = $hm.Groups[1].Value.Trim() }

    # Walk each <section>
    $sectionRx = [regex]::new('<section[^>]*>(?<body>.*?)</section>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    # Match the inner class="SectionTitle" only - NOT the wrapper class="HovableSectionTitle"
    $titleRx   = [regex]::new('class="SectionTitle"[^>]*>(?<t>[^<]+)<', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $rowRx     = [regex]::new('<tr[^>]*>(?<r>.*?)</tr>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $cellRx    = [regex]::new('<t[hd][^>]*>(?<c>.*?)</t[hd]>', [System.Text.RegularExpressions.RegexOptions]::Singleline)

    foreach ($sec in $sectionRx.Matches($content)) {
        $body = $sec.Groups['body'].Value
        $tm = $titleRx.Match($body)
        if (-not $tm.Success) { continue }
        $title = (ConvertFrom-HtmlSnippet $tm.Groups['t'].Value)

        $rows = @()
        foreach ($r in $rowRx.Matches($body)) {
            $cells = @()
            foreach ($c in $cellRx.Matches($r.Groups['r'].Value)) {
                $cells += (ConvertFrom-HtmlSnippet $c.Groups['c'].Value)
            }
            if ($cells.Count -gt 0) { $rows += , $cells }
        }

        switch -Wildcard ($title) {
            'Device Info' {
                foreach ($r in $rows) {
                    if ($r.Count -ge 2) { $result.Device[$r[0]] = $r[1] }
                }
            }
            'Connection Info' {
                foreach ($r in $rows) {
                    if ($r.Count -ge 2) {
                        $result.Connection[$r[0]] = $r[1]
                        if ($r[0] -match '^Last sync$' -and $r[1] -match '(?i)failed') {
                            $result.SyncFailed = $true
                            $result.Warnings.Add("Last MDM sync failed: $($r[1])") | Out-Null
                        }
                    }
                }
            }
            'Device Management Account' {
                foreach ($r in $rows) {
                    if ($r.Count -ge 2) { $result.Account[$r[0]] = $r[1] }
                }
            }
            'Certificates' {
                # First row is the header
                $isHeader = $true
                foreach ($r in $rows) {
                    if ($isHeader) { $isHeader = $false; continue }
                    if ($r.Count -ge 4) {
                        $cert = [ordered]@{
                            IssuedTo = $r[0]; IssuedBy = $r[1]; Expiration = $r[2]; Purpose = $r[3]
                        }
                        $result.Certificates += [pscustomobject]$cert
                        # Try to parse expiration and warn if within 90 days
                        $expDt = $null
                        try { $expDt = [datetime]::ParseExact($r[2], 'M/d/yyyy', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }
                        if (-not $expDt) { try { $expDt = [datetime]::Parse($r[2], [System.Globalization.CultureInfo]::InvariantCulture) } catch { } }
                        if ($expDt) {
                            $days = [int]([math]::Round((($expDt - (Get-Date)).TotalDays)))
                            if ($days -lt 0) {
                                $result.CertExpiringSoon += [pscustomobject]@{ IssuedTo = $r[0]; Expires = $r[2]; DaysLeft = $days; Status = 'EXPIRED' }
                                $result.Warnings.Add("Certificate '$($r[0])' EXPIRED $([math]::Abs($days)) days ago ($($r[2]))") | Out-Null
                            } elseif ($days -le 90) {
                                $result.CertExpiringSoon += [pscustomobject]@{ IssuedTo = $r[0]; Expires = $r[2]; DaysLeft = $days; Status = 'Expiring soon' }
                                $result.Warnings.Add("Certificate '$($r[0])' expires in $days days ($($r[2]))") | Out-Null
                            }
                        }
                    }
                }
            }
            'Enrolled configuration sources*' {
                $result.ConfigSourceCount = [math]::Max(0, $rows.Count - 1)
            }
            'Managed policies' {
                $result.ManagedPolicyCount = [math]::Max(0, $rows.Count - 1)
            }
            'Managed applications' {
                $isHeader = $true
                foreach ($r in $rows) {
                    if ($isHeader) { $isHeader = $false; continue }
                    if ($r.Count -ge 3) {
                        $app = [pscustomobject]@{
                            Name      = $r[0]
                            Status    = $r[1]
                            LastError = $r[2]
                        }
                        $result.ManagedApps += $app
                        if ($r[2] -and $r[2] -ne 'None' -and $r[2] -ne '0' -and $r[2] -ne '') {
                            $result.Warnings.Add("Managed app '$($r[0])' last error: $($r[2])") | Out-Null
                        }
                    }
                }
            }
            'Local Administrator Password Solution*' {
                $isHeader = $true
                foreach ($r in $rows) {
                    if ($isHeader) { $isHeader = $false; continue }
                    if ($r.Count -ge 4) {
                        $hasWarn = ($r[3] -match '(?i)warning|cannot|could not|fail')
                        $result.LapsSettings += [pscustomobject]@{
                            Setting = $r[0]; Default = $r[1]; Current = $r[2]; Notes = $r[3]; IsWarning = $hasWarn
                        }
                        if ($hasWarn) {
                            $result.Warnings.Add("LAPS '$($r[0])' note: $($r[3])") | Out-Null
                        }
                    }
                }
            }
            'Blocked Group Policies' {
                $result.BlockedGpoCount = [math]::Max(0, $rows.Count - 1)
            }
            'Unmanaged policies' {
                $result.UnmanagedPolicyCount = [math]::Max(0, $rows.Count - 1)
            }
        }
    }

    # Synthesize entries to surface in the entries timeline / table
    $now = Get-Date
    if ($result.SyncFailed) {
        $entries.Add([pscustomobject]@{
            Timestamp = $now
            Severity  = 'Error'
            Component = 'MDMDiag'
            Thread    = ''
            Message   = "MDM sync FAILED on the device. Reported in MDMDiagReport.html: $($result.Connection['Last sync'])"
            File      = $diagFile.Name
            KbTitle   = 'MDM sync failed'
            KbMeaning = 'The Windows MDM client could not complete its last scheduled or manual sync with Intune. Until this is resolved, no new policies, scripts or app assignments will reach this device.'
            KbAdvice  = 'Open Settings > Accounts > Access work or school > <work account> > Info, then click "Sync". If it fails again, check w32tm /query /status for clock skew, dsregcmd /status for the device certificate state, and Conditional Access sign-in logs in Entra for the device account.'
        }) | Out-Null
    }
    foreach ($w in $result.Warnings) {
        if ($w -like 'Last MDM sync failed*') { continue }   # already added above
        $sev = if ($w -like '*EXPIRED*') { 'Error' } else { 'Warning' }
        $entries.Add([pscustomobject]@{
            Timestamp = $now
            Severity  = $sev
            Component = 'MDMDiag'
            Thread    = ''
            Message   = $w
            File      = $diagFile.Name
            KbTitle   = 'MDM diagnostic warning'
            KbMeaning = 'Surfaced from the MDM diagnostic report. See the dedicated MDM Diagnostics panel for details.'
            KbAdvice  = 'Review the underlying setting in Intune. For LAPS notes, check the Endpoint security > Account protection policy. For certificate warnings, check the device''s MDM enrollment health (dsregcmd /status).'
        }) | Out-Null
    }

    return [pscustomobject]$result
}

$diagInfo = Get-MdmDiagInfo -DiagFolder $DiagPath

#endregion
#region ----------------- Autopilot & Enrollment health ------------------------
# Extract Autopilot/ESP and enrollment-health signals from already-parsed entries.

$espRx          = [regex]::new('EspPhase[:= ]+(?<phase>NotInEsp|DeviceESP|UserESP|FirstPolicyAndAppESP|Unknown)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$firstSyncRx    = [regex]::new('IsSyncDoneForUser as ''(?<state>True|False)''', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$firstSyncRx2   = [regex]::new('IsSyncDoneForUser[:= ]+(?<state>True|False)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$enrollRx       = [regex]::new('Enrollments\\(?<id>[0-9A-F\-]{8,40})', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$heartbeatRx    = [regex]::new('(?i)client heart beat health report failed to send')
$espTimeoutRx   = [regex]::new('(?i)(out of grace period|ESP phase timed out|ESP phase has timed out|EnrollmentStatusTracking timed out|ESP timeout reached|exceeded.*ESP.*grace|tracking timeout)')
$espTrackedRx   = [regex]::new('(?i)Tracked app[s]?.*ESP|ESP.*tracked')

$autopilot = [ordered]@{
    LatestEspPhase       = $null
    LatestEspPhaseAt     = $null
    EspPhaseHistory      = New-Object System.Collections.Generic.List[object]   # for transitions
    FirstSyncDone        = $null
    FirstSyncCheckedAt   = $null
    EnrollmentId         = $null
    HeartbeatFailures    = 0
    HeartbeatLastFailAt  = $null
    EspTimeouts          = 0
    EspTimeoutLastAt     = $null
    Warnings             = New-Object System.Collections.Generic.List[string]
}

# Walk entries (newest first since we sorted descending; for "latest" semantics that's fine)
$lastPhase = $null
foreach ($e in $entries) {
    $msg = $e.Message

    # ESP phase
    $m = $espRx.Match($msg)
    if ($m.Success) {
        $phase = $m.Groups['phase'].Value
        # Capture the LATEST phase (entries are sorted newest first, so first hit wins)
        if (-not $autopilot.LatestEspPhase) {
            $autopilot.LatestEspPhase   = $phase
            $autopilot.LatestEspPhaseAt = $e.Timestamp
        }
        # Capture phase transitions (when value differs from previous)
        if ($phase -ne $lastPhase -and $autopilot.EspPhaseHistory.Count -lt 30) {
            $autopilot.EspPhaseHistory.Add([pscustomobject]@{
                Timestamp = $e.Timestamp; Phase = $phase
            })
            $lastPhase = $phase
        }
    }

    # FirstSync state - prefer the explicit 'IsSyncDoneForUser as X' phrasing
    if (-not $autopilot.FirstSyncCheckedAt) {
        $m = $firstSyncRx.Match($msg)
        if (-not $m.Success) { $m = $firstSyncRx2.Match($msg) }
        if ($m.Success) {
            $autopilot.FirstSyncDone      = ($m.Groups['state'].Value -eq 'True')
            $autopilot.FirstSyncCheckedAt = $e.Timestamp
        }
    }

    # Enrollment GUID
    if (-not $autopilot.EnrollmentId) {
        $m = $enrollRx.Match($msg)
        if ($m.Success) { $autopilot.EnrollmentId = $m.Groups['id'].Value }
    }

    # Heartbeat failures
    if ($heartbeatRx.IsMatch($msg)) {
        $autopilot.HeartbeatFailures++
        if (-not $autopilot.HeartbeatLastFailAt) { $autopilot.HeartbeatLastFailAt = $e.Timestamp }
    }

    # ESP timeouts
    if ($espTimeoutRx.IsMatch($msg)) {
        $autopilot.EspTimeouts++
        if (-not $autopilot.EspTimeoutLastAt) { $autopilot.EspTimeoutLastAt = $e.Timestamp }
    }
}

# Warnings/status synthesis
if ($autopilot.LatestEspPhase -in 'DeviceESP','UserESP','FirstPolicyAndAppESP') {
    $autopilot.Warnings.Add("Device is still in ESP phase '$($autopilot.LatestEspPhase)' as of $($autopilot.LatestEspPhaseAt). Provisioning may be in progress or stuck.") | Out-Null
}
if ($autopilot.EspTimeouts -gt 0) {
    $autopilot.Warnings.Add("$($autopilot.EspTimeouts) ESP timeout / 'out of grace period' event(s) detected. Apps or scripts tracked by ESP exceeded the configured grace period.") | Out-Null
}
if ($autopilot.HeartbeatFailures -ge 3) {
    $autopilot.Warnings.Add("$($autopilot.HeartbeatFailures) sidecar heartbeat failures (latest $($autopilot.HeartbeatLastFailAt)). The Intune sidecar agent could not post device health to the service - may indicate network or service-side issues.") | Out-Null
}
if ($autopilot.LatestEspPhase -eq 'NotInEsp' -and $autopilot.FirstSyncDone -eq $false) {
    $autopilot.Warnings.Add("Device is past ESP but IsSyncDoneForUser for the current user is still False. User-targeted policies and apps may not have fully applied.") | Out-Null
}

# Synthesize entries so issues show up in the timeline
foreach ($w in $autopilot.Warnings) {
    $sev = if ($w -like '*stuck*' -or $w -like '*timeout*' -or $w -like '*ESP phase*') { 'Error' } else { 'Warning' }
    $entries.Add([pscustomobject]@{
        Timestamp = (Get-Date)
        Severity  = $sev
        Component = 'Autopilot'
        Thread    = ''
        Message   = $w
        File      = '(synthesized)'
        KbTitle   = 'Autopilot / Enrollment health'
        KbMeaning = 'Surfaced from the Autopilot & Enrollment health analysis. See the dedicated panel for details.'
        KbAdvice  = 'For ESP timeouts: review which apps/scripts are tracked by ESP and consider raising the timeout, removing slow apps from tracking, or fixing the underlying install. For heartbeat failures: check device connectivity to *.manage.microsoft.com endpoints and verify the IntuneManagementExtension service is running. For FirstSync incomplete: trigger a manual sync from Settings > Accounts > Access work or school.'
    }) | Out-Null
}

#endregion

#region ------------------------- Aggregation ----------------------------------

$entries = @($entries | Sort-Object Timestamp -Descending)

$counts = @{
    Total   = @($entries).Count
    Error   = @($entries | Where-Object { $_.Severity -eq 'Error'   }).Count
    Warning = @($entries | Where-Object { $_.Severity -eq 'Warning' }).Count
    Info    = @($entries | Where-Object { $_.Severity -eq 'Info'    }).Count
}

function Get-NormalisedKey {
    param([string]$Message)
    $k = $Message
    $k = [regex]::Replace($k, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<GUID>')
    $k = [regex]::Replace($k, 'S-\d-\d+(-\d+){1,14}', '<SID>')
    $k = [regex]::Replace($k, '\d{2}:\d{2}:\d{2}\.\d+', '<TIME>')
    $k = [regex]::Replace($k, '\d{1,2}/\d{1,2}/\d{4}', '<DATE>')
    $k = [regex]::Replace($k, '0x[0-9A-Fa-f]{4,}', '<HEX>')
    $k = [regex]::Replace($k, '\b\d{4,}\b', '<N>')
    if ($k.Length -gt 240) { $k = $k.Substring(0, 240) }
    return $k
}

$groups = @($entries |
    Where-Object { $_.Severity -eq 'Error' -or $_.Severity -eq 'Warning' } |
    Group-Object { Get-NormalisedKey -Message $_.Message } |
    Sort-Object Count -Descending)

$topGroups = @(foreach ($g in $groups) {
    $first = $g.Group[0]
    [pscustomobject]@{
        Count      = $g.Count
        Severity   = ($g.Group | Group-Object Severity | Sort-Object Count -Descending | Select-Object -First 1).Name
        Component  = ($g.Group | Group-Object Component | Sort-Object Count -Descending | Select-Object -First 1).Name
        Sample     = $first.Message
        FirstSeen  = ($g.Group | Sort-Object Timestamp | Select-Object -First 1).Timestamp
        LastSeen   = ($g.Group | Sort-Object Timestamp -Descending | Select-Object -First 1).Timestamp
        KbTitle    = $first.KbTitle
        KbMeaning  = $first.KbMeaning
        KbAdvice   = $first.KbAdvice
    }
})

$timeline = @{}
foreach ($e in $entries) {
    $bucket = $e.Timestamp.ToString('yyyy-MM-dd HH:00')
    if (-not $timeline.ContainsKey($bucket)) {
        $timeline[$bucket] = @{ Error = 0; Warning = 0; Info = 0 }
    }
    $timeline[$bucket][$e.Severity]++
}
$timelineSorted = $timeline.GetEnumerator() | Sort-Object Name

#endregion

#region -------------------------- HTML render ---------------------------------

function ConvertTo-SafeJson {
    param($Data, [int]$Depth = 8)
    if ($null -eq $Data) { return '[]' }
    $json = $Data | ConvertTo-Json -Depth $Depth -Compress
    if (-not $json) { return '[]' }
    $json = $json -replace '</', '<\/'
    return $json
}

$entriesForJson = $entries | ForEach-Object {
    [pscustomobject]@{
        t  = $_.Timestamp.ToString('yyyy-MM-ddTHH:mm:ss.fff')
        s  = $_.Severity
        c  = $_.Component
        th = $_.Thread
        m  = $_.Message
        f  = $_.File
        kt = $_.KbTitle
        km = $_.KbMeaning
        ka = $_.KbAdvice
    }
}

$groupsForJson = $topGroups | ForEach-Object {
    [pscustomobject]@{
        n  = $_.Count
        s  = $_.Severity
        c  = $_.Component
        m  = $_.Sample
        fs = $_.FirstSeen.ToString('yyyy-MM-dd HH:mm:ss')
        ls = $_.LastSeen.ToString('yyyy-MM-dd HH:mm:ss')
        kt = $_.KbTitle
        km = $_.KbMeaning
        ka = $_.KbAdvice
    }
}

$timelineForJson = $timelineSorted | ForEach-Object {
    [pscustomobject]@{
        b = $_.Name
        e = $_.Value.Error
        w = $_.Value.Warning
        i = $_.Value.Info
    }
}

$fileStatsForJson = $fileStats | ForEach-Object {
    [pscustomobject]@{
        name = $_.Name; folder = $_.Folder; sizeKB = $_.SizeKB; total = $_.Total; kept = $_.Kept
    }
}

$appsForJson = $appSummary | ForEach-Object {
    [pscustomobject]@{
        id   = $_.Id
        n    = $_.Name
        v    = $_.Version
        i    = $_.Intent
        st   = $_.State
        sc   = $_.StateCode
        ec   = $_.ErrorCode
        em   = $_.ErrorMeaning
        eh   = $_.ErrorHistory
        sev  = $_.Severity
        ls   = $_.LastSeen.ToString('yyyy-MM-dd HH:mm:ss')
    }
}

$reportMeta = [pscustomobject]@{
    generated   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    host        = $env:COMPUTERNAME
    user        = "$env:USERDOMAIN\$env:USERNAME"
    logPath     = $LogPath
    window      = if ($AllTime) { 'All entries' } else { "Last $Hours hours" }
    cutoff      = if ($AllTime) { 'n/a' } else { $cutoff.ToString('yyyy-MM-dd HH:mm:ss') }
    entryCount  = $counts.Total
    errorCount  = $counts.Error
    warnCount   = $counts.Warning
    infoCount   = $counts.Info
    fileCount   = $files.Count
    appCount    = @($appSummary).Count
    appFailCount = @($appSummary | Where-Object { $_.Severity -eq 'Error' }).Count
}

$entriesJson  = ConvertTo-SafeJson -Data $entriesForJson
$groupsJson   = ConvertTo-SafeJson -Data $groupsForJson
$timelineJson = ConvertTo-SafeJson -Data $timelineForJson
$filesJson    = ConvertTo-SafeJson -Data $fileStatsForJson
$appsJson     = ConvertTo-SafeJson -Data $appsForJson
$metaJson     = ConvertTo-SafeJson -Data $reportMeta
$diagJson     = ConvertTo-SafeJson -Data $diagInfo -Depth 10
$autopilotJson = ConvertTo-SafeJson -Data $autopilot -Depth 8

$totalStr = $counts.Total.ToString('N0')
$errStr   = $counts.Error.ToString('N0')
$warnStr  = $counts.Warning.ToString('N0')
$infoStr  = $counts.Info.ToString('N0')
$grpCount = @($topGroups).Count
$appCount = @($appSummary).Count
$appFailCount = @($appSummary | Where-Object { $_.Severity -eq 'Error' }).Count

$html = @"
<!DOCTYPE html>
<html lang="en-GB">
<head>
<meta charset="utf-8" />
<title>Intune Log Report - $($reportMeta.host) - $($reportMeta.generated)</title>
<style>
:root {
  --bg:#0f172a; --panel:#1e293b; --panel2:#0b1224; --text:#e2e8f0; --muted:#94a3b8;
  --accent:#3b82f6; --error:#ef4444; --warn:#f59e0b; --info:#22c55e; --line:#334155;
}
* { box-sizing: border-box; }
html,body { margin:0; padding:0; background:var(--bg); color:var(--text);
  font-family: 'Segoe UI', -apple-system, system-ui, sans-serif; font-size: 14px; }
header { padding: 24px 32px; background: linear-gradient(135deg, #1e3a8a, #1e293b);
  border-bottom: 1px solid var(--line); }
header h1 { margin: 0 0 4px 0; font-size: 22px; font-weight: 600; }
header .sub { color: var(--muted); font-size: 13px; }
main { padding: 24px 32px 80px 32px; max-width: 1600px; margin: 0 auto; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; }
.card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
.card .val { font-size: 26px; font-weight: 600; margin-top: 4px; }
.card.err .val { color: var(--error); }
.card.warn .val { color: var(--warn); }
.card.info .val { color: var(--info); }
.section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; margin-bottom: 20px; }
.section h2 { margin: 0 0 14px 0; font-size: 16px; font-weight: 600; }
.controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; }
.controls input, .controls select { background: var(--panel2); color: var(--text); border: 1px solid var(--line); border-radius: 6px; padding: 7px 10px; font-size: 13px; font-family: inherit; }
.controls input[type=text] { min-width: 280px; flex: 1; }
.tabs { display: flex; gap: 0; }
.tab { padding: 7px 14px; background: var(--panel2); border: 1px solid var(--line); cursor: pointer; user-select: none; font-size: 13px; }
.tab:first-child { border-radius: 6px 0 0 6px; }
.tab:last-child { border-radius: 0 6px 6px 0; }
.tab + .tab { border-left: none; }
.tab.active { background: var(--accent); border-color: var(--accent); color: white; font-weight: 600; }
.tab .pill { display: inline-block; min-width: 22px; padding: 0 6px; margin-left: 6px; border-radius: 10px; background: rgba(255,255,255,0.15); font-size: 11px; text-align: center; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; background: var(--panel); }
tr.row-err td.sev-cell { color: var(--error); font-weight: 600; }
tr.row-warn td.sev-cell { color: var(--warn); font-weight: 600; }
tr.row-info td.sev-cell { color: var(--info); }
tr.entry { cursor: pointer; }
tr.entry:hover { background: rgba(59, 130, 246, 0.08); }
tr.detail { display: none; }
tr.detail.open { display: table-row; }
tr.detail td { background: var(--panel2); padding: 14px 18px; }
.kb { background: rgba(59,130,246,0.08); border-left: 3px solid var(--accent); padding: 10px 14px; margin: 8px 0; border-radius: 4px; }
.kb .kb-title { font-weight: 600; color: var(--accent); margin-bottom: 4px; }
.kb .kb-row { margin: 4px 0; }
.kb .kb-row b { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
pre.msg { white-space: pre-wrap; word-break: break-word; font-family: 'Cascadia Mono', 'Consolas', monospace; font-size: 12px; margin: 0; color: #cbd5e1; }
.group { background: var(--panel2); border: 1px solid var(--line); border-radius: 6px; padding: 12px 16px; margin-bottom: 10px; }
.group .gh { display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; margin-bottom: 4px; }
.group .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge.err { background: rgba(239,68,68,0.2); color: #fca5a5; }
.badge.warn { background: rgba(245,158,11,0.2); color: #fcd34d; }
.badge.info { background: rgba(34,197,94,0.2); color: #86efac; }
.muted { color: var(--muted); font-size: 12px; }
.timeline-wrap { overflow-x: auto; }
.tl { display: flex; align-items: flex-end; gap: 2px; height: 120px; padding: 8px 4px; }
.tl-col { display: flex; flex-direction: column; justify-content: flex-end; min-width: 12px; flex-shrink: 0; cursor: default; }
.tl-col .seg { width: 100%; }
.tl-col .seg.err { background: var(--error); }
.tl-col .seg.warn { background: var(--warn); }
.tl-col .seg.info { background: var(--info); opacity: 0.55; }
.tl-labels { display: flex; gap: 2px; padding: 2px 4px 0 4px; font-size: 9px; color: var(--muted); }
.tl-labels span { min-width: 12px; flex-shrink: 0; text-align: center; transform: rotate(-45deg); transform-origin: top left; height: 30px; }
.foot { text-align: center; color: var(--muted); padding: 24px 0 8px 0; font-size: 12px; }
details { margin: 6px 0; }
summary { cursor: pointer; color: var(--muted); font-size: 12px; }
.legend { display: inline-flex; gap: 12px; font-size: 11px; color: var(--muted); align-items:center; margin-left: 8px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }
.legend i.err { background: var(--error); }
.legend i.warn { background: var(--warn); }
.legend i.info { background: var(--info); }
.app-row { background: var(--panel2); border: 1px solid var(--line); border-radius: 6px; padding: 12px 16px; margin-bottom: 8px; display: grid; grid-template-columns: 220px 110px 1fr 220px; gap: 14px; align-items: start; }
.app-row.err { border-left: 4px solid var(--error); }
.app-row.warn { border-left: 4px solid var(--warn); }
.app-row.info { border-left: 4px solid var(--info); }
.app-row .name { font-weight: 600; font-size: 14px; }
.app-row .id { color: var(--muted); font-family: Consolas, monospace; font-size: 11px; word-break: break-all; }
.app-row .state { font-weight: 600; }
.app-row .err-detail { font-size: 12px; color: #fca5a5; }
.app-row .last-seen { color: var(--muted); font-size: 12px; text-align: right; }
.app-row .extras { font-size: 12px; color: var(--muted); margin-top: 4px; }
</style>
</head>
<body>
<header>
  <h1>Intune Log Report</h1>
  <div class="sub">
    Generated <b>$($reportMeta.generated)</b> &middot;
    Host <b>$($reportMeta.host)</b> &middot;
    User <b>$($reportMeta.user)</b> &middot;
    Window <b>$($reportMeta.window)</b><br/>
    Source: <code>$($reportMeta.logPath)</code>
  </div>
</header>
<main>

  <section class="cards">
    <div class="card"><div class="label">Total entries</div><div class="val">$totalStr</div></div>
    <div class="card err"><div class="label">Errors</div><div class="val">$errStr</div></div>
    <div class="card warn"><div class="label">Warnings</div><div class="val">$warnStr</div></div>
    <div class="card info"><div class="label">Info</div><div class="val">$infoStr</div></div>
    <div class="card err"><div class="label">Apps failing</div><div class="val">$appFailCount</div></div>
    <div class="card"><div class="label">Apps total</div><div class="val">$appCount</div></div>
    <div class="card"><div class="label">Log files</div><div class="val">$($files.Count)</div></div>
    <div class="card"><div class="label">Issue groups</div><div class="val">$grpCount</div></div>
  </section>

  <section class="section" id="diagSection">
    <h2>MDM diagnostics <span class="muted" id="diagSubtitle" style="font-weight:normal;"></span></h2>
    <div id="diag"></div>
  </section>

  <section class="section" id="autopilotSection">
    <h2>Autopilot &amp; Enrollment health <span class="muted" id="autopilotSubtitle" style="font-weight:normal;"></span></h2>
    <div id="autopilot"></div>
  </section>

  <section class="section">
    <h2>Win32 app outcomes <span class="muted" style="font-weight:normal;">- per-app install state extracted from IME logs</span></h2>
    <div id="apps"></div>
  </section>

  <section class="section">
    <h2>Activity timeline (per hour) <span class="legend"><span><i class="err"></i>Error</span><span><i class="warn"></i>Warning</span><span><i class="info"></i>Info</span></span></h2>
    <div class="timeline-wrap">
      <div class="tl" id="timelineBars"></div>
      <div class="tl-labels" id="timelineLabels"></div>
    </div>
  </section>

  <section class="section">
    <h2>Top issue groups <span class="muted" style="font-weight:normal;">- repeated errors and warnings, normalised</span></h2>
    <div id="groups"></div>
  </section>

  <section class="section">
    <h2>All log entries</h2>
    <div class="controls">
      <div class="tabs" id="sevTabs">
        <div class="tab active" data-sev="all">All <span class="pill" id="cnt-all"></span></div>
        <div class="tab" data-sev="Error">Errors <span class="pill" id="cnt-Error"></span></div>
        <div class="tab" data-sev="Warning">Warnings <span class="pill" id="cnt-Warning"></span></div>
        <div class="tab" data-sev="Info">Info <span class="pill" id="cnt-Info"></span></div>
      </div>
      <select id="componentSel"><option value="">All components</option></select>
      <select id="fileSel"><option value="">All files</option></select>
      <input type="text" id="searchBox" placeholder="Search message text..." />
      <span class="muted" id="rowCount"></span>
    </div>
    <div style="max-height: 70vh; overflow: auto; border: 1px solid var(--line); border-radius: 6px;">
      <table id="entriesTbl">
        <thead><tr>
          <th style="width:160px;">Time</th>
          <th style="width:80px;">Severity</th>
          <th style="width:170px;">Component</th>
          <th>Message</th>
        </tr></thead>
        <tbody id="entriesBody"></tbody>
      </table>
    </div>
  </section>

  <section class="section">
    <h2>Files parsed</h2>
    <table>
      <thead><tr><th>File</th><th>Folder</th><th>Size (KB)</th><th>Entries in file</th><th>Kept (within window)</th></tr></thead>
      <tbody id="filesBody"></tbody>
    </table>
  </section>

  <p class="foot">Generated by Invoke-IntuneLogReport.ps1 &middot; UK English &middot; Self-contained, no external resources.</p>
</main>

<script id="dataMeta" type="application/json">$metaJson</script>
<script id="dataEntries" type="application/json">$entriesJson</script>
<script id="dataGroups" type="application/json">$groupsJson</script>
<script id="dataTimeline" type="application/json">$timelineJson</script>
<script id="dataFiles" type="application/json">$filesJson</script>
<script id="dataApps" type="application/json">$appsJson</script>
<script id="dataDiag" type="application/json">$diagJson</script>
<script id="dataAutopilot" type="application/json">$autopilotJson</script>
<script>
(function(){
  const ENTRIES  = JSON.parse(document.getElementById('dataEntries').textContent || '[]') || [];
  const GROUPS   = JSON.parse(document.getElementById('dataGroups').textContent || '[]') || [];
  const TIMELINE = JSON.parse(document.getElementById('dataTimeline').textContent || '[]') || [];
  const FILES    = JSON.parse(document.getElementById('dataFiles').textContent || '[]') || [];
  const APPS     = JSON.parse(document.getElementById('dataApps').textContent || '[]') || [];
  const DIAG     = JSON.parse(document.getElementById('dataDiag').textContent || '{}') || {};
  const AP       = JSON.parse(document.getElementById('dataAutopilot').textContent || '{}') || {};

  function esc(s) { if (s==null) return ''; return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function cls(sev) { return sev === 'Error' ? 'err' : sev === 'Warning' ? 'warn' : 'info'; }
  function fmtTime(t) { return t.replace('T',' ').slice(0,19); }

  // Autopilot / Enrollment health
  (function buildAutopilot(){
    const root = document.getElementById('autopilot');
    const sub  = document.getElementById('autopilotSubtitle');
    if (!AP || !AP.LatestEspPhase && !AP.EnrollmentId && !AP.FirstSyncCheckedAt) {
      root.innerHTML = '<div class="muted">No Autopilot or enrollment signals found in this window. If you expect ESP / Autopilot evidence, widen the window with -AllTime or -IncludeOld.</div>';
      sub.textContent = '';
      return;
    }
    sub.textContent = AP.LatestEspPhase ? ('- current ESP phase: ' + esc(AP.LatestEspPhase)) : '';
    const fsStatus = (AP.FirstSyncDone === true) ? 'Yes' : ((AP.FirstSyncDone === false) ? 'NO' : 'Unknown');
    const fsCls = (AP.FirstSyncDone === true) ? 'info' : ((AP.FirstSyncDone === false) ? 'warn' : 'info');
    const phaseCls = (AP.LatestEspPhase === 'NotInEsp') ? 'info' : ((AP.LatestEspPhase && AP.LatestEspPhase !== 'NotInEsp') ? 'err' : 'info');

    let html = '';
    if (AP.Warnings && AP.Warnings.length) {
      html += '<div class="kb" style="border-color:var(--warn)">' +
              '<div class="kb-title" style="color:var(--warn);">' + AP.Warnings.length + ' enrollment / Autopilot warning(s)</div>' +
              '<ul style="margin:6px 0 0 18px;padding:0;">' + AP.Warnings.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul>' +
              '</div>';
    }
    html += '<div class="cards" style="margin-top:14px;">' +
      '<div class="card ' + phaseCls + '"><div class="label">Current ESP phase</div><div class="val" style="font-size:18px;">' + esc(AP.LatestEspPhase || 'Unknown') + '</div></div>' +
      '<div class="card ' + fsCls + '"><div class="label">User FirstSync done</div><div class="val" style="font-size:18px;">' + esc(fsStatus) + '</div></div>' +
      '<div class="card"><div class="label">Heartbeat failures</div><div class="val">' + (AP.HeartbeatFailures || 0) + '</div></div>' +
      '<div class="card"><div class="label">ESP timeouts</div><div class="val">' + (AP.EspTimeouts || 0) + '</div></div>' +
    '</div>';

    const dt = (s) => { if (!s) return '-'; const d = new Date(s); return isNaN(d) ? esc(s) : d.toISOString().replace('T',' ').slice(0,19); };
    html += '<table style="margin-top:14px;">';
    if (AP.EnrollmentId)       html += '<tr><td style="width:30%;color:var(--muted);">Enrollment ID</td><td style="font-family:Consolas,monospace;font-size:12px;">' + esc(AP.EnrollmentId) + '</td></tr>';
    if (AP.LatestEspPhaseAt)   html += '<tr><td style="color:var(--muted);">Latest ESP phase observed</td><td>' + dt(AP.LatestEspPhaseAt) + '</td></tr>';
    if (AP.FirstSyncCheckedAt) html += '<tr><td style="color:var(--muted);">FirstSync last checked</td><td>' + dt(AP.FirstSyncCheckedAt) + '</td></tr>';
    if (AP.HeartbeatLastFailAt) html += '<tr><td style="color:var(--muted);">Last heartbeat failure</td><td>' + dt(AP.HeartbeatLastFailAt) + '</td></tr>';
    if (AP.EspTimeoutLastAt)   html += '<tr><td style="color:var(--muted);">Last ESP timeout</td><td>' + dt(AP.EspTimeoutLastAt) + '</td></tr>';
    html += '</table>';

    if (AP.EspPhaseHistory && AP.EspPhaseHistory.length > 1) {
      html += '<h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 8px 0;">ESP phase transitions</h3>';
      html += '<table><thead><tr><th>Timestamp</th><th>Phase</th></tr></thead><tbody>';
      AP.EspPhaseHistory.forEach(t => {
        html += '<tr><td style="font-family:Consolas,monospace;font-size:12px;">' + dt(t.Timestamp) + '</td><td>' + esc(t.Phase) + '</td></tr>';
      });
      html += '</tbody></table>';
    }
    root.innerHTML = html;
  })();

  // MDM diagnostics
  (function buildDiag(){
    const root = document.getElementById('diag');
    const sub  = document.getElementById('diagSubtitle');
    if (!DIAG || !DIAG.Found) {
      root.innerHTML = '<div class="muted">No MDMDiagReport.html found. Generate one via Settings &gt; Accounts &gt; Access work or school &gt; Info &gt; Create report, then re-run this script.</div>';
      sub.textContent = '';
      return;
    }
    sub.textContent = '- generated ' + esc(DIAG.Generated || '');
    const dev = DIAG.Device || {};
    const conn = DIAG.Connection || {};
    const certs = DIAG.Certificates || [];
    const certWarn = DIAG.CertExpiringSoon || [];
    const apps = DIAG.ManagedApps || [];
    const laps = DIAG.LapsSettings || [];
    const warns = DIAG.Warnings || [];

    function kvTable(obj) {
      const rows = Object.keys(obj).map(k => '<tr><td style="width:30%;color:var(--muted);">' + esc(k) + '</td><td>' + esc(obj[k]) + '</td></tr>').join('');
      return '<table>' + rows + '</table>';
    }

    let html = '';
    // Top warning banner
    if (warns.length) {
      html += '<div class="kb" style="border-color:' + (DIAG.SyncFailed ? 'var(--error)' : 'var(--warn)') + '">' +
              '<div class="kb-title" style="color:' + (DIAG.SyncFailed ? 'var(--error)' : 'var(--warn)') + ';">' + warns.length + ' diagnostic warning(s)</div>' +
              '<ul style="margin:6px 0 0 18px;padding:0;">' + warns.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul>' +
              '</div>';
    }

    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px;">';
    html += '<div><h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:0 0 8px 0;">Device</h3>' + kvTable(dev) + '</div>';
    html += '<div><h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:0 0 8px 0;">Connection</h3>' + kvTable(conn) + '</div>';
    html += '</div>';

    // Counters
    html += '<div class="cards" style="margin-top:18px;">' +
      '<div class="card"><div class="label">Config sources</div><div class="val">' + (DIAG.ConfigSourceCount||0) + '</div></div>' +
      '<div class="card"><div class="label">Managed policies</div><div class="val">' + (DIAG.ManagedPolicyCount||0) + '</div></div>' +
      '<div class="card"><div class="label">Managed apps</div><div class="val">' + apps.length + '</div></div>' +
      '<div class="card"><div class="label">Blocked GPOs</div><div class="val">' + (DIAG.BlockedGpoCount||0) + '</div></div>' +
      '<div class="card"><div class="label">Unmanaged policies</div><div class="val">' + (DIAG.UnmanagedPolicyCount||0) + '</div></div>' +
    '</div>';

    // Certificates table
    if (certs.length) {
      html += '<h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 8px 0;">Certificates</h3>';
      html += '<table><thead><tr><th>Issued to</th><th>Issued by</th><th>Expiration</th><th>Purpose</th></tr></thead><tbody>';
      certs.forEach(c => {
        const isExpiring = certWarn.some(w => w.IssuedTo === c.IssuedTo);
        const style = isExpiring ? ' style="background:rgba(245,158,11,0.08);"' : '';
        html += '<tr' + style + '><td>' + esc(c.IssuedTo) + '</td><td>' + esc(c.IssuedBy) + '</td><td>' + esc(c.Expiration) + '</td><td>' + esc(c.Purpose) + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    // Managed apps table
    if (apps.length) {
      html += '<h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 8px 0;">MDM-managed applications</h3>';
      html += '<table><thead><tr><th>Name</th><th>Status</th><th>Last error</th></tr></thead><tbody>';
      apps.forEach(a => {
        const errCls = (a.LastError && a.LastError !== 'None' && a.LastError !== '0' && a.LastError !== '') ? ' style="color:var(--error);"' : '';
        html += '<tr><td>' + esc(a.Name) + '</td><td>' + esc(a.Status) + '</td><td' + errCls + '>' + esc(a.LastError) + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    // LAPS settings (if any present)
    if (laps.length) {
      html += '<h3 style="font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 8px 0;">LAPS settings</h3>';
      html += '<table><thead><tr><th>Setting</th><th>Default</th><th>Current</th><th>Notes</th></tr></thead><tbody>';
      laps.forEach(l => {
        const style = l.IsWarning ? ' style="background:rgba(245,158,11,0.08);"' : '';
        html += '<tr' + style + '><td>' + esc(l.Setting) + '</td><td>' + esc(l.Default) + '</td><td>' + esc(l.Current) + '</td><td>' + esc(l.Notes) + '</td></tr>';
      });
      html += '</tbody></table>';
    }

    // Link to original
    if (DIAG.FilePath) {
      html += '<p class="muted" style="margin-top:14px;">Source: <code>' + esc(DIAG.FilePath) + '</code></p>';
    }
    root.innerHTML = html;
  })();

  // Apps
  (function buildApps(){
    const root = document.getElementById('apps');
    if (!APPS.length) { root.innerHTML = '<div class="muted">No Win32 app activity detected in this window.</div>'; return; }
    APPS.forEach(a => {
      const div = document.createElement('div');
      div.className = 'app-row ' + cls(a.sev);
      const errBlock = a.ec ? ('<div class="err-detail"><b>' + esc(a.ec) + '</b> &mdash; ' + esc(a.em || '') + '</div>') : '';
      const histBlock = a.eh ? ('<div class="extras">Earlier errors: ' + esc(a.eh) + '</div>') : '';
      const verBlock = a.v ? (' <span class="muted">v' + esc(a.v) + '</span>') : '';
      div.innerHTML =
        '<div>' +
          '<div class="name">' + esc(a.n) + verBlock + '</div>' +
          '<div class="id">' + esc(a.id) + '</div>' +
        '</div>' +
        '<div><span class="badge ' + cls(a.sev) + '">' + esc(a.i || '') + '</span></div>' +
        '<div>' +
          '<div class="state">' + esc(a.st) + '</div>' +
          errBlock +
          histBlock +
        '</div>' +
        '<div class="last-seen">last seen<br/>' + esc(a.ls) + '</div>';
      root.appendChild(div);
    });
  })();

  // Timeline
  (function buildTimeline(){
    const bars = document.getElementById('timelineBars');
    const labs = document.getElementById('timelineLabels');
    if (!TIMELINE.length) { bars.innerHTML = '<div class="muted">No data in this window.</div>'; return; }
    const max = Math.max(...TIMELINE.map(b => b.e + b.w + b.i));
    const H = 110;
    TIMELINE.forEach(b => {
      const total = b.e + b.w + b.i;
      const total_h = max > 0 ? (total / max) * H : 0;
      const eh = total > 0 ? (b.e / total) * total_h : 0;
      const wh = total > 0 ? (b.w / total) * total_h : 0;
      const ih = total > 0 ? (b.i / total) * total_h : 0;
      const col = document.createElement('div');
      col.className = 'tl-col';
      col.title = b.b + '\n' + b.e + ' errors, ' + b.w + ' warnings, ' + b.i + ' info';
      col.innerHTML =
        '<div class="seg info" style="height:' + ih + 'px"></div>' +
        '<div class="seg warn" style="height:' + wh + 'px"></div>' +
        '<div class="seg err"  style="height:' + eh + 'px"></div>';
      bars.appendChild(col);
      const lab = document.createElement('span');
      lab.textContent = b.b.slice(5);
      labs.appendChild(lab);
    });
  })();

  // Groups
  (function buildGroups(){
    const root = document.getElementById('groups');
    if (!GROUPS.length) { root.innerHTML = '<div class="muted">No errors or warnings in this window.</div>'; return; }
    GROUPS.slice(0, 80).forEach(g => {
      const div = document.createElement('div');
      div.className = 'group';
      let kbBlock = '';
      if (g.kt) {
        kbBlock =
          '<div class="kb">' +
            '<div class="kb-title">' + esc(g.kt) + '</div>' +
            '<div class="kb-row"><b>What it means: </b>' + esc(g.km || '') + '</div>' +
            '<div class="kb-row"><b>Suggested action: </b>' + esc(g.ka || '') + '</div>' +
          '</div>';
      }
      div.innerHTML =
        '<div class="gh">' +
          '<span class="badge ' + cls(g.s) + '">' + esc(g.s) + '</span>' +
          '<b>' + g.n.toLocaleString() + ' occurrence(s)</b>' +
          '<span class="muted">in ' + esc(g.c) + '</span>' +
          '<span class="muted">first seen ' + esc(g.fs) + ' &middot; last seen ' + esc(g.ls) + '</span>' +
        '</div>' +
        kbBlock +
        '<details><summary>Sample message</summary><pre class="msg">' + esc(g.m) + '</pre></details>';
      root.appendChild(div);
    });
  })();


  // Files
  (function buildFiles(){
    const tb = document.getElementById('filesBody');
    FILES.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td>' + esc(f.name) + '</td><td class="muted">' + esc(f.folder) + '</td><td>' + (f.sizeKB||0).toLocaleString() + '</td><td>' + (f.total||0).toLocaleString() + '</td><td>' + (f.kept||0).toLocaleString() + '</td>';
      tb.appendChild(tr);
    });
  })();

  // Entries
  const components = Array.from(new Set(ENTRIES.map(e => e.c))).filter(Boolean).sort();
  const filesList  = Array.from(new Set(ENTRIES.map(e => e.f))).filter(Boolean).sort();
  const compSel = document.getElementById('componentSel');
  components.forEach(c => { const o = document.createElement('option'); o.value = c; o.textContent = c; compSel.appendChild(o); });
  const fileSel = document.getElementById('fileSel');
  filesList.forEach(f => { const o = document.createElement('option'); o.value = f; o.textContent = f; fileSel.appendChild(o); });

  document.getElementById('cnt-all').textContent     = ENTRIES.length.toLocaleString();
  document.getElementById('cnt-Error').textContent   = ENTRIES.filter(e => e.s === 'Error').length.toLocaleString();
  document.getElementById('cnt-Warning').textContent = ENTRIES.filter(e => e.s === 'Warning').length.toLocaleString();
  document.getElementById('cnt-Info').textContent    = ENTRIES.filter(e => e.s === 'Info').length.toLocaleString();

  let activeSev = 'all';
  document.querySelectorAll('#sevTabs .tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('#sevTabs .tab').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      activeSev = t.dataset.sev;
      render();
    });
  });
  document.getElementById('searchBox').addEventListener('input', render);
  document.getElementById('componentSel').addEventListener('change', render);
  document.getElementById('fileSel').addEventListener('change', render);

  const tbody = document.getElementById('entriesBody');
  const rowCount = document.getElementById('rowCount');

  function buildRow(e) {
    const tr = document.createElement('tr');
    tr.className = 'entry row-' + cls(e.s);
    const shortMsg = (e.m||'').length > 220 ? e.m.slice(0,220) + '...' : (e.m||'');
    tr.innerHTML =
      '<td class="muted" style="white-space:nowrap;font-family:Consolas,monospace;font-size:12px;">' + fmtTime(e.t) + '</td>' +
      '<td class="sev-cell">' + esc(e.s) + '</td>' +
      '<td class="muted">' + esc(e.c || '') + '</td>' +
      '<td>' + esc(shortMsg) + '</td>';
    const dr = document.createElement('tr');
    dr.className = 'detail';
    let kbBlock = '';
    if (e.kt) {
      kbBlock =
        '<div class="kb">' +
          '<div class="kb-title">' + esc(e.kt) + '</div>' +
          '<div class="kb-row"><b>What it means: </b>' + esc(e.km || '') + '</div>' +
          '<div class="kb-row"><b>Suggested action: </b>' + esc(e.ka || '') + '</div>' +
        '</div>';
    }
    dr.innerHTML =
      '<td colspan="4">' +
        '<div class="muted" style="margin-bottom:6px;">File: <b>' + esc(e.f) + '</b> &middot; Thread: <b>' + esc(e.th) + '</b> &middot; ' + esc(e.t) + '</div>' +
        kbBlock +
        '<pre class="msg">' + esc(e.m||'') + '</pre>' +
      '</td>';
    tr.addEventListener('click', () => dr.classList.toggle('open'));
    return [tr, dr];
  }

  function render() {
    const q = document.getElementById('searchBox').value.toLowerCase();
    const comp = compSel.value;
    const fil = fileSel.value;
    tbody.innerHTML = '';
    let count = 0;
    const MAX = 1500;
    let truncated = false;
    for (const e of ENTRIES) {
      if (activeSev !== 'all' && e.s !== activeSev) continue;
      if (comp && e.c !== comp) continue;
      if (fil && e.f !== fil) continue;
      if (q && (e.m||'').toLowerCase().indexOf(q) === -1) continue;
      if (count >= MAX) { truncated = true; break; }
      const [r1, r2] = buildRow(e);
      tbody.appendChild(r1); tbody.appendChild(r2);
      count++;
    }
    rowCount.textContent = count.toLocaleString() + ' shown' + (truncated ? ' (capped at ' + MAX + ' - narrow filters to see more)' : '');
    if (count === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="4" class="muted" style="text-align:center;padding:24px;">No matching entries.</td>';
      tbody.appendChild(tr);
    }
  }

  render();
})();
</script>
</body>
</html>
"@

[System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))

$elapsed = (Get-Date) - $script:ScriptStart
Write-Host ""
Write-Host ("Report written: {0}" -f $OutputPath) -ForegroundColor Green
Write-Host ("Elapsed       : {0:N1} sec" -f $elapsed.TotalSeconds)
Write-Host ("Errors        : {0:N0}" -f $counts.Error)
Write-Host ("Warnings      : {0:N0}" -f $counts.Warning)
Write-Host ("Info          : {0:N0}" -f $counts.Info)
Write-Host ("Apps tracked  : {0:N0} ({1:N0} failing)" -f @($appSummary).Count, @($appSummary | Where-Object Severity -eq 'Error').Count)
if ($diagInfo.Found) {
    $syncStr = if ($diagInfo.SyncFailed) { 'SYNC FAILED' } else { 'sync OK' }
    Write-Host ("MDM diag      : {0}, {1} cert(s), {2} warning(s)" -f $syncStr, $diagInfo.Certificates.Count, $diagInfo.Warnings.Count)
}

if (-not $DoNotOpen) {
    try {
        Start-Process $OutputPath
    } catch {
        Write-Warning ("Could not auto-open the report: {0}" -f $_.Exception.Message)
    }
}

#endregion

