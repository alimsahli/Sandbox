<#
.SYNOPSIS
    Analyzes a given executable in a sandboxed environment, capturing screenshots
    and Sysmon events to generate a behavioral report.

.DESCRIPTION
    This script launches a specified executable, monitors it for a set duration,
    and collects detailed telemetry using Sysmon. It captures screenshots at
    intervals to provide visual context.

.PARAMETER ExePath
    The absolute path to the executable file to be analyzed.

.PARAMETER TimeoutSec
    The maximum duration in seconds to monitor the executable. Defaults to 120.

.REQUIREMENTS
    - Sysmon must be installed and running on the system.
    - The script must be run as Administrator to read Sysmon logs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [int]$TimeoutSec = 120
)

#----------------------------
# Helper functions
#----------------------------
function Take-Screenshot($path) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
        $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        if ($graphics) { $graphics.Dispose() }
        if ($bitmap) { $bitmap.Dispose() }
    }
}

function Parse-Sysmon([System.Diagnostics.Eventing.Reader.EventRecord]$e) {
    $xml = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $data[$d.Name] = $d.'#text'
    }
    [PSCustomObject]@{
        EventId           = [int]$xml.Event.System.EventID
        TimeCreated       = $e.TimeCreated
        ProcessGuid       = $data['ProcessGuid']
        ProcessId         = $data['ProcessId']
        ParentProcessGuid = $data['ParentProcessGuid']
        Image             = $data['Image']
        CommandLine       = $data['CommandLine']
        User              = $data['User']
        TargetFilename    = $data['TargetFilename']
        DestinationIp     = $data['DestinationIp']
        DestinationPort   = $data['DestinationPort']
        SourceIp          = $data['SourceIp']
        SourcePort        = $data['SourcePort']
        Protocol          = $data['Protocol']
        QueryName         = $data['QueryName']
        Details           = $data
    }
}

#----------------------------
# 1. Initialization
#----------------------------
Write-Host "[*] Preparing analysis environment..."
$startTime = Get-Date
$outDir = "C:\Detonation\Runs\$($startTime.ToString('yyyyMMdd_HHmmss'))"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

# Optional: Clear old Sysmon events to only capture new ones
try { Clear-EventLog -LogName 'Microsoft-Windows-Sysmon/Operational' } catch {}

#----------------------------
# 2. Launch executable
#----------------------------
Write-Host "[+] Launching '$ExePath'"
$proc = Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
$rootPid = $proc.Id
Start-Sleep -Seconds 1  # small delay to allow Sysmon to start logging

Take-Screenshot -path "$outDir\screenshot_0_launch.png"
Write-Host "[+] Initial screenshot saved."

# Periodic runtime screenshots
for ($i = 1; $i -le 3; $i++) {
    $sleepDuration = Get-Random -Minimum 5 -Maximum ([Math]::Max(10, $TimeoutSec / 2))
    Start-Sleep -Seconds $sleepDuration
    Take-Screenshot -path "$outDir\screenshot_$($i)_runtime.png"
    Write-Host "[+] Runtime screenshot $i saved."
}

# Wait for process to exit or timeout
Write-Host "[*] Monitoring process for $TimeoutSec seconds..."
$exited = $proc.WaitForExit($TimeoutSec * 1000)
if (-not $exited) {
    Write-Host "[!] Timeout reached. Terminating process PID: $rootPid"
    try { Stop-Process -Id $rootPid -Force } catch { Write-Warning "Could not terminate process." }
}

#----------------------------
# 3. Collect Sysmon events
#----------------------------
Write-Host "[*] Collecting Sysmon events since $($startTime.ToString('T'))..."
$filter = @{ LogName='Microsoft-Windows-Sysmon/Operational'; StartTime=$startTime }
$events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
$parsed = $events | ForEach-Object { Parse-Sysmon $_ } | Where-Object { $_.ProcessGuid }
Write-Host "[+] Found $($events.Count) raw events. Parsed $($parsed.Count) valid Sysmon records."

# Build process tree for scoping
$seedGuids = $parsed | Where-Object { $_.ProcessId -eq "$rootPid" } | Select-Object -ExpandProperty ProcessGuid -Unique
$allowList = [System.Collections.Generic.HashSet[string]]::new()
$queue = [System.Collections.Generic.Queue[string]]::new()

foreach ($guid in $seedGuids) {
    $allowList.Add($guid) | Out-Null
    $queue.Enqueue($guid)
}

while ($queue.Count -gt 0) {
    $parentGuid = $queue.Dequeue()
    $children = $parsed | Where-Object { $_.ParentProcessGuid -eq $parentGuid } | Select-Object -ExpandProperty ProcessGuid -Unique
    foreach ($childGuid in $children) {
        if ($allowList.Add($childGuid)) { $queue.Enqueue($childGuid) }
    }
}
$scoped = $parsed | Where-Object { $_.ProcessGuid -and $allowList.Contains($_.ProcessGuid) }
Write-Host "[+] Scoped analysis to $($allowList.Count) processes. Found $($scoped.Count) related events."

#----------------------------
# 4. Generate JSON reports
#----------------------------
$procEvents = $scoped | Where-Object { $_.EventId -eq 1 }
$netEvents  = $scoped | Where-Object { $_.EventId -eq 3 }
$fileEvents = $scoped | Where-Object { $_.EventId -in 2, 11 }
$regEvents  = $scoped | Where-Object { $_.EventId -in 12, 13, 14 }
$dllLoads   = $scoped | Where-Object { $_.EventId -eq 7 }
$dnsEvents  = $scoped | Where-Object { $_.EventId -eq 22 }

$scoped     | ConvertTo-Json -Depth 6 | Out-File "$outDir\all_events.json" -Encoding UTF8
$procEvents | ConvertTo-Json -Depth 6 | Out-File "$outDir\process.json" -Encoding UTF8
$netEvents  | ConvertTo-Json -Depth 6 | Out-File "$outDir\network.json" -Encoding UTF8
$fileEvents | ConvertTo-Json -Depth 6 | Out-File "$outDir\file.json" -Encoding UTF8
$regEvents  | ConvertTo-Json -Depth 6 | Out-File "$outDir\registry.json" -Encoding UTF8
$dllLoads   | ConvertTo-Json -Depth 6 | Out-File "$outDir\dll_loads.json" -Encoding UTF8
$dnsEvents  | ConvertTo-Json -Depth 6 | Out-File "$outDir\dns.json" -Encoding UTF8

Write-Host "[+] Analysis complete. Results saved in '$outDir'"
