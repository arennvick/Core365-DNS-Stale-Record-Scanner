<#
.SYNOPSIS
    Core365 DNS Stale Record Scanner - Scan and remove stale DNS records for decommissioned Domain Controllers.

.DESCRIPTION
    Scans all Forward and Reverse Lookup Zones in Active Directory DNS for stale records (NS, A, AAAA, SRV, CNAME, PTR)
    belonging to a decommissioned Domain Controller. Generates a modern, interactive HTML dashboard report and optionally
    removes the stale records.

.PARAMETER OldNameServerFQDN
    The FQDN of the decommissioned DC (e.g., "oldAD01.core365.local").

.PARAMETER OldIPAddress
    (Optional) The IPv4 address of the decommissioned DC for matching A records.

.PARAMETER DnsServerName
    (Optional) The DNS server to query. Defaults to the PDC Emulator.

.PARAMETER ReportPath
    (Optional) Folder path for the HTML report. Defaults to the script directory.

.PARAMETER RemoveRecords
    Switch to actually remove the stale records. Without this, the script only scans.

.PARAMETER WhatIf
    Switch to preview what would be removed without making any changes.

.EXAMPLE
    # Scan only (safe) - generates report
    .\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local"

.EXAMPLE
    # WhatIf preview (no changes)
    .\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local" -OldIPAddress "10.10.10.10" -WhatIf

.EXAMPLE
    # Remove stale records
    .\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local" -OldIPAddress "10.10.10.10" -RemoveRecords

.NOTES
    Author  : Antonio Rennvick Annoson
    Brand   : core365.cloud
    Website : https://blog.core365.cloud
    Script  : Core365-DNS-StaleRecord-Scanner
    Version : 1.0
#>

#Requires -Modules DnsServer, ActiveDirectory

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "FQDN of the decommissioned DC")]
    [string]$OldNameServerFQDN,

    [Parameter(Mandatory = $false, HelpMessage = "IPv4 address of the decommissioned DC")]
    [string]$OldIPAddress,

    [Parameter(Mandatory = $false, HelpMessage = "DNS server to query (defaults to PDC Emulator)")]
    [string]$DnsServerName,

    [Parameter(Mandatory = $false, HelpMessage = "Folder path for the HTML report")]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [switch]$RemoveRecords,

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# =============================================================================
# INITIALISATION
# =============================================================================

$ToolName      = "Core365 DNS Stale Record Scanner"
$RepoName      = "Core365-DNS-StaleRecord-Scanner"
$ScriptVersion = "1.0"
$StartTime     = Get-Date

# Ensure trailing dot on the FQDN (DNS stores NS records with trailing dot)
$FQDNWithDot  = if ($OldNameServerFQDN.EndsWith('.')) { $OldNameServerFQDN } else { "$OldNameServerFQDN." }
$FQDNNoDot    = $OldNameServerFQDN.TrimEnd('.')
$HostnameOnly = ($FQDNNoDot -split '\.')[0]

# Determine mode
if ($RemoveRecords -and -not $WhatIf) {
    $Mode = "REMOVE"
    $ModeLabel = "Remove Mode"
    $ModeColor  = "Red"
} elseif ($WhatIf) {
    $Mode = "WHATIF"
    $ModeLabel = "WhatIf Mode (Preview Only)"
    $ModeColor  = "Yellow"
} else {
    $Mode = "SCAN"
    $ModeLabel = "Scan Only Mode (Report)"
    $ModeColor  = "Cyan"
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  $ToolName v$ScriptVersion" -ForegroundColor Cyan
Write-Host "  Author: Antonio Rennvick Annoson | core365.cloud" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Target Server FQDN : $FQDNNoDot" -ForegroundColor White
if ($OldIPAddress) { Write-Host "  Target IP Address  : $OldIPAddress" -ForegroundColor White }
Write-Host "  Mode               : $ModeLabel" -ForegroundColor $ModeColor
Write-Host ""

# -- Discover PDC Emulator if no DNS server specified --
if (-not $DnsServerName) {
    try {
        $DnsServerName = (Get-ADDomainController -Discover -Service PrimaryDC).HostName[0]
        Write-Host "  [INFO] Using PDC Emulator: $DnsServerName" -ForegroundColor Cyan
    } catch {
        Write-Host "  [ERROR] Failed to discover PDC Emulator: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [INFO] Using specified DNS server: $DnsServerName" -ForegroundColor Cyan
}

# -- Set report path --
if (-not $ReportPath) {
    $ReportPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
    if (-not $ReportPath) { $ReportPath = $PWD.Path }
}

if (-not (Test-Path $ReportPath)) {
    New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
}

$Timestamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportFile = Join-Path $ReportPath ("{0}_Report_{1}.html" -f $RepoName, $Timestamp)
$DomainName = (Get-ADDomain).DNSRoot

Write-Host "  [INFO] Domain: $DomainName" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# SCAN ALL ZONES
# =============================================================================

Write-Host "  [SCAN] Retrieving all DNS zones..." -ForegroundColor Yellow

$allZones = Get-DnsServerZone -ComputerName $DnsServerName |
            Where-Object { $_.ZoneType -ne 'Forwarder' -and $_.ZoneName -ne 'TrustAnchors' }

$totalZones    = $allZones.Count
$staleRecords  = [System.Collections.ArrayList]::new()
$affectedZones = [System.Collections.Generic.HashSet[string]]::new()
$errorZones    = [System.Collections.ArrayList]::new()
$zoneCounter   = 0

Write-Host "  [SCAN] Found $totalZones zones. Scanning for stale records...`n" -ForegroundColor Yellow

foreach ($zone in $allZones) {
    $zoneCounter++
    $pct = [math]::Round(($zoneCounter / $totalZones) * 100)
    Write-Progress -Activity "Scanning DNS Zones" -Status "$zoneCounter of $totalZones - $($zone.ZoneName)" -PercentComplete $pct

    # Determine zone direction
    $zoneDirection = if ($zone.ZoneName -match '\.in-addr\.arpa$' -or $zone.ZoneName -match '\.ip6\.arpa$') { "Reverse" } else { "Forward" }

    try {
        $allRecords = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $DnsServerName -ErrorAction Stop

        foreach ($record in $allRecords) {
            $isMatch   = $false
            $matchData = ""

            switch ($record.RecordType) {
                "NS" {
                    if ($record.RecordData.NameServer -eq $FQDNWithDot -or
                        $record.RecordData.NameServer -eq $FQDNNoDot -or
                        $record.RecordData.NameServer -eq "$HostnameOnly.") {
                        $isMatch = $true
                        $matchData = $record.RecordData.NameServer
                    }
                }
                "A" {
                    if ($OldIPAddress -and $record.RecordData.IPv4Address -eq $OldIPAddress) {
                        $isMatch = $true
                        $matchData = $record.RecordData.IPv4Address.ToString()
                    }
                    if ($record.HostName -eq $HostnameOnly -or $record.HostName -eq $FQDNNoDot) {
                        $isMatch = $true
                        $matchData = $record.RecordData.IPv4Address.ToString()
                    }
                }
                "AAAA" {
                    if ($record.HostName -eq $HostnameOnly -or $record.HostName -eq $FQDNNoDot) {
                        $isMatch = $true
                        $matchData = $record.RecordData.IPv6Address.ToString()
                    }
                }
                "SRV" {
                    if ($record.RecordData.DomainName -eq $FQDNWithDot -or $record.RecordData.DomainName -eq $FQDNNoDot) {
                        $isMatch = $true
                        $matchData = $record.RecordData.DomainName
                    }
                }
                "CNAME" {
                    if ($record.RecordData.HostNameAlias -eq $FQDNWithDot -or $record.RecordData.HostNameAlias -eq $FQDNNoDot) {
                        $isMatch = $true
                        $matchData = $record.RecordData.HostNameAlias
                    }
                }
                "PTR" {
                    if ($record.RecordData.PtrDomainName -eq $FQDNWithDot -or $record.RecordData.PtrDomainName -eq $FQDNNoDot) {
                        $isMatch = $true
                        $matchData = $record.RecordData.PtrDomainName
                    }
                }
            }

            if ($isMatch) {
                $status = "Found"

                if ($Mode -eq "REMOVE") {
                    try {
                        Remove-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $DnsServerName -InputObject $record -Force -ErrorAction Stop
                        $status = "Removed"
                        Write-Host "    [REMOVED] $($record.RecordType) | $($zone.ZoneName) | $($record.HostName) | $matchData" -ForegroundColor Green
                    } catch {
                        $status = "Error: $($_.Exception.Message)"
                        Write-Host "    [ERROR]   $($record.RecordType) | $($zone.ZoneName) | $($_.Exception.Message)" -ForegroundColor Red
                    }
                } elseif ($Mode -eq "WHATIF") {
                    $status = "WhatIf - Not Removed"
                    Write-Host "    [WHATIF]  $($record.RecordType) | $($zone.ZoneName) | $($record.HostName) | $matchData" -ForegroundColor DarkYellow
                } else {
                    Write-Host "    [FOUND]   $($record.RecordType) | $($zone.ZoneName) | $($record.HostName) | $matchData" -ForegroundColor Yellow
                }

                [void]$staleRecords.Add([PSCustomObject]@{
                    ZoneName   = $zone.ZoneName
                    ZoneType   = $zoneDirection
                    RecordType = $record.RecordType
                    RecordName = $record.HostName
                    RecordData = $matchData
                    Status     = $status
                })

                [void]$affectedZones.Add($zone.ZoneName)
            }
        }

    } catch {
        [void]$errorZones.Add([PSCustomObject]@{ ZoneName = $zone.ZoneName; Error = $_.Exception.Message })
        Write-Host "    [ERROR] Failed to read zone: $($zone.ZoneName) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Scanning DNS Zones" -Completed

# =============================================================================
# SUMMARY STATS
# =============================================================================

$totalStale    = $staleRecords.Count
$totalAffected = $affectedZones.Count
$cleanZones    = $totalZones - $totalAffected

$nsCount    = ($staleRecords | Where-Object RecordType -eq "NS").Count
$aCount     = ($staleRecords | Where-Object RecordType -eq "A").Count
$aaaaCount  = ($staleRecords | Where-Object RecordType -eq "AAAA").Count
$srvCount   = ($staleRecords | Where-Object RecordType -eq "SRV").Count
$cnameCount = ($staleRecords | Where-Object RecordType -eq "CNAME").Count
$ptrCount   = ($staleRecords | Where-Object RecordType -eq "PTR").Count

$recordTypesFound = @()
if ($nsCount -gt 0)    { $recordTypesFound += "NS ($nsCount)" }
if ($aCount -gt 0)     { $recordTypesFound += "A ($aCount)" }
if ($aaaaCount -gt 0)  { $recordTypesFound += "AAAA ($aaaaCount)" }
if ($srvCount -gt 0)   { $recordTypesFound += "SRV ($srvCount)" }
if ($cnameCount -gt 0) { $recordTypesFound += "CNAME ($cnameCount)" }
if ($ptrCount -gt 0)   { $recordTypesFound += "PTR ($ptrCount)" }
$uniqueRecordTypes = $recordTypesFound.Count

$EndTime      = Get-Date
$Duration     = $EndTime - $StartTime
$DurationStr  = "{0:mm\:ss}" -f $Duration

Write-Host ""
Write-Host "  ==============================================" -ForegroundColor Cyan
Write-Host "  COMPLETE - Summary" -ForegroundColor Cyan
Write-Host "  ==============================================" -ForegroundColor Cyan
Write-Host "  Zones Scanned       : $totalZones"
Write-Host "  Stale Records Found : $totalStale" -ForegroundColor $(if ($totalStale -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Zones Affected      : $totalAffected"
Write-Host "  Clean Zones         : $cleanZones" -ForegroundColor Green
Write-Host "  Record Types        : $($recordTypesFound -join ', ')"
Write-Host "  Duration            : $DurationStr"
Write-Host ""

# =============================================================================
# HTML BUILD
# =============================================================================

$tableRows = ""
foreach ($rec in $staleRecords) {
    $typeBadgeClass = switch ($rec.RecordType) {
        "NS"    { "badge-ns" }
        "A"     { "badge-a" }
        "AAAA"  { "badge-aaaa" }
        "SRV"   { "badge-srv" }
        "CNAME" { "badge-cname" }
        "PTR"   { "badge-ptr" }
        default { "badge-default" }
    }

    $zoneTypeBadge = if ($rec.ZoneType -eq "Reverse") {
        '<span class="zone-badge zone-reverse">Reverse</span>'
    } else {
        '<span class="zone-badge zone-forward">Forward</span>'
    }

    $statusClass = switch -Wildcard ($rec.Status) {
        "Found"    { "status-found" }
        "Removed"  { "status-removed" }
        "WhatIf*"  { "status-whatif" }
        "Error*"   { "status-error" }
        default    { "" }
    }

    $tableRows += @"
                <tr>
                    <td>$($rec.ZoneName)</td>
                    <td>$zoneTypeBadge</td>
                    <td><span class="badge $typeBadgeClass">$($rec.RecordType)</span></td>
                    <td><code>$($rec.RecordName)</code></td>
                    <td><code>$($rec.RecordData)</code></td>
                    <td><span class="status-badge $statusClass">$($rec.Status)</span></td>
                </tr>
"@
}

if ($staleRecords.Count -eq 0) {
    $tableRows = @"
                <tr>
                    <td colspan="6" style="text-align:center; padding:40px; color:#6c757d; font-style:italic;">
                        No stale records found - all zones are clean!
                    </td>
                </tr>
"@
}

$errorTableRows = ""
if ($errorZones.Count -gt 0) {
    foreach ($ez in $errorZones) {
        $errorTableRows += @"
                <tr>
                    <td>$($ez.ZoneName)</td>
                    <td>$($ez.Error)</td>
                </tr>
"@
    }
    $errorSection = @"
        <div class="section-header" style="margin-top:30px;">
            <h2>Zone Errors ($($errorZones.Count))</h2>
        </div>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Zone Name</th>
                        <th>Error Message</th>
                    </tr>
                </thead>
                <tbody>
                    $errorTableRows
                </tbody>
            </table>
        </div>
"@
} else {
    $errorSection = ""
}

$breakdownBadges = ""
$typeMap = @(
    @{ Type = "NS";    Count = $nsCount;    Class = "badge-ns" }
    @{ Type = "A";     Count = $aCount;     Class = "badge-a" }
    @{ Type = "AAAA";  Count = $aaaaCount;  Class = "badge-aaaa" }
    @{ Type = "SRV";   Count = $srvCount;   Class = "badge-srv" }
    @{ Type = "CNAME"; Count = $cnameCount; Class = "badge-cname" }
    @{ Type = "PTR";   Count = $ptrCount;   Class = "badge-ptr" }
)

foreach ($t in $typeMap) {
    if ($t.Count -gt 0) {
        $breakdownBadges += @"
            <div class="breakdown-item">
                <span class="breakdown-icon badge $($t.Class)">$($t.Type)</span>
                <span class="breakdown-count">$($t.Count)</span>
            </div>
"@
    }
}

if (-not $breakdownBadges) {
    $breakdownBadges = '<div class="breakdown-item" style="color:#6c757d;">No stale records found.</div>'
}

$modeBannerClass = switch ($Mode) {
    'REMOVE' { 'mode-remove' }
    'WHATIF' { 'mode-whatif' }
    default  { 'mode-scan' }
}

$modeBannerText = switch ($Mode) {
    'REMOVE' { 'WARNING: REMOVE MODE -- Stale records were deleted from DNS' }
    'WHATIF' { 'WHATIF MODE -- Preview only, no records were removed' }
    default  { 'SCAN MODE -- Report only, no changes were made' }
}

$reportTimestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$csvTimestamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$ipSuffix        = if ($OldIPAddress) { " ($OldIPAddress)" } else { "" }
$targetDisplay   = "$FQDNNoDot$ipSuffix"

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$ToolName - Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; background: #f0f2f5; color: #2d3436; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #0f3460 100%); color: white; padding: 30px 40px; position: relative; overflow: hidden; }
        .header::after { content: ''; position: absolute; top: -50%; right: -10%; width: 400px; height: 400px; background: rgba(255,255,255,0.03); border-radius: 50%; }
        .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 4px; }
        .header .version { font-size: 13px; opacity: 0.7; margin-bottom: 14px; }
        .header-info { display: flex; flex-wrap: wrap; gap: 24px; font-size: 13px; opacity: 0.85; }
        .header-info span { display: flex; align-items: center; gap: 6px; }
        .mode-banner { padding: 12px 40px; font-weight: 600; font-size: 14px; text-align: center; }
        .mode-scan { background: #dfe6e9; color: #2d3436; }
        .mode-whatif { background: #ffeaa7; color: #6c5b00; }
        .mode-remove { background: #fab1a0; color: #6b1200; }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px 40px 60px; }
        .cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin-bottom: 28px; }
        .card { background: #ffffff; border-radius: 12px; padding: 22px 24px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); transition: transform 0.2s ease, box-shadow 0.2s ease; border-left: 4px solid #0f3460; }
        .card:hover { transform: translateY(-3px); box-shadow: 0 6px 20px rgba(0,0,0,0.1); }
        .card:nth-child(1) { border-left-color: #74b9ff; }
        .card:nth-child(2) { border-left-color: #e94560; }
        .card:nth-child(3) { border-left-color: #fdcb6e; }
        .card:nth-child(4) { border-left-color: #00b894; }
        .card-icon { font-size: 28px; margin-bottom: 6px; }
        .card-value { font-size: 32px; font-weight: 700; color: #1a1a2e; }
        .card-label { font-size: 13px; color: #636e72; font-weight: 500; }
        .card-sub { font-size: 14px; color: #636e72; font-weight: 400; }
        .section-header { margin-bottom: 14px; }
        .section-header h2 { font-size: 18px; font-weight: 600; color: #1a1a2e; }
        .breakdown-grid { display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 28px; }
        .breakdown-item { background: #ffffff; border-radius: 10px; padding: 14px 22px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); display: flex; align-items: center; gap: 12px; min-width: 140px; }
        .breakdown-count { font-size: 24px; font-weight: 700; color: #1a1a2e; }
        .badge { display: inline-block; padding: 3px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-ns { background: #74b9ff; color: #003580; }
        .badge-a { background: #55efc4; color: #00513a; }
        .badge-aaaa { background: #81ecec; color: #005050; }
        .badge-srv { background: #ffeaa7; color: #6c5b00; }
        .badge-cname { background: #a29bfe; color: #2e1f7a; }
        .badge-ptr { background: #fd79a8; color: #650028; }
        .badge-default { background: #dfe6e9; color: #636e72; }
        .zone-badge { display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; }
        .zone-forward { background: #dfe6e9; color: #2d3436; }
        .zone-reverse { background: #ffeaa7; color: #6c5b00; }
        .status-badge { display: inline-block; padding: 3px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; }
        .status-found { background: #ffeaa7; color: #6c5b00; }
        .status-removed { background: #55efc4; color: #00513a; }
        .status-whatif { background: #74b9ff; color: #003580; }
        .status-error { background: #fab1a0; color: #6b1200; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; }
        .search-wrapper { position: relative; width: 340px; }
        .search-wrapper input { width: 100%; padding: 10px 38px 10px 14px; border: 2px solid #dfe6e9; border-radius: 8px; font-size: 14px; transition: border-color 0.2s; outline: none; }
        .search-wrapper input:focus { border-color: #0f3460; }
        .search-clear { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; font-size: 18px; color: #b2bec3; cursor: pointer; display: none; }
        .search-clear:hover { color: #e94560; }
        .btn { padding: 10px 20px; border: none; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-export { background: #0f3460; color: white; }
        .btn-export:hover { background: #1a1a2e; }
        .table-container { background: #ffffff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.06); overflow: hidden; margin-bottom: 28px; }
        table { width: 100%; border-collapse: collapse; }
        thead { background: #1a1a2e; color: white; }
        th { padding: 14px 16px; text-align: left; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        td { padding: 12px 16px; font-size: 13px; border-bottom: 1px solid #dfe6e9; }
        tbody tr { transition: background 0.15s; }
        tbody tr:hover { background: #f8f9fa; }
        tbody tr:nth-child(even) { background: #fafbfc; }
        tbody tr:nth-child(even):hover { background: #f1f3f5; }
        code { background: #f1f3f5; padding: 2px 6px; border-radius: 4px; font-size: 12px; font-family: 'Cascadia Code', 'Consolas', monospace; }
        .footer { text-align: center; padding: 20px; font-size: 13px; color: #636e72; border-top: 1px solid #dfe6e9; margin-top: 20px; }
        .footer a { color: #0f3460; text-decoration: none; font-weight: 600; }
        .footer a:hover { text-decoration: underline; }
        @media (max-width: 768px) { .header { padding: 20px; } .container { padding: 16px; } .cards-grid { grid-template-columns: 1fr 1fr; } .search-wrapper { width: 100%; } }
    </style>
</head>
<body>

    <div class="header">
        <h1>DNS Stale Record Scanner</h1>
        <div class="version">$RepoName v$ScriptVersion -- Decommissioned DC Cleanup Report</div>
        <div class="header-info">
            <span>Date: $reportTimestamp</span>
            <span>DNS Server: $DnsServerName</span>
            <span>Domain: $DomainName</span>
            <span>Target: $targetDisplay</span>
            <span>Duration: $DurationStr</span>
        </div>
    </div>

    <div class="mode-banner $modeBannerClass">$modeBannerText</div>

    <div class="container">

        <div class="cards-grid">
            <div class="card">
                <div class="card-icon">&#128269;</div>
                <div class="card-value">$totalZones</div>
                <div class="card-label">Zones Scanned</div>
            </div>
            <div class="card">
                <div class="card-icon">&#127760;</div>
                <div class="card-value">$totalStale</div>
                <div class="card-label">Stale Records Found</div>
            </div>
            <div class="card">
                <div class="card-icon">&#128203;</div>
                <div class="card-value">$totalAffected</div>
                <div class="card-label">Zones Affected</div>
                <div class="card-sub">$cleanZones clean</div>
            </div>
            <div class="card">
                <div class="card-icon">&#128229;</div>
                <div class="card-value">$uniqueRecordTypes</div>
                <div class="card-label">Record Types Found</div>
            </div>
        </div>

        <div class="section-header"><h2>Record Type Breakdown</h2></div>
        <div class="breakdown-grid">$breakdownBadges</div>

        <div class="section-header" style="margin-top: 10px;"><h2>Stale Records Detail</h2></div>
        <div class="toolbar">
            <div class="search-wrapper">
                <input type="text" id="searchInput" placeholder="Search zones, records, types..." oninput="filterTable(); toggleClear();">
                <button class="search-clear" id="searchClear" onclick="clearSearch();">✕</button>
            </div>
            <button class="btn btn-export" onclick="exportCSV();">📥 Export CSV</button>
        </div>

        <div class="table-container">
            <table id="recordsTable">
                <thead>
                    <tr>
                        <th>Zone Name</th>
                        <th>Zone Type</th>
                        <th>Record Type</th>
                        <th>Record Name</th>
                        <th>Record Data</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    $tableRows
                </tbody>
            </table>
        </div>

        $errorSection

    </div>

    <div class="footer">
        Generated by <strong>$RepoName v$ScriptVersion</strong> | <a href="https://blog.core365.cloud" target="_blank">core365.cloud</a> | $reportTimestamp
    </div>

    <script>
        function filterTable() {
            var input = document.getElementById('searchInput').value.toLowerCase();
            var rows  = document.querySelectorAll('#recordsTable tbody tr');
            for (var i = 0; i < rows.length; i++) {
                var text = rows[i].textContent.toLowerCase();
                rows[i].style.display = text.indexOf(input) > -1 ? '' : 'none';
            }
        }
        function toggleClear() {
            var input = document.getElementById('searchInput');
            var btn   = document.getElementById('searchClear');
            btn.style.display = input.value.length > 0 ? 'block' : 'none';
        }
        function clearSearch() {
            var input = document.getElementById('searchInput');
            input.value = '';
            filterTable();
            toggleClear();
            input.focus();
        }
        function exportCSV() {
            var table = document.getElementById('recordsTable');
            var rows  = table.querySelectorAll('tr');
            var csv = [];
            for (var i = 0; i < rows.length; i++) {
                var cols = rows[i].querySelectorAll('th, td');
                var rowData = [];
                for (var j = 0; j < cols.length; j++) {
                    var text = cols[j].textContent.replace(/"/g, '""').trim();
                    rowData.push('"' + text + '"');
                }
                csv.push(rowData.join(','));
            }
            var csvContent = csv.join('\n');
            var blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
            var link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'Core365_DNS_StaleRecords_' + '$csvTimestamp' + '.csv';
            link.click();
        }
    </script>

</body>
</html>
"@


[System.IO.File]::WriteAllText(
    $ReportFile,
    $htmlContent,
    (New-Object System.Text.UTF8Encoding($true))
)


Write-Host "  [REPORT] HTML report saved to:" -ForegroundColor Green
Write-Host "           $ReportFile" -ForegroundColor White
Write-Host ""

Start-Process $ReportFile

Write-Host "  Done! Report opened in your default browser." -ForegroundColor Green
Write-Host ""
