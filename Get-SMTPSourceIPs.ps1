<#
.SYNOPSIS
  Pull last N days of IIS SMTP W3C logs from a remote server and export SMTP source IP activity.

.DESCRIPTION
  - Prompts for SMTP server FQDN
  - Prompts for credentials
  - Mounts the remote C$ share temporarily
  - Reads SMTP W3C logs
  - Aggregates by IP and date
  - Performs reverse DNS lookup
  - Produces multiple output files useful for SMTP relay lockdown analysis

.PARAMETER DaysBack
  Number of days of SMTP log data to process.
  Default: 30

.PARAMETER OutputFolder
  Folder where output files will be written.
  Default: SMTP_Output under the script folder

.PARAMETER RemoteLogPath
  Path under C$ where SMTP logs are stored.
  Default: inetpub\logs\SMTPSVC1

.EXAMPLE
  .\Get-SMTPSourceIPs.ps1 -DaysBack 60 -OutputFolder C:\Temp\SMTP
#>

[CmdletBinding()]
param(
    [int]$DaysBack = 30,
    [string]$OutputFolder = "$PSScriptRoot\SMTP_Output",
    [string]$RemoteLogPath = "inetpub\logs\SMTPSVC1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Ask user for SMTP server
$ServerFqdn = Read-Host "Enter SMTP server FQDN"

# Ask for credentials
$cred = Get-Credential -Message "Credentials for \\$ServerFqdn\c$"

function Get-W3CFieldMap {
    param([string[]]$Lines)

    $fieldsLine = $Lines | Where-Object { $_ -like "#Fields:*" } | Select-Object -First 1
    if (-not $fieldsLine) { return $null }

    $fields = $fieldsLine.Substring(8).Trim() -split "\s+"
    $map = @{}

    for ($i = 0; $i -lt $fields.Count; $i++) {
        $map[$fields[$i]] = $i
    }

    return $map
}

function Resolve-ReverseDNS {
    param($ip)

    try {
        ([System.Net.Dns]::GetHostEntry($ip)).HostName
    }
    catch {
        ""
    }
}

$driveName = "SMTPLOGS"
$rootPath  = "\\$ServerFqdn\c$"

if (Get-PSDrive $driveName -ErrorAction SilentlyContinue) {
    Remove-PSDrive $driveName -Force
}

New-PSDrive -Name $driveName -PSProvider FileSystem -Root $rootPath -Credential $cred | Out-Null

try {

    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $rawCsv     = Join-Path $OutputFolder "SMTP_Raw_${DaysBack}_Days_$timestamp.csv"
    $groupedCsv = Join-Path $OutputFolder "SMTP_Grouped_${DaysBack}_Days_$timestamp.csv"
    $uniqueTxt  = Join-Path $OutputFolder "SMTP_UniqueIPs_${DaysBack}_Days_$timestamp.txt"
    $topCsv     = Join-Path $OutputFolder "SMTP_TopSenders_${DaysBack}_Days_$timestamp.csv"

    $logDir = "$driveName`:\$RemoteLogPath"

    if (-not (Test-Path $logDir)) {
        throw "SMTP log path not found: $logDir"
    }

    Write-Host "Using SMTP logs at $logDir"

    $cutoff = (Get-Date).AddDays(-$DaysBack)
    $cutoffStr = $cutoff.ToString("yyyy-MM-dd")

    $rows = @()

    Get-ChildItem $logDir -Filter "ex*.log" | ForEach-Object {

        Write-Host "Processing $($_.Name)"

        $header = Get-Content $_.FullName -TotalCount 50
        $map = Get-W3CFieldMap $header

        if (!$map) { return }

        $dateIdx = $map["date"]
        $ipIdx   = $map["c-ip"]

        Get-Content $_.FullName | Where-Object {$_ -notlike "#*"} | ForEach-Object {

            $parts = $_ -split "\s+"

            if ($parts.Count -le $ipIdx) { return }

            $date = $parts[$dateIdx]
            $ip   = $parts[$ipIdx]

            if ($date -lt $cutoffStr) { return }
            if ($ip -eq "-" -or [string]::IsNullOrWhiteSpace($ip)) { return }

            $rows += [PSCustomObject]@{
                Date = $date
                IP   = $ip
            }

        }
    }

    if ($rows.Count -eq 0) {
        Write-Host "No matching records."
        return
    }

    $summary =
        $rows |
        Group-Object Date,IP |
        ForEach-Object {
            $split = $_.Name -split ","
            [PSCustomObject]@{
                Date  = $split[0]
                IP    = $split[1]
                Count = $_.Count
            }
        }

    $summary | Export-Csv $rawCsv -NoTypeInformation

    Write-Host "Resolving DNS names..."

    $dnsMap = @{}
    $uniqueIPs = $summary.IP | Sort -Unique

    foreach ($ip in $uniqueIPs) {
        $dnsMap[$ip] = Resolve-ReverseDNS $ip
    }

    $totals = @{}

    $summary |
        Group-Object IP |
        ForEach-Object {
            $totals[$_.Name] = ($_.Group | Measure Count -Sum).Sum
        }

    $grouped = foreach ($group in ($summary | Group-Object IP | Sort Name)) {

        $first = $true
        $name  = $dnsMap[$group.Name]
        $total = $totals[$group.Name]

        foreach ($row in ($group.Group | Sort Date -Descending)) {

            [PSCustomObject]@{
                IP    = if ($first) {$group.Name} else {""}
                Name  = if ($first) {$name} else {""}
                Date  = $row.Date
                Count = $row.Count
                Total = if ($first) {$total} else {""}
            }

            $first = $false
        }
    }

    $grouped | Export-Csv $groupedCsv -NoTypeInformation

    $uniqueIPs | Out-File $uniqueTxt

    $summary |
        Group-Object IP |
        ForEach-Object {
            [PSCustomObject]@{
                IP         = $_.Name
                Name       = $dnsMap[$_.Name]
                TotalCount = ($_.Group | Measure Count -Sum).Sum
            }
        } |
        Sort @{Expression="TotalCount";Descending=$true} |
        Export-Csv $topCsv -NoTypeInformation

    Write-Host ""
    Write-Host "Done."
    Write-Host "Raw file:      $rawCsv"
    Write-Host "Grouped file:  $groupedCsv"
    Write-Host "Unique IPs:    $uniqueTxt"
    Write-Host "Top senders:   $topCsv"

}
finally {

    Remove-PSDrive $driveName -Force -ErrorAction SilentlyContinue

}
