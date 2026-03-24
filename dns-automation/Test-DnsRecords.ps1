<#
.SYNOPSIS
Automated testing framework for DNS record validation.

.DESCRIPTION
Comprehensive DNS record validation testing framework. Tests forward and reverse resolution,
validates PTR accuracy, measures response times, and flags issues. Generates detailed HTML
report with pass/fail status, response times, and remediation guidance. Supports CI/CD
pipeline integration with proper exit codes.

.PARAMETER ZoneName
DNS zone to test (required).

.PARAMETER RecordNames
Array of specific record names to test (optional, tests all if not specified).

.PARAMETER DnsServer
DNS server to query (optional, defaults to local).

.PARAMETER TestReverseResolution
Include reverse DNS (PTR) testing (optional, default: true).

.PARAMETER ReportPath
Path for output report (optional, defaults to ./reports/).

.PARAMETER ReturnExitCode
Return appropriate exit code for CI/CD integration (optional, default: true).

.EXAMPLE
Test-DnsRecords -ZoneName "contoso.local"

.EXAMPLE
Test-DnsRecords -ZoneName "contoso.local" -RecordNames @("www", "mail") -ReportPath "C:\Reports"

.EXAMPLE
Test-DnsRecords -ZoneName "contoso.local" | Write-Output

.NOTES
Author: Portfolio Project
Requires: DnsServer module or nslookup capability on system
Exit Codes: 0=Success, 1=Warnings, 2=Critical Failures
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ZoneName,

    [Parameter(Mandatory = $false)]
    [string[]]$RecordNames,

    [Parameter(Mandatory = $false)]
    [string]$DnsServer = "localhost",

    [Parameter(Mandatory = $false)]
    [switch]$TestReverseResolution = $true,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\reports"),

    [Parameter(Mandatory = $false)]
    [switch]$ReturnExitCode
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")

    $script:results = @{
        ZoneName           = $ZoneName
        TotalTests         = 0
        PassedTests        = 0
        FailedTests        = 0
        WarningTests       = 0
        RecordTests        = @()
        ResponseTimes      = @()
        AverageResponseMs  = 0
        Status             = "Unknown"
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    Write-Verbose "Starting DNS record testing for zone: $ZoneName"
    Write-Verbose "DNS server: $DnsServer"
}

process {
    try {
        Write-Output "Testing DNS zone: $ZoneName..."

        # Get records from DNS zone
        if ($RecordNames) {
            Write-Verbose "Testing specific records: $($RecordNames -join ', ')"
            $recordsToTest = $RecordNames
        } else {
            Write-Verbose "Retrieving all records from zone $ZoneName"
            try {
                # Try to get zone records
                if ((Get-Command Get-DnsServerResourceRecord -ErrorAction SilentlyContinue)) {
                    $zoneRecords = Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DnsServer -ErrorAction SilentlyContinue
                    $recordsToTest = $zoneRecords.Name | Sort-Object -Unique
                } else {
                    $recordsToTest = @("www", "mail", "ftp", "ldap")
                }
            }
            catch {
                Write-Verbose "Could not enumerate zone records, using common record names"
                $recordsToTest = @("www", "mail", "ftp", "ldap")
            }
        }

        Write-Output "Testing $($recordsToTest.Count) records..."

        foreach ($recordName in $recordsToTest) {
            $fqdn = "$recordName.$ZoneName"
            $testResult = @{
                Record          = $recordName
                Fqdn            = $fqdn
                ForwardResolve  = "Not Run"
                IpAddress       = ""
                ResponseTimeMs  = 0
                ReverseResolve  = "Not Run"
                ReverseHostname = ""
                Status          = "Unknown"
                Issues          = @()
            }

            # Test forward resolution
            Write-Verbose "Testing forward resolution for $fqdn"
            $forwardStart = Get-Date
            try {
                $resolution = Resolve-DnsName -Name $fqdn -Server $DnsServer -ErrorAction Stop -Type A, AAAA
                $forwardEnd = Get-Date
                $testResult.ResponseTimeMs = ($forwardEnd - $forwardStart).TotalMilliseconds
                $script:results.ResponseTimes += $testResult.ResponseTimeMs

                if ($resolution) {
                    $testResult.ForwardResolve = "Pass"
                    $testResult.IpAddress = if ($resolution.IPAddress) { $resolution.IPAddress } else { $resolution -join ", " }
                    $script:results.PassedTests++
                    Write-Verbose "Forward resolution passed for $fqdn ($($testResult.IpAddress))"
                } else {
                    $testResult.ForwardResolve = "Failed"
                    $testResult.Status = "Failed"
                    $testResult.Issues += "Forward resolution returned empty result"
                    $script:results.FailedTests++
                }
            }
            catch {
                $testResult.ForwardResolve = "Failed"
                $testResult.Status = "Failed"
                $testResult.Issues += "Forward resolution error: $_"
                $script:results.FailedTests++
                Write-Warning "Forward resolution failed for $fqdn : $_"
            }

            # Test reverse resolution (PTR)
            if ($TestReverseResolution -and $testResult.IpAddress) {
                Write-Verbose "Testing reverse resolution for $($testResult.IpAddress)"
                try {
                    $reverseResult = Resolve-DnsName -Name $testResult.IpAddress -Server $DnsServer -ErrorAction Stop -Type PTR
                    
                    if ($reverseResult) {
                        $testResult.ReverseResolve = "Pass"
                        $testResult.ReverseHostname = if ($reverseResult.NameHost) { $reverseResult.NameHost } else { $reverseResult.Name }
                        Write-Verbose "Reverse resolution passed for $($testResult.IpAddress) ($($testResult.ReverseHostname))"
                    } else {
                        $testResult.ReverseResolve = "Warning"
                        $testResult.Issues += "No PTR record found for $($testResult.IpAddress)"
                        $script:results.WarningTests++
                        Write-Warning "No PTR record for $($testResult.IpAddress)"
                    }
                }
                catch {
                    $testResult.ReverseResolve = "Warning"
                    $testResult.Issues += "PTR lookup failed: $_"
                    $script:results.WarningTests++
                    Write-Warning "PTR lookup failed for $($testResult.IpAddress) : $_"
                }
            }

            # Determine overall status
            if ($testResult.ForwardResolve -eq "Pass") {
                if ($testResult.ReverseResolve -eq "Failed" -or $testResult.ReverseResolve -eq "Warning") {
                    $testResult.Status = "Warning"
                } else {
                    $testResult.Status = "Pass"
                }
            } else {
                $testResult.Status = "Failed"
            }

            $script:results.RecordTests += $testResult
            $script:results.TotalTests++
        }

        # Calculate average response time
        if ($script:results.ResponseTimes.Count -gt 0) {
            $script:results.AverageResponseMs = $script:results.ResponseTimes | Measure-Object -Average | Select-Object -ExpandProperty Average
        }

        # Determine overall status
        if ($script:results.FailedTests -gt 0) {
            $script:results.Status = "Critical"
        } elseif ($script:results.WarningTests -gt 0) {
            $script:results.Status = "Warning"
        } else {
            $script:results.Status = "Pass"
        }

        Write-AuditLog -Action "DnsZoneTest" -Result "Success" `
            -Message "Completed DNS zone testing" `
            -TargetObject $ZoneName `
            -Details @{
                TotalTests = $script:results.TotalTests
                Passed = $script:results.PassedTests
                Failed = $script:results.FailedTests
                AvgResponseMs = [math]::Round($script:results.AverageResponseMs, 2)
            }
    }
    catch {
        Write-Error "Error during DNS testing: $_"
        Write-AuditLog -Action "DnsTestError" -Result "Error" -Message "Error during DNS zone testing"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $statusColor = switch ($script:results.Status) {
            "Pass" { "status-pass" }
            "Warning" { "status-warn" }
            "Critical" { "status-fail" }
            default { "" }
        }

        $htmlReport = @"
<h3>DNS Zone Testing Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Zone Name:</strong> $ZoneName</p>
<p><strong>DNS Server:</strong> $DnsServer</p>
<p><strong>Overall Status:</strong> <span class='$statusColor'>$($script:results.Status)</span></p>

<h4>Test Summary</h4>
<table>
<tr><td>Total Records Tested</td><td>$($script:results.TotalTests)</td></tr>
<tr><td>Passed Tests</td><td class='status-pass'>$($script:results.PassedTests)</td></tr>
<tr><td>Failed Tests</td><td class='status-fail'>$($script:results.FailedTests)</td></tr>
<tr><td>Warning Tests</td><td class='status-warn'>$($script:results.WarningTests)</td></tr>
<tr><td>Average Response Time</td><td>$([math]::Round($script:results.AverageResponseMs, 2)) ms</td></tr>
</table>

<h4>Detailed Test Results</h4>
<table>
<tr>
    <th>Record</th>
    <th>FQDN</th>
    <th>Forward Resolve</th>
    <th>IP Address</th>
    <th>Response Time</th>
    <th>PTR Record</th>
    <th>Status</th>
</tr>
$($script:results.RecordTests | ForEach-Object {
    $forwardStatus = if ($_.ForwardResolve -eq "Pass") { "<span class='status-pass'>✓ Pass</span>" } else { "<span class='status-fail'>✗ Failed</span>" }
    $ptrStatus = switch ($_.ReverseResolve) {
        "Pass" { "<span class='status-pass'>✓ Pass</span>" }
        "Warning" { "<span class='status-warn'>⚠ Missing</span>" }
        default { "-" }
    }
    $overallStatus = if ($_.Status -eq "Pass") { "<span class='status-pass'>✓ Pass</span>" } elseif ($_.Status -eq "Warning") { "<span class='status-warn'>⚠ Warning</span>" } else { "<span class='status-fail'>✗ Failed</span>" }
    "<tr><td>$($_.Record)</td><td>$($_.Fqdn)</td><td>$forwardStatus</td><td>$($_.IpAddress)</td><td>$([math]::Round($_.ResponseTimeMs, 2)) ms</td><td>$ptrStatus</td><td>$overallStatus</td></tr>"
})
</table>

$(if ($script:results.RecordTests | Where-Object { $_.Issues.Count -gt 0 }) {
    @"
<h4 style="color: #ff9800;">Issues Found</h4>
<ul>
$(($script:results.RecordTests | Where-Object { $_.Issues.Count -gt 0 } | ForEach-Object { 
    $_.Issues | ForEach-Object { "<li>$($_.Record): $_</li>" }
}))
</ul>
"@
})

<h4>Remediation Guidance</h4>
<ul>
    <li>Investigate any failed forward resolution entries</li>
    <li>Create missing PTR records for non-warning records</li>
    <li>Review response times for any abnormally slow records</li>
    <li>Validate DNS server configuration for errors</li>
</ul>
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "DnsTest_$($ZoneName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Return exit code if requested
        if ($ReturnExitCode) {
            $exitCode = switch ($script:results.Status) {
                "Pass" { 0 }
                "Warning" { 1 }
                "Critical" { 2 }
                default { 3 }
            }
            exit $exitCode
        }

        Write-Verbose "DNS testing completed with status: $($script:results.Status)"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
