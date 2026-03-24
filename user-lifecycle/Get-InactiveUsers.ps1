<#
.SYNOPSIS
Identifies and reports on inactive Active Directory user accounts.

.DESCRIPTION
Scans Active Directory for user accounts inactive for specified periods (30, 60, 90 days).
Automatically excludes service accounts and administrative accounts. Flags accounts
approaching inactivity thresholds and exports findings to structured HTML report.
Supports -DryRun parameter for safe testing before taking action.

.PARAMETER InactivityDays
Number of days to consider as inactive threshold (default: 30). Multiple values analysed.

.PARAMETER ExcludeServiceAccounts
Exclude accounts marked as service accounts (optional, default: true).

.PARAMETER ExcludeAdminAccounts
Exclude administrative and privileged accounts (optional, default: true).

.PARAMETER ReportPath
Path for output HTML report (optional). Defaults to ./reports/

.PARAMETER DryRun
Test run without actual modifications; analyse only (optional).

.PARAMETER Export
Export findings to CSV in addition to HTML (optional).

.EXAMPLE
Get-InactiveUsers -InactivityDays 30

.EXAMPLE
Get-InactiveUsers -InactivityDays @(30, 60, 90) -DryRun -ReportPath "C:\Reports"

.EXAMPLE
Get-InactiveUsers -InactivityDays 90 -Export -ReportPath "\\fileserver\reports"

.NOTES
Author: Portfolio Project
Requires: ActiveDirectory module, read permissions on all users
LastLogonDate is compared against current date to determine inactivity
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int[]]$InactivityDays = @(30, 60, 90),

    [Parameter(Mandatory = $false)]
    [switch]$ExcludeServiceAccounts = $true,

    [Parameter(Mandatory = $false)]
    [switch]$ExcludeAdminAccounts = $true,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\reports"),

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$Export
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")
    . (Join-Path $utilPath "Connect-ADEnvironment.ps1")

    $script:results = @{
        TotalUsersScanned   = 0
        InactiveByDays      = @{}
        ExcludedServiceAccts = 0
        ExcludedAdminAccts   = 0
        WarningMessages     = @()
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Connect to AD
    Connect-ADEnvironment -Environment OnPremisesAD -SkipConnectivityTest

    # Initialize inactivity counters
    foreach ($days in $InactivityDays) {
        $script:results.InactiveByDays[$days] = @()
    }

    Write-Verbose "Starting inactive user scan"
    Write-Verbose "Thresholds: $($InactivityDays -join ', ') days"
}

process {
    try {
        # Get all enabled users
        Write-Verbose "Retrieving all enabled user accounts from Active Directory"
        $users = Get-ADUser -Filter "Enabled -eq `$true" -Properties LastLogonDate, Description, AdminCount -ErrorAction Stop

        $script:results.TotalUsersScanned = $users.Count
        Write-Output "Scanning $($users.Count) enabled user accounts..."

        # Admin groups for privileged account detection
        $adminGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Account Operators"
        )

        # Process each user
        foreach ($user in $users) {
            # Skip service accounts (identified by description or naming convention)
            if ($ExcludeServiceAccounts -and ($user.Description -like "*service*" -or $user.SamAccountName -like "svc_*")) {
                $script:results.ExcludedServiceAccts++
                Write-Verbose "Skipping service account: $($user.SamAccountName)"
                continue
            }

            # Skip admin accounts
            if ($ExcludeAdminAccounts -and ($user.AdminCount -eq 1 -or (Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }))) {
                $script:results.ExcludedAdminAccts++
                Write-Verbose "Skipping admin account: $($user.SamAccountName)"
                continue
            }

            # Check inactivity for each threshold
            $lastLogon = $user.LastLogonDate
            $inactiveDays = (Get-Date) - $lastLogon

            foreach ($threshold in $InactivityDays) {
                if ($inactiveDays.Days -ge $threshold) {
                    $script:results.InactiveByDays[$threshold] += @{
                        SamAccountName = $user.SamAccountName
                        UserPrincipalName = $user.UserPrincipalName
                        LastLogonDate  = $lastLogon
                        InactiveDays   = $inactiveDays.Days
                        DisplayName    = $user.DisplayName
                        Department     = $user.Department
                        DistinguishedName = $user.DistinguishedName
                    }
                }
            }
        }

        Write-Verbose "Inactive user scan completed"
        Write-AuditLog -Action "InactiveUserScan" -Result "Success" `
            -Message "Completed scan of inactive user accounts" `
            -Details @{
                TotalUsers = $script:results.TotalUsersScanned
                ServiceAcctsExcluded = $script:results.ExcludedServiceAccts
                AdminAcctsExcluded = $script:results.ExcludedAdminAccts
            }
    }
    catch {
        $script:results.WarningMessages += "Error during user scan: $_"
        Write-AuditLog -Action "InactiveUserScanError" -Result "Error" -Message "Error scanning for inactive users"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $htmlReport = @"
<h3>Inactive User Accounts Report</h3>
<p><strong>Scan Date:</strong> $timestamp</p>
<p><strong>Total Users Scanned:</strong> $($script:results.TotalUsersScanned)</p>
<p><strong>Service Accounts Excluded:</strong> $($script:results.ExcludedServiceAccts)</p>
<p><strong>Admin Accounts Excluded:</strong> $($script:results.ExcludedAdminAccts)</p>

<h4>Summary by Inactivity Threshold</h4>
<table>
<tr><th>Days Inactive</th><th>User Count</th><th>Percentage</th></tr>
"@

        foreach ($days in $InactivityDays) {
            $count = $script:results.InactiveByDays[$days].Count
            $percentage = if ($script:results.TotalUsersScanned -gt 0) { [math]::Round(($count / $script:results.TotalUsersScanned) * 100, 2) } else { 0 }
            $htmlReport += "<tr><td>$days+ days</td><td>$count</td><td>$percentage%</td></tr>"
        }

        $htmlReport += "</table>"

        # Detailed tables for each threshold
        foreach ($days in $InactivityDays) {
            $inactiveUsers = $script:results.InactiveByDays[$days]
            if ($inactiveUsers.Count -gt 0) {
                $htmlReport += @"
<h4>Users Inactive for $days+ Days ($($inactiveUsers.Count) users)</h4>
<table>
<tr>
    <th>Username</th>
    <th>Display Name</th>
    <th>Department</th>
    <th>Last Logon</th>
    <th>Inactive Days</th>
    <th>Status</th>
</tr>
"@
                foreach ($user in $inactiveUsers) {
                    $status = if ($user.InactiveDays -ge 90) { "<span class='status-fail'>Critical</span>" } elseif ($user.InactiveDays -ge 60) { "<span class='status-warn'>Warning</span>" } else { "<span class='status-pass'>Monitor</span>" }
                    $htmlReport += @"
<tr>
    <td>$($user.SamAccountName)</td>
    <td>$($user.DisplayName)</td>
    <td>$($user.Department)</td>
    <td>$($user.LastLogonDate)</td>
    <td>$($user.InactiveDays) days</td>
    <td>$status</td>
</tr>
"@
                }
                $htmlReport += "</table>"
            }
        }

        # Export to file
        $reportFile = Join-Path $ReportPath "InactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Export to CSV if requested
        if ($Export) {
            $csvData = @()
            foreach ($days in $InactivityDays) {
                foreach ($user in $script:results.InactiveByDays[$days]) {
                    $csvData += $user | Select-Object @{
                        Name       = "SamAccountName"
                        Expression = { $_.SamAccountName }
                    }, UserPrincipalName, DisplayName, Department, LastLogonDate, InactiveDays, @{
                        Name       = "InactivityThreshold"
                        Expression = { $days }
                    }
                }
            }

            $csvFile = Join-Path $ReportPath "InactiveUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Output "CSV export saved to: $csvFile"
        }

        Write-Verbose "Report generation completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
