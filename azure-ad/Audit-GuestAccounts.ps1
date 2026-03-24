<#
.SYNOPSIS
Audits guest account access, activity, and permissions in Azure AD.

.DESCRIPTION
Comprehensive analysis of all guest/external accounts in Azure AD:
- Identifies all guest and external accounts
- Reports last sign-in date and account age
- Flags guests inactive for 30, 60, 90 days
- Identifies guests with elevated permissions
- Flags guests with application access beyond expected scope
- Generates HTML access review report

.PARAMETER InactivityDays
Flag guests inactive for N days (default: @(30, 60, 90)).

.PARAMETER IncludeLastSignIn
Include detailed last sign-in timestamp for each guest (optional, may require admin consent).

.PARAMETER ReportPath
Path for output HTML report (optional). Defaults to ./reports/

.PARAMETER Export
Export findings to CSV in addition to HTML (optional).

.EXAMPLE
Audit-GuestAccounts

.EXAMPLE
Audit-GuestAccounts -InactivityDays @(30, 60) -ReportPath "C:\Reports"

.EXAMPLE
Audit-GuestAccounts -Export

.NOTES
Author: Portfolio Project
Requires: Microsoft.Graph modules, Azure AD tenant admin, guest account visibility
Uses Microsoft.Graph.Users for guest account queries
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int[]]$InactivityDays = @(30, 60, 90),

    [Parameter(Mandatory = $false)]
    [switch]$IncludeLastSignIn,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\reports"),

    [Parameter(Mandatory = $false)]
    [switch]$Export
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")
    . (Join-Path $utilPath "Connect-ADEnvironment.ps1")

    $script:results = @{
        TotalGuests              = 0
        ActiveGuests             = 0
        InactiveByDays           = @{}
        GuestsWithElevatedAccess = @()
        GuestsWithApplications   = @()
        WarningMessages          = @()
    }

    # Initialize inactivity counters
    foreach ($days in $InactivityDays) {
        $script:results.InactiveByDays[$days] = @()
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Connect to Azure AD
    Connect-ADEnvironment -Environment AzureAD -SkipConnectivityTest

    # Import Microsoft Graph modules
    Import-Module -Name Microsoft.Graph.Users -ErrorAction Stop
    Import-Module -Name Microsoft.Graph.Applications -ErrorAction Stop

    Write-Verbose "Starting Azure AD guest account audit"
}

process {
    try {
        Write-Output "Scanning guest accounts..."

        # Get all guest users (userType = "Guest")
        $guests = Get-MgUser -Filter "userType eq 'Guest'" -Property UserPrincipalName, CreatedDateTime, LastSignInDateTime, DisplayName, Mail -All -ErrorAction Stop

        $script:results.TotalGuests = $guests.Count
        Write-Output "Found $($guests.Count) guest accounts"

        # Privileged Azure AD roles to check
        $privilegedRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "User Administrator",
            "Application Administrator",
            "Exchange Administrator",
            "Security Administrator"
        )

        foreach ($guest in $guests) {
            $guestInfo = @{
                UserPrincipalName = $guest.UserPrincipalName
                DisplayName       = $guest.DisplayName
                Email             = $guest.Mail
                CreatedDateTime   = $guest.CreatedDateTime
                LastSignIn        = if ($IncludeLastSignIn) { $guest.LastSignInDateTime } else { "N/A" }
                AccountAgeInDays  = if ($guest.CreatedDateTime) { ((Get-Date) - [DateTime]$guest.CreatedDateTime).Days } else { -1 }
                Id                = $guest.Id
            }

            # Get guest's directory roles
            try {
                $roles = Get-MgUserMemberOf -UserId $guest.Id -ErrorAction SilentlyContinue | Where-Object { $_.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.directoryRole" }
                $guestInfo.Roles = $roles.DisplayName
            }
            catch {
                $guestInfo.Roles = @()
            }

            # Check for privileged roles
            $hasPrivilegedRole = $false
            foreach ($role in $guestInfo.Roles) {
                if ($role -in $privilegedRoles) {
                    $hasPrivilegedRole = $true
                    break
                }
            }

            if ($hasPrivilegedRole) {
                $script:results.GuestsWithElevatedAccess += $guestInfo
                Write-Verbose "Privileged guest account found: $($guest.UserPrincipalName)"
            }

            # Check inactivity
            if ($guest.LastSignInDateTime) {
                $lastSignIn = [DateTime]$guest.LastSignInDateTime
                $inactiveDays = (Get-Date) - $lastSignIn

                foreach ($threshold in $InactivityDays) {
                    if ($inactiveDays.Days -ge $threshold) {
                        $guestInfo.InactiveDays = $inactiveDays.Days
                        $script:results.InactiveByDays[$threshold] += $guestInfo
                    }
                }

                if ((Get-Date) - $lastSignIn -lt [TimeSpan]::FromDays(1)) {
                    $script:results.ActiveGuests++
                }
            } else {
                # Never signed in
                $guestInfo.InactiveDays = $guestInfo.AccountAgeInDays
                foreach ($threshold in $InactivityDays) {
                    if ($guestInfo.AccountAgeInDays -ge $threshold) {
                        $script:results.InactiveByDays[$threshold] += $guestInfo
                    }
                }
            }

            # Check for application assignments
            try {
                $appAssignments = Get-MgUserAppRoleAssignment -UserId $guest.Id -ErrorAction SilentlyContinue
                if ($appAssignments) {
                    $guestInfo.AssignedApps = $appAssignments.Count
                    $script:results.GuestsWithApplications += $guestInfo
                }
            }
            catch {
                $guestInfo.AssignedApps = 0
            }
        }

        Write-AuditLog -Action "GuestAccountAudit" -Result "Success" `
            -Message "Completed audit of guest accounts" `
            -Details @{
                TotalGuests = $script:results.TotalGuests
                ActiveGuests = $script:results.ActiveGuests
                PrivilegedGuests = $script:results.GuestsWithElevatedAccess.Count
            }
    }
    catch {
        $script:results.WarningMessages += "Error during guest account audit: $_"
        Write-AuditLog -Action "GuestAuditError" -Result "Error" -Message "Error auditing guest accounts"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $htmlReport = @"
<h3>Azure AD Guest Account Access Review Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>

<h4>Executive Summary</h4>
<table>
<tr><td>Total Guest Accounts</td><td>$($script:results.TotalGuests)</td></tr>
<tr><td>Recently Active Guests</td><td class='status-pass'>$($script:results.ActiveGuests)</td></tr>
<tr><td>Guests with Privileged Roles</td><td class='status-fail'>$($script:results.GuestsWithElevatedAccess.Count)</td></tr>
<tr><td>Guests with Application Access</td><td>$($script:results.GuestsWithApplications.Count)</td></tr>
</table>

$(if ($script:results.GuestsWithElevatedAccess.Count -gt 0) {
    @"
<h4 style="color: #da3b01;">⚠ CRITICAL - Guests with Privileged Roles</h4>
<p>Guests should not have administrative privileges. Immediate review required.</p>
<table>
<tr>
    <th>Guest Email</th>
    <th>Display Name</th>
    <th>Roles</th>
    <th>Created Date</th>
    <th>Action</th>
</tr>
$($script:results.GuestsWithElevatedAccess | ForEach-Object {
    "<tr><td>$($_.Email)</td><td>$($_.DisplayName)</td><td>$($_.Roles -join ', ')</td><td>$($_.CreatedDateTime)</td><td><span class='status-fail'>Remove Access</span></td></tr>"
})
</table>
"@
})

<h4>Inactive Guest Accounts by Threshold</h4>
<table>
<tr>
    <th>Days Inactive</th>
    <th>Guest Count</th>
</tr>
$($InactivityDays | ForEach-Object {
    $count = $script:results.InactiveByDays[$_].Count
    $style = if ($_ -ge 90) { "class='status-fail'" } elseif ($_ -ge 60) { "class='status-warn'" } else { "class='status-pass'" }
    "<tr><td>$_+ days</td><td $style>$count</td></tr>"
})
</table>

$(if ($script:results.InactiveByDays[90].Count -gt 0) {
    @"
<h4 style="color: #ff9800;">Guests Inactive 90+ Days (Review for Removal)</h4>
<table>
<tr>
    <th>Email</th>
    <th>Display Name</th>
    <th>Inactive Days</th>
    <th>Last Sign-In</th>
</tr>
$($script:results.InactiveByDays[90] | ForEach-Object {
    "<tr><td>$($_.Email)</td><td>$($_.DisplayName)</td><td>$($_.InactiveDays)</td><td>$($_.LastSignIn)</td></tr>"
})
</table>
"@
})

<h4>Access Review Recommendations</h4>
<ul>
    <li>Remove all guest access to privileged roles</li>
    <li>Review and disable inactive guest accounts 90+ days old</li>
    <li>Implement conditional access policies requiring MFA for guest access</li>
    <li>Set guest access expiration dates during onboarding</li>
    <li>Conduct quarterly guest access reviews</li>
    <li>Use guest access packages for temporary project-based access</li>
    <li>Monitor guest application assignments for excessive access</li>
</ul>
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "GuestAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Export to CSV if requested
        if ($Export) {
            $csvData = @()
            foreach ($days in $InactivityDays) {
                foreach ($guest in $script:results.InactiveByDays[$days]) {
                    $csvData += $guest | Select-Object UserPrincipalName, DisplayName, Email, CreatedDateTime, LastSignIn, InactiveDays, @{
                        Name       = "InactivityThreshold"
                        Expression = { $days }
                    }
                }
            }

            $csvFile = Join-Path $ReportPath "GuestAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Output "CSV export saved to: $csvFile"
        }

        Write-Verbose "Report generation completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
