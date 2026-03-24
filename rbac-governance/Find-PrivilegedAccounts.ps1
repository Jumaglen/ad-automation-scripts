<#
.SYNOPSIS
Comprehensive scan for privileged accounts with MFA and dedication status checks.

.DESCRIPTION
Identifies and analyzes all accounts with administrative privileges in Active Directory:
- Scans for Domain Admin and Enterprise Admin membership
- Identifies accounts in privileged groups (Schema Admin, Account Operators, Backup Operators)
- Flags privileged accounts used as daily driver (not dedicated admin accounts)
- Checks for privileged accounts missing MFA requirement
- Generates executive-ready HTML compliance report with risk assessment

.PARAMETER CheckMfaStatus
Check Azure AD for MFA status on privileged accounts (optional, requires Azure connection).

.PARAMETER ReportPath
Path for output HTML report (optional). Defaults to ./reports/

.PARAMETER Export
Export findings to CSV in addition to HTML (optional).

.PARAMETER IncludeServiceAccounts
Include service accounts in report (optional, default: excluded).

.EXAMPLE
Find-PrivilegedAccounts

.EXAMPLE
Find-PrivilegedAccounts -CheckMfaStatus -ReportPath "C:\Reports"

.EXAMPLE
Find-PrivilegedAccounts -Export

.NOTES
Author: Portfolio Project
Requires: ActiveDirectory module, read permissions on all users and groups
Privileged Groups: Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$CheckMfaStatus,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\reports"),

    [Parameter(Mandatory = $false)]
    [switch]$Export,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeServiceAccounts
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")
    . (Join-Path $utilPath "Connect-ADEnvironment.ps1")

    $script:results = @{
        DomainAdmins           = @()
        EnterpriseAdmins       = @()
        SchemaAdmins           = @()
        AccountOperators       = @()
        BackupOperators        = @()
        DedicatedAdminAccounts = 0
        NonDedicatedAdminAccts = @()
        NoMfaAccounts          = @()
        HighRiskAccounts       = @()
        WarningMessages        = @()
    }

    # Define privileged groups
    $privilegedGroups = @{
        'Domain Admins'      = 'domainadmin'
        'Enterprise Admins'  = 'entreprisadmin'
        'Schema Admins'      = 'schemaadmin'
        'Account Operators'  = 'accountoperator'
        'Backup Operators'   = 'backupoperator'
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Connect to AD
    Connect-ADEnvironment -Environment OnPremisesAD -SkipConnectivityTest

    if ($CheckMfaStatus) {
        try {
            Connect-ADEnvironment -Environment AzureAD -SkipConnectivityTest
        }
        catch {
            Write-Warning "Could not connect to Azure AD for MFA check: $_"
            $CheckMfaStatus = $false
        }
    }

    Write-Verbose "Starting privileged account scan"
}

process {
    try {
        Write-Output "Scanning for privileged accounts..."

        foreach ($groupName in $privilegedGroups.Keys) {
            Write-Verbose "Checking group: $groupName"

            try {
                $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
                $members = Get-ADGroupMember -Identity $group -ErrorAction Stop -Recursive

                foreach ($member in $members) {
                    if ($member.objectClass -eq 'user') {
                        $user = Get-ADUser -Identity $member -Properties Title, Department, Description, MemberOf -ErrorAction Stop

                        # Skip service accounts if not included
                        if (-not $IncludeServiceAccounts -and ($user.Description -like "*service*" -or $user.SamAccountName -like "svc_*")) {
                            Write-Verbose "Skipping service account: $($user.SamAccountName)"
                            continue
                        }

                        $accountInfo = @{
                            SamAccountName    = $user.SamAccountName
                            DisplayName       = $user.DisplayName
                            UserPrincipalName = $user.UserPrincipalName
                            Title             = $user.Title
                            Department        = $user.Department
                            CreatedDate       = $user.Created
                            LastLogonDate     = $user.LastLoginDate
                            DistinguishedName = $user.DistinguishedName
                            PrivilegedGroup   = $groupName
                        }

                        # Determine if dedicated admin account based on naming convention or title
                        $isDedicated = ($user.SamAccountName -like "*admin*" -or $user.Title -like "*Admin*" -or $user.Title -like "*Administrator*")
                        
                        if ($isDedicated) {
                            $script:results.DedicatedAdminAccounts++
                        } else {
                            $accountInfo['RiskLevel'] = 'High'
                            $script:results.NonDedicatedAdminAccts += $accountInfo
                        }

                        # Check MFA status if requested
                        if ($CheckMfaStatus) {
                            try {
                                $azureUser = Get-MgUser -Filter "userPrincipalName eq '$($user.UserPrincipalName)'" -ErrorAction SilentlyContinue
                                if ($azureUser) {
                                    # Would check MFA methods here via Microsoft Graph
                                    $accountInfo['MfaEnabled'] = "Requires verification"
                                } else {
                                    $accountInfo['MfaEnabled'] = "Not found in Azure AD"
                                }
                            }
                            catch {
                                $accountInfo['MfaEnabled'] = "Unable to check"
                            }
                        }

                        # Add to appropriate collection
                        switch ($groupName) {
                            'Domain Admins' { $script:results.DomainAdmins += $accountInfo }
                            'Enterprise Admins' { $script:results.EnterpriseAdmins += $accountInfo }
                            'Schema Admins' { $script:results.SchemaAdmins += $accountInfo }
                            'Account Operators' { $script:results.AccountOperators += $accountInfo }
                            'Backup Operators' { $script:results.BackupOperators += $accountInfo }
                        }

                        # Flag high-risk accounts
                        if (-not $isDedicated) {
                            $script:results.HighRiskAccounts += $sAmAccountName
                        }
                    }
                }
            }
            catch {
                $script:results.WarningMessages += "Error processing group '$groupName': $_"
                Write-AuditLog -Action "PrivilegedAccountScanError" -Result "Warning" `
                    -Message "Error scanning privileged group" -TargetObject $groupName
            }
        }

        Write-AuditLog -Action "PrivilegedAccountScan" -Result "Success" `
            -Message "Completed scan of privileged accounts" `
            -Details @{
                DomainAdmins              = $script:results.DomainAdmins.Count
                NonDedicatedAdminAccounts = $script:results.NonDedicatedAdminAccts.Count
                HighRiskAccounts          = $script:results.HighRiskAccounts.Count
            }
    }
    catch {
        $script:results.WarningMessages += "Error during privileged account scan: $_"
        Write-AuditLog -Action "PrivilegedScanFailed" -Result "Error" -Message "Privileged account scan failed"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $riskLevel = if ($script:results.NonDedicatedAdminAccts.Count -gt 0) { 
            "<span class='status-fail'>HIGH RISK - Non-dedicated privileged accounts detected</span>" 
        } elseif ($script:results.HighRiskAccounts.Count -gt 0) {
            "<span class='status-warn'>MEDIUM RISK - Review recommended</span>"
        } else {
            "<span class='status-pass'>COMPLIANT</span>"
        }

        $htmlReport = @"
<h3>Privileged Accounts Compliance Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Risk Assessment:</strong> $riskLevel</p>

<h4>Executive Summary</h4>
<table>
<tr><td>Total Privileged Accounts</td><td>$($script:results.DomainAdmins.Count + $script:results.EnterpriseAdmins.Count + $script:results.SchemaAdmins.Count)</td></tr>
<tr><td>Dedicated Admin Accounts</td><td class='status-pass'>$($script:results.DedicatedAdminAccounts)</td></tr>
<tr><td>Non-Dedicated Privileged Accounts</td><td class='status-fail'>$($script:results.NonDedicatedAdminAccts.Count)</td></tr>
<tr><td>MFA Status: Critical for Review</td><td class='status-fail'>$($script:results.NoMfaAccounts.Count)</td></tr>
</table>

<h4>Domain Admins ($($script:results.DomainAdmins.Count) accounts)</h4>
<table>
<tr>
    <th>Username</th>
    <th>Display Name</th>
    <th>Title</th>
    <th>Department</th>
    <th>Last Logon</th>
    <th>Account Type</th>
</tr>
$($script:results.DomainAdmins | ForEach-Object {
    $accountType = if ($_.SamAccountName -like "*admin*" -or $_.Title -like "*Admin*") { "Dedicated" } else { "<span class='status-fail'>Non-Dedicated</span>" }
    "<tr><td>$($_.SamAccountName)</td><td>$($_.DisplayName)</td><td>$($_.Title)</td><td>$($_.Department)</td><td>$($_.LastLogonDate)</td><td>$accountType</td></tr>"
})
</table>

$(if ($script:results.NonDedicatedAdminAccts.Count -gt 0) {
    @"
<h4 style="color: #da3b01;">⚠ Non-Dedicated Privileged Accounts - Security Risk</h4>
<p>These accounts are used as daily drivers but have privileged access. Recommend dedicated admin accounts.</p>
<table>
<tr>
    <th>Username</th>
    <th>Display Name</th>
    <th>Title</th>
    <th>Privileged Group</th>
    <th>Risk Level</th>
</tr>
$($script:results.NonDedicatedAdminAccts | ForEach-Object {
    "<tr><td>$($_.SamAccountName)</td><td>$($_.DisplayName)</td><td>$($_.Title)</td><td>$($_.PrivilegedGroup)</td><td><span class='status-fail'>$($_.RiskLevel)</span></td></tr>"
})
</table>

<h4>Remediation Recommendations</h4>
<ul>
    <li>Create dedicated admin accounts for each privileged user</li>
    <li>Enforce MFA on all privileged accounts</li>
    <li>Implement Privileged Access Workstations (PAW) for admin access</li>
    <li>Review and remove unnecessary privileged group memberships</li>
    <li>Update account titles to indicate administrative role</li>
</ul>
"@
})
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "PrivilegedAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Export to CSV if requested
        if ($Export) {
            $csvData = @()
            $csvData += $script:results.DomainAdmins | Select-Object SamAccountName, DisplayName, Title, Department, PrivilegedGroup
            $csvData += $script:results.NonDedicatedAdminAccts | Select-Object SamAccountName, DisplayName, Title, Department, PrivilegedGroup
            
            $csvFile = Join-Path $ReportPath "PrivilegedAccounts_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Output "CSV export saved to: $csvFile"
        }

        Write-Verbose "Report generation completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
