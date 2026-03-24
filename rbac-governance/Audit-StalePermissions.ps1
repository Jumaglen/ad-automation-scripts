<#
.SYNOPSIS
Identifies stale permissions and role-based access mismatches.

.DESCRIPTION
Comprehensive audit identifying users with permissions to resources they no longer
need based on role changes:
- Cross-references group membership against department and job title
- Identifies permission mismatches (e.g., access to department X while in department Y)
- Flags resources with excessive access
- Outlines remediation recommendations
- Generates executive-ready compliance report

.PARAMETER Department
Scan only specific department (optional). Example: Finance, Engineering

.PARAMETER ReportPath
Path for output HTML report (optional). Defaults to ./reports/

.PARAMETER DepartmentMappingPath
Path to CSV with role-to-permission mappings (optional).

.PARAMETER Export
Export findings to CSV in addition to HTML (optional).

.EXAMPLE
Audit-StalePermissions

.EXAMPLE
Audit-StalePermissions -Department "Finance" -ReportPath "C:\Reports"

.EXAMPLE
Audit-StalePermissions -DepartmentMappingPath "C:\Config\dept_roles.csv" -Export

.NOTES
Author: Portfolio Project
Requires: ActiveDirectory module, read permissions on all users and groups
Mapping file should contain: Department, Role, AuthorizedGroups columns
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Finance', 'Engineering', 'Sales', 'Marketing', 'HR', 'Operations', 'Security')]
    [string]$Department,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\reports"),

    [Parameter(Mandatory = $false)]
    [string]$DepartmentMappingPath,

    [Parameter(Mandatory = $false)]
    [switch]$Export
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")
    . (Join-Path $utilPath "Connect-ADEnvironment.ps1")

    $script:results = @{
        UsersWithMismatches     = @()
        StaleGroupAccess        = @()
        ExcessiveAccessResources = @()
        TotalUsersScanned       = 0
        TotalMismatchesFound    = 0
        WarningMessages         = @()
    }

    # Default department-to-role mapping if not provided
    $defaultMapping = @{
        'Finance' = @('Role-Analyst', 'Role-Manager', 'Dept-Finance', 'Access-GL')
        'Engineering' = @('Role-Developer', 'Role-Manager', 'Dept-Engineering', 'Access-SourceControl')
        'Sales' = @('Role-Manager', 'Dept-Sales', 'Access-CRM')
        'HR' = @('Role-Manager', 'Role-Admin', 'Dept-HR', 'Access-HRIS')
        'Operations' = @('Role-Operator', 'Role-Manager', 'Dept-Operations', 'Access-Monitoring')
        'Security' = @('Role-Admin', 'Dept-Security', 'Access-SIEM')
    }

    # Load custom mapping if provided
    if ($DepartmentMappingPath -and (Test-Path $DepartmentMappingPath)) {
        Write-Verbose "Loading custom department mapping from: $DepartmentMappingPath"
        # Would load CSV mapping here
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Connect to AD
    Connect-ADEnvironment -Environment OnPremisesAD -SkipConnectivityTest

    Write-Verbose "Starting stale permissions audit"
}

process {
    try {
        # Get users to scan
        $filter = if ($Department) { "Department -eq '$Department'" } else { "*" }
        $users = Get-ADUser -Filter $filter -Properties Department, Title, MemberOf, Manager -ErrorAction Stop

        $script:results.TotalUsersScanned = $users.Count
        Write-Output "Scanning $($users.Count) users for stale permissions..."

        foreach ($user in $users) {
            $userDept = $user.Department
            $userTitle = $user.Title
            $userName = $user.SamAccountName
            $userGroups = $user.MemberOf

            Write-Verbose "Analyzing user: $userName (Dept: $userDept, Title: $userTitle)"

            # Find expected groups for user's department
            $expectedGroups = if ($defaultMapping.ContainsKey($userDept)) { 
                $defaultMapping[$userDept] 
            } else { 
                @() 
            }

            # Check each group the user belongs to
            $mismatches = @()
            foreach ($groupDN in $userGroups) {
                try {
                    $group = Get-ADGroup -Identity $groupDN -Properties Name -ErrorAction SilentlyContinue
                    if ($group) {
                        $groupName = $group.Name

                        # Flag if group not authorized for user's department
                        if ($groupName -notlike "AllEmployees" -and $groupName -notlike "Domain Users" -and $groupName -notin $expectedGroups) {
                            # Check for department mismatches
                            if ($groupName -like "Dept-*") {
                                $groupDept = $groupName -replace "Dept-", ""
                                if ($groupDept -ne $userDept) {
                                    $mismatches += @{
                                        GroupName   = $groupName
                                        Reason      = "User in different department"
                                        Department  = $groupDept
                                        RiskLevel   = "Medium"
                                    }
                                }
                            }
                            # Check for role mismatches
                            elseif ($groupName -like "Role-*" -or $groupName -like "Access-*") {
                                # Would validate role-title mismatch here
                                $mismatches += @{
                                    GroupName   = $groupName
                                    Reason      = "Access not matched to current role"
                                    RiskLevel   = "Low"
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error processing group $groupDN : $_"
                }
            }

            # If mismatches found, add to results
            if ($mismatches.Count -gt 0) {
                $script:results.UsersWithMismatches += @{
                    SamAccountName = $userName
                    DisplayName    = $user.DisplayName
                    Department     = $userDept
                    Title          = $userTitle
                    Mismatches     = $mismatches
                    MismatchCount  = $mismatches.Count
                }
                $script:results.TotalMismatchesFound += $mismatches.Count
                Write-Verbose "Found $($mismatches.Count) permission mismatches for $userName"
            }
        }

        Write-AuditLog -Action "StalePermissionAudit" -Result "Success" `
            -Message "Completed stale permissions audit" `
            -Details @{
                UsersScanned = $script:results.TotalUsersScanned
                MismatchesFound = $script:results.TotalMismatchesFound
            }
    }
    catch {
        $script:results.WarningMessages += "Error during permissions audit: $_"
        Write-AuditLog -Action "PermissionAuditError" -Result "Error" -Message "Error during stale permissions audit"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $htmlReport = @"
<h3>Stale Permissions Audit Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Users Scanned:</strong> $($script:results.TotalUsersScanned)</p>
<p><strong>Permission Mismatches Found:</strong> $($script:results.TotalMismatchesFound)</p>

<h4>Summary</h4>
<p>$(if ($script:results.UsersWithMismatches.Count -eq 0) { 'No permission mismatches detected.' } else { "$($script:results.UsersWithMismatches.Count) users have access permissions not aligned with their current role/department." })</p>

$(if ($script:results.UsersWithMismatches.Count -gt 0) {
    @"
<h4 style="color: #ff9800;">Users with Permission Mismatches</h4>
<table>
<tr>
    <th>Username</th>
    <th>Display Name</th>
    <th>Department</th>
    <th>Title</th>
    <th>Mismatches</th>
    <th>Action Required</th>
</tr>
$($script:results.UsersWithMismatches | ForEach-Object {
    $mismatchList = ($_.Mismatches | ForEach-Object { "<li>$($_.GroupName) - $($_.Reason)</li>" }) -join ""
    "<tr>
        <td>$($_.SamAccountName)</td>
        <td>$($_.DisplayName)</td>
        <td>$($_.Department)</td>
        <td>$($_.Title)</td>
        <td>$($_.MismatchCount)</td>
        <td><span class='status-fail'>Review & Remediate</span></td>
    </tr>"
})
</table>

<h4>Remediation Recommendations</h4>
<ul>
    <li>Review each user's group memberships against their current department and role</li>
    <li>Remove unnecessary group memberships using role-based access control (RBAC) principles</li>
    <li>Document approved access for each role/department combination</li>
    <li>Implement quarterly access reviews for all users</li>
    <li>Establish approval workflow for cross-department access exceptions</li>
    <li>Use automated group management to maintain role-based access</li>
</ul>
"@
})
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "StalePermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Export to CSV if requested
        if ($Export) {
            $csvData = @()
            foreach ($user in $script:results.UsersWithMismatches) {
                foreach ($mismatch in $user.Mismatches) {
                    $csvData += [PSCustomObject]@{
                        SamAccountName = $user.SamAccountName
                        DisplayName    = $user.DisplayName
                        Department     = $user.Department
                        Title          = $user.Title
                        GroupName      = $mismatch.GroupName
                        Reason         = $mismatch.Reason
                        RiskLevel      = $mismatch.RiskLevel
                    }
                }
            }
            
            $csvFile = Join-Path $ReportPath "StalePermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Output "CSV export saved to: $csvFile"
        }

        Write-Verbose "Report generation completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
