<#
.SYNOPSIS
Exports security group memberships with nested group resolution analysis.

.DESCRIPTION
Comprehensive analysis of all security group memberships in Active Directory.
- Exports all security group memberships to structured report
- Resolves and identifies nested group memberships
- Flags empty groups for cleanup
- Flags users with excessive group memberships
- Generates HTML report with sortable tables and summary statistics

.PARAMETER IncludeDistribution
Include distribution groups in report (optional, default: security groups only).

.PARAMETER NestedGroupDepth
Maximum depth for nested group resolution (optional, default: 5).

.PARAMETER ExcessiveMembershipThreshold
Flag users in more than N groups (optional, default: 15).

.PARAMETER ReportPath
Path for output HTML report (optional). Defaults to ./reports/

.PARAMETER Export
Export findings to CSV in addition to HTML (optional).

.EXAMPLE
Get-GroupMembership

.EXAMPLE
Get-GroupMembership -IncludeDistribution -NestedGroupDepth 10 -ExcessiveMembershipThreshold 20

.EXAMPLE
Get-GroupMembership -ReportPath "\\fileserver\reports" -Export

.NOTES
Author: Portfolio Project
Requires: ActiveDirectory module, read permissions on all groups and users
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDistribution,

    [Parameter(Mandatory = $false)]
    [int]$NestedGroupDepth = 5,

    [Parameter(Mandatory = $false)]
    [int]$ExcessiveMembershipThreshold = 15,

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
        TotalGroups          = 0
        EmptyGroups          = @()
        NestedGroupChains    = @()
        ExcessiveMemberUsers = @()
        AllGroupMembers      = @()
        WarningMessages      = @()
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Connect to AD
    Connect-ADEnvironment -Environment OnPremisesAD -SkipConnectivityTest

    Write-Verbose "Starting group membership analysis"
}

process {
    try {
        # Get all security groups
        $filter = if ($IncludeDistribution) { "*" } else { "GroupCategory -eq 'Security'" }
        $groups = Get-ADGroup -Filter $filter -Properties Members, MemberOf, Info -ErrorAction Stop

        $script:results.TotalGroups = $groups.Count
        Write-Output "Analyzing $($groups.Count) groups..."

        # Helper function for recursive member resolution
        function Get-RecursiveGroupMembers {
            param($GroupDN, $Depth = 0, $VisitedGroups = @())

            if ($Depth -ge $NestedGroupDepth -or $GroupDN -in $VisitedGroups) {
                return @()
            }

            $VisitedGroups += $GroupDN
            $allMembers = @()

            try {
                $groupMembers = Get-ADGroupMember -Identity $GroupDN -ErrorAction Stop

                foreach ($member in $groupMembers) {
                    if ($member.objectClass -eq 'group') {
                        # Nested group - recurse
                        $allMembers += Get-RecursiveGroupMembers -GroupDN $member.DistinguishedName -Depth ($Depth + 1) -VisitedGroups $VisitedGroups
                    } else {
                        # User member
                        $allMembers += $member
                    }
                }
            }
            catch {
                Write-Warning "Error processing group $GroupDN : $_"
            }

            return $allMembers
        }

        # Process each group
        $userGroupCounts = @{}

        foreach ($group in $groups) {
            $groupDN = $group.DistinguishedName
            $groupName = $group.Name
            
            # Get all members (including nested)
            $members = Get-RecursiveGroupMembers -GroupDN $groupDN
            
            Write-Verbose "Processing group: $groupName ($($members.Count) total members)"

            # Flag empty groups
            if ($members.Count -eq 0) {
                $script:results.EmptyGroups += @{
                    Name                = $groupName
                    DistinguishedName   = $groupDN
                    Description         = $group.Info
                    DirectMemberCount   = ($group.Members | Measure-Object).Count
                }
                Write-Verbose "Empty group found: $groupName"
            }

            # Track user group memberships
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    $userName = $member.SamAccountName
                    if (-not $userGroupCounts.ContainsKey($userName)) {
                        $userGroupCounts[$userName] = @{
                            Count       = 0
                            Groups      = @()
                            DisplayName = $member.DisplayName
                            DN          = $member.DistinguishedName
                        }
                    }
                    $userGroupCounts[$userName].Count++
                    $userGroupCounts[$userName].Groups += $groupName
                }
            }

            # Track nested groups
            $nestedGroups = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'group' }
            if ($nestedGroups) {
                $script:results.NestedGroupChains += @{
                    ParentGroup    = $groupName
                    NestedCount    = $nestedGroups.Count
                    NestedGroups   = $nestedGroups.Name
                    TotalMembers   = $members.Count
                }
            }

            # Store group member info
            $script:results.AllGroupMembers += @{
                GroupName       = $groupName
                GroupDN         = $groupDN
                DirectMembers   = ($group.Members | Measure-Object).Count
                TotalMembers    = $members.Count
                HasNestedGroups = ($nestedGroups | Measure-Object).Count -gt 0
                MemberList     = ($members | Select-Object -ExpandProperty SamAccountName | Sort-Object) -join ", "
            }
        }

        # Flag users with excessive memberships
        foreach ($user in $userGroupCounts.GetEnumerator()) {
            if ($user.Value.Count -gt $ExcessiveMembershipThreshold) {
                $script:results.ExcessiveMemberUsers += @{
                    Username      = $user.Key
                    DisplayName   = $user.Value.DisplayName
                    GroupCount    = $user.Value.Count
                    Groups        = $user.Value.Groups | Sort-Object
                    DistinguishedName = $user.Value.DN
                }
                Write-Verbose "Excessive membership alert: $($user.Key) is in $($user.Value.Count) groups"
            }
        }

        Write-AuditLog -Action "GroupMembershipAnalysis" -Result "Success" `
            -Message "Completed group membership analysis" `
            -Details @{
                TotalGroups = $script:results.TotalGroups
                EmptyGroups = $script:results.EmptyGroups.Count
                ExcessiveUsers = $script:results.ExcessiveMemberUsers.Count
            }
    }
    catch {
        $script:results.WarningMessages += "Error during group analysis: $_"
        Write-AuditLog -Action "GroupAnalysisError" -Result "Error" -Message "Error analyzing group memberships"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $htmlReport = @"
<h3>Security Group Membership Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Total Groups Analyzed:</strong> $($script:results.TotalGroups)</p>

<h4>Summary Findings</h4>
<table>
<tr><td>Empty Groups (Cleanup Candidates)</td><td class='status-warn'>$($script:results.EmptyGroups.Count)</td></tr>
<tr><td>Groups with Nested Members</td><td class='status-pass'>$($script:results.NestedGroupChains.Count)</td></tr>
<tr><td>Users with Excessive Memberships (&gt;$ExcessiveMembershipThreshold groups)</td><td class='status-fail'>$($script:results.ExcessiveMemberUsers.Count)</td></tr>
</table>

$(if ($script:results.EmptyGroups.Count -gt 0) {
    @"
<h4 style="color: #ff9800;">Empty Groups - Cleanup Candidates</h4>
<p>These groups have no members and are candidates for removal if not required for delegation.</p>
<table>
<tr>
    <th>Group Name</th>
    <th>Description</th>
    <th>Direct Members</th>
</tr>
$($script:results.EmptyGroups | ForEach-Object {
    "<tr><td>$($_.Name)</td><td>$($_.Description)</td><td>$($_.DirectMemberCount)</td></tr>"
})
</table>
"@
})

$(if ($script:results.ExcessiveMemberUsers.Count -gt 0) {
    @"
<h4 style="color: #da3b01;">Users with Excessive Group Memberships</h4>
<p>These users are members of more than $ExcessiveMembershipThreshold groups. Consider access review.</p>
<table>
<tr>
    <th>Username</th>
    <th>Display Name</th>
    <th>Group Count</th>
</tr>
$($script:results.ExcessiveMemberUsers | ForEach-Object {
    "<tr><td>$($_.Username)</td><td>$($_.DisplayName)</td><td><span class='status-fail'>$($_.GroupCount)</span></td></tr>"
})
</table>
"@
})

<h4>Nested Group Analysis</h4>
<p>Groups containing other groups may indicate complex delegation structures.</p>
<table>
<tr>
    <th>Parent Group</th>
    <th>Nested Groups</th>
    <th>Total Members</th>
</tr>
$($script:results.NestedGroupChains | ForEach-Object {
    "<tr><td>$($_.ParentGroup)</td><td>$($_.NestedCount)</td><td>$($_.TotalMembers)</td></tr>"
})
</table>
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "GroupMembership_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Export to CSV if requested
        if ($Export) {
            $csvFile = Join-Path $ReportPath "GroupMembership_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $script:results.AllGroupMembers | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Output "CSV export saved to: $csvFile"
        }

        Write-Verbose "Report generation completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
