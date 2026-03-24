<#
.SYNOPSIS
Exports Azure AD Conditional Access policies with compliance analysis.

.DESCRIPTION
Connects to Azure AD via Microsoft Graph API and exports all conditional access policies.
Analyzes policy conditions, controls, and assignment scope. Flags policies in report-only
mode (not enforced) and policies without MFA requirement. Generates HTML compliance summary.

.PARAMETER IncludeReportOnly
Include report-only policies in detailed analysis (optional, default: flag in summary).

.PARAMETER IncludeDisabled
Include disabled policies in report (optional, default: excluded).

.PARAMETER ReportPath
Path for output HTML report (optional). Defaults to ./reports/

.PARAMETER Export
Export findings to JSON in addition to HTML (optional).

.EXAMPLE
Get-ConditionalAccessPolicies

.EXAMPLE
Get-ConditionalAccessPolicies -IncludeReportOnly -ReportPath "C:\Reports"

.EXAMPLE
Get-ConditionalAccessPolicies -Export

.NOTES
Author: Portfolio Project
Requires: Microsoft.Graph modules, Azure AD tenant admin, read permissions on policies
Uses Microsoft.Graph.Identity.SignIns for conditional access policy queries
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$IncludeReportOnly,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,

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
        TotalPolicies       = 0
        ActivePolicies      = 0
        ReportOnlyPolicies  = @()
        DisabledPolicies    = 0
        NoMfaPolicies       = @()
        RiskLevel           = "Unknown"
        Policies            = @()
        WarningMessages     = @()
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Connect to Azure AD
    Connect-ADEnvironment -Environment AzureAD -SkipConnectivityTest

    # Import Microsoft Graph modules
    Import-Module -Name Microsoft.Graph.Identity.SignIns -ErrorAction Stop

    Write-Verbose "Starting Azure AD Conditional Access policy scan"
}

process {
    try {
        Write-Output "Retrieving Azure AD Conditional Access policies..."

        # Get all conditional access policies
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop

        $script:results.TotalPolicies = $policies.Count
        Write-Output "Found $($policies.Count) Conditional Access policies"

        foreach ($policy in $policies) {
            # Filter based on parameters
            if (-not $IncludeDisabled -and $policy.State -eq 'disabled') {
                $script:results.DisabledPolicies++
                continue
            }

            $policyInfo = @{
                DisplayName          = $policy.DisplayName
                State                = $policy.State
                CreatedDateTime      = $policy.CreatedDateTime
                ModifiedDateTime     = $policy.ModifiedDateTime
                Id                   = $policy.Id
                Conditions           = @()
                GrantControls        = @()
                SessionControls      = @()
                Users                = @()
                Applications         = @()
                Locations            = @()
                Platforms            = @()
                DeviceStates         = @()
                SignInRiskLevels     = @()
                MfaRequired          = $false
            }

            # Extract conditions
            if ($policy.Conditions) {
                $cond = $policy.Conditions
                
                # User conditions
                if ($cond.Users) {
                    $policyInfo.Users = @{
                        IncludeUsers = $cond.Users.IncludeUsers
                        ExcludeUsers = $cond.Users.ExcludeUsers
                        IncludeGroups = $cond.Users.IncludeGroups
                        ExcludeGroups = $cond.Users.ExcludeGroups
                    }
                }

                # Application conditions
                if ($cond.Applications) {
                    $policyInfo.Applications = @{
                        IncludeApplications = $cond.Applications.IncludeApplications
                        ExcludeApplications = $cond.Applications.ExcludeApplications
                    }
                }

                # Location conditions
                if ($cond.Locations) {
                    $policyInfo.Locations = @{
                        IncludeLocations = $cond.Locations.IncludeLocations
                        ExcludeLocations = $cond.Locations.ExcludeLocations
                    }
                }

                # Platform conditions
                if ($cond.Platforms) {
                    $policyInfo.Platforms = $cond.Platforms.IncludePlatforms
                }

                # Risk levels
                if ($cond.SignInRiskLevels) {
                    $policyInfo.SignInRiskLevels = $cond.SignInRiskLevels
                }
            }

            # Extract grant controls (MFA check)
            if ($policy.GrantControls) {
                $grant = $policy.GrantControls
                $policyInfo.GrantControls = @{
                    Operator = $grant.Operator
                    BuiltInControls = $grant.BuiltInControls
                }

                # Check if MFA is required
                if ($grant.BuiltInControls -contains "mfa") {
                    $policyInfo.MfaRequired = $true
                }
            }

            # Extract session controls
            if ($policy.SessionControls) {
                $session = $policy.SessionControls
                $policyInfo.SessionControls = @{
                    IsSignInFrequencyEnforced = $session.IsSignInFrequencyEnforced
                    SignInFrequency           = $session.SignInFrequency
                    IsValidationRequired      = $session.ApplicationEnforcedRestrictions.IsApplicationEnforcedRestrictionsRequired
                }
            }

            # Flag report-only policies
            if ($policy.State -eq 'enabledForReportingButNotEnforced') {
                $script:results.ReportOnlyPolicies += $policyInfo
                Write-Verbose "Report-only policy found: $($policy.DisplayName)"
            }
            elseif ($policy.State -eq 'enabled') {
                $script:results.ActivePolicies++
                
                # Flag if no MFA
                if (-not $policyInfo.MfaRequired -and $policy.GrantControls.BuiltInControls -gt 0) {
                    $script:results.NoMfaPolicies += $policyInfo
                    Write-Verbose "Policy without MFA found: $($policy.DisplayName)"
                }
            }

            $script:results.Policies += $policyInfo
        }

        # Determine risk level
        if ($script:results.ReportOnlyPolicies.Count -gt 0 -or $script:results.NoMfaPolicies.Count -gt 0) {
            $script:results.RiskLevel = "High - Review Required"
        } elseif ($script:results.ActivePolicies -lt 5) {
            $script:results.RiskLevel = "Medium - Policies May Be Insufficient"
        } else {
            $script:results.RiskLevel = "Compliant"
        }

        Write-AuditLog -Action "ConditionalAccessPolicyScan" -Result "Success" `
            -Message "Completed Azure AD Conditional Access policy scan" `
            -Details @{
                TotalPolicies = $script:results.TotalPolicies
                ActivePolicies = $script:results.ActivePolicies
                ReportOnlyPolicies = $script:results.ReportOnlyPolicies.Count
                RiskLevel = $script:results.RiskLevel
            }
    }
    catch {
        $script:results.WarningMessages += "Error during policy scan: $_"
        Write-AuditLog -Action "PolicyScanError" -Result "Error" -Message "Error scanning Conditional Access policies"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $riskIndicator = if ($script:results.RiskLevel -like "*High*") {
            "<span class='status-fail'>$($script:results.RiskLevel)</span>"
        } elseif ($script:results.RiskLevel -like "*Medium*") {
            "<span class='status-warn'>$($script:results.RiskLevel)</span>"
        } else {
            "<span class='status-pass'>$($script:results.RiskLevel)</span>"
        }

        $htmlReport = @"
<h3>Azure AD Conditional Access Policies Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Risk Assessment:</strong> $riskIndicator</p>

<h4>Policy Summary</h4>
<table>
<tr><td>Total Policies</td><td>$($script:results.TotalPolicies)</td></tr>
<tr><td>Active Policies</td><td class='status-pass'>$($script:results.ActivePolicies)</td></tr>
<tr><td>Report-Only Policies (Not Enforced)</td><td class='status-warn'>$($script:results.ReportOnlyPolicies.Count)</td></tr>
<tr><td>Disabled Policies</td><td>$($script:results.DisabledPolicies)</td></tr>
<tr><td>Policies Without MFA</td><td class='status-fail'>$($script:results.NoMfaPolicies.Count)</td></tr>
</table>

$(if ($script:results.ReportOnlyPolicies.Count -gt 0) {
    @"
<h4 style="color: #ff9800;">Report-Only Policies (Not Currently Enforced)</h4>
<p>These policies are in report-only mode and will not block users. Consider gradually moving to enforcement.</p>
<ul>
$($script:results.ReportOnlyPolicies | ForEach-Object { "<li><strong>$($_.DisplayName)</strong> - Controls: $($_.GrantControls.BuiltInControls -join ', ')</li>" })
</ul>
"@
})

$(if ($script:results.NoMfaPolicies.Count -gt 0) {
    @"
<h4 style="color: #da3b01;">Policies Without MFA Requirement</h4>
<p>These active policies do not require multi-factor authentication. MFA is critical for security.</p>
<ul>
$($script:results.NoMfaPolicies | ForEach-Object { "<li><strong>$($_.DisplayName)</strong> - State: $($_.State)</li>" })
</ul>
"@
})

<h4>Policy Details</h4>
<table>
<tr>
    <th>Policy Name</th>
    <th>State</th>
    <th>MFA Required</th>
    <th>Grant Controls</th>
    <th>Last Modified</th>
</tr>
$($script:results.Policies | ForEach-Object {
    $mfaStatus = if ($_.MfaRequired) { "<span class='status-pass'>Yes</span>" } else { "<span class='status-fail'>No</span>" }
    $controls = ($_.GrantControls.BuiltInControls -join ", ") -replace $null, "No controls"
    "<tr><td>$($_.DisplayName)</td><td>$($_.State)</td><td>$mfaStatus</td><td>$controls</td><td>$($_.ModifiedDateTime)</td></tr>"
})
</table>

<h4>Recommendations</h4>
<ul>
    <li>Enforce all policies out of report-only mode</li>
    <li>Require MFA for all access policies</li>
    <li>Review and document policy exclusions quarterly</li>
    <li>Test policies in pilot groups before organization-wide rollout</li>
    <li>Monitor policy application and success rates</li>
</ul>
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "ConditionalAccessPolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        # Export to JSON if requested
        if ($Export) {
            $jsonFile = Join-Path $ReportPath "ConditionalAccessPolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $script:results.Policies | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8
            Write-Output "JSON export saved to: $jsonFile"
        }

        Write-Verbose "Report generation completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
