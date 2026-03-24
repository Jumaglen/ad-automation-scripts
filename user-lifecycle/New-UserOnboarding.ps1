<#
.SYNOPSIS
Creates new Active Directory user with comprehensive onboarding workflow.

.DESCRIPTION
Automates new user account creation in Active Directory with full configuration:
- Creates user in correct OU based on department parameter
- Assigns to appropriate security groups based on role
- Sets password policy, account expiry, and logon hours
- Generates detailed onboarding report in HTML format
- Sends notifications to manager and IT team
- Full error handling and transcript logging

.PARAMETER FirstName
User's first name (required).

.PARAMETER LastName
User's last name (required).

.PARAMETER Department
Department for OU placement (required). Example: Finance, Engineering, Sales, HR.

.PARAMETER Role
Job role for group assignment (required). Example: Manager, Analyst, Developer, Admin.

.PARAMETER Manager
Distinguished name of user's manager (required).

.PARAMETER EmailAddress
Email address for user account (required). Format: firstname.lastname@contoso.local

.PARAMETER Title
Job title for account (required).

.PARAMETER Office
Office location (optional).

.PARAMETER LogonHours
Byte array for logon hours restriction (optional). Default: no restriction.

.PARAMETER AccountExpiry
Date when account should expire (optional).

.PARAMETER SendNotification
Send HTML report to manager and IT team (optional).

.PARAMETER NotificationRecipients
Email addresses to notify (optional). Defaults from environment.

.PARAMETER WhatIf
Show what would be done without making changes.

.PARAMETER Confirm
Prompt before creating user.

.EXAMPLE
$manager = Get-ADUser -Identity "jane.smith" | Select-Object -ExpandProperty DistinguishedName
New-UserOnboarding -FirstName "John" -LastName "Doe" -Department "Engineering" `
    -Role "Developer" -Manager $manager -EmailAddress "john.doe@contoso.local" `
    -Title "Senior Software Developer"

.EXAMPLE
New-UserOnboarding -FirstName "Jane" -LastName "Johnson" -Department "Finance" `
    -Role "Analyst" -Manager $manager -EmailAddress "jane.johnson@contoso.local" `
    -Title "Financial Analyst" -Office "New York" -SendNotification

.NOTES
Author: Portfolio Project
Requires: ActiveDirectory module, proper permissions to create users and manage groups

Special Groups:
    - Dept-{Department}: Department-based access
    - Role-{Role}: Role-based access
    - AllEmployees: Universal group for all users
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$FirstName,

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$LastName,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Finance', 'Engineering', 'Sales', 'Marketing', 'HR', 'Operations', 'Security')]
    [string]$Department,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Developer', 'Manager', 'Analyst', 'Admin', 'Operator', 'Consultant')]
    [string]$Role,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Manager,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9._%+-]+@contoso\.local$')]
    [string]$EmailAddress,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Title,

    [Parameter(Mandatory = $false)]
    [string]$Office,

    [Parameter(Mandatory = $false)]
    [byte[]]$LogonHours,

    [Parameter(Mandatory = $false)]
    [DateTime]$AccountExpiry,

    [Parameter(Mandatory = $false)]
    [switch]$SendNotification,

    [Parameter(Mandatory = $false)]
    [string[]]$NotificationRecipients = @($env:MAIL_ADMIN, $env:MAIL_MANAGER)
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")
    . (Join-Path $utilPath "Send-HtmlReport.ps1")
    . (Join-Path $utilPath "Connect-ADEnvironment.ps1")

    # Initialize
    $script:result = @{
        Success          = $false
        UserCreated      = $false
        GroupsAssigned   = @()
        Errors           = @()
        WarningMessages  = @()
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFile = Join-Path -Path $env:LOG_PATH -ChildPath "onboarding_$($FirstName)_$($LastName)_$timestamp.log"
    Start-Transcript -Path $logFile -Append | Out-Null

    Write-Verbose "Starting user onboarding process for: $FirstName $LastName"
}

process {
    try {
        # Establish AD connection
        Write-Verbose "Connecting to Active Directory"
        Connect-ADEnvironment -Environment OnPremisesAD -SkipConnectivityTest

        # Build username from email
        $username = ($EmailAddress -split '@')[0]
        Write-Verbose "Generated username: $username"

        # Generate temporary password
        $tempPassword = [System.Web.Security.Membership]::GeneratePassword(16, 4) | ConvertTo-SecureString -AsPlainText -Force
        
        if ($PSCmdlet.ShouldProcess("$FirstName $LastName", "Create AD user account")) {
            # Determine target OU based on department
            $ouBase = "OU=$Department,OU=Users,DC=contoso,DC=local"
            $targetOU = "OU=Active,$ouBase"

            Write-Verbose "Target OU: $targetOU"

            # Create user account
            $userParams = @{
                SamAccountName        = $username
                UserPrincipalName     = $EmailAddress
                Name                  = "$FirstName $LastName"
                GivenName             = $FirstName
                Surname               = $LastName
                EmailAddress          = $EmailAddress
                Title                 = $Title
                Department            = $Department
                Manager               = $Manager
                Enabled               = $false
                Path                  = $targetOU
                AccountPassword       = $tempPassword
                ChangePasswordAtLogon = $true
                ErrorAction           = 'Stop'
            }

            if ($Office) {
                $userParams['Office'] = $Office
            }

            $adUser = New-ADUser @userParams -PassThru
            $script:result.UserCreated = $true
            Write-Output "User account created: $username"
            Write-AuditLog -Action "UserCreated" -Result "Success" -Message "New user account created in Active Directory" `
                -TargetObject $adUser.DistinguishedName -Details @{
                UserPrincipalName = $EmailAddress
                Department        = $Department
                OU                = $targetOU
            }

            # Assign to security groups
            $groupsToAdd = @(
                "CN=AllEmployees,OU=Security,DC=contoso,DC=local",
                "CN=Dept-$Department,OU=Security,DC=contoso,DC=local",
                "CN=Role-$Role,OU=Security,DC=contoso,DC=local"
            )

            foreach ($groupDN in $groupsToAdd) {
                try {
                    Add-ADGroupMember -Identity $groupDN -Members $adUser -ErrorAction Stop
                    $script:result.GroupsAssigned += (Get-ADGroup -Identity $groupDN).Name
                    Write-Verbose "Added user to group: $groupDN"
                    Write-AuditLog -Action "GroupMembershipAdded" -Result "Success" `
                        -Message "User added to security group" -TargetObject $groupDN
                }
                catch {
                    $script:result.WarningMessages += "Failed to add user to group $groupDN : $_"
                    Write-AuditLog -Action "GroupMembershipFailed" -Result "Warning" `
                        -Message "Failed to add user to group" -TargetObject $groupDN
                }
            }

            # Set logon hours if specified
            if ($LogonHours) {
                Set-ADUser -Identity $adUser -Replace @{logonHours = $LogonHours} -ErrorAction Stop
                Write-Verbose "Logon hours set"
            }

            # Set account expiry if specified
            if ($AccountExpiry) {
                $expiryDate = $AccountExpiry | Get-Date -Format "yyyy-MM-dd"
                Set-ADUser -Identity $adUser -AccountExpirationDate $AccountExpiry -ErrorAction Stop
                Write-Verbose "Account expiry set to: $expiryDate"
            }

            # Enable account
            Enable-ADAccount -Identity $adUser -ErrorAction Stop
            Write-Output "User account enabled"

            $script:result.Success = $true
            Write-AuditLog -Action "UserOnboardingCompleted" -Result "Success" `
                -Message "User onboarding completed successfully" -TargetObject $adUser.UserPrincipalName
        }
    }
    catch {
        $script:result.Success = $false
        $script:result.Errors += "Onboarding failed: $_"
        Write-AuditLog -Action "UserOnboardingFailed" -Result "Error" `
            -Message "User onboarding encountered critical error" -Details @{Error = $_ }
        Write-Error "Failed to complete user onboarding: $_"
        throw
    }
}

end {
    try {
        # Generate HTML report
        $htmlReport = @"
<h3>User Onboarding Report</h3>
<p><strong>User:</strong> $FirstName $LastName</p>
<p><strong>Username:</strong> $username</p>
<p><strong>Email:</strong> $EmailAddress</p>
<p><strong>Department:</strong> $Department</p>
<p><strong>Role:</strong> $Role</p>
<p><strong>Status:</strong> $(if ($script:result.Success) { "<span class='status-pass'>✓ Completed</span>" } else { "<span class='status-fail'>✗ Failed</span>" })</p>

<h4>Groups Assigned</h4>
<ul>
$(($script:result.GroupsAssigned | ForEach-Object { "<li>$_</li>" }) -join "`n")
</ul>

$(if ($script:result.WarningMessages.Count -gt 0) {
    @"
<h4 style="color: #ff9800;">Warnings</h4>
<ul>
$($script:result.WarningMessages | ForEach-Object { "<li>$_</li>" })
</ul>
"@
})

$(if ($script:result.Errors.Count -gt 0) {
    @"
<h4 style="color: #da3b01;">Errors</h4>
<ul>
$($script:result.Errors | ForEach-Object { "<li>$_</li>" })
</ul>
"@
})

<p><strong>Temporary Password:</strong> Provided securely to user via separate communication</p>
<p><strong>Action Required:</strong> User must change password on first logon</p>
"@

        if ($SendNotification -and $NotificationRecipients) {
            try {
                $metrics = @{
                    'Users Created'      = if ($script:result.UserCreated) { 1 } else { 0 }
                    'Groups Assigned'    = $script:result.GroupsAssigned.Count
                    'Status'             = if ($script:result.Success) { 'Success' } else { 'Failed' }
                }

                Send-HtmlReport -To $NotificationRecipients -Subject "User Onboarding Report: $FirstName $LastName" `
                    -HtmlBody $htmlReport -ReportTitle "New User Onboarding" -SummaryMetrics $metrics
                
                Write-Output "Notification email sent to: $($NotificationRecipients -join ', ')"
            }
            catch {
                Write-Warning "Failed to send notification email: $_"
            }
        }

        Write-Verbose "User onboarding process completed"
        Stop-Transcript | Out-Null

        # Return summary
        $script:result
    }
    catch {
        Write-Error "Error in end block: $_"
    }
}
