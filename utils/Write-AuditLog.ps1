<#
.SYNOPSIS
Centralised audit logging function for all AD automation scripts.

.DESCRIPTION
Structured audit logging that outputs to both console and log file simultaneously.
Each log entry includes timestamp, action type, user (if applicable), result status,
and target object information. Useful for compliance, troubleshooting, and maintaining
action history.

.PARAMETER Action
The action being performed (required). Examples: UserCreated, UserDisabled, GroupModified, etc.

.PARAMETER Result
Result of the action: Success, Warning, Error (required).

.PARAMETER Message
Detailed message about the action (required).

.PARAMETER TargetObject
The AD object being acted upon (optional). Example: user@contoso.local, CN=AdminGroup,DC=contoso,DC=local

.PARAMETER Details
Additional technical details as string or hashtable (optional).

.PARAMETER LogPath
Path to log file. Defaults to $env:LOG_PATH or ./logs/audit.log if not set.

.PARAMETER IncludeInvoker
Include the user who ran the script in logs (optional, useful for audit trails).

.EXAMPLE
Write-AuditLog -Action "UserCreated" -Result "Success" -Message "New user account created" -TargetObject "john.doe@contoso.local"

.EXAMPLE
Write-AuditLog -Action "GroupRemoval" -Result "Error" -Message "Failed to remove user from group" -TargetObject "john.doe@contoso.local" -Details @{Group="Admins"; Error="Access Denied"}

.NOTES
Author: Portfolio Project
Requires: Proper LOG_PATH environment variable or logs directory writeable
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Success', 'Warning', 'Error')]
    [string]$Result,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Message,

    [Parameter(Mandatory = $false)]
    [string]$TargetObject,

    [Parameter(Mandatory = $false)]
    [object]$Details,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = $env:LOG_PATH,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeInvoker
)

begin {
    # Set default log path if not provided
    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "logs" | Join-Path -ChildPath "audit.log"
    }

    # Ensure log directory exists
    $logDirectory = Split-Path -Parent $LogPath
    if (-not (Test-Path -Path $logDirectory -PathType Container)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }

    # Format timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $iso8601 = Get-Date -Format "o"

    # Get invoking user if requested
    $invoker = if ($IncludeInvoker) {
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    } else {
        "-"
    }

    # Format result with colour codes for console output
    $resultColour = @{
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
    }[$Result]

    # Build details string
    $detailsString = ""
    if ($Details) {
        if ($Details -is [hashtable]) {
            $detailsString = ($Details.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | "
        } else {
            $detailsString = $Details.ToString()
        }
    }

    # Build log entry
    $logEntry = "$iso8601 | $Result | $Action | $invoker | $TargetObject | $Message" + 
                $(if ($detailsString) { " | $detailsString" } else { "" })
}

process {
    try {
        # Write to console with colour
        $consoleMessage = "[$timestamp] [$Result] $Action - $Message"
        if ($TargetObject) {
            $consoleMessage += " (Target: $TargetObject)"
        }
        Write-Host $consoleMessage -ForegroundColor $resultColour

        # Write to log file
        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8

        if ($Details) {
            if ($Details -is [hashtable]) {
                Write-Verbose "Details: $($Details | Out-String)"
            } else {
                Write-Verbose "Details: $($Details.ToString())"
            }
        }
    }
    catch {
        Write-Error "Failed to write audit log: $_"
    }
}

end {
    Write-Debug "Audit log entry completed for action: $Action"
}
