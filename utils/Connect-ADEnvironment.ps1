<#
.SYNOPSIS
Centralised connection handler for on-premises Active Directory and Azure AD/Microsoft Graph.

.DESCRIPTION
Reads configuration from .env file, validates prerequisites, tests connectivity,
and establishes connections to both on-premises AD and Azure AD. Single point of
connection management for all automation scripts.

.PARAMETER Environment
Target environment: 'OnPremisesAD', 'AzureAD', or 'Both' (default: 'Both').

.PARAMETER EnvFilePath
Path to .env configuration file. Defaults to .env in script root.

.PARAMETER SkipConnectivityTest
Skip connectivity validation (optional, for offline testing).

.EXAMPLE
Connect-ADEnvironment -Environment OnPremisesAD

.EXAMPLE
Connect-ADEnvironment -Environment Both -EnvFilePath "C:\config\.env"

.NOTES
Author: Portfolio Project
Requires: ActiveDirectory module (for on-premises), Az.Accounts and Microsoft.Graph modules (for Azure AD)

Required environment variables in .env:
    AD_DOMAIN          - On-premises domain name (e.g., contoso.local)
    AD_USER            - AD service account (e.g., svc_automation@contoso.local)
    AD_PASSWORD        - AD service account password
    AZURE_TENANT_ID    - Azure AD tenant ID
    AZURE_CLIENT_ID    - Service principal app ID
    AZURE_CLIENT_SECRET - Service principal secret
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('OnPremisesAD', 'AzureAD', 'Both')]
    [string]$Environment = 'Both',

    [Parameter(Mandatory = $false)]
    [string]$EnvFilePath,

    [Parameter(Mandatory = $false)]
    [switch]$SkipConnectivityTest
)

begin {
    Write-Verbose "Initializing AD environment connection handler"

    # Determine .env file path
    if ([string]::IsNullOrWhiteSpace($EnvFilePath)) {
        $EnvFilePath = Join-Path -Path $PSScriptRoot -ChildPath ".env"
        if (-not (Test-Path $EnvFilePath)) {
            $EnvFilePath = Join-Path -Path (Split-Path $PSScriptRoot -Parent) -ChildPath ".env"
        }
    }

    if (-not (Test-Path -Path $EnvFilePath)) {
        throw "Environment file not found at: $EnvFilePath. Please create .env file with required configuration."
    }

    Write-Verbose "Loading environment configuration from: $EnvFilePath"

    # Load .env file
    $envContent = Get-Content -Path $EnvFilePath -ErrorAction Stop
    $envVars = @{}

    foreach ($line in $envContent) {
        $line = $line.Trim()
        # Skip empty lines and comments
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $envVars[$parts[0].Trim()] = $parts[1].Trim()
            }
        }
    }

    # Validate required variables based on environment
    $requiredVars = @()
    if ($Environment -in 'OnPremisesAD', 'Both') {
        $requiredVars += 'AD_DOMAIN', 'AD_USER', 'AD_PASSWORD'
    }
    if ($Environment -in 'AzureAD', 'Both') {
        $requiredVars += 'AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'
    }

    foreach ($var in $requiredVars) {
        if (-not $envVars.ContainsKey($var)) {
            throw "Required environment variable not found in .env file: $var"
        }
    }

    # Set environment variables
    foreach ($var in $envVars.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($var.Key, $var.Value, 'Process')
    }

    Write-Verbose "Environment variables loaded successfully"
}

process {
    try {
        # Connect to on-premises AD
        if ($Environment -in 'OnPremisesAD', 'Both') {
            Write-Verbose "Connecting to on-premises Active Directory: $($envVars['AD_DOMAIN'])"

            # Check if ActiveDirectory module is available
            if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
                throw "ActiveDirectory module not found. Install RSAT or run on domain-joined computer."
            }

            Import-Module -Name ActiveDirectory -ErrorAction Stop | Out-Null

            # Test connectivity to AD domain
            if (-not $SkipConnectivityTest) {
                Write-Verbose "Testing connectivity to domain controller"
                try {
                    Get-ADDomain -Identity $envVars['AD_DOMAIN'] -ErrorAction Stop | Out-Null
                    Write-Verbose "Successfully connected to AD domain: $($envVars['AD_DOMAIN'])"
                }
                catch {
                    throw "Failed to connect to AD domain '$($envVars['AD_DOMAIN'])': $_"
                }
            }

            Write-Output "On-premises AD connection established"
        }

        # Connect to Azure AD via Microsoft Graph
        if ($Environment -in 'AzureAD', 'Both') {
            Write-Verbose "Connecting to Azure AD via Microsoft Graph"

            # Check if Microsoft.Graph module is available
            if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
                Write-Warning "Microsoft.Graph module not found. Attempting to install..."
                Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser -ErrorAction Stop
            }

            # Import required Graph modules
            Import-Module -Name Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null

            # Create credential object from environment variables
            $clientSecretSecure = ConvertTo-SecureString -String $envVars['AZURE_CLIENT_SECRET'] -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential(
                $envVars['AZURE_CLIENT_ID'],
                $clientSecretSecure
            )

            # Connect to Microsoft Graph
            Connect-MgGraph -TenantId $envVars['AZURE_TENANT_ID'] `
                -ClientSecretCredential $credential `
                -ErrorAction Stop | Out-Null

            if (-not $SkipConnectivityTest) {
                Write-Verbose "Testing Microsoft Graph connectivity"
                try {
                    Get-MgOrganization | Out-Null
                    Write-Verbose "Successfully connected to Azure AD tenant: $($envVars['AZURE_TENANT_ID'])"
                }
                catch {
                    throw "Failed to connect to Azure AD tenant: $_"
                }
            }

            Write-Output "Azure AD (Microsoft Graph) connection established"
        }

        Write-Verbose "All requested connections established successfully"
    }
    catch {
        Write-Error "Failed to establish AD environment connection: $_"
        throw
    }
}

end {
    Write-Verbose "AD environment connection process completed"
}
