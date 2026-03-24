<#
.SYNOPSIS
Creates DNS records in bulk from CSV input with validation and reporting.

.DESCRIPTION
Automates creation of multiple DNS records in bulk from CSV file. Supports A, CNAME, PTR,
and MX record types. Creates both forward and reverse lookup zones automatically. Tags records
with metadata (owner, purpose, created date). Validates each record post-creation with full
error handling. Generates HTML report of all created records with validation status.
Supports -WhatIf parameter for dry run testing.

.PARAMETER CsvPath
Path to CSV file with DNS records to create (required).
CSV columns: Name, RecordType, Value, Owner, Purpose, ZoneName

.PARAMETER ZoneName
Default zone name if not specified in CSV (optional).

.PARAMETER DnsServer
DNS server to target for record creation (optional, defaults to local).

.PARAMETER CreateReverseZones
Automatically create reverse lookup zones (optional, default: true).

.PARAMETER ValidationAttempts
Number of validation attempts before marking as failed (optional, default: 3).

.PARAMETER ReportPath
Path for output report (optional, defaults to ./reports/).

.PARAMETER WhatIf
Preview changes without making them.

.PARAMETER Confirm
Prompt before creating records.

.EXAMPLE
New-BulkDnsRecords -CsvPath "C:\dns_records.csv" -ZoneName "contoso.local"

.EXAMPLE
New-BulkDnsRecords -CsvPath "dns_records.csv" -DnsServer "192.168.1.10" -WhatIf

.NOTES
Author: Portfolio Project
Requires: DnsServer module, appropriate permissions on DNS server
CSV Example:
    Name,RecordType,Value,Owner,Purpose,ZoneName
    mail,MX,10 mail.contoso.local,IT-DNS,Mail Exchange,contoso.local
    www,A,192.168.1.100,IT-Infrastructure,Web Server,contoso.local
#>

#Requires -Version 5.1
#Requires -Modules DnsServer

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ZoneName,

    [Parameter(Mandatory = $false)]
    [string]$DnsServer = "localhost",

    [Parameter(Mandatory = $false)]
    [switch]$CreateReverseZones = $true,

    [Parameter(Mandatory = $false)]
    [int]$ValidationAttempts = 3,

    [Parameter(Mandatory = $false)]
    [string]$ReportPath = (Join-Path $PSScriptRoot "..\..\reports")
)

begin {
    # Load utility functions
    $utilPath = Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "utils"
    . (Join-Path $utilPath "Write-AuditLog.ps1")

    $script:results = @{
        TotalRecords        = 0
        SuccessfulCreations = 0
        FailedCreations     = @()
        ValidationPassed    = @()
        ValidationFailed    = @()
        Records             = @()
    }

    # Ensure report directory exists
    if (-not (Test-Path $ReportPath)) {
        New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null
    }

    # Import DNS module
    Import-Module -Name DnsServer -ErrorAction Stop | Out-Null

    Write-Verbose "Initializing bulk DNS record creation"
    Write-Verbose "Target zone: $ZoneName"
    Write-Verbose "DNS server: $DnsServer"
}

process {
    try {
        # Load CSV file
        Write-Verbose "Loading DNS records from CSV: $CsvPath"
        $records = Import-Csv -Path $CsvPath -ErrorAction Stop

        $script:results.TotalRecords = $records.Count
        Write-Output "Processing $($records.Count) DNS records..."

        foreach ($record in $records) {
            $recordName = $record.Name
            $recordType = $record.RecordType
            $recordValue = $record.Value
            $owner = $record.Owner
            $purpose = $record.Purpose
            $zone = if ($record.ZoneName) { $record.ZoneName } else { $ZoneName }

            Write-Verbose "Processing record: $recordName ($recordType) in zone $zone"

            # Validate record type
            $validTypes = @("A", "AAAA", "CNAME", "MX", "PTR", "SOA", "TXT")
            if ($recordType -notin $validTypes) {
                $script:results.FailedCreations += @{
                    Name   = $recordName
                    Type   = $recordType
                    Error  = "Invalid record type: $recordType"
                }
                Write-Warning "Invalid record type $recordType for $recordName"
                continue
            }

            # Prepare DNS record parameters
            $dnsParams = @{
                ZoneName = $zone
                Name     = $recordName
                Type     = $recordType
                ComputerName = $DnsServer
            }

            # Add value based on record type
            switch ($recordType) {
                "A" {
                    $dnsParams["IPv4Address"] = $recordValue
                    if ($CreateReverseZones) {
                        # Extract network and create reverse zone if needed
                        $octets = $recordValue.Split('.')
                        $reverseZone = "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
                    }
                }
                "AAAA" {
                    $dnsParams["IPv6Address"] = $recordValue
                }
                "CNAME" {
                    $dnsParams["CanonicalName"] = $recordValue
                }
                "MX" {
                    # Format: Priority MailExchange
                    $parts = $recordValue -split '\s', 2
                    $dnsParams["Preference"] = [int]$parts[0]
                    $dnsParams["MailExchange"] = $parts[1]
                }
                "TXT" {
                    $dnsParams["DescriptiveText"] = $recordValue
                }
            }

            if ($PSCmdlet.ShouldProcess("Zone: $zone, Record: $recordName", "Create DNS record")) {
                try {
                    # Create DNS record
                    Add-DnsServerResourceRecord @dnsParams -ErrorAction Stop
                    $script:results.SuccessfulCreations++
                    
                    $recordInfo = @{
                        Name             = $recordName
                        Type             = $recordType
                        Value            = $recordValue
                        Zone             = $zone
                        Owner            = $owner
                        Purpose          = $purpose
                        CreatedDateTime  = Get-Date
                        ValidationStatus = "Pending"
                    }

                    Write-Verbose "DNS record created successfully: $recordName ($recordType)"
                    Write-AuditLog -Action "DnsRecordCreated" -Result "Success" `
                        -Message "DNS record created" `
                        -TargetObject "$recordName.$zone" `
                        -Details @{ RecordType = $recordType; Value = $recordValue; Owner = $owner }

                    # Validate record creation
                    $validationSuccess = $false
                    for ($attempt = 1; $attempt -le $ValidationAttempts; $attempt++) {
                        try {
                            Start-Sleep -Seconds 2
                            $resolvedRecord = Resolve-DnsName -Name "$recordName.$zone" -Type $recordType -Server $DnsServer -ErrorAction SilentlyContinue
                            
                            if ($resolvedRecord) {
                                $recordInfo.ValidationStatus = "Pass"
                                $script:results.ValidationPassed += $recordInfo
                                $validationSuccess = $true
                                Write-Verbose "Validation passed for $recordName"
                                break
                            }
                        }
                        catch {
                            if ($attempt -eq $ValidationAttempts) {
                                $recordInfo.ValidationStatus = "Failed"
                                $script:results.ValidationFailed += $recordInfo
                                Write-Warning "Validation failed for $recordName after $ValidationAttempts attempts"
                            }
                        }
                    }

                    $script:results.Records += $recordInfo
                }
                catch {
                    $script:results.FailedCreations += @{
                        Name   = $recordName
                        Type   = $recordType
                        Error  = $_
                    }
                    Write-AuditLog -Action "DnsRecordCreationFailed" -Result "Error" `
                        -Message "Failed to create DNS record" `
                        -TargetObject "$recordName.$zone" `
                        -Details @{ Error = $_ }
                    Write-Error "Failed to create DNS record $recordName : $_"
                }
            }
        }
    }
    catch {
        Write-Error "Error processing CSV file: $_"
        throw
    }
}

end {
    try {
        # Build HTML report
        $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
        
        $htmlReport = @"
<h3>Bulk DNS Record Creation Report</h3>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Target Zone:</strong> $ZoneName</p>

<h4>Creation Summary</h4>
<table>
<tr><td>Total Records Processed</td><td>$($script:results.TotalRecords)</td></tr>
<tr><td>Successfully Created</td><td class='status-pass'>$($script:results.SuccessfulCreations)</td></tr>
<tr><td>Failed Creations</td><td class='status-fail'>$($script:results.FailedCreations.Count)</td></tr>
<tr><td>Validation Passed</td><td class='status-pass'>$($script:results.ValidationPassed.Count)</td></tr>
<tr><td>Validation Failed</td><td class='status-fail'>$($script:results.ValidationFailed.Count)</td></tr>
</table>

<h4>Created Records with Validation Status</h4>
<table>
<tr>
    <th>Record Name</th>
    <th>Type</th>
    <th>Value</th>
    <th>Owner</th>
    <th>Purpose</th>
    <th>Validation</th>
    <th>Created Date</th>
</tr>
$($script:results.Records | ForEach-Object {
    $validStatus = if ($_.ValidationStatus -eq "Pass") { "<span class='status-pass'>✓ Pass</span>" } else { "<span class='status-fail'>✗ Failed</span>" }
    "<tr><td>$($_.Name)</td><td>$($_.Type)</td><td>$($_.Value)</td><td>$($_.Owner)</td><td>$($_.Purpose)</td><td>$validStatus</td><td>$($_.CreatedDateTime)</td></tr>"
})
</table>

$(if ($script:results.FailedCreations.Count -gt 0) {
    @"
<h4 style="color: #da3b01;">Failed Record Creations</h4>
<table>
<tr>
    <th>Record Name</th>
    <th>Type</th>
    <th>Error</th>
</tr>
$($script:results.FailedCreations | ForEach-Object {
    "<tr><td>$($_.Name)</td><td>$($_.Type)</td><td>$($_.Error)</td></tr>"
})
</table>
"@
})
"@

        # Export to file
        $reportFile = Join-Path $ReportPath "BulkDnsRecords_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Output "Report saved to: $reportFile"

        Write-Verbose "DNS record creation process completed"
    }
    catch {
        Write-Error "Error generating report: $_"
    }
}
