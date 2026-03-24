<#
.SYNOPSIS
Sends structured HTML email reports with professional formatting and attachments.

.DESCRIPTION
Centralised HTML email report sender used across all AD automation scripts.
Implements consistent corporate report template with header, summary table,
detail section, and footer. Supports attachments, CC recipients, and priority flags.

.PARAMETER To
Recipient email address (required). Supports multiple recipients as array.

.PARAMETER Subject
Email subject line (required).

.PARAMETER HtmlBody
HTML content for email body (required). Can be generated from ConvertTo-Html or custom HTML.

.PARAMETER SmtpServer
SMTP server address. Defaults to $env:SMTP_SERVER.

.PARAMETER From
Sender email address. Defaults to $env:MAIL_FROM.

.PARAMETER Cc
CC recipients as array (optional).

.PARAMETER Bcc
BCC recipients as array (optional).

.PARAMETER Attachments
Array of file paths to attach (optional).

.PARAMETER Priority
Email priority: Normal, High, Low. Default is Normal.

.PARAMETER CompanyLogo
URL to company logo image for report header (optional).

.PARAMETER ReportTitle
Title for the report section (optional).

.PARAMETER SummaryMetrics
Hashtable of summary metrics to display at top of report (optional).
Example: @{TotalUsers=150; FailedCount=3; WarningCount=12}

.EXAMPLE
$body = '<table><tr><td>Sample</td></tr></table>'
Send-HtmlReport -To "admin@contoso.local" -Subject "AD Audit Report" -HtmlBody $body

.EXAMPLE
$metrics = @{
    'Total Groups' = 450
    'Nested Groups' = 78
    'Empty Groups'  = 12
}
Send-HtmlReport -To "admins@contoso.local" -Subject "Group Audit" -HtmlBody $html -SummaryMetrics $metrics

.NOTES
Author: Portfolio Project
Requires: Proper SMTP configuration and environment variables set
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$To,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Subject,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$HtmlBody,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer = $env:SMTP_SERVER,

    [Parameter(Mandatory = $false)]
    [string]$From = $env:MAIL_FROM,

    [Parameter(Mandatory = $false)]
    [string[]]$Cc,

    [Parameter(Mandatory = $false)]
    [string[]]$Bcc,

    [Parameter(Mandatory = $false)]
    [string[]]$Attachments,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Normal', 'High', 'Low')]
    [string]$Priority = 'Normal',

    [Parameter(Mandatory = $false)]
    [string]$CompanyLogo,

    [Parameter(Mandatory = $false)]
    [string]$ReportTitle = 'Automation Report',

    [Parameter(Mandatory = $false)]
    [hashtable]$SummaryMetrics
)

begin {
    Write-Verbose "Initializing HTML report sender for subject: $Subject"

    # Validate required parameters
    if ([string]::IsNullOrWhiteSpace($SmtpServer)) {
        throw "SMTP server not specified and SMTP_SERVER environment variable not set"
    }

    if ([string]::IsNullOrWhiteSpace($From)) {
        throw "Sender not specified and MAIL_FROM environment variable not set"
    }

    # Build summary metrics HTML
    $metricsHtml = ""
    if ($SummaryMetrics -and $SummaryMetrics.Count -gt 0) {
        $metricsHtml = "<div style='background-color: #f5f5f5; padding: 15px; margin-bottom: 20px; border-radius: 5px;'>"
        $metricsHtml += "<h3 style='margin-top: 0; color: #333;'>Summary Metrics</h3>"
        $metricsHtml += "<table style='width: 100%; border-collapse: collapse;'>"
        
        foreach ($metric in $SummaryMetrics.GetEnumerator()) {
            $metricsHtml += "<tr style='border-bottom: 1px solid #ddd;'>"
            $metricsHtml += "<td style='padding: 8px; font-weight: bold; color: #333;'>$($metric.Key)</td>"
            $metricsHtml += "<td style='padding: 8px; text-align: right; color: #0078d4;'>$($metric.Value)</td>"
            $metricsHtml += "</tr>"
        }
        $metricsHtml += "</table></div>"
    }

    # Build professional HTML template
    $timestamp = Get-Date -Format "dddd, MMMM d, yyyy h:mm:ss tt"
    $htmlTemplate = @"
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f9f9f9; margin: 0; padding: 0; }
            .container { max-width: 800px; margin: 0 auto; background-color: white; }
            .header { background-color: #0078d4; color: white; padding: 30px; text-align: center; }
            .header h1 { margin: 0; font-size: 28px; }
            .header-logo { height: 50px; margin-bottom: 15px; }
            .content { padding: 30px; }
            .report-title { color: #0078d4; font-size: 22px; margin: 20px 0 10px 0; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
            .timestamp { color: #666; font-size: 12px; margin-bottom: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th { background-color: #f5f5f5; color: #333; padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold; }
            td { padding: 10px 12px; border-bottom: 1px solid #eee; }
            tr:hover { background-color: #f9f9f9; }
            .status-pass { color: #107c10; font-weight: bold; }
            .status-warn { color: #ff9800; font-weight: bold; }
            .status-fail { color: #da3b01; font-weight: bold; }
            .footer { background-color: #f5f5f5; padding: 20px; text-align: center; color: #666; font-size: 12px; border-top: 1px solid #ddd; }
            .metrics { background-color: #f0f7ff; padding: 15px; margin: 20px 0; border-left: 4px solid #0078d4; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                $(if ($CompanyLogo) { "<img class='header-logo' src='$CompanyLogo' alt='Company Logo'>" })
                <h1>Automated Report</h1>
            </div>
            <div class="content">
                <h2 class="report-title">$ReportTitle</h2>
                <p class="timestamp">Generated: $timestamp</p>
                $metricsHtml
                $HtmlBody
            </div>
            <div class="footer">
                <p>This is an automated report generated by Active Directory Automation Scripts.</p>
                <p>For questions or support, contact your IT administration team.</p>
            </div>
        </div>
    </body>
    </html>
"@
}

process {
    try {
        Write-Verbose "Creating email message"
        
        $mailParams = @{
            SmtpServer  = $SmtpServer
            From        = $From
            To          = $To
            Subject     = $Subject
            Body        = $htmlTemplate
            BodyAsHtml  = $true
            Priority    = $Priority
        }

        if ($Cc) {
            $mailParams['Cc'] = $Cc
            Write-Verbose "Adding CC recipients: $($Cc -join ', ')"
        }

        if ($Bcc) {
            $mailParams['Bcc'] = $Bcc
            Write-Verbose "Adding BCC recipients"
        }

        if ($Attachments) {
            $mailParams['Attachments'] = $Attachments
            Write-Verbose "Attaching files: $($Attachments -join ', ')"
        }

        Write-Verbose "Sending email to: $($To -join ', ')"
        Send-MailMessage @mailParams

        Write-Verbose "Email sent successfully"
        Write-Output "Report sent successfully to $(($To -join ', '))"
    }
    catch {
        Write-Error "Failed to send email report: $_"
        throw
    }
}

end {
    Write-Verbose "HTML report process completed"
}
