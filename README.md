# Active Directory and Azure AD Automation Scripts

Professional Enterprise-Grade PowerShell Framework for Active Directory Administration, Identity Lifecycle Management, RBAC Governance, and Automated Compliance Reporting.

> **Portfolio Project** | Infrastructure and AIOps Engineer | Enterprise Systems Automation Specialist

## 📋 Project Overview

This repository contains production-ready PowerShell automation scripts for managing enterprise Active Directory and Azure AD environments. The project demonstrates comprehensive AD administration capabilities including user lifecycle management, security group governance, privileged account auditing, and DNS infrastructure automation.

All scripts follow enterprise security practices with:
- ✅ Full error handling and transcript logging
- ✅ Role-based access control (RBAC) enforcement
- ✅ Comprehensive audit trails and compliance reporting
- ✅ Fictional domain names (contoso.local) and sample data
- ✅ Environment variable-based credential management
- ✅ HTML report generation with professional templates
- ✅ PowerShell 5.1 and 7+ compatibility

## 🏗️ Project Structure

```
ad-automation-scripts/
├── user-lifecycle/                 # User onboarding and offboarding automation
│   ├── New-UserOnboarding.ps1     # Automated user creation with group assignment
│   ├── Remove-UserOffboarding.ps1 # User termination and access revocation
│   └── Get-InactiveUsers.ps1      # Inactive account detection and reporting
│
├── rbac-governance/                # Role-based access control and auditing
│   ├── Get-GroupMembership.ps1    # Group membership analysis and export
│   ├── Find-PrivilegedAccounts.ps1 # Privileged account auditing and compliance
│   └── Audit-StalePermissions.ps1 # Permission-role mismatch identification
│
├── azure-ad/                       # Azure AD and Microsoft Entra administration
│   ├── Get-ConditionalAccessPolicies.ps1  # Conditional access policy auditing
│   └── Audit-GuestAccounts.ps1    # Guest account access review and reporting
│
├── dns-automation/                 # DNS infrastructure automation
│   ├── New-BulkDnsRecords.ps1     # Bulk DNS record creation with validation
│   └── Test-DnsRecords.ps1        # DNS record validation and testing
│
├── utils/                          # Shared utility functions
│   ├── Send-HtmlReport.ps1        # HTML email report sender
│   ├── Write-AuditLog.ps1         # Structured audit logging
│   └── Connect-ADEnvironment.ps1  # Centralized connection management
│
├── sample-data/                    # Sample input and output files
│   ├── sample_users.csv
│   ├── sample_dns_records.csv
│   └── sample_report.html
│
├── .github/workflows/
│   └── ps-lint.yml                # GitHub Actions: PSScriptAnalyzer linting
│
├── README.md                       # This file
├── CONTRIBUTING.md                 # Contribution guidelines
├── LICENSE                         # MIT License
└── .env.example                    # Environment configuration template
```

## 🚀 Key Features

### User Lifecycle Management
- **New-UserOnboarding.ps1**: Automated user account creation with comprehensive setup
  - OU placement based on department
  - Automatic security group assignment based on role
  - Password policy configuration
  - Account expiry and logon hours
  - HTML report generation
  - Email notifications to manager and IT team

- **Remove-UserOffboarding.ps1**: Complete user termination workflow
  - Immediate account disablement
  - Move to timestamped Disabled OU
  - Removal from all security groups
  - Manager delegation revocation
  - Home directory archival
  - Comprehensive audit reporting

- **Get-InactiveUsers.ps1**: Inactive account identification
  - Configurable inactivity thresholds (30/60/90 days)
  - Service account exclusion
  - Admin account filtering
  - CSV and HTML reporting

### RBAC Governance
- **Get-GroupMembership.ps1**: Group membership analysis
  - Nested group resolution
  - Empty group identification
  - Excessive membership detection
  - Sortable HTML tables

- **Find-PrivilegedAccounts.ps1**: Privileged account auditing
  - Domain Admin detection
  - Privileged group scanning
  - Non-dedicated admin account identification
  - MFA compliance checking
  - Executive-ready compliance reports

- **Audit-StalePermissions.ps1**: Role-based access validation
  - Department-role mapping
  - Permission mismatch detection
  - Unauthorized access identification
  - Remediation recommendations

### Azure AD Administration
- **Get-ConditionalAccessPolicies.ps1**: Conditional Access policy analysis
  - Policy condition export
  - Report-only policy identification
  - MFA requirement validation
  - Risk assessment

- **Audit-GuestAccounts.ps1**: Guest account access review
  - Inactive guest detection
  - Privileged guest identification
  - Application access analysis
  - Access review compliance

### DNS Infrastructure
- **New-BulkDnsRecords.ps1**: Bulk DNS record creation
  - CSV-driven record creation
  - A, CNAME, PTR, MX record support
  - Automatic reverse zone creation
  - Post-creation validation
  - Comprehensive reporting

- **Test-DnsRecords.ps1**: DNS validation framework
  - Forward resolution testing
  - Reverse PTR validation
  - Response time measurement
  - CI/CD pipeline integration (exit codes)

## 📋 Prerequisites

### System Requirements
- **PowerShell**: Version 5.1 or 7+ (cross-platform compatible)
- **Operating System**: Windows Server 2016+ or Windows 10+ (for on-premises AD)
- **Execution Policy**: RemoteSigned or less restrictive

### Required Modules
```powershell
# On-Premises Active Directory
Install-Module -Name ActiveDirectory -Force

# Azure AD and Microsoft Graph
Install-Module -Name Microsoft.Graph -Force
Install-Module -Name Microsoft.Graph.Identity.SignIns -Force

# DNS Server (Optional, for DNS automation)
# Import from Windows RSAT tools
```

### Required Permissions
- **On-Premises AD**: Domain Admin or delegated permissions for user/group management
- **Azure AD**: Global Administrator or appropriate delegated admin role
- **DNS Server**: DNS Admin or appropriate delegation
- **Email**: SMTP relay access for report delivery

### Environment Configuration
All scripts use environment variables for configuration. Create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your environment details
```

**Required Environment Variables:**
```bash
# On-Premises AD
AD_DOMAIN=contoso.local
AD_USER=svc_automation@contoso.local
AD_PASSWORD=YourSecurePassword
AD_SERVER=dc01.contoso.local

# Azure AD
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Email
SMTP_SERVER=mail.contoso.local
MAIL_FROM=automation@contoso.local
MAIL_ADMIN=admin@contoso.local

# Logging
LOG_PATH=./logs
ARCHIVE_PATH=\\fileserver\UserArchives
```

## 📖 Usage Examples

### User Onboarding
```powershell
$manager = Get-ADUser -Identity "jane.smith" | Select-Object -ExpandProperty DistinguishedName

.\user-lifecycle\New-UserOnboarding.ps1 `
    -FirstName "John" `
    -LastName "Doe" `
    -Department "Engineering" `
    -Role "Developer" `
    -Manager $manager `
    -EmailAddress "john.doe@contoso.local" `
    -Title "Senior Software Developer" `
    -Office "New York" `
    -SendNotification
```

### User Offboarding
```powershell
.\user-lifecycle\Remove-UserOffboarding.ps1 `
    -Identity "john.doe@contoso.local" `
    -PreserveHomeDirectory `
    -NotifyManagers
```

### Identify Inactive Users
```powershell
.\user-lifecycle\Get-InactiveUsers.ps1 `
    -InactivityDays @(30, 60, 90) `
    -ReportPath "C:\Reports" `
    -Export
```

### Group Membership Analysis
```powershell
.\rbac-governance\Get-GroupMembership.ps1 `
    -NestedGroupDepth 5 `
    -ExcessiveMembershipThreshold 20 `
    -Export
```

### Privileged Account Audit
```powershell
.\rbac-governance\Find-PrivilegedAccounts.ps1 `
    -CheckMfaStatus `
    -ReportPath "C:\Reports"
```

### DNS Bulk Creation
```powershell
.\dns-automation\New-BulkDnsRecords.ps1 `
    -CsvPath ".\sample-data\sample_dns_records.csv" `
    -ZoneName "contoso.local" `
    -DnsServer "dc01.contoso.local" `
    -CreateReverseZones
```

### DNS Validation
```powershell
.\dns-automation\Test-DnsRecords.ps1 `
    -ZoneName "contoso.local" `
    -DnsServer "dc01.contoso.local" `
    -TestReverseResolution `
    -ReturnExitCode
```

## 🔒 Security Considerations

### Credential Management
- ✅ **Never** hardcode credentials in scripts
- ✅ **Use environment variables** from `.env` file
- ✅ Ensure `.env` is in `.gitignore` (not committed to repo)
- ⚠️ Requires proper secret management in CI/CD pipelines

### Privileged Access
- ✅ Run scripts under dedicated service accounts
- ✅ Implement Just-In-Time Access (JIT) for admin tasks
- ✅ Enable and monitor MFA on privileged accounts
- ✅ Use Privileged AccessWorkstations (PAW) for admin operations

### Audit and Compliance
- ✅ All scripts generate comprehensive audit logs
- ✅ HTML reports for compliance documentation
- ✅ Structured logging for SIEM integration
- ✅ Transcript logging for command history

### Safe Testing
- ✅ Use `-WhatIf` parameter to preview changes
- ✅ `-DryRun` parameter for non-destructive testing
- ✅ Test in non-production environments first
- ✅ Schedule critical operations during maintenance windows

## 📊 Report Examples

All scripts generate professional HTML reports with:
- Executive summary with key metrics
- Detailed findings with sortable tables
- Status color coding (Pass/Warn/Fail)
- Timestamp and audit trail
- Remediation recommendations

**Sample Report:**
See [sample_report.html](./sample-data/sample_report.html) for example output format.

## 🔄 CI/CD Integration

### GitHub Actions Workflow
The repository includes automated PowerShell linting via GitHub Actions:

```yaml
# .github/workflows/ps-lint.yml
- PowerShell Syntax Validation
- PSScriptAnalyzer Linting
- Help Documentation Verification
- Security Scanning (hardcoded secrets)
- SARIF Report Generation
```

**Local Testing:**
```powershell
# Install PSScriptAnalyzer locally
Install-Module -Name PSScriptAnalyzer -Force

# Run linter
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Warning
```

## 📝 Script Template Example

All scripts follow consistent structure:
```powershell
#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Detailed description
.PARAMETER ParameterName
    Parameter description
.EXAMPLE
    Usage example
.NOTES
    Author, requirements, etc.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ParameterName
)

begin {
    # Initialize and load dependencies
}

process {
    # Main implementation
    try {
        # Business logic
    }
    catch {
        # Error handling with logging
    }
}

end {
    # Cleanup, report generation, notifications
}
```

## 📚 Documentation

- **[README.md](./README.md)** - This file
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Contribution guidelines
- **[LICENSE](./LICENSE)** - MIT License
- **[.env.example](./.env.example)** - Environment configuration template

### Inline Documentation
Each script includes comprehensive comment-based help:
```powershell
Get-Help .\user-lifecycle\New-UserOnboarding.ps1 -Full
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## 📋 Compliance and Certifications

This project demonstrates:
- **Azure Fundamentals (AZ-900)** - Cloud concepts and Azure services
- **Azure Administrator (AZ-104)** - In progress
- Enterprise identity management practices
- Security governance and compliance frameworks

## 📄 License

MIT License - See [LICENSE](./LICENSE) for details.

## ⚠️ Disclaimer

These are sample scripts for portfolio demonstration purposes. All domain names, usernames, and system references are fictional (contoso.local, example.com, etc.).

**Before using in production:**
- Adapt scripts to your environment
- Test thoroughly in non-production
- Review and customize for security policies
- Implement proper change management
- Monitor execution and validate results

## 👤 Author

Infrastructure and AIOps Engineer | Enterprise Systems Automation Specialist

**Current Focus:**
- Active Directory and Azure AD administration
- Infrastructure automation and orchestration
- Cloud-native technologies (Kubernetes, microservices)
- DevOps practices and CI/CD pipelines

**Certifications:**
- AZ-900 (Azure Fundamentals) ✅
- AZ-104 (Azure Administrator) 🔄

## 📞 Support

For issues, questions, or improvements:
1. Review existing documentation
2. Check inline script help: `Get-Help .\script.ps1 -Full`
3. Open an issue in the repository
4. Submit a pull request for improvements

---

**Last Updated:** March 24, 2026  
**Repository:** Active Directory Automation Scripts  
**License:** MIT
