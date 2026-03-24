# Contributing to AD Automation Scripts

Thank you for your interest in contributing to this project! This document provides guidelines for contributing code, documentation, and improvements.

## 📋 Code of Conduct

- Be respectful and professional
- Provide constructive feedback
- Help others succeed
- Report issues appropriately

## 🛠️ How to Contribute

### 1. Reporting Bugs

Before submitting a bug report:
- **Check existing issues** for duplicates
- **Test with latest code** from `develop` branch
- **Provide reproducible steps** to demonstrate the issue
- **Include environment information** (PowerShell version, OS, modules)

**Bug Report Template:**
```markdown
## Bug Description
[Clear description of the problem]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Expected vs. actual results]

## Environment
- PowerShell Version: [version]
- OS: [OS and version]
- Script: [script name and version]
- Error Message: [exact error message]

## Additional Context
[Any other relevant information]
```

### 2. Suggesting Enhancements

For feature requests:
- **Check existing requests** for duplicates
- **Explain the use case** clearly
- **Describe expected behavior** in detail
- **Provide examples** if applicable

**Enhancement Template:**
```markdown
## Enhancement Description
[Clear description of requested feature]

## Use Case
[Why is this feature needed]

## Proposed Solution
[How it should work]

## Alternative Solutions
[Any alternative approaches considered]
```

### 3. Submitting Changes

#### Fork and Clone
```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ad-automation-scripts.git
cd ad-automation-scripts

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_REPO/ad-automation-scripts.git
```

#### Create Feature Branch
```bash
# Update from upstream
git fetch upstream
git checkout develop
git merge upstream/develop

# Create feature branch
git checkout -b feature/your-feature-name
# or for bugfixes:
git checkout -b bugfix/issue-description
```

#### Make Changes
1. **Follow code style** (see guidelines below)
2. **Add comments** and documentation
3. **Test thoroughly** in non-production environment
4. **Update help documentation**
5. **Add log entries** if applicable

#### Code Style Guidelines

##### PowerShell Formatting
```powershell
# Use PascalCase for function names
function Invoke-UserOnboarding {
    # Implementation
}

# Use camelCase for variables
$firstName = "John"
$lastName = "Doe"

# Indentation: 4 spaces
if ($condition) {
    Write-Output "Message"
}

# Braces: same line for opening, new line for closing
try {
    # Code here
}
catch {
    # Error handling
}

# Comments for complex logic
# Calculate user onboarding fee
$fee = $baseRate * $adjustmentFactor
```

##### Script Structure
```powershell
#Requires -Version 5.1
#Requires -Modules Module1, Module2

<#
.SYNOPSIS
    One-line description

.DESCRIPTION
    Detailed description of functionality

.PARAMETER ParamName
    Parameter description

.EXAMPLE
    Example usage with output

.NOTES
    Additional notes, author, requirements
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [type]$ParameterName
)

begin {
    # Initialization, validation, module loading
    $script:config = @{}
}

process {
    # Main implementation
    try {
        # Implementation in try-catch blocks
    }
    catch {
        Write-Error "Error message: $_"
    }
}

end {
    # Cleanup, reporting, notifications
}
```

##### Naming Conventions
- **Functions**: `Verb-Noun` (New-User, Remove-Access, Get-Report)
- **Variables**: `$camelCase` or `$PascalCase` for complex objects
- **Constants**: `$UPPER_CASE`
- **Parameters**: `PascalCase`
- **Boolean parameters**: `-Force`, `-WhatIf`, `-Confirm`

##### Error Handling
```powershell
# Use ErrorAction and explicit error handling
try {
    Get-ADUser -Identity $userId -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve user: $_"
    Write-AuditLog -Action "UserRetrievalFailed" -Result "Error" -TargetObject $userId
    throw
}
```

##### Comment-Based Help
Every public script must include complete help:
```powershell
<#
.SYNOPSIS
    Brief description (one line)

.DESCRIPTION
    Detailed description (multiple lines)
    Explain what the function does and why

.PARAMETER ParameterName
    Description of parameter including valid values

.PARAMETER OtherParameter
    Description of another parameter

.EXAMPLE
    C:\> Function-Name -Parameter1 "value1" -Parameter2 "value2"
    Description of example output

.EXAMPLE
    C:\> Another-Example
    Description of another example

.INPUTS
    Input object type

.OUTPUTS
    Output object type or description

.NOTES
    Author: Your Name
    Date: YYYY-MM-DD
    Version: 1.0
    Requirements: Module1, appropriate permissions

.LINK
    https://relevant-documentation.url
#>
```

#### Testing

##### Test Categories
- **Unit Testing**: Individual function logic
- **Integration Testing**: Interaction with AD/Azure
- **Compliance Testing**: Proper logging and reporting
- **Security Testing**: Credential handling, no hardcoded secrets

##### Test Checklist
- [ ] Script syntax is valid (PSScriptAnalyzer)
- [ ] Help documentation is complete
- [ ] Error handling works correctly
- [ ] Logging captures all actions
- [ ] No hardcoded credentials
- [ ] `-WhatIf` parameter works
- [ ] Works on PowerShell 5.1 and 7+
- [ ] Report generation functions properly
- [ ] Tested in non-production environment
- [ ] No breaking changes to existing scripts

##### Running Tests Locally
```powershell
# Install PSScriptAnalyzer
Install-Module PSScriptAnalyzer -Force

# Run linter
Invoke-ScriptAnalyzer -Path .\script.ps1 -Verbose

# Check syntax
[System.Management.Automation.PSParser]::Tokenize(
    (Get-Content .\script.ps1), 
    [ref]$null
)

# Run script with -WhatIf
.\script.ps1 -Parameter "value" -WhatIf

# Test help
Get-Help .\script.ps1 -Full
```

#### Commit and Push

```bash
# Add changes
git add .

# Commit with descriptive message
git commit -m "feat: Add user bulk import feature

- Added bulk import from CSV
- Implemented progress indicators
- Added comprehensive error handling
- Updated help documentation
- Fixes #123"

# Push to your fork
git push origin feature/your-feature-name
```

**Commit Message Format:**
```
<type>: <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting, semicolons, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `chore`: Build, dependencies, configuration

**Example:**
```
feat: Implement new report generation

- Add HTML template caching
- Improve email delivery retry logic  
- Added CSV export option
- Performance: 40% faster report generation

Fixes #234
Closes #235
```

### 4. Pull Request Process

#### Create Pull Request
1. **Push your branch** to your fork
2. **Open a Pull Request** on GitHub
3. **Complete the PR template** thoroughly

**PR Template:**
```markdown
## Description
[Brief description of changes]

## Type of Change
- [ ] New feature
- [ ] Bug fix
- [ ] Documentation update
- [ ] Performance improvement

## Related Issues
Fixes #[issue number]

## Changes Made
- [Change 1]
- [Change 2]
- [Change 3]

## Testing Performed
- [Test 1]
- [Test 2]

## Checklist
- [ ] Code follows style guidelines
- [ ] Help documentation updated
- [ ] No breaking changes
- [ ] Local tests pass
- [ ] New dependencies documented
- [ ] .env.example updated if needed
```

#### PR Review Process
1. **Code Review**: Maintainers review for quality, security, and consistency
2. **Automated Tests**: GitHub Actions runs PSScriptAnalyzer and tests
3. **Discussion**: Questions and suggestions for improvement
4. **Approval**: Maintainer approves when all criteria met
5. **Merge**: PR merged to develop branch

#### Expected Review Timeline
- Minor fixes: 2-5 business days
- Features: 5-10 business days
- Large changes: Up to 2 weeks

## 📚 Documentation Updates

When contributing documentation:
- **Use Markdown** formatting correctly
- **Include code examples** where helpful
- **Update table of contents** in README
- **Add cross-references** to related docs
- **Check links** are valid

## 🔒 Security Guidelines

### Credential Management
- ✅ **Never** commit credentials to version control
- ✅ Use environment variables from `.env`
- ✅ Update `.env.example` with non-sensitive examples only
- ✅ Mark sensitive parameters with `[SecureString]`

### Code Review for Security
- Check for hardcoded passwords/API keys
- Verify credential handling is proper
- Ensure error messages don't leak sensitive info
- Review input validation for injection vulnerabilities

## 📖 Documentation Standards

### README Updates
- Include clear description of new features
- Provide usage examples
- Document new parameters
- Update prerequisites if needed

### Comments
```powershell
# Good: Explains WHY, not just WHAT
# Retry with exponential backoff to handle transient DNS failures
$retryCount = 0
while ($retryCount -lt 3) {
    try {
        Resolve-DnsName -Name $fqdn -ErrorAction Stop
        break
    }
    catch {
        $retryCount++
        Start-Sleep -Milliseconds (1000 * [Math]::Pow(2, $retryCount))
    }
}

# Avoid: Obvious comments that duplicate code
# Set $count to 0
$count = 0
```

## 🚀 Development Workflow

### Main Branches
- **main**: Production-ready, releases only
- **develop**: Integration branch, next release
- **feature/***: Feature development
- **bugfix/***: Bug fixes
- **docs/***: Documentation updates

### Branching Strategy
```
main (release) ← develop ← feature/new-feature
                       ↑ feature/another-feature
                       ↑ bugfix/issue-fix
```

## ✅ Verification Checklist

Before submitting your PR:

```powershell
# Run PSScriptAnalyzer
Invoke-ScriptAnalyzer -Path . -Recurse

# Check for common issues
gci *.ps1 -r | %{
    $content = Get-Content $_.FullName
    
    # Check for hardcoded credentials
    if ($content -match 'password\s*=\s*["\']') {
        Write-Warning "Possible hardcoded password: $($_.Name)"
    }
    
    # Check for proper help
    if ($content -notmatch '\.SYNOPSIS') {
        Write-Warning "Missing SYNOPSIS: $($_.Name)"
    }
}

# Syntax check
gci *.ps1 -r | %{
    [System.Management.Automation.PSParser]::Tokenize(
        (Get-Content $_), 
        [ref]$null
    )
}
```

## 📞 Questions?

- **Documentation**: Check inline comments and `Get-Help`
- **Issues**: Search existing GitHub issues
- **Discussions**: Start a GitHub discussion
- **Email**: Contact project maintainers

## 🎉 Thank You!

Thank you for contributing! Your improvements help make this project better for everyone.

---

**Last Updated:** March 24, 2026  
**Contributing Guidelines Version:** 1.0
