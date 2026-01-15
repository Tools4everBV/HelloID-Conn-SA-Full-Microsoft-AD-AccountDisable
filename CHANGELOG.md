# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.0.0] - 2026-01-15

This is the first official release of _HelloID-Conn-SA-Full-Microsoft-AD-AccountDisable_.

### Added

- Initial release of HelloID Service Automation (SA) connector for Microsoft Active Directory
- Delegated form for searching and disabling AD user accounts
- PowerShell data source for retrieving active AD users from configured OUs with wildcard search support
- Support for multiple organizational units (OUs) via semicolon-separated configuration
- User properties retrieval: SamAccountName, DisplayName, UserPrincipalName, Enabled, Description, Company, Department, Title, ObjectGuid
- Account disablement using `Disable-ADAccount` cmdlet with ObjectGuid for precise identification
- GitHub Actions workflows for automated release and changelog verification
- Comprehensive documentation and development resources
