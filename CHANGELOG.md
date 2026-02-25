# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.0.1] - 2026-02-25

### Changed

- Updated example value for `AdUsersEnabledSearchOu` global variable to provide a clearer demonstration of multiple OU syntax

## [1.0.0] - 2026-01-15

This is the first official release of _HelloID-Conn-SA-Full-Microsoft-AD-AccountDisable_.

### Added

- Initial release of HelloID Service Automation (SA) connector for Microsoft Active Directory
- Delegated form for searching and disabling AD user accounts
- PowerShell data source for retrieving enabled AD users from configured OUs with wildcard search support
- Support for multiple organizational units (OUs) via semicolon-separated configuration
- User properties retrieval: ObjectGuid, SamAccountName, DisplayName, UserPrincipalName, Enabled, Description, Company, Department, Title
- Account disablement using `Disable-ADAccount` cmdlet with ObjectGuid for precise identification
- Wildcard search capability in Name, DisplayName, UserPrincipalName, and Mail fields
- Support for searching all users using asterisk (*) wildcard
- Grid filtering and CSV download functionality in the delegated form
- GitHub Actions workflows for automated release and changelog verification
- Comprehensive documentation and development resources

### Changed

- Renamed all references from "Deactivate" to "Disable" for consistency with AD terminology
- Renamed global variable from `ADusersSearchOU` to `AdUsersEnabledSearchOu` for clarity
- Renamed datasource to `ad-account-disable | AD-Get-Enabled-Users-Wildcard-Name-DisplayName-UPN-Mail`
- Renamed delegated form and task to "AD Account - Disable"
- Updated form field key from `searchfield`/`searchUser` to `searchValue` for consistency
- Improved search placeholder text to clarify wildcard search functionality
- Reordered delegated form categories to "User Management", "Active Directory"
- Refactored user query logic to use ArrayList for better performance
- Enhanced search filter to explicitly handle asterisk (*) for retrieving all users
- Moved ObjectGuid to first position in properties list for better data organization
- Updated logging messages for improved clarity and consistency
- Enabled grid filtering (`useFilter: true`) in the dynamic form
- Removed verbose success message from task script for cleaner output

### Fixed

- Improved error handling in datasource query logic
- Corrected property selection order to match data model requirements
