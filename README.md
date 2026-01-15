# HelloID-Conn-SA-Full-Microsoft-AD-AccountDisable

| :information_source: Information |
| :------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible for acquiring the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

## Description
_HelloID-Conn-SA-Full-Microsoft-AD-AccountDisable_ is a template designed for use with HelloID Service Automation (SA) Delegated Forms. It can be imported into HelloID and customized according to your requirements. 

By using this delegated form, you can disable AD users. The following options are available:
 1. Search and select the user
 2. User is disabled in AD

## Getting started
### Requirements

- **Active Directory Service Account Permissions**:<br>
  The service account used for the connection must have permissions to:
  - Search and retrieve active user accounts from Active Directory
  - Disable user accounts using the `Disable-ADAccount` cmdlet
  - Read user properties (DisplayName, Mail, UserPrincipalName, etc.)

### Global Variables

The following global variables are used by the connector.

| Variable | Description | Mandatory |
| -------- | ---------------------------------- | --------- |
| ADusersSearchOU | The organizational units (OUs) to search for disabled AD users. Multiple OUs can be specified separated by semicolons (;) | Yes |

## Remarks

### AD Account Disable Functionality
- **PowerShell Data Source for User Search**: A PowerShell data source retrieves active AD users from the configured OUs. The search supports wildcards across DisplayName, Mail, UserPrincipalName, and SamAccountName.
- **User Properties Retrieved**: The data source returns the following properties: SamAccountName, DisplayName, UserPrincipalName, Enabled, Description, Company, Department, Title, and ObjectGuid.
- **Disable-ADAccount Usage**: The account deactivation task uses the `Disable-ADAccount` cmdlet with the user's ObjectGuid for precise identification and disablement.

## Development resources

### PowerShell Cmdlets

The following PowerShell cmdlets are used by the connector:

| Cmdlet | Description |
| -------- | ------------------------- |
| `Get-ADUser` | Retrieve active user accounts from Active Directory |
| `Disable-ADAccount` | Disable user accounts in Active Directory |

### Documentation

For more information on the PowerShell cmdlets used in this connector, please refer to:
- [Disable-ADAccount](https://docs.microsoft.com/en-us/powershell/module/activedirectory/disable-adaccount)
- [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)

## Getting help
> :bulb: **Tip:**  
> _For more information on Delegated Forms, please refer to our [documentation](https://docs.helloid.com/en/service-automation/delegated-forms.html) pages_.

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
