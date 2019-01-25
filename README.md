# Azure AD B2C PowerShell module

This module utilizes the Azure AD B2C REST API to provide the most common functionality for managing B2C policies, applications and keycontainers from the PowerShell commandline or Azure DevOps. For more info support@fortigi.nl 

The first step is to get a Azure B2C session containing the tenant ID and access token to be used in subsequent calls:
```powershell
$B2CSession = Get-AzureADB2CSession -TenantId contoso.onmicrosoft.com -Username user
```
After entering your password this command will issue a B2C session for user@contoso.onmicrosoft.com.

Now that you have a session, you can use the other functions available in this module, e.g.:
```powershell
Get-AzureADB2CPolicy -B2CSession $B2CSession
```


* Supported functions
  - Session management
    - Get-AzureADB2CSession
    - Get-AzureADB2CAccessToken

  - Policy management
    - Get-AzureADB2CPolicy
    - New-AzureADB2CPolicy
    - Remove-AzureADB2CPolicy

  - Application management
    - Get-AzureADB2CApplication
    - New-AzureADB2CApplication
    - Remove-AzureADB2CApplication
    - Set-AzureADB2CApplication

  - KeyContainer management
    - Get-AzureADB2CKeyContainer
    - New-AzureADB2CKeyContainer
    - Remove-AzureADB2CKeyContainer


