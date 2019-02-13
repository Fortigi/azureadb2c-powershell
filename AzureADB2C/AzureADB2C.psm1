<#
MIT License

Copyright (c) 2019 Fortigi. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

function Get-AzureADB2CAccessToken {
    <#
    .SYNOPSIS
        Gets an OAuth2 Access Token for Azure AD B2C
    .DESCRIPTION
        The Get-AzureADB2CAccessToken cmdlet gets an Azure Active Directory B2C OAuth2 Access Token.
        Created by fortigi (www.fortigi.nl)
    .PARAMETER TenantId
        Specifies the ID of a tenant.
    .PARAMETER Username
        Specifies the name of a user within the tenant.
    .PARAMETER Password
        Specifies the password.
    .EXAMPLE
        PS C:\>Get-AzureADB2CAccessToken -Username <username> -Password <plaintextpassword> -TenantId <your-azuread-tenant>
        This command gets an access token for your Azure AD B2C tenant and when multiple are available selects the last one issued.
    .LINK
        Get-AzureADB2CSession
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Password
    )

    # Log in to Azure.
    $User = $Username + "@" + $TenantId
    $Cred = New-Object System.Management.Automation.PSCredential ($User, ($Password | ConvertTo-SecureString -AsPlainText -Force))
    Login-AzureRmAccount -TenantId $TenantId -Credential $Cred | Out-Null

    # Retrieve all tokens
    $context = Set-AzureRmContext -TenantId $TenantId -Name B2C -Force
    $tokens = $context.TokenCache.ReadItems()

    # Get the right token
    $tokens = $tokens | Where-Object {$_.TenantId -eq $context.Tenant.TenantId}  #Tokens for this tenant
    $tokens = $tokens | Where-Object {$_.DisplayableId -eq $context.Account}  #Tokens for this user
    $token = $tokens | Sort-Object -Property ExpiresOn -Descending | Select-Object -First 1 #The most recent one.
    return $token.AccessToken
}

function Get-AzureADB2CSession {
    <#
    .SYNOPSIS
        Gets a web session for AzureADB2C module functions
    .DESCRIPTION
        The Get-AzureADB2CSession cmdlet gets an web session to access Azure AD web functions via this module's functions
        Created by fortigi (www.fortigi.nl)
    .PARAMETER TenantId
        Specifies the ID of a tenant.
    .PARAMETER Username
        Specifies the name of a user within the tenant.
    .PARAMETER Password
        Specifies the password.
    .EXAMPLE
        PS C:\>Get-AzureADB2CAccessToken -Username <username> -Password <plaintextpassword> -Tenant <your-azuread-tenant>
        This command gets a Azure AD B2C web session for username@your-azuread-tenant.
    .LINK
        Get-AzureADB2CAccessToken
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Password
    )

    $accesstoken = Get-AzureADB2CAccessToken -Username $Username -Password $Password -TenantId $TenantId

    $b2csession = [PSCustomObject]@{
        TenantId    = $TenantId
        AccessToken = $accesstoken
    }

    return $b2csession
}

function Get-AzureADB2CPolicy {
    <#
    .SYNOPSIS
        Gets an B2C policy.
    .DESCRIPTION
        The Get-AzureADB2CPolicy cmdlet gets an Azure Active Directory B2C policy.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .EXAMPLE
        PS C:\>Get-AzureADB2CPolicy -B2CSession <b2csession>
        This command gets a list of policy names from your Azure AD B2C tenant
    .LINK
        New-AzureADB2CPolicy
        Remove-AzureADB2CPolicy
    #>    
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/policyList?tenantId=$($B2CSession.TenantId)"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -ContentType "application/json" | ConvertFrom-Json
    return $response
}

function New-AzureADB2CPolicy {
    <#
    .SYNOPSIS
        Creates a B2C policy.
    .DESCRIPTION
        The New-AzureADB2CPolicy cmdlet creates an Azure Active Directory B2C policy.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER Policy
        Specifies a XML policy.
    .PARAMETER FilePath
        Specifies a path to a file.        
    .EXAMPLE
        PS C:\>New-AzureADB2CPolicy -B2CSession <b2csession> -Policy <string>
        This command creates a policy from a string in your Azure AD B2C tenant
    .EXAMPLE
        PS C:\>New-AzureADB2CPolicy -B2CSession <b2csession> -FilePath <path>
        This command creates a policy from a file in your Azure AD B2C tenant
    .LINK
        Get-AzureADB2CPolicy
        Remove-AzureADB2CPolicy
    #>  
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Policy")]
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "PolicyFile")]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, ParameterSetName = "Policy")]
        [ValidateNotNullOrEmpty()]
        [string]$Policy,
        [parameter(Mandatory = $true, ParameterSetName = "PolicyFile")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {  Test-Path -Path $_ -PathType Leaf  })]
        [string]$FilePath
    )

    if ($FilePath) {
        $Policy = (Get-Content -Path $FilePath -Encoding UTF8) -join "`n"
    }

    $uri = "https://main.b2cadmin.ext.azure.com/api/trustframework?tenantId=$($B2CSession.TenantId)&overwriteIfExists=true"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)" }

    Add-Type -AssemblyName System.Web
    $body = "<string xmlns=`"http://schemas.microsoft.com/2003/10/Serialization/`">$([System.Web.HttpUtility]::HtmlEncode($Policy))</string>"

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/xml" -Headers $headers -UseBasicParsing

    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to create policy"
    }
}

function Remove-AzureADB2CPolicy {
    <#
    .SYNOPSIS
        Deletes a B2C policy
    .DESCRIPTION
        The Remove-AzureADB2CPolicy cmdlet removes the specified policy from Azure Active Directory B2C.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER PolicyId
        Specifies the ID of a policy in Azure AD B2C.
    .EXAMPLE
        PS C:\>Remove-AzureADB2CPolicy -B2CSession <b2csession> -PolicyId <string>
        This command removes the policy with the given policyId from your Azure AD B2C tenant
    .LINK
        Get-AzureADB2CPolicy
        New-AzureADB2CPolicy
    #>  
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/trustframework?tenantId=$($B2CSession.TenantId)&policyId=$PolicyId"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers

    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to remove policy"
    }
}

function Get-AzureADB2CKeyContainer {
    <#
    .SYNOPSIS
        Gets a B2C keycontainer.
    .DESCRIPTION
        The Get-AzureADB2CKeyContainer cmdlet gets an Azure AD B2C directory keycontainer.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER Name
        Specifies the name of a keycontainer in Azure AD B2C.
    .EXAMPLE
        PS C:\>Get-AzureADB2CKeyContainer -B2CSession <b2csession>
        This command gets all keycontainers of your Azure AD B2C tenant
    .LINK
        New-AzureADB2CKeyContainer
        Remove-AzureADB2CKeyContainer        
    #>  
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Name
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/Jwks/GetKeyList?tenantId=$($B2CSession.TenantId)&options=6"
    if ($Name) {
        $uri = "https://main.b2cadmin.ext.azure.com/api/Jwks/GetKeySetMetadata?tenantId=$($B2CSession.TenantId)&storageReferenceId=$Name"
    }
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -ContentType "application/json" | ConvertFrom-Json
    
    return $response
}

function New-AzureADB2CKeyContainer {
    <#
    .SYNOPSIS
        Creates a B2C RSA keycontainer.
    .DESCRIPTION
        The New-AzureADB2CKeyContainer cmdlet creates an Azure Active Directory B2C RSA keycontainer.
        The keycontainer can be used for encryption or signing.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER Name
        Specifies the name of a keycontainer.
    .PARAMETER KeyUsage
        Specifies the key usage 
        The acceptable values for this paramter are:
        - enc
        - sig
    .EXAMPLE
        PS C:\>New-AzureADB2CKeyContainer -B2CSession <b2csession> -Name "New Name" -KeyUsage enc
        This command creates a new keycontainer for encryption in your Azure AD B2C tenant
    .EXAMPLE
        PS C:\>New-AzureADB2CKeyContainer -B2CSession <b2csession> -Name "New Name" -KeyUsage sig
        This command creates a new keycontainer for signing in your Azure AD B2C tenant
    .LINK
        Get-AzureADB2CKeyContainer
        Remove-AzureADB2CKeyContainer        
    #> 
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateSet(
            'enc',
            'sig'
        )]        
        [ValidateNotNullOrEmpty()]
        [string]$KeyUsage    
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/Jwks/PutNewKey?tenantId=$($B2CSession.TenantId)&storageReferenceId=$Name&secretType=rsa&keySize=0&keyUsage=$KeyUsage"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Method PUT -Headers $headers -UseBasicParsing

    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to create keycontainer"
    }
}

function Remove-AzureADB2CKeyContainer {
    <#
    .SYNOPSIS
        Deletes a B2C keycontainer by name. 
    .DESCRIPTION
        The Remove-AzureADB2CKeyContainer cmdlet removes an Azure Active Directory B2C keycontainer.
        Azure AD B2C will automatically create a backup with the same name followed by a .bak extension. 
        Also remove this keycontainer if you want to fully delete the keycontainer.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER Name
        Specifies the name of a keycontainer.
    .EXAMPLE
        PS C:\>Remove-AzureADB2CKeyContainer -B2CSession <b2csession> -KeyName <string>
        This command removes the keycontainer with the given name from your Azure AD B2C tenant
    .EXAMPLE
        PS C:\>Remove-AzureADB2CKeyContainer -B2CSession <b2csession> -KeyName <string>.bak
        This command removes the backup of the keycontainer with the given name from your Azure AD B2C tenant    
    .LINK
        Get-AzureADB2CKeyContainer
        New-AzureADB2CKeyContainer        
    #>  
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/Jwks/DeleteKeySet?tenantId=$($B2CSession.TenantId)&storageReferenceId=$Name"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers

    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to Remove-AzureADB2CKeyContainer"
    }
}

function Get-AzureADB2CApplication {
    <#
    .SYNOPSIS
        Gets a B2C application.
    .DESCRIPTION
        The Get-AzureADB2CApplication cmdlet gets an Azure Active Directory B2C application.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER ApplicationId
        Specifies the ID of an Azure Active Directory B2C application.
    .EXAMPLE
        PS C:\>Get-AzureADB2CApplication -B2CSession $b2csession
        This command gets all B2C applications of your Azure AD B2C tenant.
    .EXAMPLE
        PS C:\>Get-AzureADB2CApplication -B2CSession $b2csession -ApplicationId ed192e92-84d4-4baf-997d-1e190a81f28e
        This command gets an application by its ID.
    .LINK
        New-AzureADB2CApplication
        Remove-AzureADB2CApplication
        Set-AzureADB2CApplication
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationId
    )

    if ($ApplicationId) {
        $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/GetApplication?tenantId=$($B2CSession.TenantId)&applicationId=$ApplicationId"    
    }
    else {
        $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/GetAllV2Applications?tenantId=$($B2CSession.TenantId)"
    }
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -ContentType "application/json" | ConvertFrom-Json

    return $response
}

function New-AzureADB2CApplication {
    <#
    .SYNOPSIS
        Creates a B2C application.
    .DESCRIPTION
        The New-AzureADB2CApplication cmdlet creates an Azure AD B2C application.
        Reply URLs must all be hosted at the same domain or localhost.

        https://example.org
        https://example.org:1234
        https://example.org/signin-oidc
        https://subdomain.example.org
        https://localhost:1234
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER Name
        Specifies the name of an Azure AD B2C application.
    .PARAMETER ReplyUrls
        Specifies the reply URLs of an Azure AD B2C application.
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -Name "New Name" -ReplyUrls https://localhost:1234
        This command creates a B2C application in your Azure AD B2C tenant with it's reply URL set to localhost
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -Name "New Name" -ReplyUrls @("https://localhost:1234", "https://www.example.org")
        This command creates a B2C application in your Azure AD B2C tenant with multiple reply URLs
    .LINK
        Get-AzureADB2CApplication
        Remove-AzureADB2CApplication        
        Set-AzureADB2CApplication
    #> 
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ReplyUrls
    )
    
    [System.Collections.ArrayList]$replyUrlsData = @()
    if ($ReplyUrls) {
        foreach ($replyUrl in $ReplyUrls) {
            $replyUrlData = @{ "url" = "$replyUrl"; "type" = 1 }
            $replyUrlsData.Add($replyUrlData) | Out-Null
        }
    }

    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/PostNewApplication?tenantId=$($B2CSession.TenantId)"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)" }
    $body = @{ "id" = ""; "applicationVersion" = 1; "applicationId" = ""; "applicationName" = "$Name"; "enableWebClient" = "true"; "webClientAllowImplicitFlow" = "true"; "replyUrls" = $ReplyUrls; "webClientAppKeys" = @(); "enableNativeClient" = "false"; "identifierUris" = @(); "oAuth2Permissions" = @(); "replyUrlsData" = $replyUrlsData } | ConvertTo-Json -Compress

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/json" -Headers $headers -UseBasicParsing

    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to create AzureADB2CApplication"
    }
}

function Set-AzureADB2CApplication {
    <#
    .SYNOPSIS
        Updates a B2C application.
    .DESCRIPTION
        The Set-AzureADB2CApplication cmdlet updates an Azure Active Directory B2C application.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER ApplicationId
        Specifies the ID of an Azure Active Directory B2C application.        
    .PARAMETER Name
        Specifies the name of an Azure AD B2C application.
    .PARAMETER ReplyUrl
        Specifies the reply URL of an Azure AD B2C application.
    .PARAMETER ReplyUrls
        Specifies the reply URLs of an Azure AD B2C application.
    .PARAMETER RequiredResourceAccess
        Specifices the API and scopes that an Azure AD B2C application can access
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -ApplicationId ed192e92-84d4-4baf-997d-1e190a81f28e -Name "New Name" -ReplyUrl https://localhost:1234
        This command sets a new name and reply URL for a B2C application in your Azure AD B2C tenant
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -ApplicationId ed192e92-84d4-4baf-997d-1e190a81f28e -RequiredResourceAccess <scopes>
        This command sets the scopes that a B2C application can access
    .LINK
        Get-AzureADB2CApplication
        New-AzureADB2CApplication
        Remove-AzureADB2CApplication
    #> 
    [CmdletBinding(DefaultParameterSetName='Attributes')]
    Param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Attributes")]
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Scope")]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1, ParameterSetName = "Attributes")]
        [parameter(Mandatory = $true, Position = 1, ParameterSetName = "Scope")]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationId,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [string[]]$ReplyUrls,
        [parameter(Mandatory = $false, ParameterSetName = "Scope")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]$RequiredResourceAccess     
    )
    
    $application = Get-AzureADB2CApplication -B2CSession $B2CSession -ApplicationId $ApplicationId

    if ($ReplyUrls) {
        [System.Collections.ArrayList]$replyUrlsData = @()
        foreach ($replyUrl in $ReplyUrls) {
            $replyUrlData = @{ "url" = "$replyUrl"; "type" = 1 }
            $replyUrlsData.Add($replyUrlData) | Out-Null
        }

        $application.replyUrls = $ReplyUrls
        $application.replyUrlsData = $replyUrlsData
    } 

    if ($Name) {
        $application.applicationName = $Name
    }

    $response = $null
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    if ($RequiredResourceAccess) {
        $serviceprincipal = Get-AzureADServicePrincipal -Filter "AppId eq '$($RequiredResourceAccess.ResourceAppId)'"
        $permissions = Get-AzureADB2CApplicationPermission -B2CSession $B2CSession -ApplicationId $ApplicationId
        $permission = $permissions | Where-Object { $_.resourceId -eq $serviceprincipal.ObjectId }

        [System.Collections.ArrayList]$scopes = @()
        foreach ($access in $req.ResourceAccess) { 
            $scope = $serviceprincipal.Oauth2Permissions | where-object { $_.Id -eq $access.Id }
            $scopes.Add($scope.Value) | Out-Null
        }
        
        if ($permission) {
            $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/UpdatePermission?tenantId=$($B2CSession.TenantId)" 
            $permission.permissionValues = $scopes
            $body = $permission | ConvertTo-Json -Compress

            $response = Invoke-WebRequest -Uri $uri -Method PATCH -Body $body -ContentType "application/json" -Headers $headers -UseBasicParsing
        } else {
            $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/AddPermissions?tenantId=$($B2CSession.TenantId)&clientApplicationId=$ApplicationId&resourceApplicationId=$($RequiredResourceAccess.ResourceAppId)" 
            $body = ConvertTo-Json -Compress -InputObject @($scopes)
            
            $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/json" -Headers $headers
        }
    } else {
        $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/PatchApplication?tenantId=$($B2CSession.TenantId)&id=$($application.id)"
        $body = $application | ConvertTo-Json -Compress

        $response = Invoke-WebRequest -Uri $uri -Method PATCH -Body $body -ContentType "application/json" -Headers $headers -UseBasicParsing
    }
    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to update AzureADB2CApplication"
    }
}

function Remove-AzureADB2CApplication {
    <#
    .SYNOPSIS
        Deletes a B2C application.
    .DESCRIPTION
        The Remove-AzureADB2CApplication cmdlet removes an Azure Active Directory B2C application.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER ObjectId
        Specifies the object ID of an Azure Active Directory B2C application. 
    .EXAMPLE
        PS C:\>Remove-AzureADB2CApplication -B2CSession <b2csession> -ApplicationObjectId <string>
        This command removes the B2C applicaiont with the given object ID from your Azure AD B2C tenant 
    .LINK
        Get-AzureADB2CApplication
        New-AzureADB2CApplication
        Set-AzureADB2CApplication        
    #> 
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectId
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/DeleteApplication?tenantId=$($B2CSession.TenantId)&id=$ObjectId"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers
   
    if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to remove AzureADB2CApplication"
    }
}

function Get-AzureADB2CApplicationPermission {
    <#
    .SYNOPSIS
        Gets all permissions for a B2C application.
    .DESCRIPTION
        The Get-AzureADB2CApplicationPermissions cmdlet gets a list of permissions for an Azure Active Directory B2C application.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER ApplicationId
        Specifies the ID of an Azure Active Directory B2C application.
    .EXAMPLE
        PS C:\>Get-AzureADB2CApplicationPermission -B2CSession $b2csession -ApplicationId ed192e92-84d4-4baf-997d-1e190a81f28e
        This command gets a list of permissions for the given application.
    .LINK
        Set-AzureADB2CApplication
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationId
    )
            
    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/RetrievePermissions?tenantId=$($B2CSession.TenantId)&clientApplicationId=$ApplicationId"    
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -ContentType "application/json" | ConvertFrom-Json

    return $response
}
