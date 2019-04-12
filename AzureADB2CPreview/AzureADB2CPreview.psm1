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
    [OutputType([String])]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$TenantId,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Username,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Password
    )

    # Log in to Azure.
    $User = $Username + "@" + $TenantId
    $Cred = New-Object System.Management.Automation.PSCredential ($User, ($Password | ConvertTo-SecureString -AsPlainText -Force))
    [void](Connect-AzAccount -TenantId $TenantId -Credential $Cred)

    # Retrieve all tokens
    $context = Get-AzContext
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
        [String]$TenantId,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Username,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$Password
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
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Policy")]
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "PolicyFile")]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, ParameterSetName = "Policy")]
        [ValidateNotNullOrEmpty()]
        [String]$Policy,
        [parameter(Mandatory = $true, ParameterSetName = "PolicyFile")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( {  Test-Path -Path $_ -PathType Leaf  })]
        [String]$FilePath
    )

    if ($FilePath) {
        $Policy = (Get-Content -Path $FilePath -Encoding UTF8) -join "`n"
    }

    $uri = "https://main.b2cadmin.ext.azure.com/api/trustframework?tenantId=$($B2CSession.TenantId)&overwriteIfExists=true"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)" }

    Add-Type -AssemblyName System.Web
    $body = "<string xmlns=`"http://schemas.microsoft.com/2003/10/Serialization/`">$([System.Web.HttpUtility]::HtmlEncode($Policy))</string>"

    if ($pscmdlet.ShouldProcess("policy")) {
        $response = $null
        $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/xml" -Headers $headers -UseBasicParsing

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to create policy"
            return
        }
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
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$PolicyId
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/trustframework?tenantId=$($B2CSession.TenantId)&policyId=$PolicyId"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    if ($pscmdlet.ShouldProcess($PolicyId)) {
        $response = $null
        $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to remove policy"
            return
        }
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
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateSet(
            'enc',
            'sig'
        )]
        [ValidateNotNullOrEmpty()]
        [String]$KeyUsage
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/Jwks/PutNewKey?tenantId=$($B2CSession.TenantId)&storageReferenceId=$Name&secretType=rsa&keySize=0&keyUsage=$KeyUsage"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)" }

    if ($pscmdlet.ShouldProcess($Name)) {
        $response = $null
        $response = Invoke-WebRequest -Uri $uri -Method PUT -Headers $headers -UseBasicParsing

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to create keycontainer"
            return
        }
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
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/Jwks/DeleteKeySet?tenantId=$($B2CSession.TenantId)&storageReferenceId=$Name"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    if ($pscmdlet.ShouldProcess($Name)) {
        $response = $null
        $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to Remove-AzureADB2CKeyContainer"
            return
        }
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
        [String]$ApplicationId
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
    .PARAMETER EnableWebClient
        Specifies whether this is a Web App / API
    .PARAMETER AllowImplicitFlow
        Indicates whether this application allows implicit flows (when your application needs to use OpenID Connect sign-in)
    .PARAMETER IdentifierUri
        Specifies the unique URI to identify the API
    .PARAMETER ReplyUrls
        Specifies the reply URLs of an Azure AD B2C application.
    .PARAMETER EnableNativeClient
        Specifies whether this is a Native app
    .PARAMETER RedirectUris
        Specifies the redirect URIs of an Azure AD B2C application.
    .PARAMETER OAuth2Permissions
        The collection of OAuth 2.0 permission scopes that the web API (resource) application exposes to client
        applications. These permission scopes may be granted to client applications during consent.
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -Name "New Name" -ReplyUrls https://localhost:1234
        This command creates a B2C application in your Azure AD B2C tenant with it's reply URL set to localhost
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -Name "New Name" -ReplyUrls @("https://localhost:1234", "https://www.b2ccontoso.com")
        This command creates a B2C application in your Azure AD B2C tenant with multiple reply URLs
    .EXAMPLE
        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -Name "New Name" -EnableNativeClient -RedirectUris com.b2ccontoso://redirect/path
        This command creates a B2C application in your Azure AD B2C tenant with it's reply URL set to localhost
    .LINK
        Get-AzureADB2CApplication
        Remove-AzureADB2CApplication
        Set-AzureADB2CApplication
    #>
    [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = "WebClient")]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
        [parameter(Mandatory = $false, ParameterSetName = "WebClient")]
        [parameter(Mandatory = $true, ParameterSetName = "WebAndNativeClient")]
        [ValidateNotNullOrEmpty()]
        [Boolean]$EnableWebClient,
        [parameter(Mandatory = $true, ParameterSetName = "WebClient")]
        [parameter(Mandatory = $true, ParameterSetName = "WebAndNativeClient")]
        [ValidateNotNullOrEmpty()]
        [String[]]$ReplyUrls,
        [parameter(Mandatory = $false, ParameterSetName = "WebClient")]
        [parameter(Mandatory = $false, ParameterSetName = "WebAndNativeClient")]
        [ValidateNotNullOrEmpty()]
        [String]$IdentifierUri,
        [parameter(Mandatory = $false, ParameterSetName = "WebClient")]
        [parameter(Mandatory = $false, ParameterSetName = "WebAndNativeClient")]
        [ValidateNotNullOrEmpty()]
        [Boolean]$AllowImplicitFlow,
        [parameter(Mandatory = $true, ParameterSetName = "NativeClient")]
        [parameter(Mandatory = $true, ParameterSetName = "WebAndNativeClient")]
        [ValidateNotNullOrEmpty()]
        [Boolean]$EnableNativeClient,
        [parameter(Mandatory = $false, ParameterSetName = "NativeClient")]
        [parameter(Mandatory = $false, ParameterSetName = "WebAndNativeClient")]
        [ValidateNotNullOrEmpty()]
        [String[]]$RedirectUris,
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Object[]]$OAuth2Permissions
    )

    $application = @{ "id" = ""; "applicationVersion" = 1; "applicationId" = ""; "applicationName" = ""; "enableWebClient" = "false"; "webClientAllowImplicitFlow" = "false"; "replyUrls" = @(); "webClientAppKeys" = @(); "enableNativeClient" = "false"; "identifierUris" = @(); "oAuth2Permissions" = @(); "replyUrlsData" = @() }

    $application.applicationName = $Name

    if ($PSCmdlet.ParameterSetName -eq "WebClient") {
        $application.enableWebClient = $True
    } else {
        $application.enableWebClient = $EnableWebClient
    }

    $application.webClientAllowImplicitFlow = $AllowImplicitFlow
    $application.enableNativeClient = $EnableNativeClient
    if ($application.enableWebClient -eq $False -and $application.enableNativeClient -eq $False) {
        Write-Error "Application must be webclient and/or native application"
        return
    }

    if ($OAuth2Permissions) {
        $application.oAuth2Permissions = $OAuth2Permissions
    }

    [System.Collections.ArrayList]$replyUrlsData = @()
    foreach ($replyUrl in $ReplyUrls) {
        $replyUrlData = @{ "url" = "$replyUrl"; "type" = 1 }
        $replyUrlsData.Add($replyUrlData) | Out-Null
    }
    foreach ($redirectUri in $RedirectUris) {
        $replyUrlData = @{ "url" = "$redirectUri"; "type" = 2 }
        $replyUrlsData.Add($replyUrlData) | Out-Null
    }
    $application.replyUrls = @( $replyUrlsData.url )
    $application.replyUrlsData = $replyUrlsData

    if ($IdentifierUri) {
        $application.identifierUris = @( $IdentifierUri )
    }

    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/PostNewApplication?tenantId=$($B2CSession.TenantId)"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)" }
    $body = $application | ConvertTo-Json -Compress

    if ($PSCmdlet.ShouldProcess($application.applicationName)) {
        $response = $null
        $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/json" -Headers $headers -UseBasicParsing

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to create AzureADB2CApplication"
            return
        }
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
    .PARAMETER IdentifierUri
        Specifies the unique URI to identify the API
    .PARAMETER OAuth2Permissions
        The collection of OAuth 2.0 permission scopes that the web API (resource) application exposes to client
        applications. These permission scopes may be granted to client applications during consent.
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
        PS C:\>$sp = Get-AzureADServicePrincipal -ObjectId <webapi objectId>
        PS C:\>$sp.Oauth2Permissions | select Id,AdminConsentDisplayName,Value

        PS C:\>$req = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
        PS C:\>$acc1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "permissionId1","Scope"
        PS C:\>$acc2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "permissionId2","Scope"
        PS C:\>$req.ResourceAccess = $acc1,$acc2
        PS C:\>$req.ResourceAppId = "<webapi appId>"

        PS C:\>New-AzureADB2CApplication -B2CSession <b2csession> -ApplicationId ed192e92-84d4-4baf-997d-1e190a81f28e -RequiredResourceAccess $req
        This command sets the scopes that a B2C application can access to permissionId1 and permissionId2 of API webapi
    .LINK
        Get-AzureADB2CApplication
        New-AzureADB2CApplication
        Remove-AzureADB2CApplication
    #>
    [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName = "Attributes")]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$ApplicationId,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [Boolean]$EnableWebClient,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [Boolean]$AllowImplicitFlow,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [String[]]$ReplyUrls,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [String]$IdentifierUri,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [Boolean]$EnableNativeClient,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [String[]]$RedirectUris,
        [parameter(Mandatory = $false, ParameterSetName = "Attributes")]
        [ValidateNotNullOrEmpty()]
        [Object[]]$OAuth2Permissions,
        [parameter(Mandatory = $false, ParameterSetName = "Scope")]
        [ValidateNotNullOrEmpty()]
        [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]$RequiredResourceAccess
    )

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

            if ($pscmdlet.ShouldProcess($ApplicationId)) {
                $response = Invoke-WebRequest -Uri $uri -Method PATCH -Body $body -ContentType "application/json" -Headers $headers -UseBasicParsing
            }
        } else {
            $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/AddPermissions?tenantId=$($B2CSession.TenantId)&clientApplicationId=$ApplicationId&resourceApplicationId=$($RequiredResourceAccess.ResourceAppId)"
            $body = ConvertTo-Json -Compress -InputObject @($scopes)

            if ($pscmdlet.ShouldProcess($ApplicationId)) {
                    $response = Invoke-WebRequest -Uri $uri -Method POST -Body $body -ContentType "application/json" -Headers $headers
            }
        }
    } else {
        $application = Get-AzureADB2CApplication -B2CSession $B2CSession -ApplicationId $ApplicationId

        if ($Name) {
            $application.applicationName = $Name
        }

        if ($PSBoundParameters.ContainsKey('AllowImplicitFlow')) {
            $application.webClientAllowImplicitFlow = $AllowImplicitFlow
        }
        if ($PSBoundParameters.ContainsKey('EnableNativeClient')) {
            $application.enableNativeClient = $EnableNativeClient
        }

        if ($null -eq $ReplyUrls) {
            $UrlsData = $application.replyUrlsData | Where-Object {$_.type -eq '1'}
            if ($null -ne $UrlsData) {
                $ReplyUrls = $UrlsData.url
            }
        }
        if ($null -eq $RedirectUris) {
            $UrlsData = $application.replyUrlsData | Where-Object {$_.type -eq '2'}
            if ($null -ne $urls) {
                $RedirectUris = $UrlsData.url
            }
        }

        if ($PSBoundParameters.ContainsKey('EnableWebClient')) {
            if ($EnableWebClient -eq $False -and $application.enableNativeClient -eq $False) {
                Write-Error "Application must be webclient and/or native application"
                return
            }
            if ($EnableWebClient -eq $False) {
                Clear-Variable ReplyUrls
            }
        } else {
            if ($null -eq $ReplyUrls -and $application.enableNativeClient -eq $False) {
                Write-Error "Application must be webclient and/or native application"
                return
            }
        }

        [System.Collections.ArrayList]$replyUrlsData = @()
        foreach ($replyUrl in $ReplyUrls) {
            $replyUrlData = @{ "url" = "$replyUrl"; "type" = 1 }
            $replyUrlsData.Add($replyUrlData) | Out-Null
        }
        foreach ($redirectUri in $RedirectUris) {
            $replyUrlData = @{ "url" = "$redirectUri"; "type" = 2 }
            $replyUrlsData.Add($replyUrlData) | Out-Null
        }
        $application.replyUrls = @( $replyUrlsData.url )
        $application.replyUrlsData = $replyUrlsData

        if ($IdentifierUri) {
            $application.identifierUris = @( $IdentifierUri )
        }

        if ($OAuth2Permissions) {
            $application.oAuth2Permissions = $OAuth2Permissions
        }

        $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/PatchApplication?tenantId=$($B2CSession.TenantId)&id=$($application.id)"
        $body = $application | ConvertTo-Json -Compress

        if ($pscmdlet.ShouldProcess($ApplicationId)) {
            $response = Invoke-WebRequest -Uri $uri -Method PATCH -Body $body -ContentType "application/json" -Headers $headers -UseBasicParsing
        }
    }

    if ($null -ne $response -and !($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
        Write-Error "Failed to update AzureADB2CApplication"
        return
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
        This command removes the B2C application with the given object ID from your Azure AD B2C tenant
    .LINK
        Get-AzureADB2CApplication
        New-AzureADB2CApplication
        Set-AzureADB2CApplication
    #>
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]$ObjectId
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/DeleteApplication?tenantId=$($B2CSession.TenantId)&id=$ObjectId"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    if ($pscmdlet.ShouldProcess($ObjectId)) {
        $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to remove AzureADB2CApplication"
            return
        }
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
        [String]$ApplicationId
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/RetrievePermissions?tenantId=$($B2CSession.TenantId)&clientApplicationId=$ApplicationId"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -ContentType "application/json" | ConvertFrom-Json

    return $response
}

function Remove-AzureADB2CApplicationPermission {
    <#
    .SYNOPSIS
        Deletes a permission from a B2C application.
    .DESCRIPTION
        The Remove-AzureADB2CApplicationPermissions cmdlet deletes a permission from an Azure Active Directory B2C application.
    .PARAMETER B2CSession
        Specifies a B2C session object containing the B2C tenant name and an OAuth2 access token.
    .PARAMETER PermissionGrantId
        Specifies the ID of an Azure Active Directory B2C permission grant.
    .EXAMPLE
        PS C:\>Remove-AzureADB2CApplicationPermission -B2CSession $b2csession -PermissionGrantId <permissiongrantid>
        This command removes the grant with the given ID from your Azure AD B2C tenant.
    .LINK
        Not used
    #>
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$B2CSession,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$PermissionGrantId
    )

    $uri = "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/DeletePermission?tenantId=$($B2CSession.TenantId)&permissionGrantId=$PermissionGrantId"
    $headers = @{ "Authorization" = "Bearer $($B2CSession.AccessToken)"; "Accept" = "application/json, text/javascript, */*; q=0.01" }

    $response = $null
    if ($pscmdlet.ShouldProcess()) {
        $response = Invoke-WebRequest -Uri $uri -Method DELETE -Headers $headers

        if (!($response.StatusCode -ge 200 -and $response.StatusCode -le 299)) {
            Write-Error "Failed to remove Permission Grant"
            return
        }
    }

    return $response
}

