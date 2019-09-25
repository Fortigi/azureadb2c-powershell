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

Function Get-AADB2CPolicy {
    <#
    .SYNOPSIS
        Gets an Azure AD B2C policies.
    .DESCRIPTION
        The Get-AADB2CPolicy cmdlet gets an Azure Active Directory B2C policies.
    .PARAMETER CLientID
        Specify the client ID you which to use.
    .PARAMETER ClientSecret
        Specify the Client Secret you which to use.
    .PARAMETER TenantID
        Specify the Azure AD B2C tenant ID.
    .EXAMPLE
        PS C:\>Get-AADB2CPolicy -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -ClientSecret xxxxxxxxxxxxxxxxxxx -TenantId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        This command gets a list of policy names from your Azure AD B2C tenant
    .LINK
        New-AADB2CPolicy
        Remove-AADB2CPolicy
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId
    )

    #Get Token
    $Body = @{client_id = $ClientID; client_secret = $ClientSecret; grant_type = "client_credentials"; scope = "https://graph.microsoft.com/.default"; }
    $OAuthReq = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Body $Body
    $AccessToken = $OAuthReq.access_token

    #Get Policies
    $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" } -Uri  https://graph.microsoft.com/beta/trustFramework/policies -Method Get


    #Retun
    [array]$Policies = $Result.value

    return $Policies
}

function New-AADB2CPolicy {
    <#
    .SYNOPSIS
        Creates a B2C policy.
    .DESCRIPTION
        The New-AADB2CPolicy cmdlet creates an Azure Active Directory B2C policy.
    .PARAMETER CLientID
        Specify the client ID you which to use.
    .PARAMETER ClientSecret
        Specify the Client Secret you which to use.
    .PARAMETER TenantID
        Specify the Azure AD B2C tenant ID.
    .PARAMETER Policy
        Specifies a XML policy.
    .PARAMETER FilePath
        Specifies a path to a file.
    .EXAMPLE
        PS C:\>New-AADB2CPolicy -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -ClientSecret xxxxxxxxxxxxxxxxxxx -TenantId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -Policy <string>
        This command creates a policy from a string in your Azure AD B2C tenant
    .EXAMPLE
        PS C:\>New-AADB2CPolicy -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -ClientSecret xxxxxxxxxxxxxxxxxxx -TenantId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -FilePath <path>
        This command creates a policy from a file in your Azure AD B2C tenant
    .EXAMPLE
        PS C:\>New-AADB2CPolicy -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -ClientSecret xxxxxxxxxxxxxxxxxxx -TenantId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -FilePath <path> -Overwrite $True
        This command creates a policy from a file in your Azure AD B2C tenant, using the -overwrite $true will overwrite any exisitng policy.
    .LINK
        Get-AADB2CPolicy
        Remove-AADB2CPolicy
    #>
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Policy")]
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "PolicyFile")]
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        [parameter(Mandatory = $true, ParameterSetName = "Policy")]
        [ValidateNotNullOrEmpty()]
        [String]$Policy,
        [parameter(Mandatory = $true, ParameterSetName = "PolicyFile")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { Test-Path -Path $_ -PathType Leaf })]
        [String]$FilePath,
        [parameter(Mandatory = $false)]
        [System.Boolean]$Overwrite
    )

    #Get Token
    $Body = @{client_id = $ClientID; client_secret = $ClientSecret; grant_type = "client_credentials"; scope = "https://graph.microsoft.com/.default"; }
    $OAuthReq = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Body $Body
    $AccessToken = $OAuthReq.access_token

    #Get Policy Content
    if ($FilePath) {
        $Policy = (Get-Content -Path $FilePath -Encoding UTF8) -join "`n"
        [xml]$PolicyXML = (Get-Content -Path $FilePath -Encoding UTF8) -join "`n"
    }

    $PolicyID = $PolicyXML.TrustFrameworkPolicy.PolicyId

    #Check if exists
    $Result = $Null
    if ($PolicyID) {
        $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" } -Uri  https://graph.microsoft.com/beta/trustFramework/policies/$PolicyID -Method Get

        if ($Result.id) {
            if ($Overwrite) {
                if ($pscmdlet.ShouldProcess("policy")) {
        
                    #Update existing policy
                    $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" }`
                        -ContentType "application/xml"`
                        -Method PUT`
                        -Body $Policy`
                        -Uri  ('https://graph.microsoft.com/beta/trustFramework/policies/'+$Result.id+'/$value')
                }
            }
            else {
                Write-Error "Policy $PolicyId already exists. Use -Overwrite $True to overwrite."
            }
        }
        else {
            if ($pscmdlet.ShouldProcess("policy")) {
                #Upload Policy
                $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" }`
                    -ContentType "application/xml"`
                    -Method Post`
                    -Body $Policy`
                    -Uri  https://graph.microsoft.com/beta/trustFramework/policies
            }
        }
    }
    else {
        Write-Error "Policy File: $FilePat invallid."
    }
}

function Remove-AADB2CPolicy {
    <#
    .SYNOPSIS
        Removes an Azure AD B2C Policy
    .DESCRIPTION
        The Remove-AzureADB2CPolicy cmdlet removes an Azure Active Directory B2C policy.
    .PARAMETER CLientID
        Specify the client ID you which to use.
    .PARAMETER ClientSecret
        Specify the Client Secret you which to use.
    .PARAMETER TenantID
        Specify the Azure AD B2C tenant ID.
    .PARAMETER FilePath
        Specifies a path to a file.
    .EXAMPLE
        PS C:\>Remove-AADB2CPolicy -ClientId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -ClientSecret xxxxxxxxxxxxxxxxxxx -TenantId xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -PolicyID B2C_1A_xxxxxxxx
        This command removes a policy from your Azure AD B2C tenant
     .LINK
        Get-AADB2CPolicy
        New-AADB2CPolicy
    #>
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Policy")]
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "PolicyFile")]
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        [parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,
        [parameter(Mandatory = $true, ParameterSetName = "Policy")]
        [ValidateNotNullOrEmpty()]
        [String]$Policy,
        [parameter(Mandatory = $true, ParameterSetName = "PolicyFile")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { Test-Path -Path $_ -PathType Leaf })]
        [String]$FilePath,
        [parameter(Mandatory = $false)]
        [System.Boolean]$Overwrite
    )

    #Get Token
    $Body = @{client_id = $ClientID; client_secret = $ClientSecret; grant_type = "client_credentials"; scope = "https://graph.microsoft.com/.default"; }
    $OAuthReq = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token -Body $Body
    $AccessToken = $OAuthReq.access_token

    #Get Policy Content
    if ($FilePath) {
        $Policy = (Get-Content -Path $FilePath -Encoding UTF8) -join "`n"
        [xml]$PolicyXML = (Get-Content -Path $FilePath -Encoding UTF8) -join "`n"
    }

    $PolicyID = $PolicyXML.TrustFrameworkPolicy.PolicyId

    #Check if exists
    $Result = $Null
    if ($PolicyID) {
        $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" } -Uri  https://graph.microsoft.com/beta/trustFramework/policies/$PolicyID -Method Get

        if ($Result.id) {
            if ($Overwrite) {
                if ($pscmdlet.ShouldProcess("policy")) {
        
                    #Update existing policy
                    $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" }`
                        -ContentType "application/xml"`
                        -Method PUT`
                        -Body $Policy`
                        -Uri  ('https://graph.microsoft.com/beta/trustFramework/policies/'+$Result.id+'/$value')
                }
            }
            else {
                Write-Error "Policy $PolicyId already exists. Use -Overwrite $True to overwrite."
            }
        }
        else {
            if ($pscmdlet.ShouldProcess("policy")) {
                #Upload Policy
                $Result = Invoke-RestMethod -Headers @{Authorization = "Bearer $AccessToken" }`
                    -ContentType "application/xml"`
                    -Method Post`
                    -Body $Policy`
                    -Uri  https://graph.microsoft.com/beta/trustFramework/policies
            }
        }
    }
    else {
        Write-Error "Policy File: $FilePat invallid."
    }
}