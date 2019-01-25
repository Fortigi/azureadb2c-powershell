#
# Module manifest for module 'AzureADB2C'
#
# Generated by: Maatschap Fortigi
#
# Generated on: 21/01/2019
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'AzureADB2C.psm1'

    # Version number of this module.
    ModuleVersion     = '1.5'

    # Supported PSEditions
    # CompatiblePSEditions = @()

    # ID used to uniquely identify this module
    GUID              = '34eec692-8240-4a0e-9fbc-5011fc3fc559'

    # Author of this module
    Author            = 'Taeke Kooiker & Wim van den Heijkant'

    # Company or vendor of this module
    CompanyName       = 'Fortigi'

    # Copyright statement for this module
    Copyright         = '(c) 2019 Fortigi.'

    # Description of the functionality provided by this module
    Description = 'This module utilizes the Azure AD B2C REST API to provide the most common functionality for managing B2C policies, applications and keycontainers from the PowerShell commandline or Azure DevOps. For more info support@fortigi.nl'

    # Minimum version of the Windows PowerShell engine required by this module
    # PowerShellVersion = ''

    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # CLRVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @(@{"ModuleName" = "AzureRM"; "ModuleVersion" = "5.7.0"})

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @('Get-AzureADB2CAccessToken', 'Get-AzureADB2CSession', 'Get-AzureADB2CPolicy', 'New-AzureADB2CPolicy', 'Remove-AzureADB2CPolicy', 'Get-AzureADB2CKeyContainer', 'New-AzureADB2CKeyContainer', 'Remove-AzureADB2CKeyContainer', 'Get-AzureADB2CApplication', 'New-AzureADB2CApplication', 'Remove-AzureADB2CApplication', 'Set-AzureADB2CApplication')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @()

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            # ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

}

