<#
    .SYNOPSIS
        Applies Application Optimizations and configurations. Supports VDI optmizations

    .DESCRIPTION
		Applies Application Optimizations and configurations. Supports VDI optmizations
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
            Configurable using custom variables in MDT/SCCM

    .INFO
        Author:         Richard Tracy
        Email:          richard.tracy@hotmail.com
        Twitter:        @rick2_1979
        Website:        www.powershellcrack.com
        Last Update:    06/18/2019
        Version:        1.1.6
        Thanks to:      unixuser011,W4RH4WK,TheVDIGuys,cluberti,JGSpiers

    .DISCLOSURE
        THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. BY USING OR DISTRIBUTING THIS SCRIPT, YOU AGREE THAT IN NO EVENT
        SHALL RICHARD TRACY OR ANY AFFILATES BE HELD LIABLE FOR ANY DAMAGES WHATSOEVER RESULTING FROM USING OR DISTRIBUTION OF THIS SCRIPT, INCLUDING,
        WITHOUT LIMITATION, ANY SPECIAL, CONSEQUENTIAL, INCIDENTAL OR OTHER DIRECT OR INDIRECT DAMAGES. BACKUP UP ALL DATA BEFORE PROCEEDING.

    .PARAM
        '// Global Settings
        CFG_DisableAppScript
        CFG_UseLGPOForConfigs
        LGPOPath

        '// VDI Preference
        CFG_OptimizeForVDI

        '// Applications Settings
        CFG_DisableOfficeAnimation
        CFG_EnableIESoftwareRender
        CFG_EnableLyncStartup
        CFG_RemoveAppxPackages
        CFG_RemoveFODPackages

    .EXAMPLE
        #Copy this to MDT CustomSettings.ini
        Properties=CFG_DisableAppScript,CFG_UseLGPOForConfigs,LGPOPath,CFG_DisableOfficeAnimation,CFG_EnableIESoftwareRender,CFG_EnableLyncStartup,CFG_RemoveAppxPackages,CFG_RemoveFODPackages,CFG_RemoveUnusedPrinters

        #Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_UseLGPOForConfigs=True
        CFG_DisableOfficeAnimation=True
        CFG_EnableIESoftwareRender=True
        CFG_EnableLyncStartup=True
        ...

        #Add script to task sequence

    .LINK
        https://github.com/TheVDIGuys/W10_1803_VDI_Optimize
        https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1

    .CHANGE LOG
        1.1.6 - Jun 18, 2019 - Added more info page, change Get-SMSTSENV warning to verbose message
        1.1.5 - May 30, 2019 - defaulted reg type to dword if not specified, standarized registry keys captalizations
        1.1.4 - May 29, 2019 - fixed FOD issue and messages. fixed Set-LocalPolicyUserSettings default users; fixed office detection
                                resolved all VSC problems
        1.1.3 - May 28, 2019 - fixed Get-SMSTSENV log path
        1.1.2 - May 24, 2019 - Removed IE customized settings
        1.1.1 - May 15, 2019 - Added Get-ScriptPpath function to support VScode and ISE; fixed Set-LocalPolicyUserSettings
        1.1.0 - May 10, 2019 - added appx removal Feature on Demand removal, reorganized controls in categories
        1.0.4 - May 09, 2019 - added Office detection
        1.0.0 - May 07, 2019 - initial

#>

##*=============================================
##* INSTALL MODULES
##*=============================================
Install-Module -Name YetAnotherCMLogger,LGPO

Import-Module YetAnotherCMLogger
Import-Module LGPO


##*========================================================================
##* VARIABLE DECLARATION
##*========================================================================
#specify path of log
Set-YaCMLogFileName
##*===========================================================================
##* FUNCTIONS
##*===========================================================================

#region Function Get-InstalledApplication
Function Get-InstalledApplication {
    <#
    .SYNOPSIS
        Retrieves information about installed applications.
    .DESCRIPTION
        Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
        Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
    .PARAMETER Name
        The name of the application to retrieve information for. Performs a contains match on the application display name by default.
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name.
    .PARAMETER WildCard
        Specifies that the named application must be matched using a wildcard search.
    .PARAMETER RegEx
        Specifies that the named application must be matched using a regular expression search.
    .PARAMETER ProductCode
        The product code of the application to retrieve information for.
    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in results.
    .EXAMPLE
        Get-InstalledApplication -Name 'Adobe Flash'
    .EXAMPLE
        Get-InstalledApplication -ProductCode '{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
    .NOTES
    .LINK
        http://psappdeploytoolkit.com
    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string[]]$Name,
		[Parameter(Mandatory=$false)]
		[switch]$Exact = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WildCard = $false,
		[Parameter(Mandatory=$false)]
		[switch]$RegEx = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$ProductCode,
		[Parameter(Mandatory=$false)]
		[switch]$IncludeUpdatesAndHotfixes
	)

	Begin {
		 ## Get the name of this function
         [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

         #  Registry keys for native and WOW64 applications
        [string[]]$regKeyApplications = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	}
	Process {
		If ($name) {
			Write-YaCMLogEntry -Message "Get information for installed Application Name(s) [$($name -join ', ')].." -Severity 4 -Source ${CmdletName} -Passthru:$Global:Verbose
		}
		If ($productCode) {
			Write-YaCMLogEntry -Message "Get information for installed Product Code [$ProductCode].." -Severity 4 -Source ${CmdletName} -Passthru:$Global:Verbose
		}

		## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
		[psobject[]]$regKeyApplication = @()
		ForEach ($regKey in $regKeyApplications) {
			If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
				[psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
				ForEach ($UninstallKeyApp in $UninstallKeyApps) {
					Try {
						[psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
						If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
					}
					Catch{
						Write-YaCMLogEntry -Message "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]. `n$(Resolve-Error)" -Severity 2 -Source ${CmdletName} -Passthru:$Global:OutTohost
						Continue
					}
				}
			}
		}
		If ($ErrorUninstallKeyPath) {
			Write-YaCMLogEntry -Message "The following error(s) took place while enumerating installed applications from the registry. `n$(Resolve-Error -ErrorRecord $ErrorUninstallKeyPath)" -Severity 2 -Source ${CmdletName} -Passthru:$Global:OutTohost
		}

		## Create a custom object with the desired properties for the installed applications and sanitize property details
		[psobject[]]$installedApplication = @()
		ForEach ($regKeyApp in $regKeyApplication) {
			Try {
				[string]$appDisplayName = ''
				[string]$appDisplayVersion = ''
				[string]$appPublisher = ''

				## Bypass any updates or hotfixes
				If (-not $IncludeUpdatesAndHotfixes) {
					If ($regKeyApp.DisplayName -match '(?i)kb\d+') { Continue }
					If ($regKeyApp.DisplayName -match 'Cumulative Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Security Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Hotfix') { Continue }
				}

				## Remove any control characters which may interfere with logging and creating file path names from these variables
				$appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''
				$appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
				$appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]',''

				## Determine if application is a 64-bit application
				[boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }

				If ($ProductCode) {
					## Verify if there is a match with the product code passed to the script
					If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
						Write-YaCMLogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]" -Source ${CmdletName} -Passthru
						$installedApplication += New-Object -TypeName 'PSObject' -Property @{
							UninstallSubkey = $regKeyApp.PSChildName
							ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
							DisplayName = $appDisplayName
							DisplayVersion = $appDisplayVersion
							UninstallString = $regKeyApp.UninstallString
							InstallSource = $regKeyApp.InstallSource
							InstallLocation = $regKeyApp.InstallLocation
							InstallDate = $regKeyApp.InstallDate
							Publisher = $appPublisher
							Is64BitApplication = $Is64BitApp
						}
					}
				}

				If ($name) {
					## Verify if there is a match with the application name(s) passed to the script
					ForEach ($application in $Name) {
						$applicationMatched = $false
						If ($exact) {
							#  Check for an exact application name match
							If ($regKeyApp.DisplayName -eq $application) {
								$applicationMatched = $true
								Write-YaCMLogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using exact name matching for search term [$application]" -Source ${CmdletName} -Passthru
							}
						}
						ElseIf ($WildCard) {
							#  Check for wildcard application name match
							If ($regKeyApp.DisplayName -like "*$application*") {
								$applicationMatched = $true
								Write-YaCMLogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using wildcard matching for search term [$application]" -Source ${CmdletName} -Passthru
							}
						}
						ElseIf ($RegEx) {
							#  Check for a regex application name match
							If ($regKeyApp.DisplayName -match $application) {
								$applicationMatched = $true
								Write-YaCMLogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$application]" -Source ${CmdletName} -Passthru
							}
						}
						#  Check for a contains application name match
						ElseIf ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
							$applicationMatched = $true
							Write-YaCMLogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]" -Source ${CmdletName} -Passthru
						}

						If ($applicationMatched) {
							$installedApplication += New-Object -TypeName 'PSObject' -Property @{
								UninstallSubkey = $regKeyApp.PSChildName
								ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
								DisplayName = $appDisplayName
								DisplayVersion = $appDisplayVersion
								UninstallString = $regKeyApp.UninstallString
								InstallSource = $regKeyApp.InstallSource
								InstallLocation = $regKeyApp.InstallLocation
								InstallDate = $regKeyApp.InstallDate
								Publisher = $appPublisher
								Is64BitApplication = $Is64BitApp
							}
						}
					}
				}
			}
			Catch {
				Write-YaCMLogEntry -Message "Failed to resolve application details from registry for [$appDisplayName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName} -Passthru
				Continue
			}
		}

		Write-Output -InputObject $installedApplication
	}
	End {
	}
}
#endregion




##*===========================================================================
##* DEFAULTS: Configurations are here (change values if needed)
##*===========================================================================
# Global Settings
[boolean]$DisableScript =  $false
# VDI Preference
[boolean]$OptimizeForVDI = $true
# Applications Settings
[boolean]$DisableOfficeAnimation = $true
[boolean]$EnableIESoftwareRender = $false
[boolean]$EnableLyncStartup = $false
[boolean]$RemoveAppxPackages = $false
[boolean]$RemoveFODPackages = $true
[boolean]$ForceIEHomepage = $false
[boolean]$ForceEdgeHomepage = $true

# Ultimately disable the entire script. This is useful for testing and using one task sequences with many rules
If($DisableScript){
    Write-YaCMLogEntry "Script is disabled!"
    Exit 0
}

$OfficeInstalled = Get-InstalledApplication "Microsoft 365 Apps" -wildcard | Select-Object -First 1
If($OfficeInstalled){
    If( $OfficeInstalled.Is64BitApplication ) {$OfficeLocation = $env:ProgramFiles} Else {$OfficeLocation = ${env:ProgramFiles(x86)}}
    $OfficeVersion = [string]([version]$OfficeInstalled.DisplayVersion).Major + '.' + [string]([version]$OfficeInstalled.DisplayVersion).Minor
    $OfficeFolder = 'Office' + [string]([version]$OfficeInstalled.DisplayVersion).Major
    $OfficeTitle = [string]$OfficeInstalled.DisplayName
}
##*===========================================================================
##* MAIN
##*===========================================================================

If($EnableIESoftwareRender){
    Write-YaCMLogEntry -Message "Enabling Software Rendering For IE"
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'UseSWRender' -Type DWord -Value 1
}



If($ForceIEHomepage -and $Homepage){
    Write-YaCMLogEntry -Message "Setting Homepage For IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'Start Page' -Type String -Value $Homepage
    Write-YaCMLogEntry -Message "Setting Default Page For IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'Default_Page_URL' -Type String -Value $Homepage
    Write-YaCMLogEntry -Message "Enabling Continuous Browsing For IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\ContinuousBrowsing' -Name 'Enabled' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling Default browser prompt For IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'Check_Associations' -Type String -Value 'No'
    Write-YaCMLogEntry -Message "Enable new tab homepage For IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'Software\Microsoft\Internet Explorer\TabbedBrowsing' -Name 'NewTabbedPageShow' -Type DWord -Value 1 -Force
}



If($ForceEdgeHomepage -and $Homepage){
    Write-YaCMLogEntry -Message "Setting Homepage For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main' -Name 'HomeButtonPage' -Type String -Value $Homepage
    Write-YaCMLogEntry -Message "Enabling Home button For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main' -Name 'HomeButtonEnabled' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling startpage lockdown For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -Name 'DisableLockdownOfStartPages' -Type DWord -Value 1 -TryLGPO:$true
    Write-YaCMLogEntry -Message "Enabling provisioned homepages For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -Name 'ProvisionedHomePages' -Type String -Value $Homepage -TryLGPO:$true
    Write-YaCMLogEntry -Message "Disabling First run For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FirstRun' -Name 'LastFirstRunVersionDelivered' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling IE10 Tour Show For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main' -Name 'IE10TourShown' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling Default browser prompt For Edge" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main' -Name 'DisallowDefaultBrowserPrompt' -Type DWord -Value 1 -Force
}



If ($DisableOfficeAnimation -and $OfficeInstalled){
    -Message "Disabling OST Cache mode for $OfficeTitle"
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Policies\Microsoft\Office\$OfficeVersion\Outlook\ost" -Name 'NoOST' -Type DWord -Value 2
    -Message "Disabling Exchange cache mode for $OfficeTitle"
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Policies\Microsoft\Office\$OfficeVersion\Outlook\cache mode" -Name 'Enable' -Type DWord -Value 0 -Force
}



If ($DisableOfficeAnimation -and $OfficeInstalled){
    Write-YaCMLogEntry -Message "Disabling Hardware Acceleration for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\Graphics" -Name 'DisableHardwareAcceleration' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling Animation for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\Graphics" -Name 'DisableAnimation' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling First Run Boot for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\FirstRun" -Name 'BootRTM' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling First Run Movie for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\FirstRun" -Name 'DisableMovie' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling First Run Optin for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\General" -Name 'showfirstrunoptin' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling First Run Optin for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\PTWatson" -Name 'PTWOption' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling CEIP for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common" -Name 'qmenable' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Accepting Eulas for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Registration" -Name 'AcceptAllEulas' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling Default File Types for $OfficeTitle" -Passthru
    Set-LocalPolicyUserSetting -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\General" -Name 'ShownFileFmtPrompt' -Type DWord -Value 1 -Force
}




If($EnableLyncStartup -and $OfficeInstalled)
{
    Write-YaCMLogEntry -Message "Enabling Skype for Business Startup" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name "Lync" -Type String -Value """$OfficeLocation\Microsoft Office\$OfficeFolder\lync.exe"" /fromrunkey"
}



If($RemoveAppxPackages)
{
    Write-YaCMLogEntry -Message "Removing AppxPackage and AppxProvisioningPackage" -Passthru

    # Get a list of all apps
    $AppArrayList = Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Select-Object -Property Name, PackageFullName,PackageUserInformation | Sort-Object -Property Name

    # White list of appx packages to keep installed
    $WhiteListedApps = @(
        "Microsoft.DesktopAppInstaller",
        "Microsoft.MSPaint",
        "Microsoft.Windows.Photos",
        "Microsoft.StorePurchaseApp",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCalculator",
        #"Microsoft.WindowsCommunicationsApps", # Mail, Calendar etc
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.RemoteDesktop",
        "Microsoft.WindowsStore",
        "Microsoft.News"
    )

    $p = 1
    $c = 0
    $d = 0
    # Loop through the list of appx packages
    foreach ($App in $AppArrayList) {

        # If application name not in appx package white list, remove AppxPackage and AppxProvisioningPackage
        if (($App.Name -in $WhiteListedApps)) {
            Write-YaCMLogEntry -Message ("Skipping excluded application package: {0}" -f $App.Name) -Passthru
        }
        else {
            # Gather package names
            $AppPackageDetails = Get-AppxPackage -AllUsers -Name $App.Name

            $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $AppPackageDetails.Name } | Select-Object -ExpandProperty PackageName

            # Attempt to remove AppxPackage
            if ($null -ne $AppPackageDetails) {
                Write-YaCMLogEntry -Message ("Removing application package: {0}" -f $AppPackageDetails.Name) -Passthru

                try {
                    Remove-AppxPackage -AllUsers -Package $AppPackageDetails.PackageFullName -ErrorAction Stop | Out-Null

                    Write-YaCMLogEntry -Message ("Successfully removed application package: {0}" -f $AppPackageDetails.PackageFullName) -Passthru
                    $c++
                }
                catch [System.Exception] {
                    Write-YaCMLogEntry -Message ("Failed removing AppxPackage: {0}" -f $_) -Severity 3 -Passthru
                }
                Finally{
                    Write-YaCMLogEntry -Message ("--------------------------------------------------" ) -Passthru
                }
            }
            else {
                Write-YaCMLogEntry -Message ("Unable to locate AppxPackage for app: {0}" -f $AppPackageDetails.Name) -Passthru
            }

            # Attempt to remove AppxProvisioningPackage
            if ($null -ne $AppProvisioningPackageName) {
                Write-YaCMLogEntry -Message ("Removing application PROVISIONED package: {0}" -f $AppProvisioningPackageName)
                try {
                    Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop | Out-Null
                    Write-YaCMLogEntry -Message ("Successfully removed application PROVISIONED package: {0}" -f $AppProvisioningPackageName) -Passthru
                    $d++
                }
                catch [System.Exception] {
                    Write-YaCMLogEntry -Message ("Failed removing Appx PROVISIONED Package: {0}" -f $_) -Severity 3 -Passthru
                }
                Finally{
                    Write-YaCMLogEntry -Message ("--------------------------------------------------" ) -Passthru
                }
            }
            else {
                Write-YaCMLogEntry -Message ("Unable to locate Appx PROVISIONED Package for app: {0}" -f $AppPackageDetails.Name) -Passthru
            }

        }

        $p++
    }

    Write-YaCMLogEntry -Message ("Removed {0} All Users App Package's" -f $c) -Passthru
    Write-YaCMLogEntry -Message ("Removed {0} built-in App PROVISIONED Package's" -f $d) -Passthru
}



If($RemoveFODPackages)
{
    Write-YaCMLogEntry -Message "Starting Features on Demand V2 removal process" -Passthru

    # White list of Features On Demand V2 packages of what NOT to remove
    $WhiteListOnDemand = "NetFX3|Tools.Graphics.DirectX|Tools.DeveloperMode.Core|Language|Browser.InternetExplorer|ContactSupport|OneCoreUAP|Media.WindowsMediaPlayer|Rsat"

    try {
        # Get Features On Demand that should be removed
        $OnDemandFeatures = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name

        $f=1
        foreach ($Feature in $OnDemandFeatures) {
            try {
                Write-YaCMLogEntry -Message ("Removing Feature on Demand V2 package: {0}" -f $Feature) -Passthru
                $results = Remove-WindowsCapability -Name $Feature -Online -ErrorAction Stop
                if ($results.RestartNeeded -eq $true) {
                    Write-YaCMLogEntry ("Reboot is required for remving the Feature on Demand package: {0}" -f $FeatName)
                }
            }
            catch [System.Exception] {
                Write-YaCMLogEntry -Message ("Failed to remove Feature on Demand V2 package: {0}" -f $_.Message) -Severity 3 -Passthru
            }

            $f++
        }
    }
    catch [System.Exception] {
        Write-YaCMLogEntry -Message ("Failed attempting to list Feature on Demand V2 packages: {0}" -f $_.Message) -Severity 3 -Passthru
    }
    Finally{
        # Complete
        Write-YaCMLogEntry -Message "Completed Features on Demand V2 removal process" -Passthru
    }
}


Write-YaCMLogEntry -Message 'Completed App Optimizations and Configuration' -Passthru
