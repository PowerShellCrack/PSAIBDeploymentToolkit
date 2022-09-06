<#
    .SYNOPSIS
        Applies Windows 10 Optimizations and configurations. Supports VDI optmizations

    .DESCRIPTION
		Applies Windows 10 Optimizations and configurations. Supports VDI optmizations
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
            Configurable using custom variables in MDT/SCCM

    .INFO
        Author:         Richard Tracy
        Email:          richard.tracy@hotmail.com
        Twitter:        @rick2_1979
        Website:        www.powershellcrack.com
        Last Update:    06/20/2019
        Version:        3.2.1
        Thanks to:      unixuser011,W4RH4WK,TheVDIGuys,cluberti,JGSpiers

    .DISCLOSURE
        THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. BY USING OR DISTRIBUTING THIS SCRIPT, YOU AGREE THAT IN NO EVENT
        SHALL RICHARD TRACY OR ANY AFFILATES BE HELD LIABLE FOR ANY DAMAGES WHATSOEVER RESULTING FROM USING OR DISTRIBUTION OF THIS SCRIPT, INCLUDING,
        WITHOUT LIMITATION, ANY SPECIAL, CONSEQUENTIAL, INCIDENTAL OR OTHER DIRECT OR INDIRECT DAMAGES. BACKUP UP ALL DATA BEFORE PROCEEDING.

    .INPUTS
        '// Global Settings
        CFG_DisableConfigScript
        CFG_UseLGPOForConfigs
        LGPOPath



    .EXAMPLE



        #Add script to task sequence

    .LINK
        https://github.com/TheVDIGuys/W10_1803_VDI_Optimize
        https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1

    .CHANGE LOGS
        3.2.1 - Jun 20, 2019 - Added CFG_EnableShutdownEventTracker and CFG_RemoveVMToolsTrayIcon option
        3.2.0 - Jun 18, 2019 - Added more info page, change Get-SMSTSENV warning to verbose message
        3.1.9 - May 30, 2019 - defaulted reg type to DWord if not specified, standarized registry keys captalizations
        3.1.8 - May 29, 2019 - fixed UnusedFeature issue and Set-LocalPolicyUserSettings default users, and user freidnly displays for apps removal
                                resolved all VSC problems
        3.1.7 - May 28, 2019 - fixed Get-SMSTSENV log path
        3.1.6 - May 24, 2019 - Added Unused Printer removal, fixed DisableIEFirstRunWizard section
        3.1.5 - May 15, 2019 - Added Get-ScriptPpath function to support VScode and ISE; fixed Set-LocalPolicyUserSettings
        3.1.4 - May 10, 2019 - added strict smart card login scenario; reorganized controls in categories
                                fixed PS module import
        3.1.3 - May 9, 2019 - added reboot lockscreen and separated fontsmoothing option
        3.1.2 - Apr 25, 2019 - Updated SYNOPSIS, Add OptimizeNetwork switch
        3.1.1 - Apr 17, 2019 - added App-V and UE-V control
        3.1.0 - Apr 17, 2019 - added Set-LocalPolicyUserSetting function
        3.0.4 - Apr 12, 2019 - added more Windwos 10 settings check
        3.0.1 - Apr 12, 2019 - fixed progress bar for each user, removed extension script check
        3.0.0 - Apr 4, 2019 -  added progress bar for tasksequence
        2.5.0 - Mar 29, 2019 - added more options from theVDIGuys script
        2.1.6 - Mar 13, 2019 - Commented out Windows 10 old items
        2.1.5 - Mar 13, 2019 - Fixed mitigations script and removed null outputs
        2.1.3 - Mar 12, 2019 - Fixed TyLGPO Trigger on some keys
        2.1.0 - Mar 12, 2019 - Updatd LGPO process as global variable and added param for it
        2.0.0 - Mar 11, 2019 - Split STIGs and EMET mitcations to Seperate script (WIn10STIGAndMitigations.ps1)
        1.5.0 - Mar 8, 2019  - Add a lot more VDI Optimizations using Vmware OSOT xml, changed Configure-RegistryItem to Set-LocalPolicySettings
        1.2.4 - Mar 8, 2019  - Fixed relative path for LGPO.exe
        1.2.7 - Mar 7, 2019  - updated EMET aas hashtables, added SID translation for registry hive loading
        1.2.5 - Mar 7, 2019  - Cleaned up log comments, Fixed EMET mitigations for windows 10 versions
        1.2.4 - Mar 7, 2019  - Added EMET mitigations, fixed Write-YaCMLogEntry
        1.2.0 - Mar 7, 2019  - Added new capabilities, VDI Optimizations control, fixed Configure-bluetooth,Configure-RegistryItem function
        1.1.8 - Dec 14, 2018 - Added User profile registry loop
        1.1.2 - Dec 14, 2018 - Added more property checks, Merged Configure-LGPO with Configure-RegistryItem functiuon
        1.1.0 - Dec 13, 2018 - Added Bluetooth Function, LGPO Function, Added STIGs
        1.0.0 - Nov 20, 2018 - initial

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

Function Set-Bluetooth{
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$true)][ValidateSet('Off', 'On')]
    [string]$DeviceStatus
    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        Function Await($WinRtTask, $ResultType) {
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
        }
        [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        [Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
        $bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' }
        [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        If($bluetooth){
            Try{
                Await ($bluetooth.SetStateAsync($DeviceStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
            }
            Catch{
                Write-YaCMLogEntry -Message ("Unable to configure Bluetooth Settings: {0}" -f $_.Exception.Message) -Severity 3 -Source ${CmdletName}
            }
            Finally{
                #If ((Get-Service bthserv).Status -eq 'Stopped') { Start-Service bthserv }
            }
        }
        Else{
            Write-YaCMLogEntry -Message ("No Bluetooth found") -Severity 0 -Source ${CmdletName}
        }
    }
    End{}
}


function Disable-Indexing {
    Param($Drive)
    $obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
    $indexing = $obj.IndexingEnabled
    if("$indexing" -eq $True){
        Write-Host "Disabling indexing of drive $Drive"
        $obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
    }
}


function Set-PowerPlan {
    <#
     Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName= 'Balanced'" | Invoke-WmiMethod -Name Activate | Out-Null
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-SETACTIVE 381b4222-f694-41f0-9685-ff5bb260df2e" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-x -standby-timeout-ac 0" -Wait -NoNewWindow
    #>
    [CmdletBinding(SupportsShouldProcess = $True)]
    param (

        [ValidateSet("High performance", "Balanced", "Power saver")]
        [ValidateNotNullOrEmpty()]
        [string]$PreferredPlan = "High Performance",

        [ValidateSet("On", "Off")]
        [string]$Hibernate,

        [ValidateRange(0,120)]
        [int32]$ACTimeout,

        [ValidateRange(0,120)]
        [int32]$DCTimeout,

        [ValidateRange(0,120)]
        [int32]$ACMonitorTimeout,

        [ValidateRange(0,120)]
        [int32]$DCMonitorTimeout,

        [string]$ComputerName = $env:COMPUTERNAME
    )
    Begin
    {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }
        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }

    }
    Process
    {
        Write-YaCMLogEntry -Message ("Setting power plan to `"{0}`"" -f $PreferredPlan) -Source ${CmdletName}

        $guid = (Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName='$PreferredPlan'" -ComputerName $ComputerName).InstanceID.ToString()
        $regex = [regex]"{(.*?)}$"
        $plan = $regex.Match($guid).groups[1].value

        $process = Get-WmiObject -Query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -Namespace "root\cimv2" -ComputerName $ComputerName
        Try{
            If($VerbosePreference){Write-YaCMLogEntry -Message ("COMMAND: powercfg -S $plan") -Severity 4 -Source ${CmdletName} -Passthru}
            $process.Create("powercfg -S $plan") | Out-Null
        }
        Catch{
            Write-YaCMLogEntry -Message ("Failed to create power configuration:" -f $_.Exception.Message) -Severity 3 -Source ${CmdletName} -Passthru
        }

        $Output = "Power plan set to "
        $Output += "`"" + ((Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "IsActive='$True'" -ComputerName $ComputerName).ElementName) + "`""

        $params = ""

        If($Hibernate){
                $params += "-H $Hibernate"
                $Output += " with hibernate set to [$Hibernate]"
        }

        If(($ACTimeout -ge 0) -or ($DCTimeout -ge 0) -or ($ACMonitorTimeout -ge 0) -or ($DCMonitorTimeout -ge 0)){$params += " -x "}

        If($ACTimeout -ge 0){
                $params += "-standby-timeout-ac $ACTimeout "
                $Output += " . The AC System timeout was set to [$($ACTimeout.ToString())]"
        }

        If($DCTimeout -ge 0){
                $params += "-standby-timeout-dc $DCTimeout "
                $Output += " . The DC System timeout was set to [$($DCTimeout.ToString())]"
        }

        If($ACMonitorTimeout -ge 0){
                $params += "-standby-timeout-ac $ACMonitorTimeout "
                $Output += " . The AC Monitor timeout was set to [$($ACMonitorTimeout.ToString())]"
        }

        If($DCMonitorTimeout -ge 0){
                $params += "-standby-timeout-dc $DCMonitorTimeout "
                $Output += " . The DC Monitor timeout was set to [$($DCMonitorTimeout.ToString())]"
        }

        Try{
            If($VerbosePreference){Write-YaCMLogEntry -Message ("COMMAND: powercfg $params") -Severity 4 -Source ${CmdletName} -Passthru}
            $process.Create("powercfg $params") | Out-Null
        }
        Catch{
            Write-YaCMLogEntry -Message ("Failed to set power confugration:" -f $_.Exception.Message) -Severity 3 -Source ${CmdletName} -Passthru
        }
    }
    End {
        #Write-Host $Output
        Write-YaCMLogEntry -Message ("{0}" -f $Output) -Source ${CmdletName}
    }
}

#=======================================================
# MAIN
#=======================================================
$ErrorActionPreference = 'Stop'
# Global Settings
[boolean]$DisableScript = $false
# VDI Preference
[boolean]$OptimizeForVDI = $true
[boolean]$EnableVisualPerformance = $false
# User Preference
[boolean]$InstallLogonScript = $false
[string]$LogonScriptPath = "$PSscriptRoot\Win10-Logon.ps1"
[boolean]$EnableDarkTheme = $true
[boolean]$EnableTaskbarAutoColor = $false
[boolean]$DisableFontSmoothing = $false
[boolean]$CleanSampleFolders = $false
[boolean]$DisableCortana = $true
[boolean]$DisableInternetSearch = $false
[boolean]$EnableOfficeOneNote = $false
[boolean]$DisableOneDrive = $false
[boolean]$DisableWindowsFirstLoginAnimation = $false
[boolean]$DisableIEFirstRunWizard = $false
[boolean]$DisableWMPFirstRunWizard = $false
[boolean]$ShowKnownExtensions = $true
[boolean]$ShowHiddenFiles = $false
[boolean]$ShowThisPCOnDesktop = $false
[boolean]$ShowUserFolderOnDesktop = $false
[boolean]$RemoveRecycleBinOnDesktop = $false
[boolean]$Hide3DObjectsFromExplorer = $false
[boolean]$DisableEdgeShortcutCreation = $false
[boolean]$DisableStoreOnTaskbar = $true
[boolean]$DisableActivityHistory = $false
[string]$SetSmartScreenFilter = 'User' # Set to 'Off','User','Admin'
[boolean]$EnableNumlockStartup = $true
[boolean]$DisableAppSuggestions = $true
# System Settings
[string]$SetPowerCFG = 'Custom' # Set 'Custom','High Performance','Balanced'
[string]$PowerCFGFilePath = "$PSscriptRoot\AlwaysOnPowerScheme.pow"
[boolean]$EnableIEEnterpriseMode = $false
[string]$IEEMSiteListPath = ''
[boolean]$ApplyCustomHost = $false
[string]$HostPath = "$PSscriptRoot\WindowsTelemetryhosts"
[boolean]$EnableSecureLogonCAD = $true
[boolean]$DisableAllNotifications = $false
[boolean]$EnableVerboseStatusMsg = $true
[boolean]$DisableAutoRun = $true
[boolean]$PreferIPv4OverIPv6 = $false
[boolean]$EnableAppsRunAsAdmin = $false
[boolean]$HideDrivesWithNoMedia = $true
[boolean]$DisableActionCenter = $false
[boolean]$DisableFeedback = $false
[boolean]$DisableWUP2P = $false
[boolean]$DisablePreviewBuild = $true
[boolean]$DisableDriverUpdates = $true
[boolean]$DisableWindowsUpgrades = $true
[boolean]$ApplyPrivacyMitigations = $false
[boolean]$RemoveRebootOnLockScreen = $false
[boolean]$RemoveUnusedPrinters = $false
[boolean]$RemoveVMToolsTrayIcon = $false
[boolean]$EnableShutdownEventTracker = $false
# System Adv Settings
[boolean]$DisableSmartCardLogon = $false
[boolean]$ForceStrictSmartCardLogon = $false
[boolean]$EnableFIPS = $true
[boolean]$EnableCredGuard = $true
[boolean]$DisableUAC = $false
[boolean]$EnableStrictUAC = $true
[boolean]$EnableRDP = $true
[boolean]$EnableWinRM = $true
[boolean]$EnableRemoteRegistry = $true
[boolean]$EnableUEV = $false
[boolean]$EnableAppV = $false
[boolean]$EnablePSLogging = $false
[boolean]$EnableLinuxSubSystem = $false
[boolean]$DisableAdminShares = $false
[boolean]$DisableSchTasks = $false
[boolean]$DisableDefender = $false
[boolean]$DisableFirewall = $false
[boolean]$DisableWireless = $false
[boolean]$DisableBluetooth = $false
[boolean]$DisableNewNetworkDialog = $true
[boolean]$DisableInternetServices = $false
[boolean]$DisabledUnusedServices = $true
[boolean]$DisabledUnusedFeatures = $true
[boolean]$DisableIndexing = $true
[boolean]$RemoveActiveSetupComponents = $true
[boolean]$PreCompileAssemblies = $true
[boolean]$OptimizeNetwork = $true


# Ultimately disable the entire script. This is useful for testing and using one task sequences with many rules
If($DisableScript){
    Write-YaCMLogEntry -Message "Script is disabled!"
    Exit 0
}

# Get Onenote paths
$OneNotePathx86 = Get-ChildItem "${env:ProgramFiles(x86)}" -Recurse -Filter "ONENOTE.EXE"
$OneNotePathx64 = Get-ChildItem "$env:ProgramFiles" -Recurse -Filter "ONENOTE.EXE"
If($OneNotePathx86){$OneNotePath = $OneNotePathx86}
If($OneNotePathx64){$OneNotePath = $OneNotePathx64}

##*===========================================================================
##* MAIN
##*===========================================================================

If($RemoveRebootOnLockScreen){
    Write-YaCMLogEntry -Message "Disabling Shutdown on Lock screen" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Type DWord -Value 1
}


If($DisableActionCenter)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:45] :: "}
    $CFGMessage = "Disabling Windows Action Center Notifications"
    Write-YaCMLogEntry -Message("{0}{1}" -f $prefixmsg,$CFGMessage) -Passthru

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell' -Name 'UseActionCenterExperience' -Type DWord -Value 0

    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Type DWord -Value 1
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Type DWord -Value 1

}


If($DisableFeedback)
{
    Write-YaCMLogEntry -Message = "Disabling Feedback Notifications" -Passthru

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:7] [Optional] :: "}
    Write-YaCMLogEntry -Message ("{1}{0}" -f $CFGMessage,$prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0
    Set-LocalPolicyUserSetting -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'PeriodInNanoSeconds' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Disabling all feedback Scheduled Tasks" -Passthru
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

    Write-YaCMLogEntry -Message "Disabling all feedback notifications" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1

}



If($DisableWindowsUpgrades)
{
    Write-YaCMLogEntry -Message "Disabling Windows Upgrades from Windows Updates" -Passthru

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Gwx' -Name 'DisableGwx' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableOSUpgrade' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling access the Insider build controls in the Advanced Options" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type DWord -Value 1
}



If($DisableDriverUpdates)
{
    Write-YaCMLogEntry -Message "Disabling driver offering through Windows Update" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DontPromptForWindowsUpdate' -Type DWord -Value 1
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DontSearchWindowsUpdate' -Type DWord -Value 1
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DriverUpdateWizardWuSearchEnabled' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1
}



If($DisableStoreOnTaskbar)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:68] :: "}
    Write-YaCMLogEntry -Message ("{0} Disabling Pinning of Microsoft Store app on the taskbar" -f $prefixmsg) -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoPinningStoreToTaskbar' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -Type DWord -Value 1
}



If ($EnableOfficeOneNote -and $OneNotePath)
{
    Write-YaCMLogEntry -Message "Setting OneNote file association to the desktop app" -Passthru

	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	New-Item -Path 'Registry::HKCR\onenote-cmd\Shell\Open' -Name 'Command'
    New-ItemProperty -Path 'Registry::HKCR\onenote-cmd\Shell\Open\Command' -Name '@' -Type String -Value $OneNotePath.FullName
	Remove-PSDrive -Name "HKCR" | Out-Null
}



If($EnablePSLogging)
{
    Write-YaCMLogEntry -Message "Enabling Powershell Script Logging" -Passthru

	Write-YaCMLogEntry -Message "Enabling Powershell Script Block Logging" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enabling Powershell Transcription Logging" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value ""

    Write-YaCMLogEntry -Message "Enabling Powershell Module Logging" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Type DWord -Value 1
    #Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'ModuleNames' -Value ""
}



If ($EnableVerboseStatusMsg)
{
    #https://support.microsoft.com/en-us/help/325376/how-to-enable-verbose-startup-shutdown-logon-and-logoff-status-message
    Write-YaCMLogEntry -Message "Setting Windows Startup to Verbose messages" -Passthru

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'VerboseStatus' -Type DWord -Value 1
    If(Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM\DisableStatusMessages') ){
        Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableStatusMessages'
    }
}



If (($ApplyCustomHost) -and (Test-Path $HostPath) )
{
    $HostFile = Split-Path $HostPath -Leaf
    Write-YaCMLogEntry -Message ("Copying custom hosts file [{0}] to windows" -f $HostFile) -Passthru

    Copy-Item $HostPath -Destination "$env:Windir\System32\Drivers\etc\hosts"
}



If ($SetPowerCFG -eq 'Balanced')
{
    #Set Balanced to Default
    Write-YaCMLogEntry -Message ("Setting Power configurations to [{0}]"  -f $SetPowerCFG) -Passthru

    Set-PowerPlan -PreferredPlan $SetPowerCFG
}



If ($SetPowerCFG -eq 'High Performance')
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:60 & 61] :: "}
    Write-YaCMLogEntry -Message ("{0}Setting Power configurations to [{1}]"  -f $prefixmsg,$SetPowerCFG) -Passthru

    If($OptimizeForVDI){
        Set-PowerPlan -PreferredPlan $SetPowerCFG -ACTimeout 0 -DCTimeout 0 -ACMonitorTimeout 0 -DCMonitorTimeout 0 -Hibernate Off
    }
    Else{
        Set-PowerPlan -PreferredPlan $SetPowerCFG
    }

    Write-YaCMLogEntry -Message "Disabling Fast Startup"
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:54] :: "}
    Write-YaCMLogEntry -Message ("{0}Removing turn off hard disk after"  -f $prefixmsg)
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e' -Name 'Attributes' -Type DWord -Value 1
}



If (($SetPowerCFG -eq 'Custom') -and (Test-Path $PowerCFGFilePath) -and !$OptimizeForVDI)
{
    $AOPGUID = '50b056f5-0cf6-42f1-9351-82a490d70ef4'
    $PowFile = Split-Path $PowerCFGFilePath -Leaf
    Write-YaCMLogEntry -Message ("Setting Power configurations to [{0}] using file [{1}]" -f $SetPowerCFG,"$env:TEMP\$PowFile") -Passthru

    Copy-Item $PowerCFGFilePath -Destination "$env:Windir\Temp\$PowFile"
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-IMPORT `"$env:Windir\Temp\$PowFile`" $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-SETACTIVE $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-H OFF" -Wait -NoNewWindow
}



If($HideDrivesWithNoMedia)
{
    Write-YaCMLogEntry -Message "Hiding Drives With NoMedia" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideDrivesWithNoMedia' -Type DWord -Value 1
}



If ($DisableAutoRun)
{
    Write-YaCMLogEntry -Message "Disabling Autorun" -Passthru

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutorun' -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'HonorAutorunSetting' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveAutoRun' -Type DWord -Value 67108863
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutorun' -Type DWord -Value 0xFF

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -Name '(Default)' -Value "@SYS:DoesNotExist" -ErrorAction SilentlyContinue | Out-Null
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom' -Name AutoRun -Type DWord -Value 0

    #windows 10 only
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:6] [Optional] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Devices Auto" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoPlay' -Type DWord -Value 1

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:6] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Honor Autorun" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'HonorAutorunSetting' -Type DWord -Value 1
    Write-YaCMLogEntry -Message ("{0}Disabling NoDrive Autorun" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting  -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveAutoRun' -Type DWord -Value 67108863
    Write-YaCMLogEntry -Message ("{0}Disabling No DriveType Autorun" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting  -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutorun' -Type DWord -Value 0xFF
    Write-YaCMLogEntry -Message ("{0}Disabling Autoplay" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting  -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoPlay' -Type DWord -Value 1

}


If($EnableFIPS)
{
    Write-YaCMLogEntry -Message "Enabling FIPS Algorithm Policy" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -Name 'Enabled' -Type DWord -Value 1
}


If ($EnableRDP)
{
    Write-YaCMLogEntry -Message "Enabling RDP" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Type DWord -Value 1
	Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True -Action Allow -Profile Any
}


If ($EnableAPPV)
{
    Write-YaCMLogEntry -Message "Enabling Microsoft App-V" -Passthru
	If($OSBuildNumber -ge 14393){
        Enable-Uev | Out-null
    }
    Else{
        Write-YaCMLogEntry -Message ("Application Virtualization client does not exist on Windows [{0}]; install App-V client from MDOP" -f $OSBuildNumber) -Passthru
    }
}



If ($EnableUEV)
{
    Write-YaCMLogEntry -Message "Enabling Microsoft UE-V" -Passthru
    If($OSBuildNumber -ge 14393){
        Enable-Appv | Out-null
    }
    Else{
        Write-YaCMLogEntry -Message ("User Experience Virtualization client does not exist on Windows [{0}]; install UE-V client from MDOP" -f $OSBuildNumber) -Passthru
    }
}



If ($DisableOneDrive)
{
    Write-YaCMLogEntry -Message "Disabling OneDrive" -Passthru

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Type DWord -Value 1

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:50] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling synchronizing files to onedrive" -f $prefixmsg) -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Preventing OneDrive from generating network traffic" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'PreventNetworkTrafficPreUserSignIn' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableLibrariesDefaultSaveToSkyDrive' -Type DWord -Value 1

    Set-LocalPolicySetting -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder' -Name 'Attributes' -Type DWord -Value 0 -ErrorAction SilentlyContinue

    Write-YaCMLogEntry -Message "Disabling personal accounts for OneDrive synchronization" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisablePersonalSync' -Type DWord -Value 1
    Write-YaCMLogEntry -Message 'Removing Onedrive' -Passthru
    Set-LocalPolicyUserSetting -RegPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSetup' -Remove

    #uninstall  OneDrive
    if (Test-Path "C:\Windows\System32\OneDriveSetup.exe"){
        Write-YaCMLogEntry -Message ("Attempting to uninstall Onedrive from x64 system") -Passthru
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
        #Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
        Start-Process "C:\Windows\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -PassThru -WindowStyle Hidden | Out-Null
        #Start-Process -FilePath "$env:Windir\Explorer.exe" -Wait -ErrorAction SilentlyContinue
    }

    if (Test-Path "C:\Windows\SysWOW64\OneDriveSetup.exe"){
        Write-YaCMLogEntry -Message ("Attempting to uninstall Onedrive from x86 system") -Passthru
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
        #Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
        Start-Process "C:\Windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -PassThru -WindowStyle Hidden | Out-Null
        #Start-Process -FilePath "$env:Windir\Explorer.exe" -Wait -ErrorAction SilentlyContinue
    }

    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Recurse -ErrorAction SilentlyContinue

    # remove OneDrive shortcuts
    Remove-Item -Path 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk'
    Remove-Item -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk'

    #remove registry references to onedrive
    Remove-Item -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:203] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Microsoft OneDrive startup run" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name OneDrive -Type Binary -Value 0300000064A102EF4C3ED101
    If ($OSBuildNumber -le 15063)
    {
        Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}' -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}' -Recurse -ErrorAction SilentlyContinue
        Set-LocalPolicySetting -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0
        Set-LocalPolicySetting -Path 'Registry::HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0
    }
}


If($CFG_EnableShutdownEventTracker)
{
    Write-YaCMLogEntry -Message "Enabling Shutdown Event Tracker" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' -Name 'ShutdownReasonUI' -Type DWord -Value 1
}



If ($PreferIPv4OverIPv6)
{
    Write-YaCMLogEntry -Message "Modifying IPv6 bindings to prefer IPv4 over IPv6" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value 32
}



If($DisableAllNotifications)
{
    $notifications = [ordered]@{
        "Windows.SystemToast.SecurityAndMaintenance"="Security and Maintenance Notifications"
        "Microsoft.SkyDrive.Desktop"="OneDrive Notifications"
        "Microsoft.Windows.Photos_8wekyb3d8bbwe!App"="Photos Notifications"
        "Microsoft.WindowsStore_8wekyb3d8bbwe!App"="Store Notifications"
        "Windows.SystemToast.Suggested"="Suggested Notifications"
        "microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.calendar"="Calendar Notifications"
        "Microsoft.Windows.Cortana_cw5n1h2txyewy!CortanaUI"="Cortana Notifications"
        "microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"="Mail Notifications:"
        "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"="Edge Notifications"
        "Windows.SystemToast.AudioTroubleshooter"="Audio Notifications"
        "Windows.SystemToast.AutoPlay"="Autoplay Notifications"
        "Windows.SystemToast.BackgroundAccess"="Battery Saver Notifications"
        "Windows.SystemToast.BdeUnlock"="Bitlocker Notifications"
        "Microsoft.BingNews_8wekyb3d8bbwe!AppexNews"="News Notifications"
        "windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"="Settings Notifications"
        "Windows.System.Continuum"="Tablet Notifications"
        "Windows.SystemToast.RasToastNotifier"="VPN Notifications"
        "Windows.SystemToast.HelloFace"="Windows Hello Notifications"
        "Windows.SystemToast.WiFiNetworkManager"="Wireless Notifications"

    }
    Write-YaCMLogEntry -Message "Disabling Toast Notifications" -Passthru
    $i = 1
    #loop each notification
    Foreach ($key in $notifications.GetEnumerator()){
        $FriendlyName = $key.Value
        Write-YaCMLogEntry -Message ("Disabling {0} notification: {1} of {2}" -f $FriendlyName,$i,$notifications.count) -Passthru
        Set-LocalPolicyUserSetting -Path ('SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\' + $key.Key) -Name Enabled -Value 0 -Type DWord
        $i ++
    }
    Write-YaCMLogEntry -Message "Disabling Toast notifications to the lock screen" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Non-critical Notifications from Windows Security" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableEnhancedNotifications' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling All Notifications from Windows Security using" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableNotifications' -Type DWord -Value 1
}



If ($DisableIEFirstRunWizard)
{
	# Disable IE First Run Wizard
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:40] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling IE First Run Wizard" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableFirstRunCustomize' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceHasShown' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceComplete' -Type DWord -Value 1

    Write-YaCMLogEntry -Message ("{0}Disabling IE First Run Wizard" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableFirstRunCustomize' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Setting Show Run in IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceHasShown' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Setting Run Once Comleted in IE" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceComplete' -Type DWord -Value 1

}



If ($DisableWMPFirstRunWizard)
{
	# Disable IE First Run Wizard
    Write-YaCMLogEntry -Message "Disabling Media Player First Run Wizard" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name 'AcceptedEULA' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name 'FirstTime' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer' -Name 'GroupPrivacyAcceptance' -Type DWord -Value 1
}



If($EnableSecureLogonCAD)
{
  	# Disable IE First Run Wizard
	Write-YaCMLogEntry -Message "Enabling Secure Logon Screen Settings" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'BlockDomainPicturePassword' -Type DWord -Value 1
}



# Disable New Network dialog box
If ($DisableNewNetworkDialog)
{
    Write-YaCMLogEntry -Message "Disabling New Network Dialog" -Passthru
    Set-LocalPolicySetting 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -Name 'EnableActiveProbing' -Type DWord -Value 0
}



If($RemoveActiveSetupComponents){

    #https://kb.vmware.com/s/article/2100337?lang=en_US#q=Improving%20log%20in%20time
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations :: "}

    $activeComponentsGUID = [ordered]@{
        "{2C7339CF-2B09-4501-B3F3-F3508C9228ED}"="205:Theme Component"
        "{2D46B6DC-2207-486B-B523-A557E6D54B47}"="206:ie4uinit.exe –ClearIconCache"
        "{44BBA840-CC51-11CF-AAFA-00AA00B6015C}"="207:DirectDrawEx"
        "{6BF52A52-394A-11d3-B153-00C04F79FAA6}"="208:Microsoft Windows Media Player"
        "{89820200-ECBD-11cf-8B85-00AA005B4340}"="209:IE4_SHELLID"
        "{89820200-ECBD-11cf-8B85-00AA005B4383}"="210:BASEIE40_W2K"
        "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"="211:DOTNETFRAMEWORKS"
        ">{22d6f312-b0f6-11d0-94ab-0080c74c7e95}"="212:WMPACCESS"
    }
    Write-YaCMLogEntry -Message "Disabling Active Setup components" -Passthru
    $i = 1

    Foreach ($key in $activeComponentsGUID.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $FriendlyName = ($key.Value).split(":")[1]
            Write-YaCMLogEntry -Message ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Feature" -f $OSODID,$FriendlyName)
        }
        Else{
            $FriendlyName = $key.Value
            Write-YaCMLogEntry -Message ("{0}Disabling Active Setup components [{1}]" -f $prefixmsg,$FriendlyName) -Passthru
        }

        Write-YaCMLogEntry -Message ("Disabling Active Setup components: {2} ({0} of {1})" -f $i,$activeComponentsGUID.count,$FriendlyName) -Passthru

        If(Test-Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$($key.Key)" ){
            Remove-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\' + $key.Key) -Name 'StubPath' -ErrorAction SilentlyContinue | Out-Null
        }

        Start-Sleep -Seconds 1
        $i++
    }

}



If ($DisabledUnusedFeatures)
{
    $features = [ordered]@{
        "Printing-Foundation-InternetPrinting-Client"="Internet Printing"
        "FaxServicesClientPackage"="Fax and scanning"
    }

    #disable more features for VDI
    If($OptimizeForVDI){

        $features = $features + @{
            "WindowsMediaPlayer"="67:Windows Media Player"
            "WCF-Services45"="69:ASP.Net 4.5 WCF"
            "Xps-Foundation-Xps-Viewer"="70:Xps Viewer"
            "Printing-XPSServices-Features"="Xps Services"
            "WorkFolders-Client"="Work folders Client"
        }
    }
    Write-YaCMLogEntry -Message "Disabling Unused Features" -Passthru

    $i = 1
    Foreach ($key in $features.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $FriendlyName = ($key.Value).split(":")[1]
            If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations [OSOT ID:{0}] ::" -f $OSODID)}
        }
        Else{
            $FriendlyName = $key.Value
            If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations - UnusedFeatures :: ")}
        }

        Write-YaCMLogEntry -Message ("Disabling Unused Features: {2} ({0} of {1})" -f $i,$features.count,$FriendlyName) -Passthru

        Try{
            Write-YaCMLogEntry -Message ("{0} :: Disabling {1}" -f $prefixmsg,$FriendlyName) -Passthru
            $result = Get-WindowsOptionalFeature -Online -FeatureName $key.key | Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction Stop -WarningAction SilentlyContinue
            if ($results.RestartNeeded -eq $true) {
                Write-YaCMLogEntry -Message ("Reboot is required for disabling the [{0}] Feature" -f $FriendlyName) -Severity 2 -Passthru
            }
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-YaCMLogEntry -Message ("Unable to Remove {0} Feature: {1}" -f $FriendlyName,$_) -Severity 3 -Passthru
        }


        Start-Sleep -Seconds 10
        $i++
    }

    Write-YaCMLogEntry -Message "Removing Default Fax Printer" -Passthru
    Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}



If ($DisabledUnusedServices)
{

    $services = [ordered]@{
        HomeGroupListener="152:HomeGroup Listener Services"
        HomeGroupProvider="153:HomeGroup Provider Services"
        RetailDemo="172:Retail Demo"
    }

    #disable more services for VDI
    If($OptimizeForVDI){
        $services = $services + @{
            AJRouter="135:AJRouter Router"
            ALG="136:Application Layer Gateway"
            BITS="137:Background Intelligent Transfer"
            wbengine="138:Block Level Backup Engine"
            bthserv="139:Bluetooth Support"
            BthHFSrv="307:Wireless Bluetooth Headsets"
            BDESVC="140:Bitlocker Drive Encryption"
            Browser="141:Computer Browser"
            PeerDistSvc="142:BranchCache"
            #DeviceAssociationService="143:Device Association"
            DsmSvc="144:Device Setup Manager"
            DPS="145:Diagnostic Policy"
            WdiServiceHost="146:Diagnostic Service Host"
            WdiSystemHost="147:Diagnostic System Host"
            DiagTrack="148:Diagnostics Tracking"
            Fax="149:Fax"
            fdPHost="150:Function Discovery Provider Host"
            FDResPub="151:Function Discovery Resource Publication"
            vmickvpexchange="154:Hyper-V Data Exchange"
            vmicguestinterface="155:Hyper-V Guest Service Interface"
            vmicshutdown="156:Hyper-V Guest Shutdown"
            vmicheartbeat="157:Hyper-V Heartbeat"
            vmicrdv="158:Hyper-V Remote Desktop Virtualization"
            vmictimesync="159:Hyper-V Time Synchronization"
            vmicvmsession="160:Hyper-V VM Session"
            vmicvss="161:Hyper-V Volume Shadow Copy Requestor"
            UI0Detect="162:Interactive Services Detection"
            SharedAccess="163:Internet Connection Sharing (ICS)"
            iphlpsvc="164:IP Helper"
            MSiSCSI="165:Microsoft iSCSI Initiator"
            swprv="166:Microsoft Software Shadow Copy Provider"
            CscService="167:Offline Files"
            defragsvc="168:Drive Optimization Capabilities"
            PcaSvc="169:Program Compatibility Assistant"
            QWAVE="170:Quality Windows Audio Video Experience"
            wercplsupport="171:Reports and Solutions Control Panel Support"
            SstpSvc="173:Secure Socket Tunneling Protocol"
            wscsvc="174:Security Center"
            #"ShellHWDetection="178:Shell Hardware Detection"
            SNMPTRAP="179:SNMP Trap"
            svsvc="180:Spot Verifier"
            SSDPSRV="181:SSDP Discovery"
            WiaRpc="182:Still Image Acquisition Events"
            StorSvc="183:Store Storage"
            SysMain="184:Superfetch"
            TapiSrv="185:Telephony"
            Themes="186:Themes"
            #upnphost="187:Universal PnP Host"
            VSS="188:Volume Shadow Copy"
            SDRSVC="189:Windows Backup"
            WcsPlugInService="180:Windows Color System"
            wcncsvc="191:Windows Connect Now – Config Registrar"
            #WSearch="195:Windows Search"
            #wuauserv="196:Windows Update"
            Wlansvc="197:WLAN AutoConfig"
            WwanSvc="198:WWAN AutoConfig"
            WbioSrvc="298:Biometric"
            AppIDSvc="299:Identity of an Application"
            'diagnosticshub.standardcollector.service'="300:Diagnostics Hub"
            DoSvc="302:Delivery Optimization"
            EFS="303:Encrypting File System"
            Eaphost="304:Extensible Authentication Protocol"
            stisvc="311:Windows Image Acquisition (WIA)"
            NlaSvc="Network Location Awareness"
            #"Audiosrv="Audio"
            PimIndexMaintenanceSvc="Contact Data"
        }
        $i = 1

        Foreach ($key in $services.GetEnumerator()){
            #write-host ("`"{1}`"=`"{0}`"" -f $key.Key,$key.Value)

            $ColonSplit = $key.Value -match ":"
            If($ColonSplit){
                $OSODID = ($key.Value).split(":")[0]
                $SvcName = ($key.Value).split(":")[1]
                If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations [OSOT ID:{0}] ::" -f $OSODID)}
            }
            Else{
                $SvcName = $key.Value
                If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations - UnusedServices :: ")}
            }
            Write-YaCMLogEntry -Message ("Disabling Internet Service: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Passthru

            Try{
                Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
            }
            Catch [System.Management.Automation.ActionPreferenceStopException]{
                Write-YaCMLogEntry -Message ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3 -Passthru
            }

            Start-Sleep -Seconds 10
            $i++
        }
    }

    #detect if system is a tablet
    #if not disable tablet service
    Add-Type @"
using System.Runtime.InteropServices;
namespace WinAPI
{
    public class User32 {
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex); }
}
"@

    if (-not($Result = [WinAPI.User32]::GetSystemMetrics(86) -band 0x41 -eq 0x41) ) {
        Try{
            Set-Service TabletInputService -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-YaCMLogEntry -Message ("Unable to disable Tablet Service: {0}" -f $_) -Severity 3 -Passthru
        }
    }

}



# Disable Services
If ($DisableInternetServices -and $OptimizeForVDI)
{
    $services = [ordered]@{
        XblAuthManager="199:Xbox Live Auth Manager"
        XblGameSave="200:Xbox Live Game Save"
        XboxNetApiSvc="201:Xbox Live Networking"
        XboxGipSvc="Xbox Accessory Management"
        XboxGip="Xbox Game Input Protocol Driver"
        BcastDVRUserService="GameDVR and Broadcast User"
        xbgm="Xbox Game Monitoring"
        wlidsvc="309:Microsoft Account Sign-in Assistant"
        WerSvc="Windows Error Reporting"
        WMPNetworkSvc="Windows Mediaplayer Sharing"
        DiagTrack="Diagnostic Tracking"
        dmwappushservice="WAP Push Message Routing Data Collection"
        MessagingService="WIndows Text Messaging"
        CDPSvc="Connected Device Platform"
        CDPUserSvc="Connected Device Platform User"
        OneSyncSvc="Sync Host"
        icssvc="194:Windows Mobile Hotspot"
        DcpSvc="301:Data Collection and Publishing"
        lfsvc="308:Geolocation"
        MapsBroker="305:Maps Manager"
        SensorDataService="175:Sensor Data"
        SensrSvc="176:Sensor Monitoring"
        SensorService="177:Sensor"
        DusmSvc="Data Usage Subscription Management"
    }
    $i = 1

    Foreach ($key in $services.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $SvcName = ($key.Value).split(":")[1]
            Write-YaCMLogEntry -Message ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Service [{2}]" -f $OSODID,$SvcName,$key.Key) -Passthru
        }
        Else{
            $SvcName = $key.Value
            Write-YaCMLogEntry -Message ("Disabling {0} Service [{1}]" -f $SvcName,$key.Key) -Passthru
        }

        Write-YaCMLogEntry -Message ("Disabling Internet Service: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Passthru

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-YaCMLogEntry -Message ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3 -Passthru
        }

        Start-Sleep -Seconds 10
        $i++
    }

}



If($DisableSmartCardLogon){
    $services = [ordered]@{
        SCardSvr="Smart Card"
        ScDeviceEnum="Smart Card Device Enumeration Service"
        SCPolicySvc="Smart Card Removal Policy"
    }
    $i = 1

    Foreach ($key in $services.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $SvcName = ($key.Value).split(":")[1]
            Write-YaCMLogEntry -Message ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Service [{2}]" -f $OSODID,$SvcName,$key.Key) -Passthru
        }
        Else{
            $SvcName = $key.Value
            Write-YaCMLogEntry -Message ("Disabling {0} Service [{1}]" -f $SvcName,$key.Key) -Passthru
        }

        Write-YaCMLogEntry -Message ("Disabling SmartCard Service: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Passthru

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-YaCMLogEntry -Message ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3 -Passthru
        }

        Start-Sleep -Seconds 10
        $i++
    }
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'SCForeOption' -Type DWord -Value 0
}



If($ForceStrictSmartCardLogon){
    Write-YaCMLogEntry -Message "Forcing smartcard login" -Passthru

    Write-YaCMLogEntry -Message "Change provider to default to smartcard login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SYSTEM\DefaultCredentialProvider' -Name 'SmartCardCredentialProvider' -Type String -Value '{8FD7E19C-3BF7-489B-A72C-846AB3678C96}'
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'SmartCardCredentialProvider' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Allow certificates with no extended key usage certificate attribute" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowCertificatesWithNoEKU' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Allow Integrated Unblock screen to be displayed at the time of logon" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowIntegratedUnblock' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Filter duplicate logon certificates" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'FilterDuplicateCerts' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Force the reading of all certificates from the smart card" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'ForceReadingAllCertificates' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Allow signature keys valid for Logon" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowSignatureOnlyKeys' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Allow time invalid certificates" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowTimeInvalidCertificates' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Display string when smart card is blocked" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'IntegratedUnblockPromptString' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Reverse the subject name stored in a certificate when displaying" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'ReverseSubject' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Prevent plaintext PINs from being returned by Credential Manager" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'DisallowPlaintextPin' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Allow user name hint" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'X509HintsNeeded' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Allow ECC certificates to be used for logon and authentication" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'EnumerateECCCerts' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling smartcard reader if no reader found" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'DisplayEmptySmartCardTileWhenNoReader' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Configuring Smart Card removal to Force Logoff" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SCRemoveOption' -Type String  -Value 2

    Write-YaCMLogEntry -Message "Disabling Picture Password Login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}' -Name 'Disabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Windows Hello Login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8AF662BF-65A0-4D0A-A540-A338A999D36F}' -Name 'Disabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Biometrics Login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{BEC09223-B018-416D-A0AC-523971B639F5}' -Name 'Disabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling PIN Login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{cb82ea12-9f71-446d-89e1-8d0924e1256e}' -Name 'Disabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Cloud Experience Credential Login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{C5D7540A-CD51-453B-B22B-05305BA03F07}' -Name 'Disabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Password Login" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}' -Name 'Disabled' -Type DWord -Value 1
}


If ($DisableDefender)
{
    $services = [ordered]@{
        Sense="Windows Defender Advanced Threat Protection"
        WdNisSvc="Windows Defender Antivirus Network Inspection"
        SecurityHealthService="Windows Security"
        WinDefend="Windows Defender Antivirus"

    }
    $i = 1

    Foreach ($key in $services.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $SvcName = ($key.Value).split(":")[1]
            Write-YaCMLogEntry -Message ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Service [{2}]" -f $OSODID,$SvcName,$key.Key) -Passthru
        }
        Else{
            $SvcName = $key.Value
            Write-YaCMLogEntry -Message ("Disabling {0} Service [{1}]" -f $SvcName,$key.Key) -Passthru
        }

        Write-YaCMLogEntry -Message ("Disabling Defender Service: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Passthru

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-YaCMLogEntry -Message ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3 -Passthru
        }

        Start-Sleep -Seconds 10
        $i++
    }

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' -Name 'HideSystray' -Type DWord -Value 1
    If ($OSBuildNumber -eq 14393) {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'WindowsDefender' -ErrorAction SilentlyContinue
    }
    ElseIf ($OSBuildNumber -ge 15063) {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityHealth' -ErrorAction SilentlyContinue
    }

    Write-YaCMLogEntry -Message "Disabling Malicious Software Removal Tool offering" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name 'DontOfferThroughWUAU' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Windows Defender Cloud" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SubmitSamplesConsent' -Type DWord -Value 2
}



If ($EnableRemoteRegistry)
{
    Write-YaCMLogEntry -Message "Enabling Remote registry services" -Passthru
    Try{
        Get-Service 'RemoteRegistry' |Set-Service  -StartupType Automatic -ErrorAction Stop
        Start-Service 'RemoteRegistry' -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry -Message ("Unable to enable Remote registry: {0}" -f $_) -Severity 3 -Passthru
    }
}



If ($DisableWireless -or $OptimizeForVDI)
{
    Write-YaCMLogEntry -Message "Disabling Wireless Services" -Passthru
    Try{
        Get-Service 'wcncsvc' | Set-Service -StartupType Disabled -ErrorAction Stop
        Get-Service 'WwanSvc' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry -Message ("Unable to Disable Wireless Services: {0}" -f $_) -Severity 3 -Passthru
    }
}



If ($DisableBluetooth -or $OptimizeForVDI)
{
    Write-YaCMLogEntry -Message "Disabling Bluetooth" -Passthru
    Set-Bluetooth -DeviceStatus Off
}



# Disable Scheduled Tasks
If ($DisableSchTasks)
{
    Write-YaCMLogEntry -Message "Disabling Scheduled Tasks" -Passthru

	$scheduledtasks = @{
        "Microsoft Application Experience\Microsoft Compatibility Appraiser Scheduled Task"="\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "Microsoft Application Experience\ProgramDataUpdater Scheduled Task"="\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        "Microsoft Startup Application Experience\StartupAppTask Scheduled Task"="\Microsoft\Windows\Application Experience\StartupAppTask"
	    "Microsoft CEIP Consolidator Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
	    "Microsoft USB CEIP Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
	    "Microsoft Maps Toast Task Scheduled Task"="\Microsoft\Windows\Maps\MapsToastTask"
	    "Microsoft Maps Update Task Scheduled Task"="\Microsoft\Windows\Maps\MapsUpdateTask"
	    "Microsoft Family Safety Monitor Scheduled Task"="\Microsoft\Windows\Shell\FamilySafetyMonitor"
	    "Microsoft Resolution Host Scheduled Task"="\Microsoft\Windows\WDI\ResolutionHost"
	    "Microsoft Windows Media Sharing UpdateLibrary Scheduled Task"="\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"
	    "Microsoft Proxy Scheduled Task"="\Microsoft\Windows\Autochk\Proxy"
	    "Microsoft Cloud Experience Host Create Object Task Scheduled Task"="\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
	    "Microsoft Siuf DmClient Scheduled Task"="\Microsoft\Windows\Feedback\Siuf\DmClient"
	    "Microsoft Siuf\DmClientOnScenarioDownload Scheduled Task"="\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
	    "Microsoft FamilySafetyRefreshTask Scheduled Task"="\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
	    "Microsoft Windows Error Reporting\QueueReporting Scheduled Task"="\Microsoft\Windows\Windows Error Reporting\QueueReporting"
	    "Microsoft XblGameSaveTask Scheduled Task"="\Microsoft\XblGameSave\XblGameSaveTask"
    }

    Foreach ($task in $scheduledtasks.GetEnumerator()){
        Write-YaCMLogEntry -Message ('Disabling [{0}]' -f $task.Key) -Passthru
        Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
    }

    If($OptimizeForVDI)
    {
        $AdditionalScheduledTasks = @{
            "Microsoft Application Experience\AitAgent Scheduled Task"="\Microsoft\Windows\Application Experience\AitAgent"
            "Microsoft Bluetooth UninstallDeviceTask Scheduled Task"="\Microsoft\Windows\Bluetooth\UninstallDeviceTask"
            "Microsoft Customer Experience Improvement Program\BthSQM Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
            "Microsoft Customer Experience Improvement Program\KernelCeipTask Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
            "Microsoft Defrag\ScheduledDefrag Scheduled Task"="\Microsoft\Windows\Defrag\ScheduledDefrag"
            "Microsoft DiskDiagnostic\Microsoft-WindowsDiskDiagnosticDataCollector Scheduled Task"="\Microsoft\Windows\DiskDiagnostic\Microsoft-WindowsDiskDiagnosticDataCollector"
            "Microsoft DiskDiagnostic\Microsoft-WindowsDiskDiagnosticResolver Scheduled Task"="\Microsoft\Windows\DiskDiagnostic\Microsoft-WindowsDiskDiagnosticResolver"
            "Microsoft FileHistory\File History (maintenance mode) Scheduled Task"="\Microsoft\Windows\FileHistory\File History (maintenance mode)"
            "Microsoft Live\Roaming\MaintenanceTask Scheduled Task"="\Microsoft\Windows\Live\Roaming\MaintenanceTask"
            "Microsoft Live\Roaming\SynchronizeWithStorage Scheduled Task"="\Microsoft\Windows\Live\Roaming\SynchronizeWithStorage"
            "Microsoft Maintenance\WinSAT Scheduled Task"="\Microsoft\Windows\Maintenance\WinSAT"
            "Microsoft Mobile Broadband Accounts\MNO Metadata Parser Scheduled Task"="\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
            "Microsoft MobilePC\HotStart Scheduled Task"="\Microsoft\Windows\MobilePC\HotStart"
            "Microsoft Power Efficiency Diagnostics\AnalyzeSYSTEM\Microsoft\Windows\Ras\MobilityManager Scheduled Task"="\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSYSTEM\Microsoft\Windows\Ras\MobilityManager"
            "Microsoft SideShow\AutoWake Scheduled Task"="\Microsoft\Windows\SideShow\AutoWake"
            "Microsoft SideShow\GadgetManager Scheduled Task"="\Microsoft\Windows\SideShow\GadgetManager"
            "Microsoft SideShow\SessionAgent Scheduled Task"="\Microsoft\Windows\SideShow\SessionAgent"
            "Microsoft SideShow\SystemDataProviders Scheduled Task"="\Microsoft\Windows\SideShow\SystemDataProviders"
            "Microsoft SpacePort\SpaceAgentTask Scheduled Task"="\Microsoft\Windows\SpacePort\SpaceAgentTask"
            "Microsoft SystemRestore\SR Scheduled Task"="\Microsoft\Windows\SystemRestore\SR"
            #"Microsoft UPnP\UPnPHostConfig Scheduled Task"="\Microsoft\Windows\UPnP\UPnPHostConfig"
            "Microsoft Windows Defender\Windows Defender Cache Maintenance Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
            "Microsoft Windows Defender\Windows Defender Scheduled Scan Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Cleanup\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
            "Microsoft Windows Defender\Windows Defender Verification Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Verification"
            "Microsoft WindowsBackup\ConfigNotification Scheduled Task"="\Microsoft\Windows\WindowsBackup\ConfigNotification"
        }

        Foreach ($task in $AdditionalScheduledTasks.GetEnumerator()){
            Write-YaCMLogEntry -Message ('Disabling [{0}] for VDI' -f $task.Key) -Passthru
            Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
        }
    }
}



If ($DisableCortana)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:33] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Cortana" -f $prefixmsg) -Passthru

	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:14] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Search option in taskbar" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:42] :: " -f $prefixmsg}
    Write-YaCMLogEntry -Message ("{0}Disabling search and Cortana to use location") -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Disabling Cortana Consent" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Type DWord -Value 0
    Write-YaCMLogEntry -Message "Disabling Privacy Policy" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Type DWord -Value 0
    Write-YaCMLogEntry -Message "Disabling Text Collection" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling Ink Collection" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value 1
    Write-YaCMLogEntry -Message "Disabling contacts" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Name 'HarvestContacts' -Type DWord -Value 0

}



If($DisableInternetSearch){

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:12] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Bing Search" -f $prefixmsg) -Passthru

	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'BingSearchEnabled' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:47] :: "}
    Write-YaCMLogEntry -Message ("Disable search web when searching pc" -f $prefixmsg) -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:55] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Web Search in search bar" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Disabling Bing Search" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type DWord -Value 0
}



# Privacy and mitigaton settings
# See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
If ($ApplyPrivacyMitigations)
{
    Write-YaCMLogEntry -Message "Disabling Privacy Mitigations" -Passthru

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling NCSI active test" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' -Name 'NoActiveProbe' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Disabling automatic installation of network devices" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private' -Name 'AutoSetup' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling customer experience improvement program" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling sending settings to cloud" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSync' -Type DWord -Value 2

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling synchronizing files to cloud" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSyncUserOverride' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling sending additional info with error reports" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'DontSendAdditionalData' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disallowing the user to change sign-in options" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowSignInOptions' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling Microsoft accounts for modern style apps" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1

	# Disable the Azure AD Sign In button in the settings app
	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling Sending data to Microsoft for Application Compatibility Program Inventory"
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value 1

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling the Microsoft Account Sign-In Assistant" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value '3'

	# Disable the MSA Sign In button in the settings app
	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling MSA sign-in options" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowYourAccount' -Type DWord -Value 0

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling camera usage on user's lock screen" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling lock screen slideshow" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling Consumer Features" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disable the `"how to use Windows`" contextual popups" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Type DWord -Value 1

	# Offline maps
	Write-YaCMLogEntry -Message "Privacy Mitigations :: Turning off unsolicited network traffic on the Offline Maps settings page" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AllowUntriggeredNetworkTrafficOnSettingsPage' -Type DWord -Value 0

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Turning off Automatic Download and Update of Map Data" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AutoDownloadAndUpdateMapData' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\Maps' -Name 'AutoUpdateEnabled' -Type DWord -Value 0	-Force

	# Microsoft Edge
	Write-YaCMLogEntry -Message "Privacy Mitigations :: Enabling Do Not Track in Microsoft Edge" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Type DWord -Value 1

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disallow web content on New Tab page in Microsoft Edge" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' -Name 'AllowWebContentOnNewTabPage' -Type DWord -Value 0

	# General stuff
	Write-YaCMLogEntry -Message "Privacy Mitigations :: Turning off the advertising ID" -PassThru
	#Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Turning off Location Tracking" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Type String -Value "Deny"
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Type DWord -Value 0

	# Stop getting to know me
	Write-YaCMLogEntry -Message "Privacy Mitigations :: Turning off automatic learning" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value 1
	# Turn off updates to the speech recognition and speech synthesis models
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' -Name 'ModelDownloadAllowed' -Type DWord -Value 0

	Write-YaCMLogEntry -Message "Privacy Mitigations :: Disallowing Windows apps to access account information" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Type DWord -Value '2'

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling Xbox features" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling WiFi Sense" -PassThru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Name 'Value' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'Value' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'WiFISenseAllowed' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Disabling all feedback notifications"
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1

    If($OptimizeForVDI){$prefixmsg += "VDI Optimizations [OSOT ID:53] :: "}
	Write-YaCMLogEntry -Message ("Privacy Mitigations :: {0}Disabling telemetry" -f $prefixmsg)
	$OsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption
	If ($OsCaption -like "*Enterprise*" -or $OsCaption -like "*Education*"){
		$TelemetryLevel = "0"
		Write-YaCMLogEntry -Message "Privacy Mitigations :: Enterprise edition detected. Supported telemetry level: Security" -PassThru
	}
	Else{
		$TelemetryLevel = "1"
		Write-YaCMLogEntry -Message "Privacy Mitigations :: Lowest supported telemetry level: Basic" -PassThru
	}
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -Name 'NoGenTicket' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Privacy Mitigations :: Hiding 'Share' context menu item" -PassThru
    Remove-Item -LiteralPath 'Registry::HKCR\*\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Directory\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Drive\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Registry::HKCR\*\shellex\ContextMenuHandlers\ModernSharing' -ErrorAction SilentlyContinue

    Write-YaCMLogEntry -Message 'Privacy Mitigations :: Disabling Tailored Experiences' -PassThru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Type DWord -Value 1
    Write-YaCMLogEntry -Message 'Privacy Mitigations :: Hiding Microsoft Account Protection warning' -PassThru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows Security Health\State' -Name 'AccountProtection_MicrosoftAccount_Disconnected' -Type DWord -Value 1
    Write-YaCMLogEntry -Message 'Privacy Mitigations :: Disabling Website Access to Language List' -PassThru
	Set-LocalPolicyUserSetting -Path 'Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Type DWord -Value 1
    Write-YaCMLogEntry -Message 'Disabling GameBar' -Path 'SOFTWARE\Microsoft\GameBar' -PassThru
    Set-LocalPolicyUserSetting -Name 'AutoGameModeEnabled' -Type DWord -Value 0
    Write-YaCMLogEntry -Message 'Disabling Game DVR' -PassThru
	Set-LocalPolicyUserSetting -Path 'SYSTEM\GameConfigStore' -Name 'GameDVR_Enabled' -Type DWord -Value 0

}


If($DisablePreviewBuild)
{
    Write-YaCMLogEntry -Message "Disabling PreviewBuilds capability" -PassThru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'AllowBuildPreview' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'EnableConfigFlighting' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'EnableExperimentation' -Type DWord -Value 0
}

If ($EnableWinRM)
{
    Write-YaCMLogEntry -Message "Enabling WinRM" -Passthru

    $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
    $connections = $networkListManager.GetNetworkConnections()

    # Set network location to Private for all networks
    $connections | ForEach-Object{$_.GetNetwork().SetCategory(1)}

    # REQUIRED: set network to private before enabling winrm
    $netprofile = (Get-NetConnectionProfile -InterfaceAlias Ethernet*).NetworkCategory
    if (($netprofile -eq "Private") -or ($netprofile -eq "DomainAuthenticated")){<#do noting#>}Else{Set-NetConnectionProfile -NetworkCategory Private}

    Try{
        Enable-PSRemoting -SkipNetworkProfileCheck -ErrorAction SilentlyContinue | Out-Null
        Start-Process winrm -ArgumentList 'qc -quiet' -Wait -NoNewWindow -RedirectStandardOutput ((Get-SMSTSENV -ReturnLogPath) + "\winrm.log") | Out-Null

        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Port)){Set-Item WSMan:\localhost\Listener\Listener_*\Port -Value '5985'}
        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Address)){Set-Item WSMan:\localhost\Listener\Listener_*\Address -Value '*'}
        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Transport)){Set-Item WSMan:\localhost\Listener\Listener_*\Transport -Value 'HTTP'}

        Set-item WSMan:\localhost\Client\Auth\Basic -Value 'true'
        Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value 'true'
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'

        Set-Item WSMan:\localhost\Service\Auth\Basic -Value 'true'

        Set-WSManInstance -ResourceUri winrm/config -ValueSet @{MaxTimeoutms = "1800000"} | Out-Null

        Set-item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value '800'

        If(!$DisableFirewall)
        {
            netsh advfirewall firewall set rule group="Windows Remote Administration" new enable=yes  | Out-Null
            netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=yes action=allow  | Out-Null
        }

        Set-Service winrm -startuptype "auto"
        Restart-Service winrm  | Out-Null

    }
    Catch{
        Write-YaCMLogEntry -Message ("Unable to setup WinRM: {0}" -f $_.Exception.Message) -Severity 3 -Passthru
    }
}



If($EnableStrictUAC)
{
    Write-YaCMLogEntry -Message "Enabling strict UAC Level" -Passthru

    Write-YaCMLogEntry -Message "Enabling UAC prompt administrators for consent on the secure desktop" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2

    Write-YaCMLogEntry -Message "Disabling elevation UAC prompt User for consent on the secure desktop" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Enabling elevation UAC prompt detect application installations and prompt for elevation" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enabling elevation UAC UIAccess applications that are installed in secure locations" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSecureUAIPaths' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enabling Enable virtualize file and registry write failures to per-user locations." -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enabling UAC for all administrators" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Filter Local administrator account privileged tokens" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Enabling User Account Control approval mode" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling enumerating elevated administator accounts" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Enable All credential or consent prompting will occur on the interactive user's desktop" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enforce cryptographic signatures on any interactive application that requests elevation of privilege" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ValidateAdminCodeSignatures' -Type DWord -Value 0

}



If ($EnableAppsRunAsAdmin)
{
    Write-YaCMLogEntry -Message "Enabling UAC to allow Apps to run as Administrator" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1
}



If ($DisableUAC)
{
    Write-YaCMLogEntry -Message "Disabling User Access Control" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 0
}



If ($DisableAdminShares)
{
    Write-YaCMLogEntry -Message "Disabling implicit administrative shares" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0
}



If ($DisableWUP2P -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg += "VDI Optimizations [OSOT ID:31] :: "}
    Write-YaCMLogEntry -Message ("{0}Disable P2P WIndows Updates" -f $prefixmsg) -Passthru

    If ($OSBuildNumber -eq 10240) {
		# Method used in 1507
		Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DownloadMode' -Type DWord -Value 1
        Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DownloadModeRestricted' -Type DWord -Value 1
	}
    ElseIf ($OSBuildNumber -le 14393) {
		# Method used in 1511 and 1607
		Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DownloadMode' -Type DWord -Value 1
	}
    Else {
		# Method used since 1703
		Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -ErrorAction SilentlyContinue
	}
    #adds windows update back to control panel (permissions needs to be changed)
    #Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX' -Name 'IsConvergedUpdateStackEnabled' -Type DWord -Value 0
}



If ($EnableIEEnterpriseMode)
{
    Write-YaCMLogEntry -Message "Enabling Enterprise Mode option in IE" -Passthru

    If(Test-Path $IEEMSiteListPath){
        Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name 'Enable' -Type DWord -Value 1
        Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name 'Sitelist' -Value $IEEMSiteListPath
    }
    Else{
        Write-YaCMLogEntry -Message ("IE Enterprise XML Path [{0}] is not found" -f $IEEMSiteListPath)
    }
}



# Logon script
If ($InstallLogonScript -and (Test-Path $LogonScriptPath) )
{
    Write-YaCMLogEntry -Message "Copying Logon script to $env:windir\Scripts" -Passthru

	If (!(Test-Path "$env:windir\Scripts"))
	{
		New-Item "$env:windir\Scripts" -ItemType Directory
	}
	Copy-Item -Path $LogonScriptPath -Destination "$env:windir\Scripts\Logon.ps1"

    Write-YaCMLogEntry -Message "Creating RunOnce entries" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce' -Name 'Logon' -Type DWord -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $env:windir\Scripts\Logon.ps1"

}



If($EnableCredGuard)
{
    Write-YaCMLogEntry -Message "Enabling Virtualization Based Security" -Passthru

    if ($OSBuildNumber -gt 14393) {
        try {
            # For version older than Windows 10 version 1607 (build 14939), enable required Windows Features for Credential Guard
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-HyperVisor -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
            Write-YaCMLogEntry -Message "Successfully enabled Microsoft-Hyper-V-HyperVisor feature" -Passthru
        }
        catch [System.Exception] {
            Write-YaCMLogEntry -Message ("An error occured when enabling Microsoft-Hyper-V-HyperVisor. {0}" -f $_) -Severity 3 -Passthru
        }

        try {
            # For version older than Windows 10 version 1607 (build 14939), add the IsolatedUserMode feature as well
            Enable-WindowsOptionalFeature -FeatureName IsolatedUserMode -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
            Write-YaCMLogEntry -Message "Successfully enabled IsolatedUserMode feature" -Passthru
        }
        catch [System.Exception] {
            Write-YaCMLogEntry -Message ("An error occured when enabling IsolatedUserMode. {0}" -f $_) -Severity 3 -Passthru
        }
    }

    Write-YaCMLogEntry -Message "Enabling Virtualization-based protection of code integrity" -Passthru
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'Locked' -Type DWord -Value 0
    If ($OSBuildNumber -lt 14393) {
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1
    }
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Locked' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Enabling Credential Guard on domain-joined systems" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Type DWord -Value 1

    $DeviceGuardProperty = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    If($DeviceGuardProperty.VirtualizationBasedSecurityStatus -eq 1){
        Write-YaCMLogEntry -Message ("Successfully enabled Credential Guard, version: {0}" -f $DeviceGuardProperty.Version) -Passthru
    }
    Else{
        Write-YaCMLogEntry -Message "Unable to enabled Credential Guard, may not be supported on this model, trying a differnet way" -Severity 2 -Passthru
        . $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Enable -CG
    }
}



If($EnableLinuxSubSystem)
{
    Write-YaCMLogEntry -Message "Enabling Linux Subsystem" -Passthru
    If ($OSBuildNumber -eq 14393) {
		# 1607 needs developer mode to be enabled
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Type DWord -Value 1
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowAllTrustedApps' -Type DWord -Value 1
	}
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}



# VDI ONLY CONFIGS
# ===================================
If ($OptimizeForVDI)
{
    Write-YaCMLogEntry -Message "Configuring VDI Optimizations" -Passthru

    Write-YaCMLogEntry -Message "VDI Optimizations :: Hiding network options from Lock Screen" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Type DWord -Value 1

    Write-YaCMLogEntry -Message ("VDI Optimizations :: Enabling clearing of recent files on exit") -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'ClearRecentDocsOnExit' -Type DWord -Value 1

    Write-YaCMLogEntry -Message ("VDI Optimizations :: Disabling recent files lists") -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoRecentDocsHistory' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:30] :: Disabling Background Layout Service" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout' -Name 'EnableAutoLayout' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:31] :: Disabling CIfS Change Notifications" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoRemoteRecursiveEvents' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("VDI Optimizations :: Disabling Storage Sense") -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense' -Name 'AllowStorageSenseGlobal' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:32] :: Disabling customer experience improvement program" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:34] :: Enabling Automatically Reboot for the Crash Control" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AutoReboot' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:35] :: Disabling sending alert for the Crash Control" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:36] :: Disabling writing event to the system log for the Crash Control" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'LogEvent' -Type DWord -Value 0

    #Optional
    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:37] :: Disable Creation of Crash Dump and removes it" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:38] :: Disabling IPv6" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '255'

    #Optional
    #Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:39] :: Enabling wait time for disk write or read to take place on the SAN without throwing an error"
	#Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name "TimeOutValue' -Type DWord -Value '200'

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:41] :: Enabling 120 sec wait timeout for a services" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Type DWord -Value '120000'

    #Optional
    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:46] :: Removing previous versions capability" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'NoPreviousVersionsPage' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:52] :: Disabling TCP/IP Task Offload" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters' -Name 'DisableTaskOffload' -Type DWord -Value 1

    #Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:57] :: Disabling Automatic Update - important for non persistent VMs"
	#Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:63] :: Disabling NTFS Last Access Timestamp" -Passthru
    Start-process fsutil -ArgumentList 'behavior set disablelastaccess 1' -Wait -NoNewWindow

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:287] :: Disabling  Boot Optimize Function" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction' -Name 'Enable' -Type String -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Superfetch" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnableSuperfetch' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Paging Executive" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'DisablePagingExecutive' -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storing Recycle Bin Files" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoRecycleFiles' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations :: Reducing Disk Timeout Value" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\Disk' -Name 'TimeOutValue' -Type DWord -Value 200

    Write-YaCMLogEntry -Message "VDI Optimizations :: Reducing Application Event Log Max Size" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application' -Name 'MaxSize' -Type DWord -Value 100000

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Application Event Log Retention" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application' -Name 'Retention' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Reducing System Event Log Max Size" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System' -Name 'MaxSize' -Type DWord -Value 100000

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling System Event Log Retention" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System' -Name 'Retention' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Reducing Security Event Log Max Size" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security' -Name 'MaxSize' -Type DWord -Value 100000

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Security Event Log Retention" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security' -Name 'Retention' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Boot GUI" -Passthru
    Start-process bcdedit -ArgumentList '/set BOOTUX disabled' -Wait -NoNewWindow | Out-Null

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:290] :: Disabling Boot Debugging" -Passthru
    Start-process bcdedit -ArgumentList '/bootdebug off' -Wait -NoNewWindow | Out-Null

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:291] :: Disabling Debugging" -Passthru
    Start-process bcdedit -ArgumentList '/debug off' -Wait -NoNewWindow | Out-Null

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:292] :: Disabling Boot Logging" -Passthru
    Start-process bcdedit -ArgumentList '/set bootlog no' -Wait -NoNewWindow | Out-Null

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling automatic recovery mode during boot" -Passthru
    Start-process bcdedit -ArgumentList '/set BootStatusPolicy IgnoreAllFailures' -Wait -NoNewWindow | Out-Null

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling System Recovery and Factory reset" -Passthru
    Start-process reagentc -ArgumentList '/disable'  -Wait -NoNewWindow | Out-Null

    #Write-YaCMLogEntry -Message "VDI Optimizations :: Setting Data Execution Prevention (DEP) policy to OptOut"
    #Start-process bcdedit -ArgumentList '/set nx OptOut'  -Wait -NoNewWindow | Out-Null
    If((gwmi win32_computersystem).Model -ne 'Virtual Machine'){
        Write-YaCMLogEntry -Message "VDI Optimizations :: Delete Restore Points for System Restore" -Passthru
        Start-process vssadmin -ArgumentList 'delete shadows /All /Quiet' -Wait -NoNewWindow | Out-Null
    }
    <#
    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Bootup Trace Loggers" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel' -Name Start -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOOBE' -Name Start -Type DWord -Value 0    Write-YaCMLogEntry -Message
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog' -Name Start -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NtfsLog' -Name Start -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore' -Name Start -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM' -Name Start -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession' -Name Start -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession' -Name Start -Type DWord -Value 0

    #>

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling TLS 1.0" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Type DWord -Value 1
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations :: Change Explorer Default View" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT 11] :: Disable RSS Feeds" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Feeds' -Name 'SyncStatus' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:8] :: Disabling show most used apps at start menu" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:9] :: Disabling show recent items at start menu" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackDocs' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations [OSOT ID:30] :: Disabling Toast notifications to the lock screen" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "VDI Optimizations [VDIGUYS] :: Remove People Button From the Task Bar in Windows" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Settings Temporary Internet Files to Non Persistent" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache' -Name 'Persistent' -Type DWord -Value 0


    Write-YaCMLogEntry -Message "VDI Optimizations :: Reduce IE Temp File." -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths' -Name Paths -Type DWord -Value 0x4
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path1' -Name CacheLimit -Type DWord -Value 0x100
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path2' -Name CacheLimit -Type DWord -Value 0x100
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path3' -Name CacheLimit -Type DWord -Value 0x100
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Paths\path4' -Name CacheLimit -Type DWord -Value 0x100

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [01]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 01 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [02]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 02 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [04]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 04 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [08]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 08 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [32]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 32 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [128]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 128 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [256]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 256 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [512]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 512 -Type DWord -Value 0

    Write-YaCMLogEntry -Message "VDI Optimizations :: Disabling Storage Sense [2048]" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 2048 -Type DWord -Value 0

}



If($OptimizeNetwork){

    Write-YaCMLogEntry -Message "VDI Optimizations :: Configuring SMB Modifications for performance" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableBandwidthThrottling' -Type DWord -Value "1"
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileInfoCacheEntriesMax' -Type DWord -Value "1024"
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DirectoryCacheEntriesMax' -Type DWord -Value "1024"
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileNotFoundCacheEntriesMax' -Type DWord -Value "1024"
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DormantFileLimit' -Type DWord -Value "256"

    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableLargeMtu' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'MaxCmds' -Type DWord -Value '8000'
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableWsd' -Type DWord -Value 0

    # NIC Advanced Properties performance settings for network biased environments
    If(Get-NetAdapterAdvancedProperty -IncludeHidden -DisplayName "Send Buffer Size" -ErrorAction SilentlyContinue){
        Set-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" -DisplayValue 4MB
    }
}



If($DisableActivityHistory)
 {
    # Disable Activity History feed in Task View
    #Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled
    Write-YaCMLogEntry -Message "Disabling Disabling Activity History" -Passthru

	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Type DWord -Value 0
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Type DWord -Value 0
}


If($DisableFontSmoothing)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:89] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Smooth edges of screen fonts Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing' -Name 'DefaultValue' -Type DWord -Value 0
}



If($EnableVisualPerformance)
{
    #Additional Performance changes

    # thanks to camxct
    #https://github.com/camxct/Win10-Initial-Setup-Script/blob/master/Win10.psm1
    Write-YaCMLogEntry -Message "Adjusting visual effects for performance" -Passthru

    Write-YaCMLogEntry -Message ("Disabling Checkbox selections on folders and files" -f $prefixmsg) -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'AutoCheckSelect' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:83] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:84] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Animations in the taskbar Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:85] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Enable Peek Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled' -Name 'DefaultValue' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:86] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Save taskbar thumbnail previews Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:87] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Show translucent selection rectangle Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:88] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Show window contents while dragging Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:90] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect" -f $prefixmsg) -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:72] :: "}
    Write-YaCMLogEntry -Message ("{0}Setting Windows Visual Effects to Optimized for best performance" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Type DWord -Value 3

    Write-YaCMLogEntry -Message ("{0}Disabling Checkbox selections on folders and files" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'AutoCheckSelect' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:83] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:84] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Animations in the taskbar Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:85] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Enable Peek Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled' -Name 'DefaultValue' -Type DWord -Value 0
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:86] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Save taskbar thumbnail previews Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:87] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Show translucent selection rectangle Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:88] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Show window contents while dragging Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:89] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Smooth edges of screen fonts Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:90] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow' -Name 'DefaultValue' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:73] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate' -Type String -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:74] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Animations in the taskbar Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAnimations' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:75] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Peek Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\DWM' -Name 'EnableAeroPeek' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:76] :: "}
    Write-YaCMLogEntry -Message ("{0}Turning off Play animations in windows" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value 9012038010000000

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:77] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Save taskbar thumbnail previews Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\DWM' -Name 'AlwaysHibernateThumbnails' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:78] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Show translucent selection rectangle Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewAlphaSelect' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:79] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Show window contents while dragging Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Desktop' -Name 'DragFullWindows' -Type String -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:80] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Smooth edges of screen fonts Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Desktop' -Name 'FontSmoothing' -Type String -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:81] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewShadow' -Type DWord -Value 0

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:10] :: "}
    Write-YaCMLogEntry -Message ("{0}Setting Delaying Show the Reduce Menu" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Desktop' -Name MenuShowDelay -Type DWord -Value 120

    Write-YaCMLogEntry -Message ("{0}Removing Keyboard Delay the Reduce Menu" -f $prefixmsg) -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Keyboard' -Name 'KeyboardDelay' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling creating thumbnail cache [Thumbs.db] on local Folder") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'DisableThumbnailCache' -Type DWord -Value 1

    Write-YaCMLogEntry -Message ("Disabling creating thumbnail cache [Thumbs.db] on Network Folders") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'DisableThumbsDBOnNetworkFolders' -Type DWord -Value 1

    Write-YaCMLogEntry -Message ("Enabling TaskBar Icons Only") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'IconsOnly' -Type DWord -Value 1

    Write-YaCMLogEntry -Message ("Disabling Desktop Shortcut Icons") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideIcons' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Explorer Information Tip") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowInfoTip' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Combobox Slide Animations") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Window Animations") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Cursor Shadow") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Content while dragging") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Window shadows") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Listbox smooth scrolling") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Start Menu Animations") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Windows Fade") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Themes") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling Thumbnails") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon' -Name 'DefaultApplied' -Type DWord -Value 0

    Write-YaCMLogEntry -Message ("Disabling ToolTip Animations") -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation' -Name 'DefaultApplied' -Type DWord -Value 0
}



If($EnableDarkTheme)
{
    Write-YaCMLogEntry -Message "Enabling Dark Theme" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Type DWord -Value 0
}



If($EnableTaskbarAutoColor)
{
    Write-YaCMLogEntry -Message "Enabing Taskbar AutoColorization" -Passthru
    Set-LocalPolicyUserSetting -Path 'Control Panel\Desktop' -Name AutoColorization -Type DWord -Value 1
}



If($EnableNumlockStartup)
{
    Write-YaCMLogEntry -Message "Enabling NumLock after startup" -Passthru

    #Write-YaCMLogEntry -Message ("Enabing Num lock for Default")
	#Set-LocalPolicySetting -Path 'HKEY_USERS\.DEFAULT\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Type DWord -Value 2147483650
    Set-LocalPolicyUserSetting -Path 'Control Panel\Keyboard' -Name InitialKeyboardIndicators -Type DWord -Value 2147483650

	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}



If($ShowKnownExtensions)
{
    Write-YaCMLogEntry -Message "Enabling known extensions" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0

    #Write-YaCMLogEntry -Message "Showing known file extensions for SYSTEM"
	#Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0

}



If($ShowHiddenFiles)
{
    Write-YaCMLogEntry -Message "Enabling hidden files" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Type DWord -Value 1
}



If($RemoveVMToolsTrayIcon){
    if ( Test-Path "$Env:Programfiles\VMware\VMware Tools" ){
        Write-YaCMLogEntry -Message ("Removing VM Tools Tray icon from taskbar...") -Passthru
        Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools' -Name 'ShowTray' -Type DWord -Value 0
    }
}


If($ShowThisPCOnDesktop)
{
    Write-YaCMLogEntry -Message "Adding 'This PC' desktop shortcut" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0
}



If($ShowUserFolderOnDesktop)
{
    Write-YaCMLogEntry -Message "Adding 'User Folder' desktop shortcut" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0
}



If($RemoveRecycleBinOnDesktop)
{
    Write-YaCMLogEntry -Message "Removing 'Recycle Bin' desktop shortcut" -Passthru
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Type DWord -Value 1
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Type DWord -Value 1
}



# Disable Application suggestions and automatic installation
If ($DisableAppSuggestions)
{
    $AppSuggestions = [ordered]@{
        ContentDeliveryAllowed="Content Delivery"
	    OemPreInstalledAppsEnabled="Oem PreInstalled Apps"
	    PreInstalledAppsEnabled="PreInstalled Apps"
	    PreInstalledAppsEverEnabled="PreInstalled Apps Ever"
	    SilentInstalledAppsEnabled="Automatically Installing Suggested Apps"
	    "SubscribedContent-310093Enabled"="Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested"
	    "SubscribedContent-338387Enabled"="Get fun facts, tips and more from Windows and Cortana on your lock screen"
	    "SubscribedContent-338388Enabled"="Occasionally show suggestions in Start"
	    "SubscribedContent-338389Enabled"="Get Tips, Tricks, and Suggestions Notifications"
	    "SubscribedContent-338393Enabled"="Show me sggested Content in Settings app"
        "SubscribedContent-353694Enabled"="Show me sggested Content in Settings app"
        "SubscribedContent-353696Enabled"="Show me sggested Content in Settings app"
	    "SubscribedContent-353698Enabled"="Show suggestions occasionally in Timeline"
	    SystemPaneSuggestionsEnabled="SystemPane Suggestions"
    }
    $i = 1

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1

    Foreach ($key in $AppSuggestions.GetEnumerator()){
        $AdName = $key.Value
        Write-YaCMLogEntry -Message ("Disabling `"{0}`" option [{1}]" -f $AdName,$key.Key) -Passthru

        Write-YaCMLogEntry -Message ("Disabling App Suggestion: `"{2}`" ({0} of {1})" -f $i,$AppSuggestions.count,$AdName)
        Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name $key.Key -Type DWord -Value 0
        Write-YaCMLogEntry -Message "Disabling App Suggestion"
        Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name $key.Key -Type DWord -Value 0
        <#
        If ($OSBuildNumber -ge 17134) {
            Write-YaCMLogEntry  -Message "Disabling App Suggestion" -Passthru
            Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current' -Name 'Data' -Type Binary -Value ""
        }
        #>
        $i++
    }

    Stop-Process -Name "ShellExperienceHost" -ErrorAction SilentlyContinue
}



If($Hide3DObjectsFromExplorer)
{
    Write-YaCMLogEntry -Message "Hiding 3D Objects icon from Explorer namespace" -Passthru
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' -Recurse -ErrorAction SilentlyContinue  | Out-Null
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value "Hide"
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' -Recurse -ErrorAction SilentlyContinue
}



If($DisableEdgeShortcutCreation)
{
    Write-YaCMLogEntry -Message "Disabling Edge shortcut creation" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling Edge preload"
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowPrelaunch' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' -Name 'AllowTabPreloading' -Type DWord -Value 0 -Force
}



If($SetSmartScreenFilter)
{
	switch($SetSmartScreenFilter){
    'Off'  {$value = 0;$label = "to Disable"}
    'User'  {$value = 1;$label = "to Warning Users"}
    'admin' {$value = 2;$label = "to Require Admin approval"}
    default {$value = 1;$label = "to Warning Users"}
    }
    Write-YaCMLogEntry -Message "Configuring Smart Screen Filter $label" -Passthru

    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value $value
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Type String -Value "Block"

    Write-YaCMLogEntry -Message "Enabling Smart Screen Filter on Edge"
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Type DWord -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Type DWord -Value $value -Force
}



If ($DisableFirewall)
{

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:59] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling Windows Firewall on all profiles" -f $prefixmsg) -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile' -Name 'EnableFirewall' -Type DWord -Value 0

    netsh advfirewall set allprofiles state off | Out-Null
    Try{
        Get-Service 'mpssvc' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry -Message ("Unable to Disable Windows Firewall: {0}" -f $_) -Severity 3
    }
}



If($CleanSampleFolders)
{
    Write-YaCMLogEntry -Message "Cleaning Sample Folders" -Passthru

    Remove-Item "$env:PUBLIC\Music\Sample Music" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Pictures\Sample Pictures" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Recorded TV\Sample Media" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Videos\Sample Videos" -Recurse -ErrorAction SilentlyContinue | Out-Null
}



If($DisableIndexing -or $OptimizeForVDI)
{
    Write-YaCMLogEntry -Message "Disable Indexing on $env:SystemDrive" -Passthru

    Disable-Indexing $env:SystemDrive
}



If ($DisableRestore -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:66] :: "}
    Write-YaCMLogEntry -Message ("{0}Disabling system restore" -f $prefixmsg) -Passthru

    Disable-ComputerRestore -drive c:\
}



If ($PreCompileAssemblies -or $OptimizeForVDI)
{
    #https://www.emc.com/collateral/white-papers/h14854-optimizing-windows-virtual-desktops-deploys.pdf
    #https://blogs.msdn.microsoft.com/dotnet/2012/03/20/improving-launch-performance-for-your-desktop-applications/
    Write-YaCMLogEntry -Message "Pre-compile .NET framework assemblies. This can take a while" -Passthru
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "update /force" -Wait -NoNewWindow
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "executequeueditems" -Wait -NoNewWindow
}



If($RemoveUnusedPrinters)
{
    Write-YaCMLogEntry -Message ("Removing Unused Local Printers") -Passthru
    $filter = "Microsoft XPS Document Writer|Microsoft Print to PDF|OneNote" #Send To OneNote 16
    Get-Printer | Where-Object{($_.Name -notmatch $filter) -and ($_.Type -eq 'Local') } | Remove-Printer -PassThru -Confirm:$false
}


Write-YaCMLogEntry -Message ("Completed Windows 10 Optimizations") -Passthru
