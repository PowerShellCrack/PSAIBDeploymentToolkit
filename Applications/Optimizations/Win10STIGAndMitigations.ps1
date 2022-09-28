<#
	.SYNOPSIS
        Applies DISA stigs for Windows 10

    .DESCRIPTION
        Applies DISA stigs for Windows 10
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
        Configurable using custom variables in MDT/SCCM

    .INFO
        Author:         Richard Tracy
        Email:          richard.tracy@hotmail.com
        Twitter:        @rick2_1979
        Website:        www.powershellcrack.com
        Last Update:    06/18/2019
        Version:        2.1.6
        Thanks to:      unixuser011,W4RH4WK,TheVDIGuys,cluberti,JGSpiers

    .DISCLOSURE
        THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
        OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. BY USING OR DISTRIBUTING THIS SCRIPT, YOU AGREE THAT IN NO EVENT
        SHALL RICHARD TRACY OR ANY AFFILATES BE HELD LIABLE FOR ANY DAMAGES WHATSOEVER RESULTING FROM USING OR DISTRIBUTION OF THIS SCRIPT, INCLUDING,
        WITHOUT LIMITATION, ANY SPECIAL, CONSEQUENTIAL, INCIDENTAL OR OTHER DIRECT OR INDIRECT DAMAGES. BACKUP UP ALL DATA BEFORE PROCEEDING.

    .PARAM
        '// Global Settings
        DisableSTIGScript
        CFG_UseLGPOForConfigs
        LGPOPath

        '// VDI Preference
        CFG_OptimizeForVDI

        '// STIG Settings
        CFG_ApplySTIGItems
        CFG_ApplyEMETMitigations

    .EXAMPLE
        #Copy this to MDT CustomSettings.ini
        Properties=CFG_UseLGPOForConfigs,LGPOPath,CFG_OptimizeForVDI,CFG_ApplySTIGItems,CFG_ApplyEMETMitigations

        #Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_OptimizeForVDI=False
        CFG_ApplySTIGItems=True
        CFG_ApplyEMETMitigations=True

        #Add script to task sequence

    .LOGS
        2.1.6 - Jun 18, 2019 - Added more info page, change Get-SMSTSENV warning to verbose message
        2.1.5 - May 30, 2019 - defaulted reg type to dword if not specified, standarized registry keys captalizations
        2.1.4 - May 28, 2019 - fixed Set-LocalPolicyUserSettings default users,resolved all VSC problems
        2.1.3 - May 28, 2019 - fixed Get-SMSTSENV log path
        2.1.2 - May 15, 2019 - Added Get-ScriptPpath function to support VScode and ISE; fixed Set-LocalPolicyUserSettings
        2.1.1 - May 10, 2019 - reorganized controls in categories
        2.1.0 - Apr 17, 2019 - added Set-LocalPolicyUserSetting function
        2.0.0 - Apr 12, 2019 - added more Windows 10 settings check
        1.5.0 - Mar 29, 2019 - added more options from theVDIGuys script
        1.1.5 - Mar 13, 2019 - Fixed mitigations script and removed null outputs
        1.1.0 - Mar 12, 2019 - Updatd LGPO process as global variable and added param for it
        1.0.0 - Nov 20, 2018 - split from config script
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
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
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
                Write-YaCMLogEntry  ("Unable to configure Bluetooth Settings: {0}" -f $_.Exception.Message) -Severity 3 -Source ${CmdletName}
            }
            Finally{
                #If ((Get-Service bthserv).Status -eq 'Stopped') { Start-Service bthserv }
            }
        }
        Else{
            Write-YaCMLogEntry  ("No Bluetooth found") -Severity 0 -Source ${CmdletName}
        }
    }
    End{}
}

#=======================================================
# MAIN
#=======================================================
$ErrorActionPreference = 'Stop'
[boolean]$DisableScript = $false
# VDI Preference
[boolean]$OptimizeForVDI = $true
# STIG Settings
[boolean]$ApplySTIGItems = $true
[boolean]$ApplyEMETMitigations = $true

# Ultimately disable the entire script. This is useful for testing and using one task sequences with many rules
If($DisableScript){
    Write-YaCMLogEntry  "Script is disabled!" -Passthru
    Exit 0
}

[int]$OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
[string]$OsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption
##*===========================================================================
##* MAIN
##*===========================================================================

If($ApplySTIGItems )
{

    Write-YaCMLogEntry -Message "Applying STIG Items" -Passthru

    If($OptimizeForVDI){
        Write-YaCMLogEntry  "Ignoring Stig Rule ID: SV-77813r4_rule :: Enabling TPM" -Passthru
        Write-YaCMLogEntry  "Ignoring Stig Rule ID: SV-91779r3_rule :: Enabling UEFI" -Passthru
        Write-YaCMLogEntry  "Ignoring Stig Rule ID: SV-91781r2_rule :: Enabling SecureBoot" -Passthru
        Write-YaCMLogEntry  "Ignoring Stig Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security" -Passthru
        Write-YaCMLogEntry  "Ignoring Stig Rule ID: SV-78089r7_rule :: Enabling Credential Guard" -Passthru
        Write-YaCMLogEntry  "Ignoring Stig Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity" -Passthru
    }

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-83411r1_rule :: Enabling Powershell Script Block Logging" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Applying STIG Items" -Passthru

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78039r1_rule :: Disabling Autorun for local volumes" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78161r1_rule :: Disabling Autorun for local machine" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutorun' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78163r1_rule :: Disabling Autorun for local drive" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF

    Write-YaCMLogEntry -Message "Disabling Bluetooth" -Passthru
    Set-Bluetooth -DeviceStatus Off

    Write-YaCMLogEntry -Message "TIG Rule ID: SV-78301r1_rule :: Enabling FIPS Algorithm Policy" -Passthru
    Set-LocalPolicySetting -Path 'HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -Name 'Enabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-96851r1_rule :: Disabling personal accounts for OneDrive synchronization" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisablePersonalSync' -Type DWord -Value 1

    # Privacy and mitigaton settings
    # See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78039r1_rule :: Privacy Mitigations :: Disabling Microsoft accounts for modern style apps" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78035r1_rule :: Privacy Mitigations :: Disabling camera usage on user's lock screen" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78039r1_rule :: Privacy Mitigations :: Disabling lock screen slideshow" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-86395r2_rule :: Privacy Mitigations :: Disabling Consumer Features" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1| Out-Null

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-89091r1_rule :: Privacy Mitigations :: Disabling Xbox features" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0

	Write-YaCMLogEntry  ("STIG Rule ID: SV-78173r3_rule :: Privacy Mitigations :: {0}Disabling telemetry" -f $prefixmsg) -Passthru
	If ($OsCaption -like "*Enterprise*" -or $OsCaption -like "*Education*"){
		$TelemetryLevel = "0"
		Write-YaCMLogEntry  "Privacy Mitigations :: Enterprise edition detected. Supported telemetry level: Security" -Passthru
	}
	Else{
		$TelemetryLevel = "1"
		Write-YaCMLogEntry  "Privacy Mitigations :: Lowest supported telemetry level: Basic" -Passthru
	}
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-96859r1_rule: Disabling access the Insider build controls in the Advanced Options." -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77825r1_rule :: Disabling Basic Authentication for WinRM" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77829r1_rule :: Disabling unencrypted traffic for WinRM" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77831r1_rule :: Disabling Digest authentication for WinRM" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77831r1_rule :: Disabling Digest authentication for WinRM" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78309r1_rule :: Enabling UAC prompt administrators for consent on the secure desktop" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78311r1_rule :: Disabling elevation UAC prompt User for consent on the secure desktop" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC prompt detect application installations and prompt for elevation" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC UIAccess applications that are installed in secure locations" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSecureUAIPaths' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78321r1_rule :: Enabling Enable virtualize file and registry write failures to per-user locations." -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78319r1_rule :: Enabling UAC for all administrators" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78087r2_rule :: FIlter Local administrator account privileged tokens" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78307r1_rule :: Enabling User Account Control approval mode" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78307r1_rule :: Disabling enumerating elevated administator accounts" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Enable All credential or consent prompting will occur on the interactive user's desktop" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enforce cryptographic signatures on any interactive application that requests elevation of privilege" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ValidateAdminCodeSignatures' -Type DWord -Value 0


    If(!$OptimizeForVDI)
    {

        Write-YaCMLogEntry  "STIG Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security" -Passthru

        if ($OSBuildNumber -gt 14393) {
            try {
                # For version older than Windows 10 version 1607 (build 14939), enable required Windows Features for Credential Guard
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-HyperVisor -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
                Write-YaCMLogEntry  "Successfully enabled Microsoft-Hyper-V-HyperVisor feature" -Passthru
            }
            catch [System.Exception] {
                Write-YaCMLogEntry  ("An error occured when enabling Microsoft-Hyper-V-HyperVisor. {0}" -f $_) -Severity 3 -Passthru
            }

            try {
                # For version older than Windows 10 version 1607 (build 14939), add the IsolatedUserMode feature as well
                Enable-WindowsOptionalFeature -FeatureName IsolatedUserMode -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
                Write-YaCMLogEntry  "Successfully enabled IsolatedUserMode feature" -Passthru
            }
            catch [System.Exception] {
                Write-YaCMLogEntry  ("An error occured when enabling IsolatedUserMode. {0}" -f $_) -Severity 3 -Passthru
            }
        }

        Write-YaCMLogEntry  "Enabling Windows Defender Application Guard" -Passthru
        Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity" -Passthru
        #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 1
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'Locked' -Type DWord -Value 0
        If ($OSBuildNumber -lt 14393) {
            Set-LocalPolicySetting -Path 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1
        }
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Type DWord -Value 1
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Locked' -Type DWord -Value 0

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-78089r7_rule :: Enabling Credential Guard on domain-joined systems" -Passthru
        Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Type DWord -Value 1

        $DeviceGuardProperty = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
        If($DeviceGuardProperty.VirtualizationBasedSecurityStatus -eq 1){
            Write-YaCMLogEntry  ("Successfully enabled Credential Guard, version: {0}" -f $DeviceGuardProperty.Version) -Passthru
        }
        Else{
            Write-YaCMLogEntry  "Unable to enabled Credential Guard, may not be supported on this model, trying a differnet way" -Severity 2 -Passthru
            . $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Enable -CG
        }
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    }

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-80171r3_rule :: Disable P2P WIndows Updates" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DownloadMode' -Type DWord -Value 0

	switch($SetSmartScreenFilter){
        'Off'   {$value = 0;$label = "to Disable"}
        'User'  {$value = 1;$label = "to Warning Users"}
        'admin' {$value = 2;$label = "to Require Admin approval"}
        default {$value = 1;$label = "to Warning Users"}
    }
    Write-YaCMLogEntry -Message "Configuring Smart Screen Filter :: Configuring Smart Screen Filter $label" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value $value
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Type String -Value "Block"

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78189r5_rule :: Enabling Smart Screen Filter warnings on Edge" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78191r5_rule :: Prevent bypassing SmartScreen Filter warnings" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78191r5_rule :: Enabling SmartScreen filter for Microsoft Edge" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78219r1_rule :: Disabling saved password for RDP" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78223r1_rule :: Forcing password prompt for RDP connections" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78221r1_rule :: Preventing sharing of local drives with RDP Session Hosts" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78221r1_rule :: Enabling RDP Session Hosts secure RPC communications" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78221r1_rule :: Enabling RDP encryption level to High" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Value 3

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78207r5_rule :: Enabling hardware security device requirement with Windows Hello" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'RequireSecurityDevice' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78211r5_rule :: Enabling minimum pin length of six characters or greater" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name 'MinimumPINLength' -Value 6

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78107r1_rule :: Enabling Audit policy using subcategories" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78125r1_rule :: Disabling Local accounts with blank passwords" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78229r1_rule :: Disabling Anonymous SID/Name translation" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'TurnOffAnonymousBlock' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78235r1_rule :: Disabling Anonymous enumeration of SAM accounts" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78239r1_rule :: Disabling Anonymous enumeration of shares" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-86393r3_rule :: Restricting Remote calls to the Security Account Manager (SAM) to Administrators" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)"

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78253r1_rule :: Restricting Services using Local System that use Negotiate when reverting to NTLM authentication" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78245r1_rule :: Disabling prevent anonymous users from having the same rights as the Everyone group" -Passthru
    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77863r2_rule :: Disabling Let everyone permissions apply to anonymous users" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78255r1_rule :: Disabling NTLM from falling back to a Null session" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0' -Name 'allownullsessionfallback' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78295r1_rule :: Disabling requirement for NTLM SSP based clients" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0' -Name 'NTLMMinClientSec' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78257r1_rule :: Disabling PKU2U authentication using online identities" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\LSA\pku2u' -Name 'AllowOnlineID' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78285r1_rule :: Disabling Kerberos encryption types DES and RC4" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Type DWord -Name 'SupportedEncryptionTypes' -Value 0x7ffffff8

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78287r1_rule :: Disabling LAN Manager hash of passwords for storage" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78291r1_rule :: Disabling NTLMv2 response only, and to refuse LM and NTLM" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78293r1_rule :: Enabling LDAP client signing level" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78129r1_rule :: Enabling Outgoing secure channel traffic encryption or signature" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78133r1_rule :: Enabling Outgoing secure channel traffic encryption when possible" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78137r1_rule :: Enabling Outgoing secure channel traffic encryption when possible" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78143r1_rule :: Disabling the ability to reset computer account password" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78151r1_rule :: Configuring maximum age for machine account password to 30 days" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge' -Value 30

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78155r1_rule :: Configuring strong session key for machine account password" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78159r2_rule :: Configuring machine inactivity limit must be set to 15 minutes" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900

    <#
    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78165r2_rule :: Configuring legal notice logon notification" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Type String -Name LegalNoticeText -Value ("`
        You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.`
        By using this IS (which includes any device attached to this IS), you consent to the following conditions:`
        -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.`
        -At any time, the USG may inspect and seize data stored on this IS.`
        -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.`
        -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.`
        -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details")`


    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78171r1_rule :: Configuring legal notice logon title box" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Type String -Name LegalNoticeCaption -Value "DoD Notice and Consent Banner"
    #>

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78177r1_rule :: Disabling Caching of logon credentials" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Type String -Value 10

    If($OptimizeForVDI){
        Write-YaCMLogEntry  "STIG Rule ID: SV-78187r1_rule :: Configuring Smart Card removal to Force Logoff" -Passthru
        Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SCRemoveOption' -Type String -Value 2
    }
    Else{
        Write-YaCMLogEntry  "STIG Rule ID: SV-78187r1_rule :: Configuring Smart Card removal to Lock Workstation" -Passthru
        Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SCRemoveOption' -Type String -Value 1
    }

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-89399r1_rule :: Disabling Server Message Block (SMB) v1 Service " -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-89393r1_rule :: Disabling Secondary Logon service" -Passthru
    Try{
        Get-Service 'seclogon' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry  ("Unable to disable Secondary Login Service: {0}" -f $_) -Severity 3 -Passthru
    }

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-83439r2_rule :: Enabling Data Execution Prev ention (DEP) boot configuration" -Passthru
	Manage-Bde -Protectors -Disable C:
    Start-process bcdedit -ArgumentList '/set nx OptOut' -Wait -NoNewWindow | Out-Null

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78185r1_rule :: Enabling Explorer Data Execution Prevention policy" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78181r3_rule :: Enabling File Explorer shell protocol protected mode" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-89089r2_rule :: Preventing Microsoft Edge browser data from being cleared on exit" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy' -Name 'ClearBrowsingHistoryOnExit' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-83445r4_rule :: Disabling Session Kernel Exception Chain Validation" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78045r1_rule/SV-78049r1_rule :: Setting IPv6 source routing to highest protection" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIpSourceRouting' -Value 2

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78053r1_rule :: Disabling ICMP redirects from overriding Open Shortest Path First (OSPF) generated routes" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78057r1_rule :: Disabling NetBIOS name release requests except from WINS servers" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -Name 'NoNameReleaseOnDemand' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-86387r1_rule :: Disabling WDigest Authentication" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -Name 'UseLogonCredential' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-86953r1_rule :: Removing Run as different user contect menu" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Classes\batfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78059r2_rule :: Disabling insecure logons to an SMB server" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78193r1_rule :: Enabling SMB packet signing" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78197r1_rule :: Enabling SMB packet signing when possible" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78201r1_rule :: Disabling plain text password on SMB Servers" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-85261r2_rule :: Disabling Server Message Block (SMB) v1 on Server" -Passthru
    Try{
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        #Set-SmbServerConfiguration -EnableSMB2Protocol $false
        Disable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry  ("Unable to remove SMB1Protocol Feature: {0}" -f $_) -Severity 3 -Passthru
    }

    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78209r1_rule :: Enabling SMB Server packet signing" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78213r1_rule :: Enabling SMB Srver packet signing when possible" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78249r1_rule :: Disabling  Anonymous access to Named Pipes and Shares" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-86389r1_rule :: Disabling Internet connection sharing" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78067r1_rule :: Disabling Internet connection sharing" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1"
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1"

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-89087r1_rule :: Enabling prioritize ECC Curves with longer key lengths" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'EccCurves' -Type MultiString -Value "NistP384 NistP256"

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78071r2_rule :: Limiting simultaneous connections to the Internet or a Windows domain" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78075r1_rule :: Limiting simultaneous connections to the Internet or a Windows domain" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-83409r1_rule :: Enabling event logging for command line " -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-89373r1_rule :: Enabling Remote host allows delegation of non-exportable credentials" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78097r1_rule :: Disabling Early Launch Antimalware, Boot-Start Driver Initialization Policy" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Value 8

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78099r1_rule :: Enabling Group Policy objects reprocessing" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoGPOListChanges' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78105r1_rule :: Disablng Downloading print driver packages over HTTP" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78111r1_rule :: Disablng Web publishing and online ordering wizards" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWebServices' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78113r1_rule :: Disablng Printing over HTTP" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78117r1_rule :: Enabling device authentication using certificates if possible" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'DevicePKInitEnabled' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78119r1_rule :: Disabling network selection user interface (UI) on the logon screen" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78123r1_rule :: Disabling local user enumerating" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78135r1_rule :: Enabling users must be prompted for a password on resume from sleep (on battery)" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78139r1_rule :: Enabling users must be prompted for a password on resume from sleep (on battery)" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78141r1_rule :: Disabling Solicited Remote Assistance" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78147r1_rule :: Disabling Unauthenticated RPC clients" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'RestrictRemoteClients' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78149r2_rule :: Disabling Microsoft accounts for modern style apps" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78167r3_rule :: Enabling enhanced anti-spoofing for facial recognition" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-96853r1_rule :: Preventing certificate error overrides in Microsoft Edge" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -Name 'PreventCertErrorOverrides' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78195r4_rule :: Disabling InPrivate browsing in Microsoft Edge" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowInPrivate' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78195r4_rule :: Disabling password manager in Microsoft Edge" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'FormSuggest Passwords' -Type String -Value "no"

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78233r1_rule :: Disabling attachments from RSS feeds" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78237r1_rule :: Disabling Basic authentication to RSS feeds" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'AllowBasicAuthInClear' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78241r1_rule :: Disabling indexing of encrypted files" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77811r1_rule :: Disabling changing installation options for users" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77815r1_rule :: Disabling Windows Installer installation with elevated privileges" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77819r1_rule :: Enabling notification if a web-based program attempts to install" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77823r1_rule :: Disabling Automatically signing in the last interactive user after a system-initiated restart" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Value 0

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-78331r2_rule :: Perserving Zone information on attachments"
    Set-LocalPolicyUserSetting -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -Name 'SaveZoneInformation' -Type DWord -Value 2

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-18420r1_rule :: Disabling File System's 8.3 Name Creation" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -Value 1

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77873r1_rule :: Disabling Simple TCP/IP Services and Feature" -Passthru
    Try{
        Disable-WindowsOptionalFeature -FeatureName SimpleTCP -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry  ("Unable to remove Simple TCP/IP Feature: {0}" -f $_) -Severity 3 -Passthru
    }

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-77875r1_rule :: Disabling Telnet Client Feature" -Passthru
    Try{
        Disable-WindowsOptionalFeature -FeatureName TelnetClient -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry  ("Unable to remove TelnetClient: {0}" -f $_) -Severity 3 -Passthru
    }

    Write-YaCMLogEntry -Message "STIG Rule ID: SV-85259r1_rule :: Disabling Windows PowerShell 2.0 Feature" -Passthru
    Try{
        Disable-WindowsOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2' -Online -NoRestart -ErrorAction Stop | Out-Null
        Disable-WindowsOptionalFeature -FeatureName 'MicrosoftWindowsPowerShellV2Root' -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-YaCMLogEntry  ("Unable to remove PowerShellV2 Feature: {0}" -f $_) -Severity 3 -Passthru
    }

    #Write-YaCMLogEntry -Message "STIG Rule ID: SV-78069r4_rule :: DoD Root CA certificates must be installed in the Trusted Root Store" -Passthru
    #Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

    #Write-YaCMLogEntry -Message "STIG Rule ID: SV-78073r3_rule :: External Root CA certificates must be installed in the Trusted Root Store on unclassified systems" -Passthru
    #Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter

    #Write-YaCMLogEntry -Message "STIG Rule ID: SV-78077r4_rule :: DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systemss" -Passthru
    #Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter

    #Write-YaCMLogEntry -Message "STIG Rule ID: SV-78079r3_rule :: US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems" -Passthru
    #Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter

    #Write-YaCMLogEntry -Message "Clearing Session Subsystem's" -Passthru
    #Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems' -Name 'Optional' -Type MultiString -Value ""

    <#
    Write-YaCMLogEntry -Message "Disabling RASMAN PPP Parameters" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'DisableSavePassword' -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'Logging' -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedData' -Value 1
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedPassword' -Value 2
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'SecureVPN' -Value 1
    #>

    Write-YaCMLogEntry -Message "Disabling LLMNR" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0

    Write-YaCMLogEntry -Message "Disabling NCSI active test" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' -Name 'NoActiveProbe' -Type DWord -Value 1

	Write-YaCMLogEntry -Message "Setting unknown networks profile to private" -Passthru
	Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24' -Name 'Category' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Disabling automatic installation of network devices" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private' -Name 'AutoSetup' -Type DWord -Value 0
}



If($ApplyEMETMitigations)
{
    Write-YaCMLogEntry -Message "Enabling Controlled Folder Access" -Passthru
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue

    Write-YaCMLogEntry -Message "Disabling Controlled Folder Access" -Passthru
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue

    Write-YaCMLogEntry -Message "Enabling Core Isolation Memory Integrity" -Passthru
    Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Type DWord -Value 1

    Write-YaCMLogEntry -Message "Enabling Windows Defender Application Guard" -Passthru
	Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null

    if ($OSBuildNumber -gt 17763) {

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-91787r3_rule :: Enabling Data Execution Prevention (DEP) for exploit protection" -Passthru
        If((Get-ProcessMitigation -System).DEP.Enable -eq "OFF"){
              Set-Processmitigation -System -Enable DEP
        }

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-91791r4_rule :: Enabling (Bottom-Up ASLR) for exploit protection" -Passthru
        If((Get-ProcessMitigation -System).ASLR.BottomUp -eq "OFF"){
            Set-Processmitigation -System -Enable BottomUp
        }

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-91793r3_rule :: Enabling Control flow guard (CFG) for exploit protection" -Passthru
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable CFG
        }

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-91797r3_rule :: Enabling Validate exception chains (SEHOP) for exploit protection" -Passthru
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable SEHOP
        }

        Write-YaCMLogEntry -Message "STIG Rule ID: SV-91799r3_rule :: Enabling Validate heap integrity for exploit protection" -Passthru
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable TerminateOnError
        }


        #DEP: ON
        $ApplicationMitigationsDep = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91897r2_rule"="EXCEL.EXE"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91891r2_rule"="chrome.exe"
            "SV-91905r2_rule"="FLTLDR.EXE"
            "SV-91909r2_rule"="GROOVE.EXE"
            "SV-91913r2_rule"="iexplore.exe"
            "SV-91917r2_rule"="INFOPATH.EXE"
            "SV-91919r2_rule Part 1"="java.exe"
            "SV-91919r2_rule Part 2"="javaw.exe"
            "SV-91919r2_rule Part 3"="javaws.exe"
            "SV-91923r2_rule"="lync.exe"
            "SV-91927r2_rule"="MSACCESS.EXE"
            "SV-91929r2_rule"="MSPUB.EXE"
            "SV-91935r2_rule"="OIS.EXE"
            "SV-91931r2_rule"="OneDrive.exe"
            "SV-91939r2_rule"="OUTLOOK.EXE"
            "SV-91941r2_rule"="plugin-container.exe"
            "SV-91943r2_rule"="POWERPNT.EXE"
            "SV-91945r2_rule"="PPTVIEW.EXE"
            "SV-91951r2_rule"="VISIO.EXE"
            "SV-91955r2_rule"="VPREVIEW.EXE"
            "SV-91959r2_rule"="WINWORD.EXE"
            "SV-91963r2_rule"="wmplayer.exe"
            "SV-91965r2_rule"="wordpad.exe"
        }

        #ASLR: BottomUp: ON
        $ApplicationMitigationsASLR_BU = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91913r2_rule"="iexplore.exe"
        }

        #ASLR: ForceRelocateImages: ON
        $ApplicationMitigationsASLR_FRI = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91897r2_rule"="EXCEL.EXE"
            "SV-91913r2_rule"="iexplore.exe"
            "SV-91917r2_rule"="INFOPATH.EXE"
            "SV-91923r2_rule"="lync.exe"
            "SV-91927r2_rule"="MSACCESS.EXE"
            "SV-91929r2_rule"="MSPUB.EXE"
            "SV-91931r2_rule"="OneDrive.exe"
            "SV-91939r2_rule"="OUTLOOK.EXE"
            "SV-91943r2_rule"="POWERPNT.EXE"
            "SV-91945r2_rule"="PPTVIEW.EXE"
            "SV-91951r2_rule"="VISIO.EXE"
            "SV-91955r2_rule"="VPREVIEW.EXE"
            "SV-91959r2_rule"="WINWORD.EXE"
        }

        #BlockRemoteImageLoads: ON
        $ApplicationMitigationsImageLoad = @{
            "SV-91905r2_rule"="FLTLDR.EXE"
             "SV-91909r2_rule"="GROOVE.EXE"
             "SV-91931r2_rule"="OneDrive.exe"
        }

        #Payload All options: ON
        $ApplicationMitigationsAllPayload = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91891r2_rule"="chrome.exe"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91897r2_rule"="EXCEL.EXE"
            "SV-91905r2_rule"="FLTLDR.EXE"
            "SV-91909r2_rule"="GROOVE.EXE"
            "SV-91913r2_rule"="iexplore.exe"
            "SV-91917r2_rule"="INFOPATH.EXE"
            "SV-91919r2_rule Part 1"="java.exe"
            "SV-91919r2_rule Part 2"="javaw.exe"
            "SV-91919r2_rule Part 3"="javaws.exe"
            "SV-91923r2_rule"="lync.exe"
            "SV-91927r2_rule"="MSACCESS.EXE"
            "SV-91929r2_rule"="MSPUB.EXE"
            "SV-91935r2_rule"="OIS.EXE"
            "SV-91931r2_rule"="OneDrive.exe"
            "SV-91939r2_rule"="OUTLOOK.EXE"
            "SV-91941r2_rule"="plugin-container.exe"
            "SV-91943r2_rule"="POWERPNT.EXE"
            "SV-91945r2_rule"="PPTVIEW.EXE"
            "SV-91951r2_rule"="VISIO.EXE"
            "SV-91955r2_rule"="VPREVIEW.EXE"
            "SV-91959r2_rule"="WINWORD.EXE"
            "SV-91965r2_rule"="wordpad.exe"
        }

        #EnableRopStackPivot: ON
        #EnableRopCallerCheck: ON
        #EnableRopSimExec: ON
        $ApplicationMitigationsPayloadROP = @{
            "SV-91963r2_rule"="wmplayer.exe"
        }


        #DisallowChildProcessCreation: ON
        $ApplicationMitigationsChild = @{
            "SV-91905r2_rule"="FLTLDR.EXE"
             "SV-91909r2_rule"="GROOVE.EXE"
        }

        Foreach ($Mitigation in $ApplicationMitigationsDep.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [DEP : ON] for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable DEP
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsASLR_BU.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [ASLR:BottomUp : ON] for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable BottomUp
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsASLR_FRI.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [ASLR:ForceRelocateImages : ON] for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable ForceRelocateImages
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsImageLoad.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [BlockRemoteImageLoads : ON] for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable BlockRemoteImageLoads
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsAllPayload.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation[Payload:Export & Rop* : ON] options for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable EnableExportAddressFilter
                Set-ProcessMitigation $Mitigation.Value -enable EnableExportAddressFilterPlus
                Set-ProcessMitigation $Mitigation.Value -enable EnableImportAddressFilter
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopStackPivot
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopCallerCheck
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopSimExec
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsPayloadROP.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [Payload:Rop* : ON] for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopStackPivot
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopCallerCheck
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopSimExec
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsChild.GetEnumerator()){
            Write-YaCMLogEntry  ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [DisallowChildProcessCreation : ON] for {1}" -f $Mitigation.Key,$Mitigation.Value) -Passthru
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable DisallowChildProcessCreation
            }
        }
    }
    Else{
        Write-YaCMLogEntry  ("Unable to process mitigations due to OS version [{0}]. Please upgrade or install EMET" -f $OSBuildNumber) -Passthru
    }
}


Write-YaCMLogEntry -Message ('Completed Windows 10 STIGS and Mitigations') -Passthru
Write-Host "Exit code:" $LASTEXITCODE
