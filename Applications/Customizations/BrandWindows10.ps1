<#
.SYNOPSIS
    Brand Windows 10

.DESCRIPTION
    This script adds driver group to TS driver injection. This process should be ran in WINPE before driver injection.

.PARAMETER LogFileName
    Set the name of the log file produced by the firmware.

.EXAMPLE


.NOTES
    FileName:    Check-TBSupportedModels.ps1
    Author:      Richard tracy
    Contact:     richard.j.tracy@gmail.com
    Created:     2018-08-24

    Version history:
    1.0.0 - (2018-08-24) Script created
#>

param(
    $SourceRootPath = "C:\Temp\Applications\Customizations",
    [string]$DefaultAssocFile = "DefaultAppAssociations.xml",
    [string]$LockscreenPath = "$env:Windir\Web\DTOLAB\Lockscreen",
    [string]$WallpaperPath = "$env:Windir\Web\DTOLAB\Wallpaper",
    [switch]$StartLayout = $false,
    [switch]$ChangeAvatar = $false,
    [switch]$LoadDefaultHive = $false,
    [switch]$AddSupportInfo = $true

)

$ErrorActionPreference = "Stop"
##*=============================================
##* INSTALL MODULES
##*=============================================
#Install-Module -Name YetAnotherCMLogger,LGPO

#Import-Module YetAnotherCMLogger
#Import-Module LGPO

##*========================================================================
##* VARIABLE DECLARATION
##*========================================================================
#specify path of log
#Set-YaCMLogFileName

$Manufacturer = "DTOLAB AVD Baseline Image"
$SupportHours = "ritracyi"
$SupportPhone = "Helpdesk: 919-888-2804"
$SupportURL = "https://outlook.office365.com/mail/"

##*===========================================================================
##* MAIN
##*===========================================================================
##* Takeownership and replace Wallpaper Folder
takeown /F "$env:windir\Web\Wallpaper" /R /D Y
icacls "$env:windir\Web\Wallpaper\*" /grant Administrators:f /T

##* Takeownership and replace Screen Folder
takeown /F "$env:windir\Web\Screen" /R /D Y
icacls "$env:windir\Web\Screen\*" /grant Administrators:f /T

##* Takeownership and replace Screen Folder
takeown /F "$env:windir\Resources\Themes" /R /D Y
icacls "$env:windir\Resources\Themes\*" /grant Administrators:f /T
Copy-Item "$SourceRootPath\aero.theme" -Destination "$env:windir\Resources\Themes\aero.theme" -Force

New-Item -Path $LockscreenPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $WallpaperPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Copy-Item "$SourceRootPath\Lockscreen.jpg" -Destination $LockscreenPath -Force
Copy-Item "$SourceRootPath\Wallpaper.jpg" -Destination $WallpaperPath -Force

If($ChangeAvatar){
    $Avatars = Get-ChildItem $SourceRootPath -filter *.png | Where{$_.Name -like 'profile*'}
    If($Avatars){
        Foreach($Avatar in $Avatars){
            Try{
                Write-YaCMLogEntry -Message ("Copying [{0}] to [{1}]" -f $Avatar,"$env:ALLUSERSPROFILE\Microsoft\User Account Pictures") -Passthru
                Copy-Item $Avatar -Destination "$env:ALLUSERSPROFILE\Microsoft\User Account Pictures" -Force -ErrorAction SilentlyContinue
            }
            Catch{
                Write-YaCMLogEntry -Message ("Unable to copy [{0}] to [{1}]. Error: {2}" -f $Avatar,"$env:ALLUSERSPROFILE\Microsoft\User Account Pictures",$_.errormessage) -Passthru
            }
        }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'UseDefaultTile' -PropertyType DWord -Value 1 -Force
    }
}

##* |			Registry Branding to Current logged on User				|
##* =====================================================================
##* Set Extension Associations
If(Test-Path "$SourceRootPath\$DefaultAssocFile"){
    $result = Start-Process dism.exe -ArgumentList "/online /Import-defaultAppAssociations:`"$SourceRootPath\$DefaultAssocFile`" /LogPath:`"$env:Windir\Logs\DefaultAppAssociationsLog-RunCMDLine.log`"" -PassThru -Wait
    If($result.ExitCode -ne -0){
        Write-Host ("Unable to apply default association file [{0}]: {1}" -f "$SourceRootPath\$DefaultAssocFile",$result.ExitCode) -ForegroundColor Red
    }
}

##* Startmenu Customization
#New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage' -Name 'OpenAtLogon' -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage' -Name 'DesktopFirst' -PropertyType DWord -Value 1 -Force


##* Open new window by default
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\Launcher" -Name 'DesktopAppsAlwaysLaunchNewInstance' -PropertyType DWord -Value 1 -Force

###* Set Desktop Screensaver and wallpaper
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'TileWallpaper' -Value "0" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath\Wallpaper.jpg" -Force

##* Set Internet Explorer Settings
New-Item "HKCU:\Software\Microsoft\Internet Explorer" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer" -Name 'DisableFirstRunCustomize' -PropertyType DWord -Value 1 -Force

New-Item "HKCU:\Software\Microsoft\Internet Explorer\Main" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceHasShown' -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceComplete' -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'ApplicationTileImmersiveActivation' -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'AssociationActivationMode' -PropertyType DWord -Value 2 -Force

New-Item "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'NewTabPageShow' -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'OpenAllHomePages' -PropertyType DWord -Value 0 -Force

##* Remove Autorun
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -ItemType Directory -ErrorAction SilentlyContinue
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWord -Value 67108863 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWord -Value 255 -Force
##* Disable Action Center Icon
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HideSCAHealth' -PropertyType DWord -Value 1 -Force

##* Show CDROM drive even when empty
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name '"HideDrivesWithNoMedia"' -PropertyType DWord -Value 0 -Force

##* ##*ove 'shortcut to' text
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name 'link' -PropertyType Binary -Value 00000000 -Force

##* |			Registry Branding to Default User				|
##* =============================================================
IF($LoadDefaultHive){

    reg load "HKU:\Temp" "$env:SystemDrive\Users\Default\NTUSER.DAT"

    ##* Startmenu Customization
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name 'OpenAtLogon' -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name 'DesktopFirst' -PropertyType DWord -Value 1 -Force

    ##* Open new window by default
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\Launcher" -Name 'DesktopAppsAlwaysLaunchNewInstance' -PropertyType DWord -Value 1 -Force

    ###* Set Desktop Screensaver and wallpaper
    New-ItemProperty -Path "HKU:\Temp\Control Panel\Desktop" -Name 'TileWallpaper' -Value "0" -Force
    New-ItemProperty -Path "HKU:\Temp\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath\Wallpaper.jpg" -Force

    New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name 'TileWallpaper' -Value "0" -Force
    New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath\Wallpaper.jpg" -Force

    ##* Set Internet Explorer Settings
    Remove-Item "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.com/fwlink/?LinkID=219472&clcid=0x409" -Force -ErrorAction SilentlyContinue

    New-Item "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -ItemType Directory -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceHasShown' -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceComplete' -PropertyType DWord -Value 1 -Force

    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'ApplicationTileImmersiveActivation' -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'AssociationActivationMode' -PropertyType DWord -Value 2 -Force

    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'NewTabPageShow' -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'OpenAllHomePages' -PropertyType DWord -Value 0 -Force

    If(Test-Path "$SourceRootPath\Internet Explorer.lnk"){
        ##* # Pin Internet Explorer to the Start Menu
        $TARGET='C:\Program Files\Internet Explorer\iexplore.exe'
        $SHORTCUT='$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk'
        $ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut($SHORTCUT); $s.TargetPath = $TARGET; $s.save();
        ##* Copy IE Shortcut
        Copy-Item "$SourceRootPath\Internet Explorer.lnk" "$env:SystemDrive\Users\default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows Accessories\"
    }

    ##* Add My Documents and Computer to Desktop
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -PropertyType DWord -Value 0 -Force
    MultiStringDWord
    ##* Disable Action Center Icon
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HideSCAHealth' -PropertyType DWord -Value 1 -Force

    ##* Show CDROM drive even when empty
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name '"HideDrivesWithNoMedia"' -PropertyType DWord -Value 0 -Force

    ##* ##*ove Autorun
    Remove-Item "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -Force -ErrorAction SilentlyContinue
    New-Item -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ItemType Directory -ErrorAction SilentlyContinue

    New-Item "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies" -ItemType Directory -ErrorAction SilentlyContinue
    New-Item "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ItemType Directory -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWord -Value 67108863 -Force
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWord -Value 255 -Force

    New-Item "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies" -ItemType Directory -ErrorAction SilentlyContinue
    New-Item "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ItemType Directory -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWord -Value 67108863 -Force
    New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWord -Value 255 -Force

    ##* ##*ove 'shortcut to' text
    New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name 'link' -PropertyType Binary -Value 00000000 -Force

    reg unload "HKU:\Temp"

    ##* Delete recent used themes
    Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Themes" -Force
    Remove-Item "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Themes\*.theme" -Force
    Remove-Item "$env:TEMP\*.bmp" -Force
}


##* |			Registry Branding to System					|
##* =========================================================
##* # OEM Registry Keys
If($AddSupportInfo){
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'Manufacturer' -PropertyType String -Value "$Manufacturer" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportHours' -PropertyType String -Value "$SupportHours" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportPhone' -PropertyType String -Value "$SupportPhone" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportURL' -PropertyType String -Value "$SupportURL" -Force
}


##* # Personalization Registry Keys
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ItemType Directory -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name 'NoChangingLockScreen' -PropertyType DWord -Value "1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name 'LockScreenImage' -PropertyType String -Value "$LockscreenPath\LockScreen.jpg" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name 'DisableLogonBackgroundImage' -PropertyType DWord -Value 1 -Force

##* First Login Animation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'EnableFirstLogonAnimation' -PropertyType DWord -Value 0 -Force

##* LOGON SCREEN SETTINGS
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DisableCAD' -PropertyType DWord -Value 0 -Force
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'DontDisplayLastUserName' -PropertyType DWord -Value 1 -Force

##* ##*ove Autorun
New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" -ItemType Directory -ErrorAction SilentlyContinue
Set-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" -Value "@SYS:DoesNotExist" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWord -Value 67108863 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWord -Value 255 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom" -Name 'AutoRun' -PropertyType DWord -Value 0 -Force

##* Set Networking Location
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name 'EnableActiveProbing' -PropertyType DWord -Value 0 -Force

Write-Host "Completed Branding script" -ForegroundColor Green
