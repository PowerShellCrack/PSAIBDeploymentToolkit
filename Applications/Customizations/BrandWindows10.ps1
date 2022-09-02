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
    $SourceRootPath = "$Env:Windir\AIB\Customizations",
    [string]$DefaultAssocFile = "DefaultAppAssociations.xml",
    [string]$LockscreenPath = "$env:Windir\Web\DTOLAB\Lockscreen",
    [string]$WallpaperPath = "$env:Windir\Web\DTOLAB\Wallpaper",
    [switch]$StartLayout = $false,
    [switch]$ForceAvatar = $false
)

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

##*===========================================================================
##* MAIN
##*===========================================================================
##* Takeownership and replace Wallpaper Folder
takeown -Force "$env:windir\Web\Wallpaper" /R -Value Y
icacls "$env:windir\Web\Wallpaper\*" /grant Administrators:f /T

##* Takeownership and replace Screen Folder
takeown -Force "$env:windir\Web\Screen" /R -Value Y
icacls "$env:windir\Web\Screen\*" /grant Administrators:f /T

##* Takeownership and replace Screen Folder
#takeown -Force "$env:windir\Resources\Themes" /R -Value Y
#icacls "$env:windir\Resources\Themes\*" /grant Administrators:f /T
Copy-Item "$SourceRootPath\aero.theme" -Destination '$env:windir\Resources\Themes\aero.theme' -Force -ErrorAction SilentlyContinue | Out-Null

New-Item -Path $LockscreenPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $WallpaperPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Copy-Item "$SourceRootPath\Lockscreen.jpg" -Destination $LockscreenPath -Force -ErrorAction SilentlyContinue | Out-Null
Copy-Item "$SourceRootPath\Wallpaper.jpg" -Destination $WallpaperPath -Force -ErrorAction SilentlyContinue | Out-Null


If($ForceAvatar){
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
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'UseDefaultTile' -PropertyType DWORD -Value 1 -Force
    }
}


##* |			Registry Branding to Current logged on User				|
##* =====================================================================
##* Set Extension Associations
#dism.exe /online /Import-defaultAppAssociations:"DefaultAppAssociatons.xml" /LogPath:"$env:temp\DefaultAppAssociationsLog-RunCMDLine.log"

##* Startmenu Customization
#New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage' -Name 'OpenAtLogon' -PropertyType DWORD -Value 0 -Force
#New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage' -Name 'DesktopFirst' -PropertyType DWORD -Value 1 -Force


##* Open new window by default
#New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\Launcher" -Name 'DesktopAppsAlwaysLaunchNewInstance' -PropertyType DWORD -Value 1 -Force

###* Set Desktop Screensaver and wallpaper
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'TileWallpaper' -Value "0" -Force
New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath\Wallpaper.jpg" -Force

##* Set Internet Explorer Settings
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceHasShown' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceComplete' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'NewTabPageShow' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'OpenAllHomePages' -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'ApplicationTileImmersiveActivation' -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'AssociationActivationMode' -PropertyType DWORD -Value 2 -Force

##* Disable Action Center Icon
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HideSCAHealth' -PropertyType DWORD -Value 1 -Force

##* Show CDROM drive even when empty
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name '"HideDrivesWithNoMedia"' -PropertyType DWORD -Value 0 -Force

##* Remove Autorun
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWORD -Value 67108863 -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWORD -Value 255 -Force
#New-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWORD -Value 1 -Force
#New-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWORD -Value 67108863 -Force
#New-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWORD -Value 255 -Force

##* ##*ove 'shortcut to' text
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name 'link' -PropertyType REG_BINARY -Value 00000000 -Force
<#
CLS
##* |			Registry Branding to Default User				|
##* =============================================================
reg load "HKU:\Temp" "%SYSTEMDRIVE%\Users\Default\NTUSER.DAT"

##* Startmenu Customization
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name 'OpenAtLogon' -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name 'DesktopFirst' -PropertyType DWORD -Value 1 -Force

##* Open new window by default
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\Launcher" -Name 'DesktopAppsAlwaysLaunchNewInstance' -PropertyType DWORD -Value 1 -Force

###* Set Desktop Screensaver and wallpaper
New-ItemProperty -Path "HKU:\Temp\Control Panel\Desktop" -Name 'TileWallpaper -Value "0" -Force
New-ItemProperty -Path "HKU:\Temp\Control Panel\Desktop" -Name 'Wallpaper -Value "$env:windir\Web\Wallpaper\Windows\img0.jpg" -Force

New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name 'TileWallpaper -Value "0" -Force
New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name 'Wallpaper -Value "$env:windir\Web\Wallpaper\Windows\img0.jpg" -Force

##* Set Internet Explorer Settings
reg DELETE "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.com/fwlink/?LinkID=219472&clcid=0x409" -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceHasShown' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceComplete' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'NewTabPageShow' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'OpenAllHomePages' -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'ApplicationTileImmersiveActivation' -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'AssociationActivationMode' -PropertyType DWORD -Value 2 -Force

##* # Pin Internet Explorer to the Start Menu
$TARGET='C:\Program Files\Internet Explorer\iexplore.exe'
$SHORTCUT='$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk'
$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut($SHORTCUT); $s.TargetPath = $TARGET; $s.save();

##* Copy IE Shortcut
copy /Y "Internet Explorer.lnk" "%systemdrive%\Users\default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows Accessories\"

##* Add My Documents and Computer to Desktop
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -PropertyType DWORD -Value 0 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -PropertyType DWORD -Value 0 -Force

##* Disable Action Center Icon
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HideSCAHealth' -PropertyType DWORD -Value 1 -Force

##* Show CDROM drive even when empty
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name '"HideDrivesWithNoMedia"' -PropertyType DWORD -Value 0 -Force

##* ##*ove Autorun
reg DELETE "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWORD -Value 67108863 -Force
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWORD -Value 255 -Force
New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWORD -Value 67108863 -Force
New-ItemProperty -Path "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWORD -Value 255 -Force

##* ##*ove 'shortcut to' text
New-ItemProperty -Path "HKU:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name 'link' -PropertyType REG_BINARY -Value 00000000 -Force

reg unload "HKU:\Temp"

##* Delete recent used themes
rmdir /S /Q "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Themes"
del /Q -Force "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Themes\*.theme"
del /Q -Force "$env:TEMP\*.bmp"
#>
CLS
##* |			Registry Branding to System					|
##* =========================================================
##* # OEM Registry Keys
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'Manufacturer' -PropertyType REG_SZ -Value "DTOLAB AVD Simple Image" -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportHours' -PropertyType REG_SZ -Value "ritracyi" -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportPhone' -PropertyType REG_SZ -Value "B: 919-888-2804" -Force
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportURL' -PropertyType REG_SZ -Value "https://mail.dtolab.ltd/owa" -Force

##* # Personalization Registry Keys
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name 'NoChangingLockScreen' -PropertyType DWORD -Value "1" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name 'LockScreenImage' -PropertyType REG_SZ -Value "$LockscreenPath\LockScreen.jpg" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name 'DisableLogonBackgroundImage' -PropertyType DWORD -Value 1 -Force

##* First Login Animation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'EnableFirstLogonAnimation' -PropertyType DWORD -Value 0 -Force

##* System Policies
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EdgeUI" -Name 'DisableHelpSticker' -PropertyType DWORD -Value 1 -Force
#New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name 'BlockDomainPicturePassword' -PropertyType DWORD -Value 1 -Force

##* LOGON SCREEN SETTINGS
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DisableCAD' -PropertyType DWORD -Value 0 -Force
#New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'DontDisplayLastUserName' -PropertyType DWORD -Value 1 -Force

##* ##*ove Autorun
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" /ve -Value "@SYS:DoesNotExist" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -PropertyType DWORD -Value 1 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -PropertyType DWORD -Value 67108863 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -PropertyType DWORD -Value 255 -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom" -Name 'AutoRun' -PropertyType DWORD -Value 0 -Force

##* Set Networking Location
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Force
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name 'EnableActiveProbing' -PropertyType DWORD -Value 0 -Force

##* STIG
#New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'AutoRestartShell' -PropertyType DWORD -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name 'DisableExceptionChainValidation' -PropertyType DWORD -Value 0 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name 'NtfsDisable8dot3NameCreation' -PropertyType DWORD -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems" -Name 'Optional' -PropertyType REG_MULTI_SZ -Value "" -Force

##* STIG RASMAN
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters" -Name 'DisableSavePassword' -PropertyType DWORD -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters" -Name 'Logging' -PropertyType DWORD -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP" -Name 'ForceEncryptedData' -PropertyType DWORD -Value 1 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP" -Name 'ForceEncryptedPassword' -PropertyType DWORD -Value 2 -Force
#New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP" -Name 'SecureVPN' -PropertyType DWORD -Value 1 -Force
