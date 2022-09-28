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
$SourceRootPath = "$PSScriptRoot"
$DefaultAssocFile = "DefaultAppAssociations.xml"
$WallpaperPath = "$env:Windir\Web\Wallpaper\MyWallpaper.jpg"
$StartLayout = "$SourceRootPath\AVDStartMenu.xml"
$ChangeAvatar = $False
$LoadDefaultHive = $false
$AddSupportInfo = $true

$Manufacturer = "DTOLAB AVD Baseline Image"
$SupportHours = "ritracyi"
$SupportPhone = "Helpdesk: 919-888-2804"
$SupportURL = "https://outlook.office365.com/mail/"

##*===========================================================================
##* MAIN
##*===========================================================================

##*===========================================================================
##* MAIN
##*===========================================================================
##* Takeownership and replace Wallpaper Folder

Write-host  ('Configuring themes and wallpaper...') -NoNewline
Start-Process takeown -ArgumentList "/F ""$env:windir\Web\Wallpaper"" /R /D Y" -WindowStyle Hidden -Wait | Out-Null
Start-Process icacls -ArgumentList """$env:windir\Web\Wallpaper\*"" /grant Administrators:f /T" -WindowStyle Hidden -Wait | Out-Null

##* Takeownership and replace Screen Folder
Start-Process takeown -ArgumentList "/F ""$env:windir\Web\Screen"" /R /D Y" -WindowStyle Hidden -Wait | Out-Null
Start-Process icacls -ArgumentList """$env:windir\Web\Screen\*"" /grant Administrators:f /T" -WindowStyle Hidden -Wait | Out-Null

##* Takeownership and replace Screen Folder
Start-Process takeown -ArgumentList "/F ""$env:windir\Resources\Themes"" /R /D Y" -WindowStyle Hidden -Wait | Out-Null
Start-Process icacls -ArgumentList """$env:windir\Resources\Themes\*"" /grant Administrators:f /T" -WindowStyle Hidden -Wait | Out-Null
Copy-Item "$SourceRootPath\aero.theme" -Destination "$env:windir\Resources\Themes\aero.theme" -Force

$WallpaperPathFolder = Split-Path $WallpaperPath -Parent
$WallpaperPathFile = Split-Path $WallpaperPath -Leaf
New-Item -Path $WallpaperPathFolder -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Copy-Item "$SourceRootPath\$WallpaperPathFile" -Destination $WallpaperPath -Force
Write-Host ("Done") -ForegroundColor Green

If($ChangeAvatar){
    $Avatars = Get-ChildItem "$SourceRootPath\Avatars" -filter *.png | Where{$_.Name -like 'profile*'}
    If($Avatars){
        Foreach($Avatar in $Avatars){
            Try{
                Write-Host -Message ("Copying [{0}] to [{1}]" -f $Avatar,"$env:ALLUSERSPROFILE\Microsoft\User Account Pictures")
                Copy-Item $Avatar -Destination "$env:ALLUSERSPROFILE\Microsoft\User Account Pictures" -Force -ErrorAction SilentlyContinue
            }
            Catch{
                Write-Host -Message ("Unable to copy [{0}] to [{1}]. Error: {2}" -f $Avatar,"$env:ALLUSERSPROFILE\Microsoft\User Account Pictures",$_.errormessage)
            }
        }
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'UseDefaultTile' -Type DWord -Value 1 -Force
    }
}

If(Test-Path $StartLayout){
    Write-host  ('Configuring startmenu...') -NoNewline
    Try{
        Import-StartLayout -LayoutPath $StartLayout -MountPath $env:SystemDrive\
        Write-Host ('Done') -ForegroundColor Green
    }Catch{
        Write-Host ('Failed: {0}' -f $_.exception.message) -ForegroundColor Red
    }
}

##* |           Registry Branding to System                 |
##* =========================================================
Write-host  ('Configuring branding...') -NoNewline

##* # OEM Registry Keys
If($AddSupportInfo){
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'Manufacturer' -Type String -Value "$Manufacturer" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportHours' -Type String -Value "$SupportHours" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportPhone' -Type String -Value "$SupportPhone" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name 'SupportURL' -Type String -Value "$SupportURL"  -Force -ErrorAction SilentlyContinue | Out-Null
}

##* # Personalization Registry Keys
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name 'NoChangingLockScreen' -Type DWord -Value "1" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name 'LockScreenImage' -Type String -Value "$LockscreenPath\LockScreen.jpg" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name 'DisableLogonBackgroundImage' -Type DWord -Value 1 -Force

##* First Login Animation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'EnableFirstLogonAnimation' -Type DWord -Value 0 -Force

##* LOGON SCREEN SETTINGS
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'DisableCAD' -Type DWord -Value 0 -Force
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'DontDisplayLastUserName' -Type DWord -Value 1 -Force

##* ##*ove Autorun
New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" -Value "@SYS:DoesNotExist" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -Type DWord -Value 67108863 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom" -Name 'AutoRun' -Type DWord -Value 0 -Force

##* |           Registry Branding to Current logged on User             |
##* =====================================================================
##* Set Extension Associations
If(Test-Path "$SourceRootPath\$DefaultAssocFile"){
    $result = Start-Process dism.exe -ArgumentList "/online /Import-defaultAppAssociations:`"$SourceRootPath\$DefaultAssocFile`" /LogPath:`"$env:Windir\Logs\DefaultAppAssociationsLog-RunCMDLine.log`"" -Wait
    If($result.ExitCode -ne -0){
        Write-Host ("Unable to apply default association file [{0}]: {1}" -f "$SourceRootPath\$DefaultAssocFile",$result.ExitCode) -ForegroundColor Red
    }
}

##* Startmenu Customization
#Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage' -Name 'OpenAtLogon' -Type DWord -Value 0 -Force
#Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage' -Name 'DesktopFirst' -Type DWord -Value 1 -Force

##* Open new window by default
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\Launcher" -Name 'DesktopAppsAlwaysLaunchNewInstance' -Type DWord -Value 1 -Force

###* Set Desktop Screensaver and wallpaper
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'TileWallpaper' -Value "0" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath" -Force

##* Set Internet Explorer Settings
New-Item "HKCU:\Software\Microsoft\Internet Explorer" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer" -Name 'DisableFirstRunCustomize' -Type DWord -Value 1 -Force

New-Item "HKCU:\Software\Microsoft\Internet Explorer\Main" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceHasShown' -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceComplete' -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'ApplicationTileImmersiveActivation' -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" -Name 'AssociationActivationMode' -Type DWord -Value 2 -Force

New-Item "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'NewTabPageShow' -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'OpenAllHomePages' -Type DWord -Value 0 -Force

##* Remove Autorun
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -Type DWord -Value 67108863 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Force
##* Disable Action Center Icon
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HideSCAHealth' -Type DWord -Value 1 -Force

##* Show CDROM drive even when empty
##New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ItemType Directory -ErrorAction SilentlyContinue
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name '"HideDrivesWithNoMedia"' -Type DWord -Value 0 -Force

##* ##*ove 'shortcut to' text
New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name 'link' -Type Binary -Value 00000000 -Force

##* |           Registry Branding to Default User               |
##* =============================================================
IF($LoadDefaultHive){

    #mount default hive and add registry settings
    reg load "HKU\Temp" "$env:SystemDrive\Users\Default\NTUSER.DAT" | Out-Null

    ##* Startmenu Customization
    New-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name StartPage -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name 'OpenAtLogon' -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" -Name 'DesktopFirst' -Type DWord -Value 1 -Force

    ##* Open new window by default
    #Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\Launcher" -Name 'DesktopAppsAlwaysLaunchNewInstance' -Type DWord -Value 1 -Force

    ###* Set Desktop Screensaver and wallpaper
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Control Panel\Desktop" -Name 'TileWallpaper' -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath" -Force

    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name 'TileWallpaper' -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop" -Name 'Wallpaper' -Value "$WallpaperPath" -Force

    ##* Set Internet Explorer Settings
    Remove-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.com/fwlink/?LinkID=219472&clcid=0x409" -Force -ErrorAction SilentlyContinue

    New-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\Main" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceHasShown' -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'RunOnceComplete' -Type DWord -Value 1 -Force

    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'ApplicationTileImmersiveActivation' -Type DWord -Value 0 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\Main" -Name 'AssociationActivationMode' -Type DWord -Value 2 -Force

    New-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'NewTabPageShow' -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Internet Explorer\TabbedBrowsing" -Name 'OpenAllHomePages' -Type DWord -Value 0 -Force

    If(Test-Path "$SourceRootPath\Internet Explorer.lnk"){
        ##* # Pin Internet Explorer to the Start Menu
        $TARGET='C:\Program Files\Internet Explorer\iexplore.exe'
        $SHORTCUT='$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Internet Explorer.lnk'
        $ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut($SHORTCUT); $s.TargetPath = $TARGET; $s.save();
        ##* Copy IE Shortcut
        Copy-Item "$SourceRootPath\Internet Explorer.lnk" "$env:SystemDrive\Users\default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows Accessories\"
    }

    ##* Add My Documents and Computer to Desktop
    #Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0 -Force
    #Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0 -Force

    ##* Disable Action Center Icon
    #Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HideSCAHealth' -Type DWord -Value 1 -Force

    ##* Show CDROM drive even when empty
    #Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name '"HideDrivesWithNoMedia"' -Type DWord -Value 1 -Force

    ##* Remove Autorun
    #Remove-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -Force -ErrorAction SilentlyContinue
    #New-Item -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" -ItemType Directory -ErrorAction SilentlyContinue

    New-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Policies" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -Type DWord -Value 67108863 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Force

    New-Item "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'HonorAutorunSetting' -Type DWord -Value 1 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveAutoRun' -Type DWord -Value 67108863 -Force
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 -Force

    ##* ##Remove 'shortcut to' text
    Set-ItemProperty -Path "Registry::HKEY_USERS\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name 'link' -Type Binary -Value 0 -Force

    reg unload "HKU\Temp" | Out-Null

    ##* Delete recent used themes
    Remove-Item "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Themes" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Themes\*.theme" -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:TEMP\*.bmp" -Force -ErrorAction SilentlyContinue | Out-Null
}

Write-Host "Done" -ForegroundColor Green
