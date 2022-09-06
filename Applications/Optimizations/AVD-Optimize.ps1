

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

#=======================================================
# MAIN
#=======================================================
$ErrorActionPreference = 'Stop'
#Reference: https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image

Write-YaCMLogEntry -Message ('Disable Automatic Updates...') -Passthru
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type DWORD -Value 1

Write-YaCMLogEntry -Message ('Specify Start layout for Windows 10 PCs...') -Passthru
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SpecialRoamingOverrideAllowed -Type DWORD -Value 1

Write-YaCMLogEntry -Message ('Set up time zone redirection...') -Passthru
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fEnableTimeZoneRedirection -Type DWORD -Value 1

Write-YaCMLogEntry -Message ('Disable Storage Sense...') -Passthru
Set-LocalPolicySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 01 -Type DWORD -Value 0

Write-YaCMLogEntry -Message ('Smooth edges of screen fonts') -Passthru
Set-LocalPolicySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type DWORD -Value 2

Write-YaCMLogEntry -Message ('Other applications and registry configuration...') -Passthru
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type DWORD -Value 3

#remove CorporateWerServer* from Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting

Write-YaCMLogEntry -Message ('fix 5k resolution support...') -Passthru
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxMonitors -Type DWORD -Value 4
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxXResolution -Type DWORD -Value 5120
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxYResolution -Type DWORD -Value 2880

#New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -ItemType directory
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -Name MaxMonitors -Type DWORD -Value 4
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -Name MaxXResolution -Type DWORD -Value 5120
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -Name MaxYResolution -Type DWORD -Value 2880 -Force

Write-YaCMLogEntry -Message ('Completed AVD optimizations') -Passthru
