
##*=============================================
##* Runtime Function - REQUIRED
##*=============================================
##*=============================================
##* INSTALL MODULES
##*=============================================
Install-Module -Name YetAnotherCMLogger,MSFTLinkDownloader,LGPO

Import-Module MSFTLinkDownloader
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

# Disable Automatic Updates...
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Type DWORD -Value 1 -Force

# Specify Start layout for Windows 10 PCs...
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name SpecialRoamingOverrideAllowed -Type DWORD -Value 1 -Force

# Set up time zone redirection...
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fEnableTimeZoneRedirection -Type DWORD -Value 1 -Force

# Disable Storage Sense...
Set-LocalPolicySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name 01 -Type DWORD -Value 0 -Force

#Smooth edges of screen fonts
Set-LocalPolicySetting -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name VisualFXSetting -Type DWORD -Value 2 -Force

# Other applications and registry configuration...
Set-LocalPolicySetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Type DWORD -Value 3 -Force

#remove CorporateWerServer* from Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting

# fix 5k resolution support...
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxMonitors -Type DWORD -Value 4 -Force
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxXResolution -Type DWORD -Value 5120 -Force
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxYResolution -Type DWORD -Value 2880 -Force

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs"
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -Name MaxMonitors -Type DWORD -Value 4 -Force
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -Name MaxXResolution -Type DWORD -Value 5120 -Force
Set-LocalPolicySetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\rdp-sxs" -Name MaxYResolution -Type DWORD -Value 2880 -Force

Write-YaCMLogEntry -Message ('Completed optimizations') -Passthru
