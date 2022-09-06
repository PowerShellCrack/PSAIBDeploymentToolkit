
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

$Diskpartscript = "
san policy=onlineall
exit
"

$Diskpartscript | Set-Content "$env:temp\diskpartsanonline.txt"
#Get-Content "$env:temp\diskpartsanonline.txt"

Write-YaCMLogEntry -Message ('Set the disk SAN policy to Onlineall') -Passthru
diskpart /s "$env:temp\diskpartsanonline.txt"

Write-YaCMLogEntry -Message ('Set Coordinated Universal Time (UTC) time for Windows') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation' -Name RealTimeIsUniversal  -Type DWord -Value 1
Set-Service -Name w32time -StartupType Automatic

Write-YaCMLogEntry -Message ('Set the power profile to high performance') -Passthru
powercfg.exe /setactive SCHEME_MIN

Write-YaCMLogEntry -Message ('Make sure the environmental variables TEMP and TMP are set to their default values') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name TEMP -Type ExpandString -Value "%SystemRoot%\TEMP"
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name TMP -Type ExpandString -Value "%SystemRoot%\TEMP"

Write-YaCMLogEntry -Message ('Check the Windows services') -Passthru
Get-Service -Name BFE, Dhcp, Dnscache, IKEEXT, iphlpsvc, nsi, mpssvc, RemoteRegistry |
  Where-Object StartType -ne Automatic |
    Set-Service -StartupType Automatic

Get-Service -Name Netlogon, Netman, TermService |
  Where-Object StartType -ne Manual |
    Set-Service -StartupType Manual

Write-YaCMLogEntry -Message ('Remote Desktop Protocol (RDP) is enabled') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Type DWord -Value 0
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDenyTSConnections -Type DWord -Value 0

Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name RemoteAppLogoffTimeLimit -Type DWord -Value 0
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fResetBroken -Type DWord -Value 1
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxConnectionTime -Type DWord -Value 10800000
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name RemoteAppLogoffTimeLimit -Type DWord -Value 0
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxDisconnectionTime -Type DWord -Value 5000
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -Type DWord -Value 10800000

Write-YaCMLogEntry -Message ('The RDP port is set up correctly using the default port of 3389') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name PortNumber -Type DWord -Value 3389

Write-YaCMLogEntry -Message ('The listener is listening on every network interface') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name LanAdapter -Type DWord -Value 0

Write-YaCMLogEntry -Message ('Configure network-level authentication (NLA) mode for the RDP connections') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Type DWord -Value 1

Write-YaCMLogEntry -Message ('Set the keep-alive value') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name KeepAliveEnable -Type DWord -Value 1
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name KeepAliveInterval -Type DWord -Value 1
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name KeepAliveTimeout -Type DWord -Value 1

Write-YaCMLogEntry -Message ('Set the reconnect options') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableAutoReconnect -Type DWord -Value 0
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name fInheritReconnectSame -Type DWord -Value 1
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name fReconnectSame -Type DWord -Value 1

Write-YaCMLogEntry -Message ('Limit the number of concurrent connections') -Passthru
#Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name MaxInstanceCount -Type DWord -Value 4294967295

Write-YaCMLogEntry -Message ('Remove any self-signed certificates tied to the RDP listener') -Passthru
if ((Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').Property -contains 'SSLCertificateSHA1Hash')
{
    Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SSLCertificateSHA1Hash
}

Write-YaCMLogEntry -Message ('Turn on Windows Firewall on the three profiles (domain, standard, and public)') -Passthru
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

Write-YaCMLogEntry -Message ('allow WinRM through the three firewall profiles (domain, private, and public)') -Passthru
Enable-PSRemoting
Set-NetFirewallRule -Name WINRM-HTTP-In-TCP -Enabled True
#Set-NetFirewallRule -Name WINRM-HTTP-In-TCP, WINRM-HTTP-In-TCP-PUBLIC -Enabled True

Write-YaCMLogEntry -Message ('Enable the following firewall rules to allow the RDP traffic') -Passthru
Set-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Enabled True

Write-YaCMLogEntry -Message ('Enable the rule for file and printer sharing') -Passthru
Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Enabled True

Write-YaCMLogEntry -Message ('Create a rule for the Azure platform network') -Passthru
New-NetFirewallRule -DisplayName AzurePlatform -Direction Inbound -RemoteAddress 168.63.129.16 -Profile Any -Action Allow -EdgeTraversalPolicy Allow
New-NetFirewallRule -DisplayName AzurePlatform -Direction Outbound -RemoteAddress 168.63.129.16 -Profile Any -Action Allow

#chkdsk.exe

Write-YaCMLogEntry -Message ('Set the Boot Configuration Data (BCD) settings') -Passthru
bcdedit.exe /set "{bootmgr}" integrityservices enable
bcdedit.exe /set "{default}" device partition=C:
bcdedit.exe /set "{default}" integrityservices enable
bcdedit.exe /set "{default}" recoveryenabled Off
bcdedit.exe /set "{default}" osdevice partition=C:
bcdedit.exe /set "{default}" bootstatuspolicy IgnoreAllFailures

Write-YaCMLogEntry -Message ('Enable Serial Console Feature') -Passthru
bcdedit.exe /set "{bootmgr}" displaybootmenu yes
bcdedit.exe /set "{bootmgr}" timeout 5
bcdedit.exe /set "{bootmgr}" bootems yes
bcdedit.exe /ems "{current}" ON
bcdedit.exe /emssettings EMSPORT:1 EMSBAUDRATE:115200

Write-YaCMLogEntry -Message ('Enable the dump log; can be helpful in troubleshooting') -Passthru
# Set up the guest OS to collect a kernel dump on an OS crash event
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Type DWord -Value 2
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name DumpFile -Type ExpandString -Value "%SystemRoot%\MEMORY.DMP"
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name NMICrashDump -Type DWord -Value 1

Write-YaCMLogEntry -Message ('Set up the guest OS to collect user mode dumps on a service crash event') -Passthru
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Name DumpFolder -Type String -Value 'C:\CrashDumps'
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Name CrashCount -Type DWord -Value 10
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Name DumpType -Type DWord -Value 2

Set-Service -Name WerSvc -StartupType Manual

Write-YaCMLogEntry -Message ('Verify that the Windows Management Instrumentation (WMI) repository is consistent') -Passthru
winmgmt.exe /verifyrepository

Write-YaCMLogEntry -Message ('Make sure no other applications than TermService are using port 3389') -Passthru
netstat.exe -anob | findstr 3389
Write-Host "tasklist /svc | findstr 4056"

#Chkdsk /f
sfc /scannow
DISM /online /Cleanup-Image /StartComponentCleanup
DISM /online /Cleanup-Image /StartComponentCleanup /ResetBase

Write-YaCMLogEntry -Message 'Completed AVD Prepare script' -Passthru
