$ErrorActionPreference = 'Stop'

$Diskpartscript = "
san policy=onlineall
exit
"

$Diskpartscript | Set-Content "$env:temp\diskpartsanonline.txt"
#Get-Content "$env:temp\diskpartsanonline.txt"

#Set the disk SAN policy to Onlineall
diskpart /s "$env:temp\diskpartsanonline.txt"

#Set Coordinated Universal Time (UTC) time for Windows
Set-LocalPolicySetting -Path HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation -Name RealTimeIsUniversal -Value 1 -Type DWord -Force
Set-Service -Name w32time -StartupType Automatic

#Set the power profile to high performance
powercfg.exe /setactive SCHEME_MIN

#Make sure the environmental variables TEMP and TMP are set to their default values
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name TEMP -Value "%SystemRoot%\TEMP" -Type ExpandString -Force
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name TMP -Value "%SystemRoot%\TEMP" -Type ExpandString -Force

#Check the Windows services
Get-Service -Name BFE, Dhcp, Dnscache, IKEEXT, iphlpsvc, nsi, mpssvc, RemoteRegistry |
  Where-Object StartType -ne Automatic |
    Set-Service -StartupType Automatic

Get-Service -Name Netlogon, Netman, TermService |
  Where-Object StartType -ne Manual |
    Set-Service -StartupType Manual

#Remote Desktop Protocol (RDP) is enabled
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDenyTSConnections -Value 0 -Type DWord -Force

Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name RemoteAppLogoffTimeLimit -Value REG_DWORD -Value 0 -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fResetBroken -Value REG_DWORD -Value 1 -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxConnectionTime -Value REG_DWORD -Value 10800000 -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name RemoteAppLogoffTimeLimit -Value REG_DWORD -Value 0 -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxDisconnectionTime -Value REG_DWORD -Value 5000 -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name MaxIdleTime -Value REG_DWORD -Value 10800000 -Force

#The RDP port is set up correctly using the default port of 3389
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name PortNumber -Value 3389 -Type DWord -Force

#The listener is listening on every network interface
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name LanAdapter -Value 0 -Type DWord -Force

#Configure network-level authentication (NLA) mode for the RDP connections
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Type DWord -Force

#Set the keep-alive value:
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name KeepAliveEnable -Value 1  -Type DWord -Force
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name KeepAliveInterval -Value 1  -Type DWord -Force
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name KeepAliveTimeout -Value 1 -Type DWord -Force

#Set the reconnect options:
Set-LocalPolicySetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name fDisableAutoReconnect -Value 0 -Type DWord -Force
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name fInheritReconnectSame -Value 1 -Type DWord -Force
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name fReconnectSame -Value 1 -Type DWord -Force

#Limit the number of concurrent connections
#Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\Winstations\RDP-Tcp' -Name MaxInstanceCount -Value 4294967295 -Type DWord -Force

#Remove any self-signed certificates tied to the RDP listener
if ((Get-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').Property -contains 'SSLCertificateSHA1Hash')
{
    Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SSLCertificateSHA1Hash -Force
}

#Turn on Windows Firewall on the three profiles (domain, standard, and public)
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# allow WinRM through the three firewall profiles (domain, private, and public)
Enable-PSRemoting -Force
Set-NetFirewallRule -Name WINRM-HTTP-In-TCP -Enabled True
#Set-NetFirewallRule -Name WINRM-HTTP-In-TCP, WINRM-HTTP-In-TCP-PUBLIC -Enabled True

#Enable the following firewall rules to allow the RDP traffic
Set-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Enabled True

#Enable the rule for file and printer sharing
Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Enabled True

#Create a rule for the Azure platform network
New-NetFirewallRule -DisplayName AzurePlatform -Direction Inbound -RemoteAddress 168.63.129.16 -Profile Any -Action Allow -EdgeTraversalPolicy Allow
New-NetFirewallRule -DisplayName AzurePlatform -Direction Outbound -RemoteAddress 168.63.129.16 -Profile Any -Action Allow

#chkdsk.exe -Force

#Set the Boot Configuration Data (BCD) settings
bcdedit.exe /set "{bootmgr}" integrityservices enable
bcdedit.exe /set "{default}" device partition=C:
bcdedit.exe /set "{default}" integrityservices enable
bcdedit.exe /set "{default}" recoveryenabled Off
bcdedit.exe /set "{default}" osdevice partition=C:
bcdedit.exe /set "{default}" bootstatuspolicy IgnoreAllFailures

#Enable Serial Console Feature
bcdedit.exe /set "{bootmgr}" displaybootmenu yes
bcdedit.exe /set "{bootmgr}" timeout 5
bcdedit.exe /set "{bootmgr}" bootems yes
bcdedit.exe /ems "{current}" ON
bcdedit.exe /emssettings EMSPORT:1 EMSBAUDRATE:115200

#Enable the dump log; can be helpful in troubleshooting
# Set up the guest OS to collect a kernel dump on an OS crash event
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name CrashDumpEnabled -Type DWord -Force -Value 2
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name DumpFile -Type ExpandString -Force -Value "%SystemRoot%\MEMORY.DMP"
Set-LocalPolicySetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name NMICrashDump -Type DWord -Force -Value 1

# Set up the guest OS to collect user mode dumps on a service crash event
$key = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
if ((Test-Path -Path $key) -eq $false) {(New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name LocalDumps)}
New-ItemProperty -Path $key -Name DumpFolder -Type ExpandString -Force -Value 'C:\CrashDumps'
New-ItemProperty -Path $key -Name CrashCount -Type DWord -Force -Value 10
New-ItemProperty -Path $key -Name DumpType -Type DWord -Force -Value 2
Set-Service -Name WerSvc -StartupType Manual

#Verify that the Windows Management Instrumentation (WMI) repository is consistent
winmgmt.exe /verifyrepository

#Make sure no other applications than TermService are using port 3389
netstat.exe -anob | findstr 3389
Write-Host "tasklist /svc | findstr 4056"
