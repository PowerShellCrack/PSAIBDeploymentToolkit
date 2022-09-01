
Param(
    [ValidateSet('Internet','Blob','SMBShare')]
    [string]$SourceType = 'Internet',
    [string]$BlobURI,
    [string]$BlobSaSKey,
    [string]$SharePath,
    [string]$InternetURI = 'https://teams.microsoft.com/downloads/desktopurl?env=production&plat=windows&arch=x64&managedInstaller=true&download=true',
    [switch]$UseProxy,
    [string]$proxyURI
)
#=======================================================
# VARIABLES
#=======================================================
$ErrorActionPreference = "Stop"
$Label = 'Microsoft Teams'
$LocalPath = "$env:Windir\AIB\apps\teams"
$Installer = 'teams.msi'
$visCplusURL = 'https://aka.ms/vs/16/release/vc_redist.x64.exe'
$webSocketsURL = 'https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RE4AQBt'
$AVDScenario = $True
##*=============================================
##* INSTALL MODULES
##*=============================================
Install-Module -Name YetAnotherCMLogger,LGPO

Import-Module YetAnotherCMLogger
Import-Module LGPO


function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Retrieves a list of all software installed
    .EXAMPLE
        Get-InstalledSoftware

        This example retrieves all software installed on the local computer
    .PARAMETER Name
        The software title you'd like to limit the query to.
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    $UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS
    $UninstallKeys += Get-ChildItem HKU: -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    if (-not $UninstallKeys) {
        Write-Verbose -Message 'No software registry keys found'
    } else {
        foreach ($UninstallKey in $UninstallKeys) {
            if ($PSBoundParameters.ContainsKey('Name')) {
                $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "$Name*") }
            } else {
                $WhereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) }
            }
            $gciParams = @{
                Path        = $UninstallKey
                ErrorAction = 'SilentlyContinue'
            }
            $selectProperties = @(
                @{n='Name'; e={$_.GetValue('DisplayName')}},
                @{n='GUID'; e={$_.PSChildName}},
                @{n='Version'; e={$_.GetValue('DisplayVersion')}},
                @{n='Uninstall'; e={$_.GetValue('UninstallString')}}
            )
            Get-ChildItem @gciParams | Where $WhereBlock | Select-Object -Property $selectProperties
        }
    }
}
##*========================================================================
##* VARIABLE DECLARATION
##*========================================================================
#specify path of log
Set-YaCMLogFileName

If($UseProxy){
    [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($proxyURI)
    [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
}Else{
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

#=======================================================
# MAIN
#=======================================================

#Test/Create Temp Directory
Try{
    #Test/Create Temp Directory
    if((Test-Path $Localpath) -eq $false) {
        Write-YaCMLogEntry -Message ('Creating temp directory [{0}]' -f $Localpath) -Passthru
        New-Item -Path $Localpath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to create directory [{0}]. {1}' -f $Localpath, $_.Exception.message) -Severity 3 -Passthru
    Break
}

If($AVDScenario){
    # set teams registry to support AVD
    Write-YaCMLogEntry -Message ('Setting {1} AVD mode in registry [{0}]...' -f 'IsWVDEnvironment',$label) -Passthru
    Set-LocalPolicySetting -RegPath 'HKLM:\SOFTWARE\Microsoft\Teams' -Name IsWVDEnvironment -Type DWord -Value 1 -Force
}

 # install vc
 #-----------
$visCplusURLexe = Split-Path $visCplusURL -Leaf
$outputPath = Join-Path $LocalPath -ChildPath $visCplusURLexe
Try{
    Write-YaCMLogEntry -Message ('Downloading Microsoft Visual C++ Redistributable from [{0}]...' -f $visCplusURL) -Passthru
    Invoke-WebRequest -Uri $visCplusURL -OutFile $outputPath -Verbose
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to download {0}. {1}' -f $visCplusURLexe,$_.Exception.message) -Severity 3 -Passthru
    Break
}

Try{
    $InstallArguments = "/install /quiet /norestart /log $env:Windir\Logs\teams_vcdist.log"
    Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -Passthru -WindowStyle Hidden' -f $outputPath,$InstallArguments) -Passthru
    $Result = Start-Process -FilePath $outputPath -Args $InstallArguments -Wait -Passthru -WindowStyle Hidden
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to install {0}. {1}' -f $visCplusURLexe,$_.Exception.message) -Severity 3 -Passthru
    Break
}

# install webSoc svc
#--------------------
If($AVDScenario){
    $webSocketsInstallerMsi = 'webSocketSvc.msi'
    $outputPath = Join-Path $LocalPath -ChildPath $webSocketsInstallerMsi
    $InstallArguments = "/i $outputPath /quiet /norestart /log $env:Windir\Logs\teams_webSocket.log"

    Try{
        Write-YaCMLogEntry -Message ('Downloading {1} WebSocket Service from [{0}]...' -f $webSocketsURL,$Label) -Passthru
        Invoke-WebRequest -Uri $webSocketsURL -OutFile $outputPath -Verbose
    }
    Catch{
        Write-YaCMLogEntry -Message ('Unable to download {0}. {1}' -f $webSocketsInstallerMsi,$_.Exception.message) -Severity 3 -Passthru
        Break
    }

    Try{
        Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "msiexec.exe" -ArgumentList "{0}" -Wait -Passthru -WindowStyle Hidden' -f $InstallArguments) -Passthru
        $Result = Start-Process -FilePath msiexec.exe -Args $InstallArguments -Wait -Passthru -WindowStyle Hidden
    }
    Catch{
        Write-YaCMLogEntry -Message ('Unable to install {0}. Exit: {1}. Error: {2}' -f $webSocketsInstallerMsi,$Result.ExitCode,$_.Exception.message) -Severity 3 -Passthru
        Break
    }
}


#download teams
#--------------------
Try{
    Write-YaCMLogEntry -Message ('Downloading {1} from [{0}]...' -f $InternetURI,$Label) -Passthru
    Invoke-WebRequest -Uri $InternetURI -OutFile $outputPath -Verbose
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to download {0}. {1}' -f $installer,$_.Exception.message) -Severity 3 -Passthru
    Break
}

#uninstall teams from current user
#--------------------
$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
$TeamsUpdateExePath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Update.exe')

if (Test-Path -Path $TeamsUpdateExePath) {
    Write-YaCMLogEntry -Message ('Uninstalling Teams from [{0}]' -f $TeamsUpdateExePath) -Passthru

    # Uninstall app
    Try{
        Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "$TeamsUpdateExePath" -ArgumentList "-uninstall -s" -Wait -Passthru -WindowStyle Hidden' -f $InstallArguments) -Passthru
        $Result = Start-Process -FilePath $TeamsUpdateExePath -Args "-uninstall -s" -Wait -Passthru -WindowStyle Hidden
    }
    Catch{
        Write-YaCMLogEntry -Message ('Unable to uninstall {0}. Exit: {1}. Error: {2}' -f $Installer,$Result.ExitCode,$_.Exception.message) -Severity 3 -Passthru
        Break
    }
}

if (Test-Path -Path $TeamsPath) {
    Write-YaCMLogEntry -Message ('Deleting Teams directory [{0}]' -f $TeamsPath) -Passthru
    Remove-Item -Path $TeamsPath -Recurse -ErrorAction SilentlyContinue | Out-Null
}

#uninstall teams system wide installer
#--------------------
$MachineWide = Get-InstalledSoftware | Where Name -eq "Teams Machine-Wide Installer"
#$MachineWide = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Teams Machine-Wide Installer"}
If($MachineWide){
    $UninstallArguments = "/x $($MachineWide.GUID) /quiet /norestart /log $env:Windir\Logs\teams_uninstall.log"
    Try{
        Write-YaCMLogEntry -Message ('Uninstalling {0} version [{1}]' -f $MachineWide.Name,$MachineWide.Version) -Passthru
        Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "msiexec.exe" -ArgumentList "{0}" -Wait -Passthru -WindowStyle Hidden' -f $UninstallArguments) -Passthru
        $Result = Start-Process -FilePath msiexec.exe -Args $UninstallArguments -Wait -Passthru -WindowStyle Hidden
    }
    Catch{
        Write-YaCMLogEntry -Message ('Unable to uninstall {0}. Exit: {1}. Error: {2}' -f $MachineWide.Name,$Result.ExitCode,$_.Exception.message) -Severity 3 -Passthru
        Break
    }
}


# install Teams
#--------------------
$outputPath = Join-Path $LocalPath -ChildPath $Installer
$InstallArguments = "/i $outputPath /quiet /norestart OPTIONS=`"noAutoStart=true`" ALLUSER=1 /log $env:Windir\Logs\teams.log"
Try{
    Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "msiexec.exe" -ArgumentList "{0}" -Wait -Passthru -WindowStyle Hidden' -f $InstallArguments) -Passthru
    $Result = Start-Process -FilePath msiexec.exe -Args $InstallArguments -Wait -Passthru -WindowStyle Hidden
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to install {0}. Exit: {1}. Error: {2}' -f $Installer,$Result.ExitCode,$_.Exception.message) -Severity 3 -Passthru
    Break
}


# setup firewall
#--------------------
Try{
    Write-YaCMLogEntry -Message ('Setting Firewall policy for {0}...' -f $Label) -Passthru
    New-NetFirewallRule -DisplayName "Teams.exe" -Program "%LocalAppData%\Microsoft\Teams\current\Teams.exe" -Profile Domain -Direction Inbound -Action Allow -Protocol Any -EdgeTraversalPolicy Block
    New-NetFirewallRule -DisplayName "Teams.exe" -Program "%LocalAppData%\Microsoft\Teams\current\Teams.exe" -Profile Public,Private -Direction Inbound -Action Block -Protocol Any -EdgeTraversalPolicy Block
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to setup firewall. Error: {2}' -f $_.Exception.message) -Severity 3 -Passthru
    Break
}

#Cleanup and Complete
Remove-Item $LocalPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-YaCMLogEntry -Message ('Completed {0} install' -f $Label) -Passthru
