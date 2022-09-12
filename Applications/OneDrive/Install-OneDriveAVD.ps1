
Param(
    [ValidateSet('Internet','Blob','SMBShare')]
    [string]$SourceType = 'Internet',
    [string]$BlobURI,
    [string]$BlobSaSKey,
    [string]$SharePath,
    [string]$InternetURI = 'https://go.microsoft.com/fwlink/?linkid=844652',
    [switch]$UseProxy,
    [string]$proxyURI,
    [string]$TenantID
)
#=======================================================
# VARIABLES
#=======================================================
$ErrorActionPreference = "Stop"
$ProductName = "Microsoft OneDrive"
$Localpath = "$env:Windir\AIB\apps\onedrive"
$Installer = 'OneDriveSetup.exe'
$InstallArguments = "/allusers"
$AVDScenario = $True
$ValidExitCodes = @(0,3010)
##*=============================================
##* INSTALL MODULES
##*=============================================
#Install-Module -Name YetAnotherCMLogger,MSFTLinkDownloader,LGPO
Install-Module -Name YetAnotherCMLogger,LGPO

#Import-Module MSFTLinkDownloader
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
    Write-YaCMLogEntry -Message ('Unable to create directory [{0}]. {1}' -f $Localpath, $_.Exception.message) -Severity 3
    Break
}

# PRE INSTALL
#================

$outputPath = Join-Path $LocalPath -ChildPath $Installer

If( ($SourceType -eq 'Blob') -and $BlobURI -and $SaSKey){
    #Download via URI using SAS
    Write-YaCMLogEntry -Message ('Downloading {1} from Blob [{0}]' -f "$BlobUri",$ProductName) -Passthru
    (New-Object System.Net.WebClient).DownloadFile("$BlobUri$SasKey", $outputPath)
}
ElseIf(($SourceType -eq 'SMBShare') -and ($SharePath)){
    Write-YaCMLogEntry -Message ('Downloading {1} from share [{0}]' -f "$SharePath",$ProductName) -Passthru
    Copy-Item $SharePath -Destination $outputPath -Force
}
Else{
    Write-YaCMLogEntry -Message ('Downloading {1} from URL [{0}]' -f $InternetURI,$ProductName) -Passthru
    Invoke-WebRequest -Uri $InternetURI -OutFile $outputPath
}

$Onedrive = Get-InstalledSoftware | Where Name -eq $ProductName
If($OneDrive){
    #uninstall any existing OneDrive per-user installations
    Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList ""/uninstall"" -Wait -Passthru -WindowStyle Hidden' -f $outputPath,$InstallArguments) -Passthru
    $Result = Start-Process -FilePath $outputPath -ArgumentList "/uninstall" -Wait -Passthru -WindowStyle Hidden


    #get results and see if they are valid
    If($Result.ExitCode -notin $ValidExitCodes){
        Write-YaCMLogEntry -Message ('Unable to uninstall {1}. {0}' -f $Result.ExitCode,$Installer) -Severity 3 -Passthru
        Return $Result.ExitCode
    }
}


# INSTALL
#================
#set the AllUsersInstall registry value:
If($AVDScenario){
    Set-LocalPolicySetting -RegPath 'HKLM:\Software\Microsoft\OneDrive' -Name "AllUsersInstall" -Type DWord -Value 1
}
#install OneDrive in per-machine mode:
Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -Passthru -WindowStyle Hidden' -f $outputPath,$InstallArguments) -Passthru
$Result = Start-Process -FilePath $outputPath -ArgumentList $InstallArguments -Wait -Passthru -WindowStyle Hidden

#get results and see if they are valid
If($Result.ExitCode -notin $ValidExitCodes){
    Write-YaCMLogEntry -Message ('Unable to install {1}. {0}' -f $Result.ExitCode,$ProductName) -Severity 3 -Passthru
    Return $Result.ExitCode
}

# POST-INSTALL
#================
#configure OneDrive to start at sign in for all users:
Set-LocalPolicySetting -RegPath "HKLM:\Microsoft\Windows\CurrentVersion\Run" -Name "OneDrive" -Type String -Value "`"C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background`""

#Enable Silently configure user account by running the following command.
Set-LocalPolicySetting -RegPath "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive" -Name "SilentAccountConfig" -Type DWord -Value 1

If($TenantID){
    #Redirect and move Windows known folders to OneDrive by running the following command.
    Set-LocalPolicySetting -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name "KFMSilentOptIn" -Type String -Value $TenantID -Force
}

#Cleanup and Complete
Remove-Item $Localpath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-YaCMLogEntry -Message ('Completed {0} install' -f $ProductName) -Passthru

Write-Host "Exit code:" $LASTEXITCODE
