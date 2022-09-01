
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
$Label = 'Onedrive'
$Localpath = "$env:Windir\AIB\apps\onedrive"
$Installer = 'OneDriveSetup.exe'
$InstallArguments = "/allusers"
$AVDScenario = $True
##*=============================================
##* INSTALL MODULES
##*=============================================
#Install-Module -Name YetAnotherCMLogger,MSFTLinkDownloader,LGPO
Install-Module -Name YetAnotherCMLogger,LGPO

#Import-Module MSFTLinkDownloader
Import-Module YetAnotherCMLogger
Import-Module LGPO

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
    Write-YaCMLogEntry -Message ('Downloading {1} from Blob [{0}]' -f "$BlobUri",$Label) -Passthru
    (New-Object System.Net.WebClient).DownloadFile("$BlobUri$SasKey", $outputPath)
}
ElseIf(($SourceType -eq 'SMBShare') -and ($SharePath)){
    Write-YaCMLogEntry -Message ('Downloading {1} from share [{0}]' -f "$SharePath",$Label) -Passthru
    Copy-Item $SharePath -Destination $outputPath -Force
}
Else{
    Write-YaCMLogEntry -Message ('Downloading {1} from URL [{0}]' -f $InternetURI,$Label) -Passthru
    Invoke-WebRequest -Uri $InternetURI -OutFile $outputPath
}

#uninstall any existing OneDrive per-user installations
Try{
    Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList ""/uninstall"" -Wait -Passthru -WindowStyle Hidden' -f $outputPath,$InstallArguments) -Passthru
    $Result = Start-Process -FilePath $outputPath -ArgumentList "/uninstall" -Wait -Passthru -WindowStyle Hidden
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to uninstall {0}. {1}' -f $Installer,$_.Exception.message) -Severity 3 -Passthru
    Break
}
# INSTALL
#================
#set the AllUsersInstall registry value:
If($AVDScenario){
    Set-LocalPolicySetting -RegPath 'HKLM:\Software\Microsoft\OneDrive' -Name "AllUsersInstall" -Type DWord -Value 1
}
#install OneDrive in per-machine mode:
Try{
    Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -Passthru -WindowStyle Hidden' -f $outputPath,$InstallArguments) -Passthru
    $Result = Start-Process -FilePath $outputPath -ArgumentList $InstallArguments -Wait -Passthru -WindowStyle Hidden
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to uninstall {0}. {1}' -f $Installer,$_.Exception.message) -Severity 3 -Passthru
    Break
}
# POST-INSTALL
#================
#configure OneDrive to start at sign in for all users:
Set-LocalPolicySetting -RegPath 'HKLM:\Microsoft\Windows\CurrentVersion\Run' -Name "OneDrive" -Type String -Value "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe /background" -Force

#Enable Silently configure user account by running the following command.
Set-LocalPolicySetting -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name "SilentAccountConfig" -Type DWord -Value 1

If($TenantID){
    #Redirect and move Windows known folders to OneDrive by running the following command.
    Set-LocalPolicySetting -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' -Name "KFMSilentOptIn" -Type String -Value $TenantID -Force
}

#Cleanup and Complete
Remove-Item $Localpath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-YaCMLogEntry -Message ('Completed {0} install' -f $Label) -Passthru
