<#
.LINK
https://www.microsoft.com/en-us/download/details.aspx?id=55319
#>
Param(
    [ValidateSet('Internet','Blob','SMBShare')]
    [string]$SourceType = 'Internet',
    [string]$BlobURI,
    [string]$BlobSaSKey,
    [string]$SharePath,
    [string]$InternetURI = 'https://www.microsoft.com/en-us/download/details.aspx?id=55319',
    [switch]$UseProxy,
    [string]$proxyURI
)
#=======================================================
# CONSTANT VARIABLES
#=======================================================
$ErrorActionPreference = "Stop"
$ProductName = 'LGPO'
$Localpath = "$Env:ALLUSERSPROFILE\LGPO"
$Installer = 'LGPO.zip'
##*=============================================
##* INSTALL MODULES
##*=============================================
Install-Module -Name YetAnotherCMLogger,MSFTLinkDownloader

Import-Module MSFTLinkDownloader
Import-Module YetAnotherCMLogger

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
#Test/Create LGPO Directory
if((Test-Path $Localpath) -eq $false) {
    Write-YaCMLogEntry -Message ('Creating LGPO directory [{0}]' -f $Localpath) -Passthru
    New-Item -Path $Localpath -ItemType Directory -Force -ErrorAction SilentlyContinue
}

# Download LGPO
If( ($SourceType -eq 'Blob') -and $BlobURI -and $SaSKey){
    #Download via URI using SAS
    Write-YaCMLogEntry -Message ('Downloading {1} from Blob [{0}]' -f "$BlobUri",$ProductName) -Passthru
    (New-Object System.Net.WebClient).DownloadFile("$BlobUri$SasKey", "$Localpath\$Installer")
}
ElseIf(($SourceType -eq 'SMBShare') -and ($SharePath)){
    Write-YaCMLogEntry -Message ('Downloading {1} from share [{0}]' -f "$SharePath",$ProductName) -Passthru
    Copy-Item $SharePath -Destination "$Localpath\$Installer" -Force
}
Else{
    Write-YaCMLogEntry -Message ('Downloading {1} from URL [{0}]' -f $InternetURI,$ProductName) -Passthru
    $Null = $InternetURI -match '\d+$'
    $LinkID = $Matches[0]
    #Get-MsftLink -LinkID $LinkID
    Invoke-MsftLinkDownload -LinkID $LinkID -DestPath "$Localpath" -Filter $ProductName -Extract -Cleanup
}


# Extract LGPO Files
#Write-YaCMLogEntry -Message ('Unzipping LGPO file [{0}]' -f "$Localpath\$Installer") -Passthru
#Expand-Archive -LiteralPath "$Localpath\$Installer" -DestinationPath $Localpath -Force -Verbose

#prepare Directory
$LGPOFile = Get-ChildItem $Localpath -Recurse -Filter LGPO.exe
$LGPOFile | Move-Item -Destination $Localpath -Force
#Remove-Item "$Localpath\$Installer" -Force -ErrorAction SilentlyContinue

try{
    Write-YaCMLogEntry -Message ('Installing NuGet package dependency') -Passthru
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
}Catch{
    Write-YaCMLogEntry -Message ('Unable to install nuget package. {0}' -f $_.Exception.message) -Severity 3
    Break
}

try{
    Write-YaCMLogEntry -Message ('Installing {0} module' -f $ProductName) -Passthru
    Install-Module LGPO -Force -ErrorAction Stop
}Catch{
    Write-YaCMLogEntry -Message ('Unable to install {1} module. {0}' -f $_.Exception.message,$ProductName) -Severity 3
    Break
}


Write-YaCMLogEntry -Message ('Completed {0} install' -f $ProductName) -Passthru
Write-Host "Exit code:" $LASTEXITCODE
