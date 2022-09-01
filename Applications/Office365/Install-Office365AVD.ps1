<#
.LINK
https://www.microsoft.com/en-us/download/details.aspx?id=55319
https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image
#>
Param(
    [ValidateSet('Internet','Blob','SMBShare')]
    [string]$SourceType = 'Internet',
    [string]$BlobURI,
    [string]$BlobSaSKey,
    [string]$SharePath,
    [string]$InternetURI = 'https://www.microsoft.com/en-us/download/details.aspx?id=49117',
    [switch]$UseProxy,
    [string]$proxyURI
)
#=======================================================
# CONSTANT VARIABLES
#=======================================================
$ErrorActionPreference = "Stop"
$Label = 'Office 365'
$Localpath = "$env:Windir\AIB\apps\office"
$Installer = "setup.exe"
$InstallArguments = "/configure $Localpath\configuration.xml"
$AVDScenario = $True
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

# PRE INSTALL
#================
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

#build Office configuration for AVD
$xml = @"
<Configuration>
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise">
    <Product ID="O365ProPlusRetail">
      <Language ID="en-US" />
      <Language ID="MatchOS" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="OneDrive" />
      <ExcludeApp ID="Teams" />
    </Product>
  </Add>
  <RemoveMSI/>
  <Updates Enabled="FALSE"/>
  <Display Level="None" AcceptEULA="TRUE" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/>
"@

If($AVDScenario){
    $xml += @"
    `r
  <Property Name="SharedComputerLicensing" Value="1"/>
  <Logging Level="Standard" Path="%windir%\Logs\O365AVDInstall" />
"@
}Else{
    $xml += @"
    `r
  <Property Name="SharedComputerLicensing" Value="0"/>
  <Logging Level="Standard" Path="%windir%\Logs\O365Install" />
"@
}
$xml += @"
`r
</Configuration>
"@

Write-YaCMLogEntry -Message ("Building configuration file [{0}]" -f "$Localpath\configuration.xml") -Passthru
$xml | Out-file "$Localpath\configuration.xml" -Force

If( ($SourceType -eq 'Blob') -and $BlobURI -and $SaSKey){
    #Download via URI using SAS
    Write-YaCMLogEntry -Message ('Downloading {1} from Blob [{0}]' -f "$BlobUri",$Label) -Passthru
    (New-Object System.Net.WebClient).DownloadFile("$BlobUri$SasKey", "$Localpath\$Installer")
}
ElseIf(($SourceType -eq 'SMBShare') -and ($SharePath)){
    Write-YaCMLogEntry -Message ('Downloading {1} from share [{0}]' -f "$SharePath",$Label) -Passthru
    Copy-Item $SharePath -Destination "$Localpath\$Installer" -Force
}
Else{
    Write-YaCMLogEntry -Message ('Downloading {1} from URL [{0}]' -f $InternetURI,$Label) -Passthru
    $Null = $InternetURI -match '\d+$'
    $LinkID = $Matches[0]
    #Get-MsftLink -LinkID $LinkID
    Invoke-MsftLinkDownload -LinkID $LinkID -DestPath "$Localpath" -Extract -Cleanup
}

# INSTALL
#================
#Office Install
try{
    Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -Passthru -WindowStyle Hidden' -f $Installer ,$InstallArguments) -Passthru
    $Result = Start-Process -FilePath "$Localpath\$Installer" -ArgumentList $InstallArguments -Wait -Passthru -WindowStyle Hidden
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to install {1}. {0}' -f $Result.ExitCode,$Label) -Severity 3 -Passthru
    Break
}

# POST INSTALL
#================
# Set Outlook's Cached Exchange Mode behavior
If($AVDScenario){
    Write-YaCMLogEntry -Message ("Set Outlook's Cached Exchange Mode behavior") -Passthru
    Set-LocalPolicyUserSetting -RegPath 'HCKU:\software\policies\microsoft\office\16.0\outlook\cached mode' -Name enable -Type DWord -Value 1 -Force
    Set-LocalPolicyUserSetting -RegPath 'HCKU:\software\policies\microsoft\office\16.0\outlook\cached mode' -Name syncwindowsetting -Type DWord -Value 1 -Force
    Set-LocalPolicyUserSetting -RegPath 'HCKU:\software\policies\microsoft\office\16.0\outlook\cached mode' -Name CalendarSyncWindowSetting -Type DWord -Value 1 -Force
    Set-LocalPolicyUserSetting -RegPath 'HCKU:\software\policies\microsoft\office\16.0\outlook\cached mode' -Name CalendarSyncWindowSettingMonths -Type DWord -Value 1 -Force

    # Set the Office Update UI behavior.
    Write-YaCMLogEntry -Message ("Set the {0} Update UI behavior" -f $Label) -Passthru
    Set-LocalPolicySetting -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate' -Name hideupdatenotifications -Type DWord -Value 1 -Force
    Set-LocalPolicySetting -RegPath 'HKLM:\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate' -Name hideenabledisableupdates -Type DWord -Value 1 -Force
}
#Cleanup and Complete
Remove-Item $Localpath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-YaCMLogEntry -Message ('Completed {0} install' -f $Label) -Passthru
