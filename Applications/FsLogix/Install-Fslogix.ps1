
Param(
    [ValidateSet('Internet','Blob','SMBShare')]
    [string]$SourceType = 'Internet',
    [string]$BlobURI,
    [string]$BlobSaSKey,
    [string]$SharePath,
    [string]$InternetURI = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=104223',
    [string]$ProfilePath,
    [string]$RedirectionPath,
    [string[]]$AppMaskingRulesFilePath = @('https://avdimageresources.blob.core.usgovcloudapi.net/apps/FSLogix App Masking for RSAT.zip'),
    [switch]$UseProxy,
    [string]$proxyURI
)

#=======================================================
# VARIABLES
#=======================================================
$ProductName = 'Microsoft FSLogix Apps'
$LocalPath = "$env:Windir\AIB\apps\fslogix"
$Installer = 'FSLogixAppsSetup.exe'
$ValidExitCodes = @(0,3010)
$ErrorActionPreference = "Stop"
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
Try{
    #Test/Create Temp Directory
    if((Test-Path $LocalPath) -eq $false) {
        Write-YaCMLogEntry -Message ('Creating temp directory [{0}]' -f $LocalPath) -Passthru
        New-Item -Path $LocalPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to create directory [{0}]. {1}' -f $LocalPath, $_.Exception.message) -Severity 3 -Passthru
    Break
}

# Download FSlogix
Try{
    Write-YaCMLogEntry -Message ('Downloading {1} from URL [{0}]' -f $InternetURI,$ProductName) -Passthru
    $Null = $InternetURI -match '\d+$'
    $LinkID = $Matches[0]
    Invoke-MsftLinkDownload -LinkID $LinkID -DestPath $Localpath -Extract -Cleanup
}
Catch{
    Write-YaCMLogEntry -Message ('Unable to download {1)}. {0}' -f $_.Exception.message,$ProductName) -Severity 3 -Passthru
    Break
}


#prep device for fslogix
Write-YaCMLogEntry -Message ('Copy {1} policy template files to [{0}]' -f "$env:Windir\PolicyDefinitions",$ProductName) -Passthru
Copy-Item "$LocalPath\fslogix.adml" "$env:Windir\PolicyDefinitions\en-US" -ErrorAction SilentlyContinue -Force
Copy-Item "$LocalPath\fslogix.admx" "$env:Windir\PolicyDefinitions" -ErrorAction SilentlyContinue -Force


# FSLogix Install
$InstallExecutable = "$LocalPath\x64\Release\$Installer"
$InstallArguments = "/install /quiet"
Write-YaCMLogEntry -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -Passthru -WindowStyle Hidden' -f $InstallExecutable,$InstallArguments) -Passthru
$Result = Start-Process -FilePath $InstallExecutable -ArgumentList $InstallArguments -Wait -Passthru -WindowStyle Hidden
#get results and see if they are valid
If($Result.ExitCode -notin $ValidExitCodes){
    Write-YaCMLogEntry -Message ('Unable to install {1}. {0}' -f $Result.ExitCode,$ProductName) -Severity 3 -Passthru
    Return $Result.ExitCode
}



# Get FSLogix App masking rules
$FSLogixInstallPath = "${Env:ProgramFiles}\FSLogix\Apps\Rules"

#TEST $Rule = $AppMaskingRulesFilePath[0]
Foreach($Rule in $AppMaskingRulesFilePath)
{
    $File = Split-path $Rule -Leaf

    If($Rule -match 'http'){
        Try{
            Write-YaCMLogEntry -Message ('Downloading {2} app rule file [{0}] to [{1}]' -f $File,$FSLogixInstallPath,$ProductName) -Passthru
            Invoke-WebRequest -Uri "$Rule" -OutFile "$FSLogixInstallPath\$File" -UseBasicParsing
        }
        Catch{
            Write-YaCMLogEntry -Message ('Unable to download {1} rule file. {0}' -f $_.Exception.message,$ProductName) -Severity 2 -Passthru
            Break
        }
    }
    ElseIf($Rule -match '\\\\'){
        Write-YaCMLogEntry -Message ('Copy {2} app rule zipped file [{0}] to [{1}]' -f $File,$FSLogixInstallPath,$ProductName) -Passthru
        Copy-Item "$Rule" "$FSLogixInstallPath" -ErrorAction SilentlyContinue -Force
    }

    If([System.IO.Path]::GetExtension($File) -eq '.zip'){
        Expand-Archive -LiteralPath "$FSLogixInstallPath\$File" -DestinationPath $FSLogixInstallPath -Force
        Remove-Item "$FSLogixInstallPath\$File" -Force -ErrorAction SilentlyContinue
    }
}

$LocalAdmin = Get-LocalGroup -Name Administrators | Get-LocalGroupMember
$FslogixGroups = @('FSLogix ODFC Exclude List','FSLogix Profile Exclude List')

Foreach($Group in $FslogixGroups){
    If( $LocalAdmin.name -notin (Get-LocalGroup -Name $Group | Get-LocalGroupMember).Name ){
        Write-YaCMLogEntry -Message ('Adding local admin [{0}] to FSLogix exclude list [{1}]...' -f $LocalAdmin.name,$Group) -Passthru
        Add-LocalGroupMember -Group $Group -Member $LocalAdmin.name
    }
    Else{
        Write-YaCMLogEntry -Message ('Local admin [{0}] is already in FSLogix exclude list [{1}]!' -f $LocalAdmin.name,$Group) -Passthru
    }
}

# FSLogix Local Policy Profile Settings
Write-YaCMLogEntry -Message ('Configure {0} Profile Settings' -f $ProductName) -Passthru
#Optimize Fslogix
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type DWord -Value 1 -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "SizeInMBs" -Type DWord -Value "30000" -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "FlipFlopProfileDirectoryName" -Type DWord -Value 1 -Force
#Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "SIDDirNamePattern" -Type String -Value "%username%%sid%" -Force
#Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "SIDDirNameMatch" -Type String -Value "%username%%sid%" -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "DeleteLocalProfileWhenVHDShouldApply" -Type DWord -Value 1 -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "DeleteProfileOnLogoff" -Type DWord -Value 1 -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "VolumeType" -Type String -Value "vhdx" -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "RoamSearch" -Type DWord -Value 0 -Force
Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "OutlookCacheMode" -Type DWord -Value 1 -Force

#Enable and set profile
If($ProfilePath -match 'http'){
    Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type DWord -Value 1 -Force
    Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "CCDLocations" -Type MultiString -Value "type=smb,connectionString=$ProfilePath" -Force
}
ElseIf($ProfilePath -match '\\\\'){
    Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type DWord -Value 1 -Force
    Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "VHDLocations" -Type MultiString -Value $ProfilePath -Force
}

If($RedirectionPath){
    If(Test-Path "$RedirectionPath\redirections.xml"){
        Set-LocalPolicySetting -RegPath HKLM:\Software\FSLogix\Profiles -Name "RedirXMLSourceFolder" -Type MultiString -Value $RedirectionPath -Force
    }
}

#Cleanup and Complete
Remove-Item $LocalPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-YaCMLogEntry -Message ('Completed {0} install' -f $ProductName) -Passthru
