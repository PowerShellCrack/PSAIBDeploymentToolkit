
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

$ErrorActionPreference = "Stop"

##*========================================================================
##* VARIABLE DECLARATION
##*========================================================================
#specify path of log
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
        Write-Host -Message ('Creating temp directory [{0}]' -f $LocalPath)
        New-Item -Path $LocalPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
Catch{
    Write-Host -Message ('Unable to create directory [{0}]. {1}' -f $LocalPath, $_.Exception.message) -Severity 3
    Break
}

# Download FSlogix
Try{
    Write-Host -Message ('Downloading {1} from URL [{0}]' -f $InternetURI,$ProductName)
    Invoke-WebRequest $InternetURI -OutFile "$Localpath\Fslogix.zip"
    Expand-Archive  "$Localpath\Fslogix.zip" -DestinationPath $Localpath -Force
}
Catch{
    Write-Host -Message ('Unable to download {1)}. {0}' -f $_.Exception.message,$ProductName) -Severity 3
    Break
}


#prep device for fslogix
Write-Host -Message ('Copy {1} policy template files to [{0}]' -f "$env:Windir\PolicyDefinitions",$ProductName)
Copy-Item "$LocalPath\fslogix.adml" "$env:Windir\PolicyDefinitions\en-US" -ErrorAction SilentlyContinue -Force
Copy-Item "$LocalPath\fslogix.admx" "$env:Windir\PolicyDefinitions" -ErrorAction SilentlyContinue -Force


# FSLogix Install
$InstallExecutable = "$LocalPath\x64\Release\$Installer"
$InstallArguments = "/install /quiet"
Write-Host -Message ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -WindowStyle Hidden' -f $InstallExecutable,$InstallArguments)
$Result = Start-Process -FilePath $InstallExecutable -ArgumentList $InstallArguments -Wait -WindowStyle Hidden
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
            Write-Host -Message ('Downloading {2} app rule file [{0}] to [{1}]' -f $File,$FSLogixInstallPath,$ProductName)
            Invoke-WebRequest -Uri "$Rule" -OutFile "$FSLogixInstallPath\$File" -UseBasicParsing -Verbose
        }
        Catch{
            Write-Host -Message ('Unable to download {1} rule file. {0}' -f $_.Exception.message,$ProductName) -Severity 2
            Break
        }
    }
    ElseIf($Rule -match '\\\\'){
        Write-Host -Message ('Copy {2} app rule zipped file [{0}] to [{1}]' -f $File,$FSLogixInstallPath,$ProductName)
        Copy-Item "$Rule" "$FSLogixInstallPath" -ErrorAction SilentlyContinue -Force
    }

    If([System.IO.Path]::GetExtension($File) -eq '.zip'){
        Expand-Archive -LiteralPath "$FSLogixInstallPath\$File" -DestinationPath $FSLogixInstallPath -Force -Verbose
        Remove-Item "$FSLogixInstallPath\$File" -Force -ErrorAction SilentlyContinue
    }
}

$LocalAdmin = Get-LocalGroup -Name Administrators | Get-LocalGroupMember
$FslogixGroups = @('FSLogix ODFC Exclude List','FSLogix Profile Exclude List')

Foreach($Group in $FslogixGroups){
    If( $LocalAdmin.name -notin (Get-LocalGroup -Name $Group | Get-LocalGroupMember).Name ){
        Write-Host -Message ('Adding local admin [{0}] to FSLogix exclude list [{1}]...' -f $LocalAdmin.name,$Group)
        Add-LocalGroupMember -Group $Group -Member $LocalAdmin.name
    }
    Else{
        Write-Host -Message ('Local admin [{0}] is already in FSLogix exclude list [{1}]!' -f $LocalAdmin.name,$Group)
    }
}

# FSLogix Local Policy Profile Settings
Write-Host -Message ('Configure {0} Profile Settings' -f $ProductName)
#Optimize Fslogix
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type DWord -Value 1 -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "SizeInMBs" -Type DWord -Value "30000" -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "FlipFlopProfileDirectoryName" -Type DWord -Value 1 -Force
#Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "SIDDirNamePattern" -Type String -Value "%username%%sid%" -Force
#Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "SIDDirNameMatch" -Type String -Value "%username%%sid%" -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "DeleteLocalProfileWhenVHDShouldApply" -Type DWord -Value 1 -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "DeleteProfileOnLogoff" -Type DWord -Value 1 -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "VolumeType" -Type String -Value "vhdx" -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "RoamSearch" -Type DWord -Value 0 -Force
Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "OutlookCacheMode" -Type DWord -Value 1 -Force

#Enable and set profile
If($ProfilePath -match 'http'){
    Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type DWord -Value 1 -Force
    Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "CCDLocations" -Type MultiString -Value "type=smb,connectionString=$ProfilePath" -Force
}
ElseIf($ProfilePath -match '\\\\'){
    Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "Enabled" -Type DWord -Value 1 -Force
    Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "VHDLocations" -Type MultiString -Value $ProfilePath -Force
}

If($RedirectionPath){
    If(Test-Path "$RedirectionPath\redirections.xml"){
        Set-ItemProperty -RegPath HKLM:\Software\FSLogix\Profiles -Name "RedirXMLSourceFolder" -Type MultiString -Value $RedirectionPath -Force
    }
}

#Cleanup and Complete
Remove-Item $LocalPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
Write-Host -Message ('Completed {0} install' -f $ProductName)
