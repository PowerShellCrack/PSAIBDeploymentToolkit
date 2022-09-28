$ErrorActionPreference = "Stop"
#=======================================================
# VARIABLES
#=======================================================
$ProductName = 'Azure Monitor'
$LocalPath = "$env:Windir\AIB\apps\azuremonitor"
$FileName = 'MMASetup-AMD64.exe'
$InternetURI = 'https://go.microsoft.com/fwlink/?LinkId=828603'
$WorkspaceID = ''
$PrimaryKey = ''

#=======================================================
# MAIN
#=======================================================
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Download Azure Monitor agent
Try{
    Write-host ('Downloading {1} from URL [{0}]' -f $InternetURI,$ProductName)
    Invoke-WebRequest $InternetURI -OutFile "$env:temp\$FileName"
}
Catch{
    Write-host ('Unable to download {1}. {0}' -f $_.Exception.message,$ProductName) -Severity 3
    Break
}

# Configure prereqs
Write-host ('Configure {0} TLS Settings...' -f $ProductName) -NoNewline
New-Item -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2" -Name "Client" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Type DWord -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
Write-host ('Reboot may be Required!') -ForegroundColor Yellow

# Azure Monitor agent Install
Write-host  ('Installing {0}...' -f $ProductName) -NoNewline
#extract exe
Start-Process -FilePath "$env:temp\$FileName" -ArgumentList "/Q /C /T:$env:temp\AzureMonitor" -Wait -WindowStyle Hidden | Out-NUll

$InstallArguments = "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=1 OPINSIGHTS_WORKSPACE_ID=""$WorkspaceID"" OPINSIGHTS_WORKSPACE_KEY=""$PrimaryKey"" AcceptEndUserLicenseAgreement=1"
Write-Verbose ('Running Command: Start-Process -FilePath "{0}" -ArgumentList "{1}" -Wait -WindowStyle Hidden' -f $InstallExecutable,$InstallArguments)
$InstallArguments = @(
    "/i ""$env:temp\AzureMonitor\MOMAgent.msi""",
    "/qn NOAPM=1 ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_AZURE_CLOUD_TYPE=1",
    "OPINSIGHTS_WORKSPACE_ID=""$WorkspaceID""",
    "OPINSIGHTS_WORKSPACE_KEY=""$PrimaryKey""",
    "AcceptEndUserLicenseAgreement=1"
)
$Result = Start-Process -FilePath c:\windows\system32\msiexec.exe -ArgumentList $InstallArguments -PassThru -Wait -WindowStyle Hidden
If($result.ExitCode -ne 0 -and $result.ExitCode -ne 3010 ){
    Write-Host ('Failed: {0}' -f $result.ExitCode) -ForegroundColor Red
}Else{
    Write-Host ('Done: {0}' -f $result.ExitCode) -ForegroundColor Green
}

#Cleanup and Complete
Remove-Item "$env:temp\$FileName" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item "$env:temp\AzureMonitor" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
