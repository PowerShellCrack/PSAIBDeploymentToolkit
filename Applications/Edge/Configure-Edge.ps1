
$ErrorActionPreference = "Stop"
#=======================================================
$ProductName = "Microsoft Edge"
$homepage = ''
$AllowList = ''
$SiteList = 'sitelist.xml'
$ProxyPacURL = 'proxy.pac'
$InternetURI = 'https://aka.ms/avdgpo'
#=======================================================
# MAIN
#=======================================================
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Download Azure Monitor agent
Try{
    Write-Host ('Downloading {1} from URL [{0}]' -f $InternetURI,$ProductName)
    Invoke-WebRequest $InternetURI -OutFile "$env:temp\AVDGPTemplate.cab"
}
Catch{
    Write-Host ('Unable to download {1)}. {0}' -f $_.Exception.message,$ProductName)
}

Write-Host ('Copy {1} policy template files to [{0}]' -f "$env:Windir\PolicyDefinitions",$ProductName)
Copy-Item "$PSScriptRoot\terminalserver-avd.adml" "$env:Windir\PolicyDefinitions\en-US" -ErrorAction SilentlyContinue -Force
Copy-Item "$PSScriptRoot\terminalserver-avd.admx" "$env:Windir\PolicyDefinitions" -ErrorAction SilentlyContinue -Force

# Edge Local Policy Profile Settings
Write-Host ('Configure {0} Settings...' -f $ProductName) -NoNewline
Try{
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -name Edge -Force -ErrorAction SilentlyContinue | Out-Null
    If($AllowList){Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AuthServerAllowlist" -Value $AllowList -Force}
    If($AllowList){Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HomepageLocation" -Value $homepage -Force}
    If(Test-Path $SiteList){
        et-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "InternetExplorerIntegrationSiteList" -Value $SiteList -Force
    }
    If(Test-Path $ProxyPacURL){
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ProxyMode" -Value 'pac_script' -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ProxyPacUrl" -Value $ProxyPacURL -Force
        Start-Process Bitsadmin -ArgumentList "/util /setieproxy LOCALSYSTEM AUTOSCRIPT $ProxyPacURL" -Wait -NoNewWindow | Out-Null
    }
    Write-Host ("Done") -ForegroundColor Green
}Catch{
    Write-Host ("Failed: {0}" -f $_.exception.message) -ForegroundColor Red
}
