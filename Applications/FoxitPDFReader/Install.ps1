<#
.SYNOPSIS
    Software install Script

.NOTES
    Source Script: https://github.com/tsrob50/AIB

.LINK

    Applications to install:

    Foxit Reader Enterprise Packaging (requires registration)
    https://kb.foxitsoftware.com/hc/en-us/articles/360040658811-Where-to-download-Foxit-Reader-with-Enterprise-Packaging-MSI-
    https://cdn01.foxitsoftware.com/product/reader/desktop/win/12.0.0/FoxitPDFReader1201_L10N_Setup.zip
    https://cdn01.foxitsoftware.com/product/phantomPDF/desktop/win/12.0.0/tools/Foxit PDF Reader120_enu_admx&adml.zip

#>

#region Set logging
$logFile = $PSScriptRoot + "\" + (get-date -format 'yyyyMMdd') + '_softwareinstall.log'
function Write-Log {
    Param($message)
    Write-Output "$(get-date -format 'yyyyMMdd HH:mm:ss') $message" | Out-File -Encoding utf8 $logFile -Append
}
#endregion

#region Foxit Reader
try {
    Start-Process -filepath msiexec.exe -Wait -ErrorAction Stop -ArgumentList '/i', "$PSScriptRoot\FoxitPDFReader1201_enu_Setup.msi", '/quiet', 'ADDLOCAL="FX_PDFVIEWER"'
    if (Test-Path "C:\Program Files (x86)\Foxit Software\Foxit PDF Reader\FoxitPDFReader.exe") {
        Write-Log "Foxit Reader has been installed"
    }
    else {
        write-log "Error locating the Foxit Reader executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing Foxit Reader: $ErrorMessage"
}
#endregion
Write-Host "Exit code:" $LASTEXITCODE
