<#
.SYNOPSIS
    Software install Script

.NOTES
    Source Script: https://github.com/tsrob50/AIB

.LINK

    Applications to install:

    Notepad++
    https://notepad-plus-plus.org/downloads/v8.4.4/
    See comments on creating a custom setting to disable auto update message
    https://community.notepad-plus-plus.org/post/38160
#>

#region Set logging
$logFile = $PSScriptRoot + "\" + (get-date -format 'yyyyMMdd') + '_softwareinstall.log'
function Write-Log {
    Param($message)
    Write-Output "$(get-date -format 'yyyyMMdd HH:mm:ss') $message" | Out-File -Encoding utf8 $logFile -Append
}
#endregion

#region Notepad++
try {
    Start-Process -filepath "$PSScriptRoot\npp.8.4.4.Installer.x64.exe" -Wait -ErrorAction Stop -ArgumentList '/S'
    Copy-Item "$PSScriptRoot\config.model.xml" 'C:\Program Files\Notepad++'
    Rename-Item 'C:\Program Files\Notepad++\updater' 'C:\Program Files\Notepad++\updaterOld'
    if (Test-Path "C:\Program Files\Notepad++\notepad++.exe") {
        Write-Log "Notepad++ has been installed"
    }
    else {
        write-log "Error locating the Notepad++ executable"
    }
}
catch {
    $ErrorMessage = $_.Exception.message
    write-log "Error installing Notepad++: $ErrorMessage"
}
#endregion

Write-Host "Exit code:" $LASTEXITCODE
