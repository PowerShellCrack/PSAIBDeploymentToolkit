#=======================================================
# VARIABLES
#=======================================================
$ErrorActionPreference = "Stop"
##*=============================================
##* INSTALL MODULES
##*=============================================
Install-Module -Name YetAnotherCMLogger
Import-Module YetAnotherCMLogger

##*========================================================================
##* VARIABLE DECLARATION
##*========================================================================
#specify path of log
Set-YaCMLogFileName
#=======================================================
# MAIN
#=======================================================
$listGUIDs = @(
'{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}',
'{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}',
'{d3162b92-9365-467a-956b-92703aca08af}',
'{1CF1260C-4DD0-4ebb-811F-33C572699FDE}',
'{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}',
'{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}',
'{24ad3ad4-a569-4530-98e1-ab02f9417aa8}',
'{A0953C92-50DC-43bf-BE83-3742FED03C9C}',
'{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}'
)

foreach ($GUID in $listGUIDs)
{
    Try{
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\$GUID\" -Force -ErrorAction Stop
        Remove-item "HKLM:\SOFTWARE\Wow6432Node\Microsoft\WIndows\CurrentVersion\Explorer\MyComputer\NameSpace\$GUID\" -Force -ErrorAction Stop
        Write-YaCMLogEntry -Message ("Removed {0}" -f $GUID) -Passthru
    }Catch{
        Write-YaCMLogEntry -Message ("Unable to remove {0}: {1}" -f $GUID, $_.Exception.Message) -Passthru
    }
}
Write-YaCMLogEntry -Message ('Completed desktop Icon removal') -Passthru
