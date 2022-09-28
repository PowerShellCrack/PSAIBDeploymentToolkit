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
$AppList = @(
    "onenet”,
    "3dbuilder",
    "officehub",
    "skypeapp",
    "getstarted",
    "solitairecollection",
    "bingfinance",
    "OneConnect",
    "windowsphone",
    "bingsports",
    "Office.Sway",
    "Microsoft.GetHelp",
    "Microsoft.WindowsMaps",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Print3D",
    "Xbox",
    "Microsoft.XboxGameOverlay",
    "WindowsSoundRecorder",
    "Microsoft.BingWeather",
    "Microsoft.WindowsMaps",
    "Microsoft.YourPhone",
    "Microsoft.Wallet",
    "Zune"
)

$AppListCount = $AppList.Count
$AppRemovalProgress = 1
$AllUserAppx = Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Sort-Object -Property Name


#loop through each app
#TEST $App = $AllUserAppx[0]
foreach ($App in $AllUserAppx)
{
    Write-YaCMLogEntry -Message ("Looking for appx match [{0}]..." -f $App.Name) -Passthru

    If($App.Name -match ($AppList -join '|') )
    {

        Write-YaCMLogEntry -Message ("  Removing user appx: {0}..." -f $App.Name) -Passthru

        Try{
            Remove-AppxPackage -Package $App.PackageFullName -AllUsers -ErrorAction Stop | Out-Null
        }
        Catch{
            Write-YaCMLogEntry -Message ("Failed: {0}" -f $_.exception.message) -Passthru
        }

        $ProvisionedPackage = Get-AppxProvisionedPackage -Online | where {$_.Displayname -like "*$($App.Name)*"}
        Write-YaCMLogEntry -Message ("  Removing system appx: {0}..." -f $App.Name) -Passthru

        If($ProvisionedPackage){
            Try{
                Remove-AppxProvisionedPackage -PackageName $ProvisionedPackage.PackageName -Online -AllUsers -ErrorAction Stop | Out-Null
            }
            Catch{
                Write-YaCMLogEntry -Message ("Failed: {0}" -f $_.exception.message) -Passthru
            }
        }
        Else{
            Write-YaCMLogEntry -Message ("[{0}] Does not exist" -f $App.Name) -Passthru
        }
    }
    Else{
        Write-YaCMLogEntry -Message ("Skipped app [{0}]" -f $App.Name) -Passthru
    }

}

Write-YaCMLogEntry -Message ('Completed App removal') -Passthru
Write-Host "Exit code:" $LASTEXITCODE
