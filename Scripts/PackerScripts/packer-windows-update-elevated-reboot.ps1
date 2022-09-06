Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
trap {
    Write-Output "ERROR: $_"
    Write-Output (($_.ScriptStackTrace -split '\r?\n') -replace '^(.*)$','ERROR: $1')
    Write-Output (($_.Exception.ToString() -split '\r?\n') -replace '^(.*)$','ERROR EXCEPTION: $1')
    Exit 1
}
$name = "packer-windows-update-pending-reboot-6313ac0d-08c4-ccc7-d1bf-ca4d0b101234"
$log = "$env:SystemRoot\Temp\$name.out"
$s = New-Object -ComObject "Schedule.Service"
$s.Connect()
$t = $s.NewTask($null)
$t.XmlText = @'
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Description>Packer Windows update pending reboot elevated task</Description>
    </RegistrationInfo>
    <Principals>
        <Principal id="Author">
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
    </Principals>
    <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <StartWhenAvailable>false</StartWhenAvailable>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
            <StopOnIdleEnd>false</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>false</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>PT24H</ExecutionTimeLimit>
        <Priority>4</Priority>
    </Settings>
    <Actions Context="Author">
        <Exec>
            <Command>cmd</Command>
            <Arguments>/c PowerShell -ExecutionPolicy Bypass -OutputFormat Text -EncodedCommand QwA6AC8AVwBpAG4AZABvAHcAcwAvAFQAZQBtAHAALwBwAGEAYwBrAGUAcgAtAHcAaQBuAGQAbwB3AHMALQB1AHAAZABhAHQAZQAuAHAAcwAxACAALQBPAG4AbAB5AEMAaABlAGMAawBGAG8AcgBSAGUAYgBvAG8AdABSAGUAcQB1AGkAcgBlAGQA &gt;%SYSTEMROOT%\Temp\packer-windows-update-pending-reboot-6313ac0d-08c4-ccc7-d1bf-ca4d0b101234.out 2&gt;&amp;1</Arguments>
        </Exec>
    </Actions>
</Task>
'@
$username = "SYSTEM"
$password = ""
if (!$password) {
    $password = $null
}
$f = $s.GetFolder("\")
$f.RegisterTaskDefinition($name, $t, 6, $username, $password, 1, $null) | Out-Null
$t = $f.GetTask("\$name")
$t.Run($null) | Out-Null
$timeout = 10
$sec = 0
while ((!($t.state -eq 4)) -and ($sec -lt $timeout)) {
    Start-Sleep -Seconds 1
    $sec++
}
# Windows PowerShell 2 on Windows 7 does not have Get-CimInstance.
# PowerShell 6 does not have Get-WmiObject.
if (!(Get-Command Get-CimInstance -ErrorAction:SilentlyContinue)) {
    function Get-CimInstance {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True, Position = 0)]
            [string]
            $ClassName
        )
        Get-WmiObject -Class $ClassName
    }
}
$reportProgressInterval = New-TimeSpan -Minutes 1
$startDate = Get-Date
$line = 0
do {
    Start-Sleep -Seconds 5
    if (Test-Path $log) {
        Get-Content $log | Select-Object -skip $line | ForEach-Object {
            ++$line
            Write-Output $_
        }
    }
    $currentDate = Get-Date
    if ($currentDate.Subtract($startDate) -ge $reportProgressInterval) {
        $startDate = $currentDate
        $cpuUsage = (Get-CimInstance CIM_Processor | Measure-Object -Property LoadPercentage -Average).Average / 100
        $os = Get-CimInstance Win32_OperatingSystem
        $memoryUsage = 1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize
        Write-Output ("Waiting for operation to complete (system performance: {0:P0} cpu; {1:P0} memory)..." -f $cpuUsage,$memoryUsage)
    }
} while (!($t.state -eq 3))
$result = $t.LastTaskResult
if (Test-Path $log) {
    Remove-Item $log -Force -ErrorAction SilentlyContinue | Out-Null
}
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($s) | Out-Null
exit $result
