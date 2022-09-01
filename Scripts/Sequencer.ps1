Function ConvertTo-AIBCustomization{
    <#
    .SYNOPSIS
    Convert customization properties to AIB support format

    .NOTES
    $BlobUrl = (Get-Content .\Control\settings-gov.json -raw | ConvertFrom-Json).Resources.resourceBlobURI
    $SequenceData = Get-Content .\Control\Win10avdBaselineImage\aib.json -raw | ConvertFrom-Json | Select -expandProperty customSequence
    [System.Object[]]$CustomData = $SequenceData | Where Type -eq 'Application' | Select -index 4
    [System.Object[]]$CustomData = $SequenceData | Where Type -eq 'Script' | Select -first 1

    {
        "type": "PowerShell",
        "name":   "<name>",
        "scriptUri": "<path to script>",
        "runElevated": <true false>,
        "sha256Checksum": "<sha256 checksum>"
    },
    {
        "type": "PowerShell",
        "name": "<name>",
        "inline": "<PowerShell syntax to run>",
        "validExitCodes": <exit code>,
        "runElevated": <true or false>
    }
    {
        "type": "File",
        "name": "<name>",
        "sourceUri": "<source location>",
        "destination": "<destination>",
        "sha256Checksum": "<sha256 checksum>"
    }


    .LINK
    https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=azure-powershell
    #>

    Param(
        $BlobURL,
        [System.Object[]]$CustomData,
        [string]$FileCopyDest = "C:\Windows\AIB",
        [switch]$SkipChecksum,
        [switch]$Cleanup,
        [switch]$Passthru
    )

    $ObjectArray = @()

    switch($CustomData.type){
        #convert application into a variety of AIB Customization support types based on extension
        'Application' {
            switch -regex ( [System.IO.Path]::GetExtension($CustomData.executable) ){
                'ps1$' {

                    If($CustomData.fileDependency.count -gt 0){
                        Foreach($file in $CustomData.fileDependency){
                            #Gen File copy for each dependency file
                            $object = New-Object -TypeName PSObject
                            $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "File"
                            $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Copying " + $file)
                            $object | Add-Member -MemberType NoteProperty -Name 'sourceUri' -Value ('https://' + $BlobURL + '/application-' + $CustomData.workingDirectory.ToLower()  + '/' + $file)
                            $object | Add-Member -MemberType NoteProperty -Name 'destination' -Value ($env:Temp + '\' + $file)
                            If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $file)) -and !$SkipChecksum){
                                $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $file) | Select -ExpandProperty Hash
                                $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
                            }
                            $ObjectArray += $object
                        }
                    }

                    #AIB does nto support arguments, so the process must be broken down into copy file and inline script call
                    If($CustomData.arguments.Length -gt 0){
                        $Arguments = $CustomData.arguments -replace '<destination>',$env:Temp

                        #Step 1: Gen File copy for ps1 file
                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "File"
                        $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Copying " + $CustomData.workingDirectory)
                        $object | Add-Member -MemberType NoteProperty -Name 'sourceUri' -Value ('https://' + $BlobURL + '/application-' + $CustomData.workingDirectory.ToLower()  + '/' + $CustomData.executable)
                        $object | Add-Member -MemberType NoteProperty -Name 'destination' -Value ($env:Temp + '\' + $CustomData.executable)
                        If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable)) -and !$SkipChecksum){
                            $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable) | Select -ExpandProperty Hash
                            $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
                        }
                        $ObjectArray += $object

                        #Step 2: Gen inline with argument for ps1 call
                        $InlineCommands = @(
                            "& $env:Temp\$($CustomData.executable) $Arguments"
                        )
                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                        $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ($CustomData.name -replace '\s+','').ToLower()
                        $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                        $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                        $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands
                        $ObjectArray += $object
                    }Else{
                        $object = New-Object -TypeName PSObject
                        $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                        $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ($CustomData.name -replace '\s+','').ToLower()
                        $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                        $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                        $object | Add-Member -MemberType NoteProperty -Name 'scriptUri' -Value ('https://' + $BlobURL + '/application-' + $CustomData.workingDirectory.ToLower() + '/' + $CustomData.executable)
                        #grab hash first
                        If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable)) -and !$SkipChecksum){
                            $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable) | Select -ExpandProperty Hash
                            $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
                        }
                        If($CustomData.exitCodes){
                            $object | Add-Member -MemberType NoteProperty -Name 'validExitCodes' -Value $CustomData.exitCodes
                        }
                        $ObjectArray += $object
                    }


                }

                'exe$|msi$' {
                    #Step 1. Gen app working directory creation
                    $InlineCommands = @(
                        "New-Item '$FileCopyDest\\$($CustomData.workingDirectory)' -ItemType Directory -ErrorAction SilentlyContinue"
                    )
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Creating folder '" + $FileCopyDest + '\' + $CustomData.workingDirectory + "'")
                    $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands
                    $ObjectArray += $object

                    #Step 2: Gen File copy for each dependency file
                    If($CustomData.fileDependency.count -gt 0){
                        Foreach($file in $CustomData.fileDependency | Where {$_ -ne $CustomData.executable}){

                            $object = New-Object -TypeName PSObject
                            $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "File"
                            $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Copying " + $file)
                            $object | Add-Member -MemberType NoteProperty -Name 'sourceUri' -Value ('https://' + $BlobURL + '/application-' + $CustomData.workingDirectory.ToLower()  + '/' + $file)
                            $object | Add-Member -MemberType NoteProperty -Name 'destination' -Value ($FileCopyDest +'\' + $CustomData.workingDirectory + '\' + $file)
                            If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $file)) -and !$SkipChecksum){
                                $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $file) | Select -ExpandProperty Hash
                                $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
                            }
                            $ObjectArray += $object
                        }
                    }

                    #Step 3: Gen File copy for executable file
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "File"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Copying " + $CustomData.workingDirectory)
                    $object | Add-Member -MemberType NoteProperty -Name 'sourceUri' -Value ('https://' + $BlobURL + '/application-' + $CustomData.workingDirectory.ToLower()  + '/' + $CustomData.executable)
                    $object | Add-Member -MemberType NoteProperty -Name 'destination' -Value ($FileCopyDest + '\' + $CustomData.workingDirectory + '\' + $CustomData.executable)
                    If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable)) -and !$SkipChecksum){
                        $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable) | Select -ExpandProperty Hash
                        $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
                    }
                    $ObjectArray += $object

                    #Step 4. Gen powershell inline command to call executable
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Installing " + $CustomData.workingDirectory)
                    $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                    #if msi change installer to msiexec

                    switch([System.IO.Path]::GetExtension($CustomData.executable) ){
                        '.exe' {$FilePath= ($FileCopyDest + '\' +  $CustomData.workingDirectory + '\' + $CustomData.executable)}
                        '.msi' {$FilePath='C:\Windows\system32\msiexec.exe';$Arguments = "$FileCopyDest$\$($CustomData.workingDirectory)\$($CustomData.executable)" + ' ' + $Arguments}
                    }
                    If($CustomData.arguments.Length -gt 0){
                        $Arguments = $CustomData.arguments -replace '<destination>',$FileCopyDest

                        $InlineCommands = @(
                            "`$Result = Start-Process -FilePath $FilePath -ArgumentList '$Arguments' -Wait -PassThru"
                            "Return `$Result.ExitCode"
                        )
                    }Else{
                        $InlineCommands = @(
                            "`$Result = Start-Process -FilePath $FilePath -Wait -PassThru",
                            "Return `$Result.ExitCode"
                        )
                    }
                    $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands

                    If($CustomData.exitCodes){
                        $object | Add-Member -MemberType NoteProperty -Name 'validExitCodes' -Value $CustomData.exitCodes
                    }
                    $ObjectArray += $object
                }


                'zip$|cab$' {
                    #Step 1. Create app working directory
                    $InlineCommands = @(
                        "New-Item '$FileCopyDest$\$($CustomData.workingDirectory)' -ItemType Directory -ErrorAction SilentlyContinue"
                    )
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Creating folder '" + $FileCopyDest + '\' + $CustomData.workingDirectory + "'")
                    $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands
                    $ObjectArray += $object

                    #Step 2: Copy file
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "File"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Copying " + $CustomData.workingDirectory)
                    $object | Add-Member -MemberType NoteProperty -Name 'sourceUri' -Value ('https://' + $BlobURL + '/application-' + $CustomData.workingDirectory.ToLower()  + '/' + $CustomData.executable)
                    $object | Add-Member -MemberType NoteProperty -Name 'destination' -Value ("$FileCopyDest" + $CustomData.workingDirectory + '\' + $CustomData.executable)
                    If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable)) -and !$SkipChecksum){
                        $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable) | Select -ExpandProperty Hash
                        $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
                    }
                    $ObjectArray += $object

                    #Step 3. Extract file
                    $InlineCommands = @(
                        "Expand-Archive -Path '$FileCopyDest$\$($CustomData.workingDirectory)\$($CustomData.executable)' -DestinationPath '$FileCopyDest$\$($CustomData.workingDirectory)' -Force"
                    )
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Extracting " + $CustomData.executable)
                    $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands
                    $ObjectArray += $object

                    #Step 4. Install file
                    $object = New-Object -TypeName PSObject
                    $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
                    $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Installing " + $CustomData.workingDirectory)
                    $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
                    $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
                    If($CustomData.arguments.Length -gt 0){
                        $Arguments = $CustomData.arguments -replace '<destination>',$FileCopyDest
                        $InlineCommands = @(
                            "`$Result = Start-Process -FilePath '$FileCopyDest$\$($CustomData.workingDirectory)\$($CustomData.executable)' -ArgumentList '$Arguments' -Wait -PassThru"
                            "Return `$Result.ExitCode"
                        )
                    }Else{
                        $InlineCommands = @(
                            "`$Result = Start-Process -FilePath '$FileCopyDest$\$($CustomData.workingDirectory)\$($CustomData.executable)' -Wait -PassThru",
                            "Return `$Result.ExitCode"
                        )
                    }
                    $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands

                    If($CustomData.exitCodes){
                        $object | Add-Member -MemberType NoteProperty -Name 'validExitCodes' -Value $CustomData.exitCodes
                    }
                    $ObjectArray += $object
                }
            }

        }

        'File' {
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "File"
            $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Copying " + $CustomData.workingDirectory)
            $object | Add-Member -MemberType NoteProperty -Name 'sourceUri' -Value ('https://' + $BlobURL + '/packages/' + $CustomData.File)
            $object | Add-Member -MemberType NoteProperty -Name 'destination' -Value $CustomData.destination
            If( (Test-Path ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.file)) -and !$SkipChecksum){
                $CheckSum = Get-FileHash ('.\Applications\' + $CustomData.workingDirectory + '\' + $CustomData.executable) | Select -ExpandProperty Hash
                $object | Add-Member -MemberType NoteProperty -Name 'sha256Checksum' -Value $CheckSum
            }
            $ObjectArray += $object
        }

        'Script' {
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
            $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ($CustomData.name -replace '\s+','').ToLower()
            $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
            $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
            $object | Add-Member -MemberType NoteProperty -Name 'scriptUri' -Value ('https://' + $BlobURL + '/scripts/' + $CustomData.scriptfile)
            If($CustomData.exitCodes){
                $object | Add-Member -MemberType NoteProperty -Name 'validExitCodes' -Value $CustomData.exitCodes
            }
            $ObjectArray += $object
        }

        'Restart' {
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "WindowsRestart"
            $object | Add-Member -MemberType NoteProperty -Name 'restartCheckCommand' -Value "write-host 'restarting after $($CustomData.name)'"
            $object | Add-Member -MemberType NoteProperty -Name 'restartTimeout' -Value "5m"
            $ObjectArray += $object
        }

        'WindowsUpdate' {
            $Filters = @(
                "exclude:`$_.Title -like '*Preview*'",
                "include:`$true"
            )
            $object = New-Object -TypeName PSObject
            $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "WindowsUpdate"
            $object | Add-Member -MemberType NoteProperty -Name 'searchCriteria' -Value "IsInstalled=0"
            $object | Add-Member -MemberType NoteProperty -Name 'filters' -Value $Filters
            $object | Add-Member -MemberType NoteProperty -Name 'updateLimit' -Value 40
            $ObjectArray += $object
        }
    }

    #Step 5. Gen app working directory deletion
    If($Cleanup){
        $InlineCommands = @(
            "Remove-Item -path '$FileCopyDest$\$($CustomData.workingDirectory)' -recurse -ErrorAction SilentlyContinue",
            "Remove-Item -path '$env:temp\*' -ErrorAction SilentlyContinue"
        )
        $object = New-Object -TypeName PSObject
        $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
        $object | Add-Member -MemberType NoteProperty -Name 'name' -Value ("Removing folders")
        $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
        $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
        $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands
        $ObjectArray += $object
    }

    #add an additional restart AIB customization if exists
    If( ($CustomData.restart -eq $True) -or ($CustomData.restartTimeout.length -gt 0) ){
        $object = New-Object -TypeName PSObject
        $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "WindowsRestart"
        $object | Add-Member -MemberType NoteProperty -Name 'restartCheckCommand' -Value "write-host 'restarting after $($CustomData.name)'"
        If($CustomData.restartTimeout.length -gt 0){
            $object | Add-Member -MemberType NoteProperty -Name 'restartTimeout' -Value $CustomData.restartTimeout
        }ElseIf($CustomData.type -eq 'WindowsUpdate'){
            $object | Add-Member -MemberType NoteProperty -Name 'restartTimeout' -Value "10m"
        }Else{
            $object | Add-Member -MemberType NoteProperty -Name 'restartTimeout' -Value "5m"
        }
        $ObjectArray += $object
    }

    If($Passthru){
        $ObjectArray
    }Else{
        $Json = $ObjectArray | ConvertTo-Json
        #fix the \u0027 issue
        ([regex]'(?i)\\u([0-9a-h]{4})').Replace($Json, {param($Match) "$([char][int64]"0x$($Match.Groups[1].Value)")"})
    }

}


Function ConvertFrom-CustomSequence{
    <#
    .SYNOPSIS
    Convert sequence properties to AIB support format

    .NOTES
    $BlobUrl = (Get-Content .\Control\settings-gov.json -raw | ConvertFrom-Json).Resources.resourceBlobURI
    $SequenceData = Get-Content .\Control\Win10avdBaselineImage\aib.json -raw | ConvertFrom-Json | Select -expandProperty customSequence
    $SequenceData = Get-Content .\Control\Win10avdSimpleImage\aib.json -raw | ConvertFrom-Json | Select -expandProperty customSequence
    $SequenceData = Get-Content .\Control\Win10avdHardenedImage\aib.json -raw | ConvertFrom-Json | Select -expandProperty customSequence
    [System.Object[]]$CustomData = $SequenceData | Where Type -eq 'Application' | Select -first 1
    [System.Object[]]$CustomData = $SequenceData | Where Type -eq 'Script' | Select -first 1

    .EXAMPLE
    . .\Scripts\Sequencer.ps1
    ConvertFrom-CustomSequence -BlobURL $BlobUrl -SequenceData $SequenceData
    .LINK
    https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=azure-powershell
    #>

    Param(
        $BlobURL,
        [System.Object[]]$SequenceData,
        [switch]$Passthru
    )

    $Data = @()
    #collect all data types of Modules and build a single inline command
    If($SequenceData.type -eq "Module"){
        $InlineCommands = @()
        Foreach($Repo in $SequenceData.trustedRepos | Select -Unique){
            $InlineCommands += "Set-PSRepository -Name '$Repo' -InstallationPolicy Trusted"
        }
        $Modules = ($SequenceData.modules | Select -Unique) -Join ','
        $InlineCommands += @(
            "Install-Module -Name $Modules -Force",
            "Import-Module -Name $Modules -Force"
        )
        #Step 1: Gen inline to set repository to trusted
        $object = New-Object -TypeName PSObject
        $object | Add-Member -MemberType NoteProperty -Name 'type' -Value "PowerShell"
        $object | Add-Member -MemberType NoteProperty -Name 'name' -Value "Install Modules"
        $object | Add-Member -MemberType NoteProperty -Name 'runElevated' -Value $True
        $object | Add-Member -MemberType NoteProperty -Name 'runAsSystem' -Value $True
        $object | Add-Member -MemberType NoteProperty -Name 'inline' -Value $InlineCommands
        $Data += $object
    }

    #loop through aib.json CustomSequence section and generate in AIB format
    Foreach($Sequence in $SequenceData){
        $Data += ConvertTo-AIBCustomization -BlobURL $BlobURL -CustomData $Sequence -Passthru -SkipCheckSum
    }

    If($Passthru){
        $Data
    }Else{
        $Json = $Data | ConvertTo-Json
        #fix the \u0027 issue
        ([regex]'(?i)\\u([0-9a-h]{4})').Replace($Json, {param($Match) "$([char][int64]"0x$($Match.Groups[1].Value)")"})
    }
}
