<#
.SYNOPSIS


.LINK
https://rozemuller.com/configure-wvd-start-vm-on-connect-automated-with-role-assignments-and-graph-api/
https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resources-powershell
https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/custom-script-windows
#>

##======================
## VARIABLES
##======================
$ErrorActionPreference = "Stop"

$GovAzureConfigs = @{
    HostpoolName = 'dtolabgov-avd-hostpool'
    ResourceGroupName = 'dtolabgov-avd-rg'
    TenantID = 'a18e4f0a-1a04-4662-b8e4-f72188b41725'
    SubscriptiuonID ='f5e1060d-4404-401e-b04d-129f3b620293'
    LocationName='usgovvirginia'

    VnetName='dtolab-us-gova-spoke-vnet'
    SubnetName='dtolab-us-gova-avd-subnet'
    NSGName='dtolab-us-gova-spoke-nsg'
}

$GovVMConfigs = @{
    VMRefName='AVDP-REF1'
    DiskStorageAccountName='dtolabgovavdvmsa'
    Size = "Standard_D2s_v3"
    LocalAdminUser='xAdmin'
    LocalAdminPassword='!QAZ1qaz!QAZ1qaz'
}

$GovVMCustomizations = @{
    StorageAccountName='avdimageresources'
    StorageAccountKey='Ew1L8NtIsLnYu2N2i8BN73E7WAOCQhR+Rdp8peaQaXHTJzgBo5ESwmpAPetmOLuwLMFFFg243f0WTgxMbAQ+5A=='
    SasKey = '?sv=2020-08-04&ss=bf&srt=sco&sp=rltf&se=2022-06-02T08:28:24Z&st=2022-06-02T00:28:24Z&sip=10.21.2.4&spr=https&sig=wds2Kx%2FKrQTbBDmgh84b04ofscdxqaaRpM6EfK7uAhI%3D'

    fileUris = @(
        #"https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Deploy.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/application-lgpo/Install-LGPO.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Remove-Appx.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Install-Office365AVD.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Install-OnedriveAVD.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Install-TeamsAVD.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Remove-DekstopIcons.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/Install-Fslogix.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/AVD-Optimize.ps1"
        "https://avdimageresources.blob.core.usgovcloudapi.net/scripts/AVD-Prepare.ps1"
    )
}

$GovVMCustomizations += @{
    protectedSettings = @{
        storageAccountName = $GovVMCustomizations.StorageAccountName
        storageAccountKey = $GovVMCustomizations.StorageAccountKey
        commandToExecute = "powershell -ExecutionPolicy Unrestricted -File .\Deploy.ps1 -SasKey $SasKey"
    }
}
##======================
## MAIN
##======================
#connect to government cloud to build VM

Connect-AzAccount -Environment AzureUSGovernment

#https://docs.microsoft.com/en-us/powershell/module/az.compute/new-azvm?view=azps-2.8.0
#Example 3: Create a VM from a marketplace image without a Public IP
#region Create a resource group:
if (!(Get-AzResourceGroup -Name $GovAzureConfigs.ResourceGroupName -Location $GovAzureConfigs.LocationName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)){
    New-AzResourceGroup -Name $GovAzureConfigs.ResourceGroupName -Location $GovAzureConfigs.LocationName
}
#endregion

#region Create Storage Account
if (!(Get-AzStorageAccount -ResourceGroupName $GovAzureConfigs.ResourceGroupName -Name $GovVMConfigs.DiskStorageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)){
    #build random char for storage name
    $storageAcct = New-AzStorageAccount -ResourceGroupName $GovAzureConfigs.ResourceGroupName -Name $GovVMConfigs.DiskStorageAccountName -SkuName "Standard_LRS" -Location $GovAzureConfigs.LocationName -Kind Storage -verbose
}
#endregion

#region Creating a new NSG to allow PS Remoting Port 5986 and RDP Port 3389
#grab Vnet for NSG and NIC configurations
$Vnet = Get-AzVirtualNetwork -Name $GovAzureConfigs.VnetName
$subnet = $Vnet.Subnets | Where Name -eq $GovAzureConfigs.SubnetName
#endregion

if (!(Get-AzVM -Name $GovVMConfigs.VMRefName)){
    #region Attach VM to avd subnet
    #$randomInt = (Get-Random -Count 1 -InputObject (100..999)).ToString()
    $NIC = New-AzNetworkInterface -Name ($GovVMConfigs.VMRefName + '-ni').ToLower() -ResourceGroupName $GovAzureConfigs.ResourceGroupName -Location $GovAzureConfigs.LocationName -SubnetId $subnet.Id
    #endregion

    #region Build local admin credentials for VM
    $LocalAdminSecurePassword = ConvertTo-SecureString $GovVMConfigs.LocalAdminPassword -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential ($GovVMConfigs.LocalAdminUser, $LocalAdminSecurePassword);
    #endregion

    #region Build VM configurations
    $VirtualMachine = New-AzVMConfig -VMName $GovVMConfigs.VMRefName -VMSize $GovVMConfigs.Size
    $VirtualMachine = Set-AzVMOperatingSystem -VM $VirtualMachine -Windows -ComputerName $GovVMConfigs.VMRefName -Credential $Credential -ProvisionVMAgent
    $VirtualMachine = Add-AzVMNetworkInterface -VM $VirtualMachine -Id $NIC.Id
    #$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'office-365' -Skus 'win11-21h2-avd-m365' -Version latest
    $VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'Windows-10' -Skus 'win10-21h2-avd-g2' -Version latest
    #$VirtualMachine = Set-AzVMSourceImage -VM $VirtualMachine -PublisherName 'MicrosoftWindowsDesktop' -Offer 'office-365' -Skus 'win10-21h2-avd-m365-g2' -Version latest
    #endregion

    #region Deploy VM
    New-AzVM -ResourceGroupName $GovAzureConfigs.ResourceGroupName -Location $GovAzureConfigs.LocationName -VM $VirtualMachine -Verbose
}
#endregion


#START VM????
<#
#Using multiple scripts
Set-AzVMExtension -ResourceGroupName $GovAzureConfigs.ResourceGroupName `
    -Location $GovAzureConfigs.LocationName `
    -VMName $GovVMConfigs.VMRefName `
    -Name 'Baseline' `
    -Publisher "Microsoft.Compute" `
    -ExtensionType "CustomScriptExtension" `
    -TypeHandlerVersion "1.10" `
    -Settings $GovVMCustomizations.fileUris `
    -ProtectedSettings $GovVMCustomizations.protectedSettings


#
#Set-AzVMCustomScriptExtension -ResourceGroupName $GovAzureConfigs.ResourceGroupName -VMName $GovVMConfigs.VMRefName `
    -Location $GovAzureConfigs.LocationName `
    -FileUri <fileUrl> `
    -Run 'myScript.ps1' `
    -Name DemoScriptExtension
#>
#splat common args to reduce repetition
$RunCommandCommonArgs = @{
    Name=$GovVMConfigs.VMRefName
    ResourceGroupName=$GovAzureConfigs.ResourceGroupName
    CommandId='RunPowerShellScript'
}

<#
#Install LGPO
Try{
    $Result = Invoke-AzVMRunCommand @RunCommandCommonArgs -ScriptPath E:\LABs\DTOLAB\AIB\Scripts\Install-LGPO.ps1
}Catch{
    Write-Error $_.exception.message
}
#>


Foreach($script in $GovVMCustomizations.fileUris)
{
    $scriptName = Split-Path $script -Leaf
    $LocalPath = Join-Path "$PSScriptRoot\Scripts" -ChildPath $scriptName
    Write-Host ("Invoking script [{0}] on azure VM [{1}]..." -f $scriptName, $GovVMConfigs.VMRefName) -NoNewline
    Try{
        $Result = Invoke-AzVMRunCommand @RunCommandCommonArgs -ScriptPath $LocalPath
        Write-Host ("Done. {0}" -f $Result) -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed! {0}" -f $_.exception.message) -ForegroundColor Red
        Break
    }
}


CApture

#buld SVD\


POst p

#connect to Commericial cloud to get AVD host pool settings
#Connect-AzAccount -Environment AzureCloud
