#https://docs.microsoft.com/en-us/azure/storage/blobs/storage-quickstart-blobs-powershell
#https://docs.microsoft.com/en-us/azure/storage/scripts/storage-common-rotate-account-keys-powershell?toc=%2Fpowershell%2Fmodule%2Ftoc.json
Function Set-StorageBlobPublicAccess {
    Param(
        $ResourceGroup,
        $accountName,
        [switch]$Disable
    )
    # Read the AllowBlobPublicAccess property for the newly created storage account.
    (Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $accountName).AllowBlobPublicAccess

    If($Disable){
        # Set AllowBlobPublicAccess set to false
        Set-AzStorageAccount -ResourceGroupName $ResourceGroup `
            -Name $accountName `
            -AllowBlobPublicAccess $false
    }
    # Read the AllowBlobPublicAccess property.
    (Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $accountName).AllowBlobPublicAccess
}

Function Set-StorageContainerPublicAccess {
    Param(
        $ResourceGroup,
        $accountName,
        $containerName
    )

    # Get context object.
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $accountName
    $ctx = $storageAccount.Context

    # Create a new container with public access setting set to Off.
    New-AzStorageContainer -Name $containerName -Permission Off -Context $ctx

    # Read the container's public access setting.
    Get-AzStorageContainerAcl -Container $containerName -Context $ctx

    # Update the container's public access setting to Container.
    Set-AzStorageContainerAcl -Container $containerName -Permission Container -Context $ctx

    # Read the container's public access setting.
    Get-AzStorageContainerAcl -Container $containerName -Context $ctx
}
