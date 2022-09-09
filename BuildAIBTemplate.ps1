<#
    .SYNOPSIS
    Deploy json arm template as Azure Image Builder

    .LINK
    https://github.com/Azure/azvmimagebuilder/tree/main/solutions/14_Building_Images_WVD
    https://github.com/Azure/azure-quickstart-templates/tree/master/demos/imagebuilder-windowsbaseline
    https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot
    https://docs.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-virtual-desktop
    https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-permissions-powershell

#>
Param(
    [Parameter(Mandatory = $true)]
    [ArgumentCompleter( {
        param ( $commandName,
                $parameterName,
                $wordToComplete,
                $commandAst,
                $fakeBoundParameters )


        $Template = Get-Childitem "$PSScriptRoot\Control" -Directory | Select -ExpandProperty Name

        $Template | Where-Object {
            $_ -like "$wordToComplete*"
        }

    } )]
    [Alias("Image")]
    [string]$Template,

    [Parameter(Mandatory = $false)]
    [ArgumentCompleter( {
        param ( $commandName,
                $parameterName,
                $wordToComplete,
                $commandAst,
                $fakeBoundParameters )


        $Settings = Get-Childitem "$PSScriptRoot\Control" -Filter Settings* | Where Extension -eq '.json' | Select -ExpandProperty Name

        $Settings | Where-Object {
            $_ -like "$wordToComplete*"
        }

    } )]
    [Alias("Config","Setting")]
    [string]$ControlSetting = "$PSScriptRoot\Control\Settings-Gov.json",

    [switch]$BuildImage,

    [switch]$CreateVM,

    [switch]$DeleteLogs,

    [switch]$CleanOnFailure
)

$ErrorActionPreference = "Stop"

If($DeleteLogs){
    Remove-Item "$PSScriptRoot\Logs\*" -recurse -ErrorAction SilentlyContinue | Out-Null
}
New-Item "$PSScriptRoot\Logs" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
$Date = Get-Date

$DateLogFormat = $Date.ToString('yyyy-MM-dd_Thh-mm-ss-tt')
$LogfileName = ('buildaibtemplate_' + $Template.ToLower() + '_' + $DateLogFormat + '.log')
Try{Start-transcript "$PSScriptRoot\Logs\$LogfileName" -ErrorAction Stop}catch{Start-Transcript "$PSScriptRoot\$LogfileName"}

#get the settings
$Settings = Get-Content "$PSScriptRoot\Control\$ControlSetting" -Raw | ConvertFrom-Json

#get the template settings
$TemplateConfigs = Get-Content "$PSScriptRoot\Control\$Template\aib.json" -Raw | ConvertFrom-Json

# Add AZ PS modules to support AzUserAssignedIdentity and Az AIB
Import-Module 'Az.Accounts','Az.ImageBuilder', 'Az.ManagedServiceIdentity'

#region Sequencer custom functions
. "$PSScriptRoot\Scripts\Sequencer.ps1"
#=======================================================
# CONNECT TO AZURE
#=======================================================
Connect-AzAccount -Environment $Settings.Environment.azureEnvironment
Set-AzContext -Subscription $Settings.Environment.subscriptionName

# Step 2: get existing context
$currentAzContext = Get-AzContext
# your subscription, this will get your current subscription
$subscriptionID=$currentAzContext.Subscription.Id

#Requires -Modules Az.Accounts,Az.Resources,Az.Network
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true" | Out-Null

##======================
## MAIN
##======================
<#
#Reference: https://docs.microsoft.com/en-us/azure/virtual-machines/image-builder-overview?tabs=azure-powershell
Get-AzResourceProvider -ProviderNamespace Microsoft.Compute, Microsoft.KeyVault, Microsoft.Storage, Microsoft.VirtualMachineImages, Microsoft.Network |
    Where-Object RegistrationState -ne Registered | Register-AzResourceProvider
#>
$AzureProviders = Get-AzResourceProvider -ProviderNamespace Microsoft.Compute, Microsoft.KeyVault, Microsoft.Storage, Microsoft.VirtualMachineImages, Microsoft.Network
If((Get-AzContext).Environment.Name -eq 'AzureUSGovernment'){
    If('NotRegistered' -in $AzureProviders.RegistrationState){
        Register-AzProviderPreviewFeature -ProviderNamespace Microsoft.VirtualMachineImages -Name FairfaxPublicPreview
    }
}
Else{
    #install Devlabs for Arm Templates support
    If($AzureProviders){
        Foreach ($Provider in $AzureProviders){
            If($Provider.RegistrationState -eq 'NotRegistered'){
                Write-Host ("Registering Azure resource provider [{0}] is already registered for type [{1}]..." -f $Provider.ProviderNamespace,($Provider.ResourceTypes.ResourceTypeName)) -ForegroundColor White -NoNewline
                Try{
                    Register-AzResourceProvider -ProviderNamespace $Provider.ProviderNamespace | Out-Null
                    Write-Host "Done" -ForegroundColor Green
                }
                Catch{
                    Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
                    Stop-Transcript;Break
                }

            }Else{
                Write-Host ("Azure resource provider [{0}] is already registered for type [{1}]" -f $Provider.ProviderNamespace,($Provider.ResourceTypes.ResourceTypeName)) -ForegroundColor Green
            }
        }
    }Else{
        Write-Host ("Azure resource provider [Microsoft.VirtualMachineImages] is not available, unable to continue!") -ForegroundColor Red
        Stop-Transcript;Break
    }
}
#>

# create resource group
#=======================================================
If(-Not(Get-AzResourceGroup -Name $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue))
{
    Write-Host ("Creating Azure resource group [{0}]..." -f $Settings.Resources.imageResourceGroup) -ForegroundColor White -NoNewline
    Try{
        New-AzResourceGroup -Name $Settings.Resources.imageResourceGroup -Location $Settings.Environment.location -ErrorAction Stop | Out-Null
        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("Using Azure resource group [{0}]" -f $Settings.Resources.imageResourceGroup) -ForegroundColor Green
}

# Create AIB user identity
#=======================================================
#https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-permissions-powershell
If(-Not($AssignedID = Get-AzUserAssignedIdentity -Name $Settings.ManagedIdentity.identityName -ResourceGroupName $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue ))
{
    Write-Host ("Creating Azure identity for AIB [{0}]..." -f $Settings.ManagedIdentity.identityName) -ForegroundColor White -NoNewline
    Try{
        $IdentityParams = @{
            Name = $Settings.ManagedIdentity.identityName
            ResourceGroupName = $Settings.Resources.imageResourceGroup
            Location = $Settings.Environment.location
        }
        $AssignedID = New-AzUserAssignedIdentity @IdentityParams -ErrorAction Stop
        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("Using Azure Managed identity [{0}]" -f $AssignedID.Name) -ForegroundColor Green
}

#grab resource Id and Principal ID
#=======================================================
$IdentityNameResourceId = $AssignedID.Id
$identityNamePrincipalId = $AssignedID.PrincipalId
$IdentityGuid = ($AssignedID.Name).replace(($identityPrefix + '-'),'')
#Reference: https://docs.microsoft.com/en-us/powershell/module/az.resources/New-azRoleDefinition?view=azps-8.0.0
# Create a unique role name to avoid clashes in the same Azure Active Directory domain
$imageRoleDefName="Azure Image Builder Image Def (" + $IdentityGuid + ")"

# Assign permissions for identity to distribute images
#======================================================
$roleDefinitionUri = "https://$($Settings.Resources.resourceBlobURI)/templates/$($Settings.ManagedIdentity.roleDefinitionTemplate)"
$roleDefinitionPath = Join-Path $env:TEMP -ChildPath $Settings.ManagedIdentity.roleDefinitionTemplate
# Use a web request to download the sample JSON description
Invoke-WebRequest -Uri $roleDefinitionUri -Outfile $roleDefinitionPath -UseBasicParsing

# Update the JSON definition placeholders with variable values
((Get-Content -path $roleDefinitionPath -Raw) -replace '<subscriptionID>',$subscriptionID) | Set-Content -Path $roleDefinitionPath
((Get-Content -path $roleDefinitionPath -Raw) -replace '<rgName>', $Settings.Resources.imageResourceGroup) | Set-Content -Path $roleDefinitionPath
((Get-Content -path $roleDefinitionPath -Raw) -replace 'Azure Image Builder Service Image Creation Role', $imageRoleDefName) | Set-Content -Path $roleDefinitionPath

# Create a custom role from the aibRoleImageCreation.json description file.
#======================================================
If(-Not($RoleDef = Get-AzRoleDefinition -Name $imageRoleDefName -ErrorAction SilentlyContinue))
{
    Write-Host ("Creating Azure role definition [{0}]..." -f $imageRoleDefName) -ForegroundColor White -NoNewline
    Try{
        # create role definition
        #$RoleDef = New-AzRoleDefinition -Role $role -ErrorAction Stop
        $RoleDef = New-AzRoleDefinition -InputFile $roleDefinitionPath
        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("Using Azure role definition [{0}]" -f $imageRoleDefName) -ForegroundColor Green
}

# Get the user-identity properties
#======================================================
$identityNameResourceId=$(Get-AzUserAssignedIdentity -ResourceGroupName $Settings.Resources.imageResourceGroup).Id
$identityNamePrincipalId=$(Get-AzUserAssignedIdentity -ResourceGroupName $Settings.Resources.imageResourceGroup).PrincipalId

# grant role definition to image builder service principal
#=========================================================
If(-Not($RoleAssignment = Get-AzRoleAssignment -ObjectId $IdentityNamePrincipalId -ErrorAction SilentlyContinue))
{
    Write-Host ("Creating Azure role assignment for AIB definition [{0}]..." -f $imageRoleDefName) -ForegroundColor White -NoNewline
    Try{
        # Grant the custom role to the user-assigned managed identity for Azure Image Builder.
        $parameters = @{
            ObjectId = $identityNamePrincipalId
            RoleDefinitionName = $imageRoleDefName
            Scope = '/subscriptions/' + $subscriptionID + '/resourceGroups/' + $Settings.Resources.imageResourceGroup
        }
        $RoleAssignment = New-AzRoleAssignment @parameters

        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("Using Azure role assignment for AIB definition [{0}]" -f $imageRoleDefName) -ForegroundColor Green
}

### NOTE: If you see this error: 'New-AzRoleDefinition: Role definition limit exceeded. No more role definitions can be created.' See this article to resolve:
#https://docs.microsoft.com/en-us/azure/role-based-access-control/troubleshooting

# add managed identity for Azure blob Storage access
#=======================================================
#Connect-AzAccount -Identity -Environment AzureUSGovernment
$StorageContext = New-AzStorageContext -StorageAccountName $Settings.Resources.resourceBlobURI.split('.')[0]
#Get blobs in a container by using the pipeline
#Get-AzStorageContainer -Name 'scripts' -Context $StorageContext | Get-AzStorageBlob -IncludeDeleted

# Grant the storage reader to the user-assigned managed identity for Azure Image Builder.
If(-Not($StorageRoleAssignment = Get-AzRoleAssignment -ObjectId $IdentityNamePrincipalId -ErrorAction SilentlyContinue | Where RoleDefinitionName -eq 'Storage Blob Data Reader'))
{
    Write-Host ("Assigning [Storage Blob Data Reader] for AIB Managed Identity [{0}]..." -f $AssignedID.Name) -ForegroundColor White -NoNewline
    Try{
        # Grant the custom role to the user-assigned managed identity for Azure Image Builder.
        $parameters = @{
            ObjectId = $identityNamePrincipalId
            RoleDefinitionName = "Storage Blob Data Reader"
            Scope = '/subscriptions/' + $subscriptionID + '/resourceGroups/' + $Settings.Resources.imageResourceGroup + '/providers/Microsoft.Storage/storageAccounts/' + $StorageContext.StorageAccountName
        }
        $StorageRoleAssignment = New-AzRoleAssignment @parameters

        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("[Storage reader role] is already assigned to AIB Managed Identity [{0}]" -f $AssignedID.Name) -ForegroundColor Green
}


# Create the Shared Image Gallery
#=======================================================
If(-Not($Gallery = Get-AzGallery -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $Settings.Resources.imageComputeGallery -ErrorAction SilentlyContinue)){
    Try{
        Write-Host ("Creating Azure Gallery [{0}]..." -f $Settings.Resources.imageComputeGallery) -ForegroundColor White -NoNewline
        $parameters = @{
            GalleryName = $Settings.Resources.imageComputeGallery
            ResourceGroupName = $Settings.Resources.imageResourceGroup
            Location = $Settings.Environment.location
        }
        $Null = New-AzGallery @parameters
        Write-Host "Done" -ForegroundColor Green
    }Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("Using Azure Gallery [{0}]" -f $Settings.Resources.imageComputeGallery) -ForegroundColor Green
}


# Generate Image template
#=======================================================
#Get current image versions; increment if needed
Write-Host ("Defining Image version...") -ForegroundColor White -NoNewline
$Year=$Date.ToString('yyyy')
$Month=$Date.ToString('MM')
$Day=$Date.ToString('dd')
$buildOutputName=('sig' + $Date.ToString('Thhmmsstt'))

If($ImageVersions = Get-AzGalleryImageVersion -ResourceGroupName $Settings.Resources.imageResourceGroup -GalleryName $Settings.Resources.imageComputeGallery -GalleryImageDefinitionName $TemplateConfigs.ImageDefinition.Name | Select -Last 1){
    $v = [version]$ImageVersions.Name
    If($v -eq [version]("{0}.{1}.{2}.{3}" -f $Year, $Month, $Day, 1)){
        [string]$NewVersion = [version]::New($v.Major,$v.Minor,$v.Build,$v.Revision + 1)
    }Else{
        [string]$NewVersion = ("{0}.{1}.{2}.{3}" -f $Year, $Month, $Day, 1)
    }
}Else{
    [string]$NewVersion = ("{0}.{1}.{2}.{3}" -f $Year, $Month, $Day, 1)
}
Write-Host ("{0}" -f [string]$NewVersion) -ForegroundColor Green

# Download template and configure
#=======================================================
Try{
    Write-Host ("Generating template...") -NoNewline
    #Reference: https://docs.microsoft.com/en-us/azure/templates/microsoft.virtualmachineimages/imagetemplates?tabs=json&pivots=deployment-language-arm-template
    $templateUri = "https://$($Settings.Resources.resourceBlobURI)/templates/$($TemplateConfigs.Template.templateFile)"
    $templateFilePath = Join-Path "$PSScriptRoot\Logs" -ChildPath ('aibtemplate_' + $Template.ToLower() + '_' + $NewVersion + '.json')
    $commandsFilePath = Join-Path "$PSScriptRoot\Logs" -ChildPath ('poshcommands_' + $Template.ToLower() + '_' + $NewVersion + '.ps1')

    #Download standard template from Blob URL
    Invoke-WebRequest -Uri $templateUri -OutFile $templateFilePath -UseBasicParsing
    #pars file and replace <value> with selected tasksequence values
    $TemplateContent = (Get-Content -path $templateFilePath -Raw)
    $TemplateContent = $TemplateContent -replace '<subscriptionID>',$subscriptionID `
                    -replace '<rgName>',$Settings.Resources.imageResourceGroup `
                    -replace '<region>',$Settings.Environment.location `
                    -replace '<runOutputName>',$buildOutputName `
                    -replace '<imageDefName>',$TemplateConfigs.ImageDefinition.Name `
                    -replace '<sharedImageGalName>',$Settings.Resources.imageComputeGallery `
                    -replace '<region1>',$Settings.Environment.location `
                    -replace '<imgBuilderId>',$IdentityNameResourceId `
                    -replace '<imgVmSize>',$TemplateConfigs.ImageDefinition.VMSize `
                    -replace '<OSSku>',$TemplateConfigs.ImageDefinition.OSSku `
                    -replace '<imageresourceblob>',$Settings.Resources.resourceBlobURI
    #save file
    $TemplateContent | Set-Content -Path $templateFilePath -Force

    #build customization if exists
    If($TemplateConfigs.customSequence.count -gt 0){
        $SequenceTypes = $TemplateConfigs.customSequence | Where sasToken -ne $null
        #TEST $Type = $SequenceTypes[0]
        Foreach($Type in $SequenceTypes){
            Write-Host ("Sas Token found.`nChecking SaS Token for [{0}]..." -f $Type.name) -ForegroundColor White -NoNewline
            $ExpiryDate = [System.Text.RegularExpressions.Regex]::Match($Type.sasToken, '^sp=r&st=(?<Start>.*)&se=(?<Expiry>.*)&spr=(?<Date>.*)').Groups['Expiry'].value
            If((Get-Date) -gt [DateTime]$ExpiryDate){
                Write-Host ("expired on [{0}]..." -f $ExpiryDate) -ForegroundColor Yellow
                    $NewSasToken = Read-host ("What is the new SaS Token for [{0}]" -f $Type.name)
                    $Type.sasToken = $NewSasToken
                    #TODO: need to update aib.json with new Sastoken
                    
            }Else{
                Write-Host ("still valid until [{0}]" -f $ExpiryDate) -ForegroundColor Green
            }
        }
    }

    #grab the edited aib template; convert to object
    # $TemplateData = Get-Content -path .\$templateFilePath -Raw | ConvertFrom-Json
    $TemplateData = Get-Content -path $templateFilePath -Raw | ConvertFrom-Json

    #Update build timeout
    If($TemplateConfigs.buildTimeout){
        $TemplateData.resources.properties.buildTimeoutInMinutes = $TemplateConfigs.buildTimeout
    }
    #Update Disk size
    If($TemplateConfigs.buildDiskSize){
        $TemplateData.resources.properties.vmProfile.osDiskSizeGB = $TemplateConfigs.buildDiskSize
    }

    #update Image version to new version
    $galleryImageId = "$($TemplateData.resources.properties.distribute.galleryImageId)/versions/$NewVersion"
    $TemplateData.resources.properties.distribute | ForEach-Object { $_.galleryImageId = $galleryImageId }

    #convert the selected aib.json's customsequence section into aib format (as psobjects)
    #$customizeData = ConvertFrom-CustomSequence -BlobURL $Settings.Resources.resourceBlobURI -SequenceData $TemplateConfigs.customSequence -Passthru
    $customizeData = ConvertFrom-CustomSequence -BlobURL $Settings.Resources.resourceBlobURI -SequenceData $TemplateConfigs.customSequence -ProvisionVMMode -Passthru
    $SupportCmds = ConvertTo-PoshCommands -BlobURL $Settings.Resources.resourceBlobURI -SequenceData $TemplateConfigs.customSequence
    #add new customizations to templates customize property
    #$TemplateCustomizations = $TemplateData.resources.properties.customize
    $TemplateData.resources.properties.customize += $customizeData

    #convert back to json
    $NewAIBTemplate = $TemplateData | ConvertTo-Json -Depth 6
    #fix the \u0027 issue and save file
    ([regex]'(?i)\\u([0-9a-h]{4})').Replace($NewAIBTemplate, {param($Match) "$([char][int64]"0x$($Match.Groups[1].Value)")"}) | Set-Content -Path $templateFilePath -Force
    #export commands to a support file (for testing)
    $SupportCmds | Set-Content -Path $commandsFilePath -Force

    Write-Host ("Done.") -ForegroundColor Green
    Write-Host ("Copy of template file is located: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $templateFilePath) -ForegroundColor Green
    Write-Host ("Template [run output name] will be: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $buildOutputName) -ForegroundColor Green
}
Catch{
    Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
    Stop-Transcript;Break
}

<#
# Defining Image version
#=======================================================
#https://docs.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-powershell
Try{
    #Define Version
    $distributorObjectParameters = @{
        ManagedImageDistributor = $true
        GalleryImageId         = "$($TemplateData.resources.properties.distribute.galleryImageId)/versions/$NewVersion"
        ReplicationRegion      = $TemplateData.resources.properties.distribute.replicationRegions
        ArtifactTag            = $TemplateData.resources.properties.distribute.artifactTags
        RunOutputName          = $TemplateData.resources.properties.distribute.runOutputName
        ExcludeFromLatest      = $false
    }
    $distributorObject = New-AzImageBuilderDistributorObject @distributorObjectParameters
    Write-Host "Done" -ForegroundColor Green
}
Catch{
    Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
    Stop-Transcript;Break
}

# Defining Image template
#=======================================================
If(-Not(Get-AzImageBuilderTemplate -ImageTemplateName $TemplateConfigs.Template.imageTemplateName -ResourceGroupName $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue)){
    Write-Host ("Defining Image template [{0}]..." -f $TemplateConfigs.Template.imageTemplateName) -ForegroundColor White -NoNewline
    Try{
        $SrcObjParams = @{
            SourceTypePlatformImage = $true
            Publisher = $TemplateData.resources.properties.source.publisher
            Offer = $TemplateData.resources.properties.source.offer
            Sku = $TemplateData.resources.properties.source.sku
            Version = $TemplateData.resources.properties.source.version
        }
        $srcPlatform = New-AzImageBuilderSourceObject @SrcObjParams

        $ImgTemplateParams = @{
            ImageTemplateName = $TemplateConfigs.Template.imageTemplateName
            ResourceGroupName = $Settings.Resources.imageResourceGroup
            Source = $srcPlatform
            Distribute = $distributorObject
            Customize = @(ConvertFrom-CustomSequence -BlobURL $Settings.Resources.resourceBlobURI -SequenceData $TemplateConfigs.customSequence -ProvisionVMMode -Passthru)
            Location = $Settings.Environment.location
            UserAssignedIdentityId = $identityNameResourceId
        }
        New-AzImageBuilderTemplate @ImgTemplateParams
        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        Stop-Transcript;Break
    }
}
#>

# Create gallery definition
#=======================================================
If(-Not($AzImageDef = Get-AzGalleryImageDefinition -ResourceGroupName $Settings.Resources.imageResourceGroup -GalleryName $Settings.Resources.imageComputeGallery | Where {$_.Identifier.Publisher -eq $Settings.Environment.domain -and $_.Identifier.Sku -eq $TemplateConfigs.ImageDefinition.sku })){
    Try{
        Write-Host ("Creating Azure Image definition [{0}]..." -f $TemplateConfigs.ImageDefinition.Name) -ForegroundColor White -NoNewline
        $AzImageDef = New-AzGalleryImageDefinition `
                            -GalleryName $Settings.Resources.imageComputeGallery `
                            -ResourceGroupName $Settings.Resources.imageResourceGroup `
                            -Location $Settings.Environment.location `
                            -Name $TemplateConfigs.ImageDefinition.Name `
                            -OsState generalized `
                            -OsType Windows `
                            -Publisher $Settings.Environment.domain `
                            -Offer $TemplateConfigs.ImageDefinition.Offer `
                            -Sku $TemplateConfigs.ImageDefinition.sku `
                            -HyperVGeneration V2
        Write-Host "Done" -ForegroundColor Green
    }Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        Stop-Transcript;Break
    }
}ElseIf($TemplateConfigs.ImageDefinition.Name -ne $AzImageDef.Name){
    Write-Host ("Definition already exists, using Azure Image definition [{0}] instead" -f $AzImageDef.Name) -ForegroundColor Yellow
    #update definition name
    $TemplateConfigs.ImageDefinition.Name = $AzImageDef.Name
}Else{
    Write-Host ("Using Azure Image definition [{0}]" -f $TemplateConfigs.ImageDefinition.Name) -ForegroundColor Green
}


# Submit the template; upload generated json to AIB service
#==========================================================
If(-Not($AzDeployGroup = Get-AzResourceGroupDeployment -Name $TemplateConfigs.Template.imageTemplateName -ResourceGroupName $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue)){
    Try{
        Write-Host ("Creating Azure Deployment [{0}]..." -f $TemplateConfigs.Template.imageTemplateName) -ForegroundColor White -NoNewline

        $AzDeployGroup = New-AzResourceGroupDeployment `
                                -imageTemplateName $TemplateConfigs.Template.imageTemplateName `
                                -ResourceGroupName $Settings.Resources.imageResourceGroup `
                                -svclocation $Settings.Environment.location `
                                -TemplateFile $templateFilePath `
                                -api-version "2021-10-01"

        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        Get-AzImageBuilderTemplate -ImageTemplateName $TemplateConfigs.Template.imageTemplateName -ResourceGroupName $Settings.Resources.imageResourceGroup | Select-Object ProvisioningState, ProvisioningErrorMessage
        If($CleanOnFailure){
            Remove-AzResourceGroupDeployment -Name $TemplateConfigs.Template.imageTemplateName -ResourceGroupName $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue
        }
        Stop-Transcript;Break
    }
}Else{
    Write-Host ("Using Azure Deployment [{0}]" -f $TemplateConfigs.ImageDefinition.Name) -ForegroundColor Green
}

<# Optional - if you have any errors running the above, run:
$getStatus=$(Get-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $TemplateConfigs.Template.imageTemplateName)
$getStatus.ProvisioningErrorCode
$getStatus.ProvisioningErrorMessage
#>


# Build the image template
#=======================================================
If($BuildImage){
    Try{
        Write-Host ("Creating Azure Image Builder Template [{0}]..." -f $TemplateConfigs.Template.imageTemplateName) -ForegroundColor White -NoNewline

        $AzAIBTemplate = Start-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $TemplateConfigs.Template.imageTemplateName -NoWait
        Write-Host "Done" -ForegroundColor Green
    }Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        If($CleanOnFailure){
            Remove-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -InputObject $AzAIBTemplate -ErrorAction SilentlyContinue
        }
        Stop-Transcript;Break
    }

    #stop logging the loop. Logging will restart afterward.
    Stop-Transcript | Out-Null

    $AzAIBTemplate = Get-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $TemplateConfigs.Template.imageTemplateName
    Write-Host ('Building Azure Image Builder image [{0}]' -f $TemplateConfigs.Template.imageTemplateName) -NoNewline
    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()
    do {
        Start-Sleep 5
        Write-Host '.' -NoNewline -ForegroundColor Gray
        $AzAIBTemplate = Get-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $TemplateConfigs.Template.imageTemplateName
    } until (
        #must return true
        ($AzAIBTemplate.LastRunStatusRunState -eq 'Succeeded' -or $AzAIBTemplate.LastRunStatusRunState -eq 'Failed')
    )
    $stopwatch.Stop()
    #$totalSecs = [math]::Round($stopwatch.Elapsed.TotalSeconds,0)
    $ts = [timespan]::fromseconds($stopwatch.Elapsed.TotalSeconds)
    $totalTime = ($ts.ToString("mm") + 'min, ' + $ts.ToString("ss") + 'sec')

    Write-Host '.' -ForegroundColor Gray
    Start-transcript "$PSScriptRoot\Logs\$LogfileName" -ErrorAction Stop -Append
    # these show the status the build
    $RemoveTemplate = $false
    Switch($AzAIBTemplate.LastRunStatusRunState){
        'Succeeded' {Write-Host ("Done [{0}]" -f $totalTime) -ForegroundColor Green
                    $ImageMsg = "Image created!"
                    #grab the output data
                    $result = Get-AzImageBuilderRunOutput -ImageTemplateName $TemplateConfigs.Template.imageTemplateName -ResourceGroupName $Settings.Resources.imageResourceGroup -RunOutputName $buildOutputName
                    Get-AzImageBuilderRunOutput -InputObject $result | Select *
                    If($CreateVM){
                        $VMName = Read-host "What will be the VM name be?"
                        $Cred = Get-Credential
                        $ArtifactId = (Get-AzImageBuilderRunOutput -ImageTemplateName $TemplateConfigs.Template.imageTemplateName -ResourceGroupName $Settings.Resources.imageResourceGroup).ArtifactId
                        New-AzVM -ResourceGroupName $Settings.Resources.imageResourceGroup -Image $ArtifactId -Name $VMName -Credential $Cred -size Standard_B2s
                    }
                    #no need to keep template if success
                    $RemoveTemplate = $true
                }
        'Failed' {
                $ImageMsg = "Image failed to create!"
                Write-Host ("Failed after [{0}]: {1}" -f $totalTime,$AzAIBTemplate.LastRunStatusMessage) -BackgroundColor Red
                $AzAIBTemplate.LastRunStatusMessage -match 'location:\s+(http[s]?)(:\/\/)([^\s,]+)' | Out-Null
                $CustomizationLogUri = 'https://' + ($Matches[3] -replace '\.$','')
                $ErrorStorageAccount = $Matches[3].split('/')[0]
                $Container = $Matches[3].split('/')[1]
                $BlobFolder = $Matches[3].split('/')[2]
                $BlobFile = $Matches[3].split('/')[3] -replace('\.$','')
                Try{
                    Write-Host ("Attempting to export customization.log [{0}]..." -f  $CustomizationLogUri) -NoNewline
                    #$PSScriptRoot\Tools\azcopy.exe copy "$CustomizationLogUri?$($SasToken)" "$PSScriptRoot\Logs\$($LogfileName.replace('buildaibtemplate','customization'))"
                    Invoke-WebRequest $CustomizationLogUri -OutFile "$PSScriptRoot\Logs\$($LogfileName.replace('buildaibtemplate','customization'))"
                    Write-Host "Done" -ForegroundColor Green
                    #Write-Host ('View [telemetry] logs for errors: {0}' -f ("$PSScriptRoot\Logs\$($LogfileName.replace('buildaibtemplate','customization'))")) -ForegroundColor Yellow
                    $RemoveTemplate = $true
                }
                Catch{
                    Stop-Transcript;Break
                    Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
                    Write-Host ('To view AIB packer log:')
                    Write-Host ('   Navigate to storage account: ') -NoNewline
                    Write-Host ('{0}' -f $ErrorStorageAccount) -ForegroundColor Yellow
                    Write-Host ('   Open container named: ') -NoNewline
                    Write-Host ('{0}' -f $Container) -ForegroundColor Yellow
                    Write-Host ('   Open blob folder named: ') -NoNewline
                    Write-Host ('{0}' -f $BlobFolder) -ForegroundColor Yellow
                    Write-Host ('   Download blob file named: ') -NoNewline
                    Write-Host ('{0}' -f $BlobFile) -ForegroundColor Yellow
                    Write-Host ('   Search for (Telemetry) ') -ForegroundColor Yellow
                }

        }
    }
}


# Remove the template (this removes the storage account as well!)
#=======================================================
If($RemoveTemplate){

    If($AzAIBTemplate = Get-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $TemplateConfigs.Template.imageTemplateName -ErrorAction SilentlyContinue){
        Try{
            Write-Host ("{1} Removing Azure Image template [{0}]..." -f $TemplateConfigs.ImageDefinition.Name,$ImageMsg) -ForegroundColor Yellow -NoNewline
            Remove-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -ImageTemplateName $TemplateConfigs.Template.imageTemplateName | Out-Null
            Write-Host "Done" -ForegroundColor Green
        }
        Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
            Stop-Transcript;Break
        }
    }
}

If($DeleteLogs -and ($AzAIBTemplate.LastRunStatusRunState -eq 'Succeeded')){
    # Find Storage Accounts for Packer logs
    #https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#customization-log
    #=======================================================
    If($packerLogs = Get-AzResourceGroup -Name "IT_avdimagebuilder-rg_$($TemplateConfigs.Template.imageTemplateName)*" -ErrorAction SilentlyContinue)
    {
        Write-Host ("Azure Image builder completed successfully! Logs were stored") -ForegroundColor Green -NoNewline
        Write-Host ("  Deleting unused resource group that a storage account logs [{0}]..." -f $packerLogs.ResourceGroupName) -ForegroundColor Yellow -NoNewline
        Try{
            $packerLogs | Remove-AzResourceGroup -Force | Out-Null
            Write-Host "Done" -ForegroundColor Green
        }
        Catch{
            Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
            Stop-Transcript;Break
        }
    }
}

Stop-Transcript
