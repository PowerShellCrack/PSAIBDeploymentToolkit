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
#Requires -Modules Az.Accounts,Az.ImageBuilder,Az.ManagedServiceIdentity,Az.Resources,Az.Storage,Az.Compute,Az.Monitor
# Add AZ PS modules to support AzUserAssignedIdentity and Az AIB
Import-Module 'Az.Accounts','Az.ImageBuilder','Az.ManagedServiceIdentity','Az.Resources','Az.Storage','Az.Compute','Az.Monitor'

$ErrorActionPreference = "Stop"

If($DeleteLogs){
    Remove-Item "$PSScriptRoot\Logs\*" -recurse -ErrorAction SilentlyContinue | Out-Null
}
New-Item "$PSScriptRoot\Logs" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
$Date = Get-Date

$DateLogFormat = $Date.ToString('yyyy-MM-dd_Thh-mm-ss-tt')
$LogfileName = ('buildaibtemplate_' + $Template.ToLower() + '_' + $DateLogFormat + '.log')
Start-transcript "$PSScriptRoot\Logs\$LogfileName" -ErrorAction Stop

#get the settings
$Settings = Get-Content "$PSScriptRoot\Control\$ControlSetting" -Raw | ConvertFrom-Json

#get the template settings
$TemplateConfigs = Get-Content "$PSScriptRoot\Control\$Template\aib.json" -Raw | ConvertFrom-Json

#Build Parameters splats
$AIBMessageParam =@{
    TemplateName=$TemplateConfigs.Template.imageTemplateName
    ResourceGroup=$Settings.Resources.imageResourceGroup
    Cleanup=$CleanOnFailure
}

$AIBTemplateParams = @{
    ImageTemplateName=$TemplateConfigs.Template.imageTemplateName
    ResourceGroupName=$Settings.Resources.imageResourceGroup
}

$AIBDeploymentParams = @{
    Name=$TemplateConfigs.Template.imageTemplateName
    ResourceGroupName=$Settings.Resources.imageResourceGroup
}

#region Sequencer custom functions
. "$PSScriptRoot\Scripts\Sequencer.ps1"
. "$PSScriptRoot\Scripts\LogAnalytics.ps1"
#=======================================================
# CONNECT TO AZURE
#=======================================================
Connect-AzAccount -Environment $Settings.Environment.azureEnvironment
Set-AzContext -Subscription $Settings.Environment.subscriptionName

# Step 2: get existing context
$currentAzContext = Get-AzContext
# your subscription, this will get your current subscription
$subscriptionID=$currentAzContext.Subscription.Id

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
        #Write-Host ("Azure resource provider [Microsoft.VirtualMachineImages] is not available, unable to continue!") -ForegroundColor Red
        #Stop-Transcript;Break
        Send-AIBMessage -Message ("Azure resource provider [Microsoft.VirtualMachineImages] is not available, unable to continue!") -Severity 3 -BreakonError
    }
}
#>

# create resource group
#=======================================================
If(-Not(Get-AzResourceGroup -Name $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue))
{
    Write-Host ("Creating Azure Resource Group [{0}]..." -f $Settings.Resources.imageResourceGroup) -ForegroundColor White -NoNewline
    Try{
        New-AzResourceGroup -Name $Settings.Resources.imageResourceGroup -Location $Settings.Environment.location -ErrorAction Stop | Out-Null
        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        #Stop-Transcript;Break
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
    }
}Else{
    Write-Host ("Using Azure Resource Group [{0}]" -f $Settings.Resources.imageResourceGroup) -ForegroundColor Green
}

# Create the Shared Image Gallery
#=======================================================
If(-Not($Gallery = Get-AzGallery -ResourceGroupName $Settings.Resources.imageResourceGroup -Name $Settings.Resources.imageComputeGallery -ErrorAction SilentlyContinue)){
    Try{
        Write-Host ("Creating Azure Shared Image Gallery [{0}]..." -f $Settings.Resources.imageComputeGallery) -ForegroundColor White -NoNewline
        $parameters = @{
            GalleryName = $Settings.Resources.imageComputeGallery
            ResourceGroupName = $Settings.Resources.imageResourceGroup
            Location = $Settings.Environment.location
        }
        $Null = New-AzGallery @parameters
        Write-Host "Done" -ForegroundColor Green
    }Catch{
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        #Stop-Transcript;Break
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
    }
}Else{
    Write-Host ("Using Azure Shared Image Gallery [{0}]" -f $Settings.Resources.imageComputeGallery) -ForegroundColor Green
}


# Create AIB user identity
#=======================================================
#https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-permissions-powershell
If(-Not($AssignedID = Get-AzUserAssignedIdentity -Name $Settings.ManagedIdentity.identityName -ResourceGroupName $Settings.Resources.imageResourceGroup -ErrorAction SilentlyContinue ))
{
    Write-Host ("Creating Azure Managed Identity for AIB [{0}]..." -f $Settings.ManagedIdentity.identityName) -ForegroundColor White -NoNewline
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
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        #Stop-Transcript;Break
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
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
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        #Stop-Transcript;Break
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
    Write-Host ("Creating Azure role assignment for definition [{0}]..." -f $imageRoleDefName) -ForegroundColor White -NoNewline
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
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -ForegroundColor Black -BackgroundColor Red
        #Stop-Transcript;Break
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
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

# Grant the storage reader to the user-assigned managed identity for the storage .
If(-Not($StorageRoleAssignment = Get-AzRoleAssignment -ObjectId $IdentityNamePrincipalId -ErrorAction SilentlyContinue | Where RoleDefinitionName -eq 'Storage Blob Data Reader'))
{
    Write-Host ("Assigning [Storage Blob Data Reader] for AIB Managed Identity [{0}] to storage account [{1}]..." -f $AssignedID.Name,$StorageContext.StorageAccountName) -ForegroundColor White -NoNewline
    Try{
        # Grant the custom role to the user-assigned managed identity for Azure Image Builder.
        $parameters = @{
            ObjectId = $identityNamePrincipalId
            RoleDefinitionName = "Storage Blob Data Reader"
            Scope = '/subscriptions/' + $subscriptionID + '/resourceGroups/' + $Settings.Resources.imageResourceGroup + '/providers/Microsoft.Storage/storageAccounts/' + $StorageContext.StorageAccountName
            #Scope = '/subscriptions/' + $subscriptionID + '/resourceGroups/' + $Settings.Resources.imageResourceGroup + '/providers/Microsoft.Storage/storageAccounts/' + $StorageContext.StorageAccountName + '/blobServices/default/containers/' + <Storage account container>
        }
        $StorageRoleAssignment = New-AzRoleAssignment @parameters

        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
    }
}Else{
    Write-Host ("[Storage reader role] is already assigned to AIB Managed Identity [{0}]" -f $AssignedID.Name) -ForegroundColor Green
}

#sometimes if new role is created, the old role needs to be removed.
If($UnknownRole = Get-AzRoleAssignment | Where-Object {$_.ObjectType.Equals("Unknown")})
{
    Write-Host ("Removing Unknown User Identity to assignments [{0}]..." -f $UnknownRole.RoleDefinitionName) -ForegroundColor White -NoNewline
    Try{
        $UnknownRole = Get-AzRoleAssignment | Where-Object {$_.ObjectType.Equals("Unknown")}
        Remove-AzRoleAssignment -ObjectId $UnknownRole.ObjectId -RoleDefinitionName $UnknownRole.RoleDefinitionName -Scope $UnknownRole.Scope | Out-Null

        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 2
    }
}

# Generate Image template
#=======================================================
#Get current image versions; increment if needed
Write-Host ("Defining Arm Template version...") -ForegroundColor White -NoNewline
$Year=$Date.ToString('yyyy')
$Month=$Date.ToString('MM')
#$Day=$Date.ToString('dd')
$buildOutputName=('sig' + $Date.ToString('Thhmmsstt'))

If($ImageVersions = Get-AzGalleryImageVersion -ResourceGroupName $Settings.Resources.imageResourceGroup -GalleryName $Settings.Resources.imageComputeGallery -GalleryImageDefinitionName $TemplateConfigs.ImageDefinition.Name | Select -Last 1){
    $v = [version]$ImageVersions.Name
    If($v -eq [version]("{0}.{1}.{2}" -f $Year, $Month, 1)){
        [string]$NewVersion = [version]::New($v.Major,$v.Minor,$v.Build + 1)
    }Else{
        [string]$NewVersion = ("{0}.{1}.{2}" -f $Year, $Month, 1)
    }
}Else{
    [string]$NewVersion = ("{0}.{1}.{2}" -f $Year, $Month, 1)
}
Write-Host ("{0}" -f [string]$NewVersion) -ForegroundColor Green

# Download template and configure
#=======================================================
Try{
    Write-Host ("Generating Arm Template...") -NoNewline
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
            Write-Host ("Sas Token found.`nChecking SaS Token for [{0}]..." -f $Type.name) -ForegroundColor Yellow -NoNewline
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

    $TemplateCustomizedSteps = $TemplateData.resources.properties.customize.name

    #convert back to json
    $NewAIBTemplate = $TemplateData | ConvertTo-Json -Depth 6
    #fix the \u0027 issue and save file
    $FormattedAIBTemplate = ([regex]'(?i)\\u([0-9a-h]{4})').Replace($NewAIBTemplate, {param($Match) "$([char][int64]"0x$($Match.Groups[1].Value)")"})
    $FormattedAIBTemplate | Set-Content -Path $templateFilePath -Force
    #export commands to a support file (for testing)
    $SupportCmds | Set-Content -Path $commandsFilePath -Force

    Write-Host ("Done.") -ForegroundColor Green
    Write-Host ("Copy of Arm Template file is located: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $templateFilePath) -ForegroundColor Green
    Write-Host ("Template deployment [runOutputName] will be: ") -ForegroundColor White -NoNewline
    Write-Host ("{0}" -f $buildOutputName) -ForegroundColor Green
}
Catch{
    #Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
    #Stop-Transcript;Break
    Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
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
If(-Not(Get-AzImageBuilderTemplate @AIBTemplateParams -ErrorAction SilentlyContinue)){
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
        Write-Host ("Creating Azure VM Image Definition [{0}]..." -f $TemplateConfigs.ImageDefinition.Name) -ForegroundColor White -NoNewline
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
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        #Stop-Transcript;Break
        Send-AIBMessage -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
    }
}ElseIf($TemplateConfigs.ImageDefinition.Name -ne $AzImageDef.Name){
    Write-Host ("Definition already exists, using Azure VM Image Definition [{0}]" -f $AzImageDef.Name) -ForegroundColor Yellow
    #update definition name
    $TemplateConfigs.ImageDefinition.Name = $AzImageDef.Name
}Else{
    Write-Host ("Using Azure VM Image Definition [{0}]" -f $TemplateConfigs.ImageDefinition.Name) -ForegroundColor Green
}


# Submit the template; upload generated json to AIB service
#==========================================================
If(-Not($AzDeployGroup = Get-AzResourceGroupDeployment @AIBDeploymentParams -ErrorAction SilentlyContinue)){
    Try{
        Write-Host ("Creating a deployment for Image Template [{0}]..." -f $TemplateConfigs.Template.imageTemplateName) -ForegroundColor White -NoNewline

        $AzDeployGroup = New-AzResourceGroupDeployment @AIBTemplateParams `
                                -svclocation $Settings.Environment.location `
                                -TemplateFile $templateFilePath `
                                -api-version "2021-10-01"

        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        Get-AzImageBuilderTemplate @AIBTemplateParams | Select-Object ProvisioningState, ProvisioningErrorMessage
        If($CleanOnFailure){
            Remove-AzResourceGroupDeployment @AIBDeploymentParams -ErrorAction SilentlyContinue
        }
        #Stop-Transcript;Break
        Send-AIBMessage @AIBMessageParam -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
    }
}Else{
    Write-Host ("Using Azure Deployment [{0}]" -f $TemplateConfigs.ImageDefinition.Name) -ForegroundColor Green
}

<# Optional - if you have any errors running the above, run:
$getStatus=$(Get-AzImageBuilderTemplate @AIBTemplateParams)
$getStatus.ProvisioningErrorCode
$getStatus.ProvisioningErrorMessage
#>


# Build the image template
#=======================================================
If($BuildImage){
    Try{
        Write-Host ("Starting Azure Image Template [{0}]..." -f $TemplateConfigs.Template.imageTemplateName) -ForegroundColor White -NoNewline

        $AzAIBTemplate = Start-AzImageBuilderTemplate @AIBDeploymentParams -NoWait
        Write-Host "Done" -ForegroundColor Green
    }Catch{
        If($CleanOnFailure){
            Remove-AzImageBuilderTemplate -ResourceGroupName $Settings.Resources.imageResourceGroup -InputObject $AzAIBTemplate -ErrorAction SilentlyContinue
        }
        Send-AIBMessage @AIBMessageParam -Message ("Failed: {0}" -f $_.Exception.message) -Severity 3 -BreakonError
        #Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
        #Stop-Transcript;Break
    }

    #stop logging the loop. Logging will restart afterward.
    Stop-Transcript | Out-Null
    $StartTime = Get-date
    $AzAIBTemplate = Get-AzImageBuilderTemplate @AIBTemplateParams
    Write-Host ('Monitoring Azure Image Template deployment [{0}]' -f $buildOutputName) -NoNewline
    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()
    do {
        Start-Sleep 5
        Write-Host '.' -NoNewline -ForegroundColor Gray
        $AzAIBTemplate = Get-AzImageBuilderTemplate @AIBTemplateParams

    } until (
        #must return true
        $AzAIBTemplate.LastRunStatusRunState -ne 'Running'
    )
    $stopwatch.Stop()
    #$totalSecs = [math]::Round($stopwatch.Elapsed.TotalSeconds,0)
    $ts = [timespan]::fromseconds($stopwatch.Elapsed.TotalSeconds)
    $totalTime = ($ts.ToString("mm") + 'min, ' + $ts.ToString("ss") + 'sec')

    $endTime = Get-date
    Write-Host '.' -ForegroundColor Gray
    # these show the status the build
    $PackerLogsExported = $false

    Switch($AzAIBTemplate.LastRunStatusRunState){
        'Succeeded' {
                $ImageMsg = "Image created!"
                Write-Host ("Done [{0}]" -f $totalTime) -ForegroundColor Green
                If($CreateVM){
                    $VMName = Read-host "What will be the VM name be?"
                    $Cred = Get-Credential
                    New-AzVM -ResourceGroupName $Settings.Resources.imageResourceGroup -Image $RunOutputDetails.ArtifactId -Name $VMName -Credential $Cred -size Standard_B2s
                }
        }

        'Failed' {
                $ImageMsg = "Image failed to create!"
                Write-Host ("Failed after [{0}]: {1}" -f $totalTime,$AzAIBTemplate.LastRunStatusMessage) -BackgroundColor Red
        }

        'Canceled' {
            $ImageMsg = "Image was cancelled!"
            Write-Host ("Cancelled after [{0}]: {1}" -f $totalTime,$AzAIBTemplate.LastRunStatusMessage) -BackgroundColor Yellow
        }
    }

    #grab the output data
    Write-Host ('Run output [{0}] results are...' -f $buildOutputName)
    $RunOutputDetails = Get-AzImageBuilderTemplateRunOutput @AIBTemplateParams -RunOutputName $buildOutputName
    Get-AzImageBuilderTemplateRunOutput -InputObject $RunOutputDetails | Select *

    # Export Packer logs
    #https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-troubleshoot#customization-log
    If($ErrorRG = Get-AzResourceGroup -Name "IT_avdimagebuilder-rg_$($TemplateConfigs.Template.imageTemplateName)*" -ErrorAction SilentlyContinue)
    {
        Try{
            Write-Host ("Attempting to export log from [{0}]..." -f $ErrorRG.ResourceGroupName) -NoNewline
            #Get resource group
            $PackerResourceGroup = Get-AzResourceGroup -Name $ErrorRG.ResourceGroupName
            #Get the storage account tied to resrouce group
            $PackerStorage = Get-AzStorageAccount -ResourceGroupName $PackerResourceGroup.ResourceGroupName
            #Get primary Storage key
            $StorageAccountKey = (Get-AzStorageAccountKey -StorageAccountName $PackerStorage.StorageAccountName -ResourceGroup $PackerResourceGroup.ResourceGroupName).Value[0]
            #Build storage context
            $StorageContext = New-AzStorageContext -StorageAccountName $PackerStorage.StorageAccountName -StorageAccountKey $StorageAccountKey
            #get storage container
            $PackerLogs = Get-AzStorageContainer -Context $StorageContext -name 'packerlogs'
            #get storage blob in container
            $Blob = Get-AzStorageBlob -Container $packerLogs.name -Context $StorageContext
            #download customization.log
            Get-AzStorageBlobContent -Blob $Blob.Name -Container $packerLogs.name -Destination "$PSScriptRoot\Logs" -Context $StorageContext -Force | Out-Null

            #download the blob as text into memory
            #$BlobBlock = $PackerLogs.CloudBlobContainer.GetBlockBlobReference($Blob.Name)
            #$BlobContent = $BlobBlock.DownloadText()

            Write-Host "Done" -ForegroundColor Green
            #move and rename the file
            $NewPackerLogPath = ($PSScriptRoot + '\Logs\customization_' + $Template.ToLower() + '_' + $NewVersion + '_' + $DateLogFormat + '.log')
            Move-Item -Path "$PSScriptRoot\Logs\$($Blob.Name.replace('/','\'))" -Destination $NewPackerLogPath -Force | Out-Null
            $BlobFolder = Split-Path $Blob.Name -Parent
            Remove-Item -Path "$PSScriptRoot\Logs\$BlobFolder" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            If(Test-path $NewPackerLogPath){
                Write-Host ("Packager log is now here: ") -NoNewline
                Write-Host ("[{0}]" -f  $NewPackerLogPath) -ForegroundColor Green
            }
            $PackerLogsExported = Send-AIBMessage @AIBMessageParam -Passthru
        }
        Catch{
            Write-Host ("Failed to export log: {0}" -f $_.Exception.message) -BackgroundColor Red
            If($PackerLogsExported -eq $false){
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

    Try{
        Write-Host ("Sending data to log Analytics workspace [{0}]..." -f $Settings.LogAnalytics.Name) -ForegroundColor White -NoNewline
        #send info to log analytics
        $DataParams = @{
            WorkspaceId = $Settings.LogAnalytics.workspaceId
            WorkspaceKey = $Settings.LogAnalytics.WorkspaceKey
            DeploymentName = $TemplateConfigs.Template.imageTemplateName
            TemplateName = $TemplateConfigs.Template.imageTemplateName
            JsonTemplate = $FormattedAIBTemplate
            CustomizationCount = $TemplateData.resources.properties.customize.count
            #CustomizationList = $TemplateCustomizedSteps
            ImageName = $TemplateConfigs.ImageDefinition.Name
            RunOutputName = $buildOutputName
            ImageVersion = $NewVersion
            StartDateTime = $StartTime
            EndDateTime = $endTime
            TotalTime = $totalTime
            Status = $AzAIBTemplate.LastRunStatusRunState
            Message = $AzAIBTemplate.LastRunStatusMessage
            Cloud = $Settings.Environment.azureEnvironment
        }
        #$DataParams
        Write-AIBStatus @DataParams
        Write-Host "Done" -ForegroundColor Green
    }
    Catch{
        Write-Host ("Failed: {0}" -f $_.Exception.message) -BackgroundColor Red
    }
}
