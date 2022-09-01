# A project to manage multiple images for AIB

The original idea was to take a standard On-premise MDT _build and capture_ deploymentshare to move it into a supported AIB deployment. The structure is similar to MDT's and each defined "sequenced" process is within the _Control_ folder. Each sequence contains an **aib.json** file. This file is not a schema that follows the Azure IMage builder schema; this file is used in conjunction of the _Scripts_\Sequence.ps1 and a standard template file, within the _Template_ folder, will generate a supported ARM template file for AIB. The next process is to create an automated process that will copy applications, templates and configurations into a blob container for AIB to consume.

# THIS IS A WORK IN PROGRESS


These are the images i have planned or have tested with this toolkit and the results

Image|Included|Tested|Results|Comments
--|--|--|--|--
Win10avdMarketImage | 21h2 | Yes | **Success** | Gen2 Marketplace VM no updates. Just to see if AIB worked
Win10avdLatestUpdates | 21h2, Updates | Yes | **Success** | Gen2 Marketplace VM with updates set to run.
Win10avdO365Image | 21h2, Office 365, Updates | Yes | **Success** | Gen2 Marketplace VM with M365 apps and updates set to run.
Win10avdSimpleImage| 21h2, Branding, Updates |Yes|**Success** | Gen2 Marketplace VM with branding script (wallpaper and lockscreen) and updates set to run.
Win10avdBaselineImage | 21h2, Office 365, Teams, Fslogix, Onedrive, Updates, Optimizations, VM Preparation | Yes | Failed| Gen2 Marketplace VM; added scripts to install Microsoft 365 apps to latest version in Multisession mode with policy configured
Win10avdHardenedImage | 21h2, Office 365, Teams, Fslogix, Onedrive, Updates, Optimizations, VM Preparation, STIGS | No | | Gen2 Marketplace VM; added scripts to install Microsoft 365 apps to latest version in Multisession mode with STIG policy configured


## TODOs

- Looking into developing a User Interface to allow easier configurations.
- Looking at building language pack support using the  _Packages_ folder (https://docs.microsoft.com/en-us/azure/virtual-desktop/language-packs)
- Build a script to convert MDT environment to AIB environment. Basically to copy the Applications,templates,and scripts to a blob storage. Structure should look be in a format like:

  eg. **\<type\>-\<productname\>-\<version | latest\>**

    - Storage Account
        - Blob Storage Containers
            - scripts
            - templates
            - application-customizations
            - application-fslogix-latest
            - application-lgpo-latest
            - application-office365-latest
            - application-onedrive-latest
            - application-teams-latest

- Version control. I don't fully understand AIB's VM image versions.


## Prereqs

- Azure Image Builder registered
- Azure Managed Identity
- Blob Container with Anonymous & public access


## recommended

If you are contributing or using the code. Please create a copy of the _Settings.json_ file in control folder and name it something like _Settings-\<user\>\.json_. (keep the **Settings-** in the filename); this file will be ignored during pull request.
> You don't want your secrets to be public.

## Scripts

- **BuildAIBTemplate.ps1** <-- Main script to build aib template
- **InvokeScriptsOnAzureVM.ps1** <-- designed to run post configs using Powershell extension NOT WORKING / TESTING
- **PrepareAIBMDTEnv.ps1** <-- Starting to work AIB configurator. NOT WORKING / TESTING

## Examples

```powershell
.\BuildAIBTemplate.ps1 -Template Win10avdSimpleImage -ControlSetting Settings.json -BuildImage
```
## **aib.json** auto formatting

There is an _aib.json_ (...kind of like the TS.xml in MDT. :grin:) file in each sequence is a custom format designed decide what template to use and to simplify the complex deployment of scripts & applications for AIB.

1. _Example:_ To deploy a branding customization that has both theme, wallpaper, and lockscreen requires several customize steps will need to be set:
    - 3x copy steps
    - inline script step
    - inline clean up script (optional)

It would look something like this in an actual ARM template for AIB:

```json
"customize":  [
      {
          "type":  "file",
          "name":  "Copying aero.theme",
          "sourceUri":  "https://devicecustomizations.blob.core.windows.net/application-customizations/aero.theme",
          "destination":  "C:\\windows\\temp\\aero.theme"
      },
      {
          "type":  "file",
          "name":  "Copying Lockscreen.jpg",
          "sourceUri":  "https://devicecustomizations.blob.core.windows.net/application-customizations/Lockscreen.jpg",
          "destination":  "C:\\windows\\temp\\Lockscreen.jpg"
      },
      {
          "type":  "file",
          "name":  "Copying Wallpaper.jpg",
          "sourceUri":  "https://devicecustomizations.blob.core.windows.net/application-customizations/Wallpaper.jpg",
          "destination":  "C:\\windows\\temp\\Wallpaper.jpg"
      },
      {
          "type":  "file",
          "name":  "Copying DefaultAppAssociations.xml",
          "sourceUri":  "https://devicecustomizations.blob.core.windows.net/application-customizations/DefaultAppAssociations.xml",
          "destination":  "C:\\windows\\temp\\DefaultAppAssociations.xml"
      },
      {
          "type":  "PowerShell",
          "name":  "customizesystem",
          "runElevated":  true,
          "runAsSystem":  true,
          "scriptUri":  "https://devicecustomizations.blob.core.windows.net/application-customizations/BrandWindows10.ps1"
      },
      {
          "type":  "WindowsRestart",
          "restartCheckCommand":  "write-host 'restarting after Customize System'",
          "restartTimeout":  "5m"
      }
  ],
```

Where the **aib.json** file just needs a single application with file dependencies and the sequencer.ps1 will generate the code above during deployment

```json
"customSequence":  [
        {
            "type": "Application",
            "name": "Customize System",
            "workingDirectory": "Customizations",
            "executable": "BrandWindows10.ps1",
            "fileDependency": [
                "aero.theme",
                "Lockscreen.jpg",
                "Wallpaper.jpg",
                "DefaultAppAssociations.xml"
            ],
            "restart": "true"
        }
    ],
```


2. _Example:_ to install an application from blob source, say it requires a reboot step and dealing with file dependency like the _example 1_. In the **aib.json** you can specify items like:
  - arguments
  - restart


In the customsequence it would look like:
```json
 {
            "type": "Application",
            "name": "Install Office365 for MultiSession",
            "workingDirectory": "Office365",
            "executable": "setup.exe",
            "arguments": "/configure <destination>\\Customization.xml",
            "fileDependency": [
                "Customization.xml"
            ],
            "restart": "True"
        },
```
When ran with sequencer.ps1, it will produce the needed customizations for azure image builder

```json
 {
    "type":  "PowerShell",
    "name":  "Creating folder 'C:\\Windows\\AIB\\Office365'",
    "runElevated":  true,
    "runAsSystem":  true,
    "inline":  [
                  "New-Item 'C:\\Windows\\AIB\\Office365' -ItemType Directory -ErrorAction SilentlyContinue"
              ]
},
{
    "type":  "file",
    "name":  "Copying Customization.xml",
    "sourceUri":  "https://devicecustomizations.blob.core.windows.net/application-office365/Customization.xml",
    "destination":  "C:\\Windows\\AIB\\Office365\\Customization.xml"
},
{
    "type":  "file",
    "name":  "Copying Office365",
    "sourceUri":  "https://devicecustomizations.blob.core.windows.net/application-office365/setup.exe",
    "destination":  "C:\\Windows\\AIB\\Office365\\setup.exe"
},
{
    "type":  "PowerShell",
    "name":  "Installing Office365",
    "runElevated":  true,
    "runAsSystem":  true,
    "inline":  [
                  "$result = Start-Process -FilePath C:\\Windows\\AIB\\Office365\\setup.exe -ArgumentList '/configure C:\\Windows\\AIB\\Office365\\Customization.xml' -Wait -PassThru",
                  "Return $result.ExitCode"
              ]
},
{
    "type":  "WindowsRestart",
    "restartCheckCommand":  "write-host 'restarting after Install Office365 for MultiSession'",
    "restartTimeout":  "5m"
},

```
## Reference

- https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=azure-powershell
- https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image
- https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-golden-image

# DISCLAIMER
> Even though I have tested this to the extend that I could, I want to ensure your aware of Microsoft’s position on developing scripts.

This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.

This posting is provided "AS IS" with no warranties, and confers no rights. Use of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.
