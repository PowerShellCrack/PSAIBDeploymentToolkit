# A project to manage multiple images for AIB

The original idea was to replicate a standard on-premise MDT _build and capture_ Task sequence and it's deploymentshare into a supported AIB deployment template. The structure is similar to MDT's and each defined "sequenced" process is within the _Control_ folder. Each "sequence" contains an **aib.json** file.
This file is not a schema that follows the Azure Image builder schema, however with this file in conjunction with a basic template file (within the _Template_ folder), the _Scripts_\Sequence.ps1 will generate a supported ARM template file for AIB.
The next process is to create an automated process that will copy applications, templates and configurations into a blob containers for AIB to consume.

# THIS IS A WORK IN PROGRESS

## Image Tests
These are the images that have been planned or have been tested with this toolkit and the results

Image|Description|Included|Tested|Results|Comments
--|--|--|--|--|--
Win10avdMarketImage |Gen2 Marketplace VM no updates. Just to see if AIB worked | 21h2  | Yes | **Success** | 30minutes
Win10avdLatestUpdates | Gen2 Marketplace VM with updates set to run. | 21h2, Updates | Yes | **Success**|
Win10avdO365Image | Gen2 Marketplace VM with M365 apps and updates set to run. | 21h2, Office 365, Updates | Yes | **Success**
Win10avdTestImage | Gen2 Marketplace VM with two apps (Foxit and Notepad++)| 21h2, Foxit, Notepad++ |Yes|**Success**| 32min build time
Win10avdTest2Image | Gen2 Marketplace VM with branding and multiple apps and updates set to run.| 21h2, Branding, Foxit, Notepad++, Adobe Reader, LAPS, Microsoft News Appx, Updates |Yes|**Success but failed**| 11min build time. Image completed with no errors, but the distribution timed out.
Win10avdSimpleImage | Gen2 Marketplace VM with branding script (wallpaper and lockscreen) and updates set to run.| 21h2, Branding, Updates |Yes|**Success**| Needs work on branding script
Win10avdBaseImage| Gen2 Marketplace VM; added scripts to install Microsoft 365 apps to latest version in Multisession mode with policy configured | 21h2, Office 365, Teams, Fslogix, Onedrive, Updates, Optimizations, VM Preparation | Yes | Failed: Operation timed out | Some issues with application scripts and installer for modules; added PSGallery trust and Nuget update for anything PowerShell calls. Manually running scripts on AVD reference Image using psexec to simulate SYSTEM works just fine
Win10avdBaselineImage| Gen2 Marketplace VM; added scripts to install Microsoft 365 apps to latest version in Multisession mode with policy configured, and baseline software | 21h2, Office 365, Teams, Fslogix, Onedrive, Adobe Acrobat DC, Laps, Microsoft News app, Updates, Optimizations, VM Preparation |  | |
Win10avdHardenedImage| Gen2 Marketplace VM; added scripts to install Microsoft 365 apps to latest version in Multisession mode with STIG policy configured | 21h2, Office 365, Teams, Fslogix, Onedrive, Updates, Optimizations, VM Preparation, STIGS | No ||Working on STIG scripts


## Apps tested
Name|Version|Image Association|Install Type|Results|Comments
--|--|--|--|--|--
Office365 | Latest | Win10avdBaselineImage | setup.exe | | Downloads the setup and builds the configuration and installed with settings
Teams Machine Wide Installer | Latest| Win10avdBaselineImage | Teams_windows_x64.msi | | Downloads the setup and builds the installed with AVD mode
Onedrive | Latest| Win10avdBaselineImage | OnedriveSetup.msi | | Downloads the setup and install in all users
Fslogix | Latest | Win10avdBaselineImage | FslogixAppsSetup.exe | | Downloads, extracts the setup and install and configures
LAPS |  | Win10avdTestImage | Laps.x64.msi |  | Used inline command with sas token for zip download
Adobe Acrobat Reader DC |  | Win10avdBaselineImage | | | Used inline command with sas token for zip download and extract locally and installs
AzureMonitor |  | Win10avdTestImage | Laps.x64.msi | | Used inline command with sas token for zip download and extract locally and installs
FoxitPDFReader | 1201 | Win10avdTestImage | FoxitPDFReader1201_enu_Setup.msi |  | Used inline command with sas token for zip download
Notepad Plus Plus | 8.4.4| Win10avdTestImage | npp.8.4.4.Installer.x64.exe |  | Used inline command with sas token for zip download

## TODOs

- Develop a MDT-like User Interface to allow easier configurations.
- Build language pack support using the _Packages_ folder (https://docs.microsoft.com/en-us/azure/virtual-desktop/language-packs)
- Build a script to convert MDT environment to AIB environment. Basically convert TS.xml into a aib.json and copy the applications,templates,and scripts to a blob storage. Structure would be in a format like:

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

- Develop a method to document definition version (after each build) using custom table in log analytics.
- Azure Image Version cleanup

## Prereqs

- Azure Image Builder registered in tenant (Azure GCCH specifically)
- Azure Managed Identity
- Blob Container with Anonymous & public access or SAS token

## contributing

If you are contributing or using the code. Please create a copy of the _Settings.json_ file in control folder and name it something like _Settings-\<user\>\.json_. (keep the **Settings-** in the filename); this file will be ignored during pull request.
> You don't want your secrets to be public.

## Scripts

- **BuildAIBTemplate.ps1** <-- Main script to build aib template
- **InvokeScriptsOnAzureVM.ps1** <-- designed to run post configs using Powershell extension. **NOT WORKING / TESTING**
- **PrepareAIBMDTEnv.ps1** <-- Starting to work AIB configurator. **NOT WORKING / TESTING**

## Examples

```powershell
.\BuildAIBTemplate.ps1 -Template Win10avdSimpleImage -ControlSetting Settings.json -BuildImage
```

## Output

There is a _Logs_ folder that will contain a dated transcript of the AIB sequence called and the json arm template is generated there for reference.

## **aib.json** auto formatting

There is an _aib.json_ (...kind of like the TS.xml in MDT. :grin:) file in each control sequence. It is in a custom format designed to simplify the complex deployment of scripts & applications for AIB.

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


2. _Example:_ to install an application from blob source and say it requires a reboot step while dealing with file dependency like the _example 1_. In the **aib.json** you can specify items like:
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
When ran with _sequencer.ps1_, it will produce the needed customizations for azure image builder

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

# CustomSequence properties

The AIB Deployment Toolkit supports multiple `customsequences`. A customSequence is the order of how to install items such as script, apps, modules, updates and even reboots. It simplifies the need to call multiple customize property found [here](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=azure-powershell)

Here are the many `customsequences` types that can be used:

> All types support **restart** Boolean property

## Type: **Applications**
> All applications and scripts are **elevated** and run as **system**.

Supported parameters are:
- **Name** - Name of the process
- **workingDirectory** – Folder at which the application is installed from. The root starts with _c:\temp_
- **executable** – The executable to run. This can be [ps1, exe or msi]
- **arguments** – Optional, Provide the parameters need to run silently. The _\<destination\>_ designated allows for additional path support
- **fileDependency** - Optional, array, triggers the _File copy_ customization.
- **sasToken** – Optional, Provide Sas token from blob container. Do not provide full URI, it is built from this

> When using _sastoken_ in conjunction with _fileDependency_, only one file is supported


### Example one
_Install application using script from blob uri (no file download)_
```json
"customSequence":  [
      {
            "type": "Application",
            "name": "Install LGPO",
            "workingDirectory": "LGPO",
            "executable": "Install-LGPO.ps1",
            "arguments": "",
            "restart": "False"
        }
    ]
```
### Example two
_download all files and install application using script from blob uri, then reboot when complete_
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
                "Wallpaper.jpg"
            ],
            "restart": "true"
        }
    ]
```
### Example three
_Download zipped file using a SaS token and extract, then install application using command and argument_
```json
"customSequence":  [
        {
            "type": "Application",
            "name": "Install Foxit PDF Reader",
            "workingDirectory": "FoxitPDFReader",
            "fileDependency": [
                "FoxitPDFReader.zip"
            ],
            "sasToken": "sp=r&st=2022-09-06T15:11:06Z&se=2022-09-06T23:11:06Z&spr=https&sv=2021-06-08&sr=b&sig=o0Y3SZ9jJBakVyxtIb8rhbEzJFiCcc5K%2FxvRWsTaS8U%3D",
            "executable": "FoxitPDFReader1201_enu_Setup.msi",
            "arguments": "/quiet ADDLOCAL=\"FX_PDFVIEWER\""
        },
    ]
```


## Type: **ModernApp**

Uses the _Inline_ customization in AIB, but specifically designed to install appx bundles offline.

Supported parameters are:
- **Name** - Name of the process
- **workingDirectory** – Folder at which the zip files is extracted to. The root starts with _c:\temp_
- **appxDependency** - Optional, array, triggers the _File copy_ customization
- **appxBundle** – the Appx bundle to install.
- **appxLicense** – the License file to load during install
- **sasToken** – Optional, Provide Sas token from blob container. Do not provide full URI, it is built from this

> When using _sastoken_ in conjunction with _appxDependency_, only one zip file is supported. **Include all appx, bundle, and license files in zip**

### Example 1
_download each appx dependency include license and bundle, and install_
```json
"customSequence":  [
        {
            "type": "ModernApp",
            "name": "Install Microsoft News App",
            "workingDirectory": "NewsAppx",
            "appxDependency": [
                "Microsoft.NET.Native.Framework.2.2_2.2.29512.0_x64__8wekyb3d8bbwe.appxbundle",
                "Microsoft.NET.Native.Runtime.2.2_2.2.28604.0_x64__8wekyb3d8bbwe.appxbundle",
                "Microsoft.UI.Xaml.2.1_2.11906.6001.0_x64__8wekyb3d8bbwe.appxbundle",
                "Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe.appxbundle"
            ],
            "appxBundle": "Microsoft.BingNews_4.9.30001.0_neutral_~_8wekyb3d8bbwe.appxbundle",
            "appxLicense": "Microsoft.BingNews_8wekyb3d8bbwe_1f63b8c3-2d48-9497-0a0a-2cbd462ede76.xml"
        },
    ]
```
### Example 2
_download appx dependency zipped file, extract and install_
```json
"customSequence":  [
        {
            "type": "ModernApp",
            "name": "Install Microsoft News App",
            "workingDirectory": "NewsAppx",
            "sasToken": "sp=r&st=2022-09-03T19:23:53Z&se=2022-09-04T03:23:53Z&spr=https&sv=2021-06-08&sr=b&sig=2FoV6VhJ2lFMK8OOrhFvwpYYICEeHqNUq5UwOZmsjfA%3D",
            "appxDependency": [
                "Microsoft.BingNews.4.9.30001.0.zip"
            ],
            "appxBundle": "Microsoft.BingNews_4.9.30001.0_neutral_~_8wekyb3d8bbwe.appxbundle",
            "appxLicense": "Microsoft.BingNews_8wekyb3d8bbwe_1f63b8c3-2d48-9497-0a0a-2cbd462ede76.xml"
        },
    ]
```

## Type: **Command**

Based on the idea of the _Inline_ customization in AIB, but builds the inline commands automatically to include the ability to arguments and reboot

Supported parameters are:
- **Name** - Name of the process
- **workingDirectory** – Folder at which the zip files is extracted to. The root starts with _c:\temp_
- **command** – The command to run; this will read the commands extension and determine the appropriate inline command (supported file extensions: .vbs, .ps1, .exe, .msi)
- **arguments** – Optional, Provide the parameters need to run silently. The _\<destination\>_ designated allows for additional path support

### Example 1
_run script._ Assume its downloaded already
```json
"customSequence":  [
        {
            "type": "Command",
            "name": "Install Apps",
            "workingDirectory": "Apps",
            "command": "Install.ps1",
            "restart": "false"
        }
    ]
```
### Example 2
_Run dism command and reboot_
```json
"customSequence":  [
        {
            "type": "Command",
            "name": "Cleanup image base",
            "command": "Dism.exe",
            "arguments": "/online /Cleanup-Image /StartComponentCleanup /ResetBase",
            "restart": "true"
        }
    ]
```


## Type: **Module**

Uses the _Inline_ customization in AIB, but specifically targets PowerShell modules.

Supported parameters are:
- **modules** – Array, The list of modules to install
- **TrustedRepos** - Optional, array, a list of repository to trust.

```json
"customSequence":  [
        {
            "type": "Module",
            "modules": [
                "LGPO",
                "YetAnotherCMLogger",
                "MSFTLinkDownloader"
            ],
            "trustedRepos": [
                "PSgallery"
            ]
        },
    ]
```

## Type: **Archive**

This process generates additional _Inline_ customizations to auto download AzCopy and trigger AzCopy copy commands to support the optional SAS Token URI

Supported parameters are:
- **Name** - Name of the process
- **workingDirectory** – Folder at which the zip files is extracted to. The root starts with _c:\temp_
- **archiveFile** – The single archive file to extract (supported extensions: .zip and .cab). This can be [ps1, exe or msi]
- **sasToken** – Optional, Provide Sas token from blob container. Do not provide full URI, it is built from this

```json
"customSequence":  [
        {
            "type": "Archive",
            "name": "Get Apps",
            "workingDirectory": "Apps",
            "archiveFile": "Apps.zip",
            "sasToken": "sp=r&st=2022-09-03T19:23:53Z&se=2022-09-04T03:23:53Z&spr=https&sv=2021-06-08&sr=b&sig=2FoV6VhJ2lFMK8OOrhFvwpYYICEeHqNUq5UwOZmsjfA%3D"
        }
    ]
```

## Type: **WindowsUpdate**

Based on the idea of the _WindowsUpdate_ command for the AIB customization, but with standard options. Filter capability not available; but may be coming soon

Supported parameters are:
- **restartTimeout** - Optional, boolean, generates the _WindowsRestart_ customization with 10 minute timeout

```json
"customSequence":  [
        {
            "type": "WindowsUpdate",
            "restartTimeout": "10"
        }
    ]
```


## Type: **Restart**

Based on the idea of the _WindowsRestart_ for the AIB customization, but simpler. **Not typically used since most other `customsequence` support restarts**

Supported parameters are:
- **Name** - Name of the process

```json
"customSequence":  [
        {
            "type": "Restart",
            "Name": "One last reboot"
        }
    ]
```

# References

- https://github.com/danielsollondon/azvmimagebuilder/tree/master/quickquickstarts/0_Creating_a_Custom_Windows_Managed_Image
- https://docs.microsoft.com/en-us/azure/virtual-machines/linux/image-builder-json?tabs=azure-powershell
- https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-customize-master-image
- https://docs.microsoft.com/en-us/azure/virtual-desktop/set-up-golden-image
- https://docs.microsoft.com/en-us/azure/virtual-machines/windows/image-builder-powershell

# DISCLAIMER
> Even though I have tested this to the extend that I could, I want to ensure your aware of Microsoft’s position on developing custom scripts.

This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.

This posting is provided "AS IS" with no warranties, and confers no rights. Use of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.
