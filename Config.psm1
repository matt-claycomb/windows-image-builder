# Copyright 2017 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
Import-Module "$localResourcesDir\ini.psm1"

function Get-AvailableConfigOptions {
    return @(
        @{"Name" = "wim_file_path"; "DefaultValue" = "D:\Sources\install.wim";
          "Description" = "The location of the WIM file from the mounted Windows ISO."},
        @{"Name" = "image_name"; "DefaultValue" = "Windows Server 2012 R2 SERVERSTANDARD";
          "Description" = "This is the complete name of the Windows version that will be generated.
                           In order to find the possible options, use the Get-WimFileImagesInfo command
                           and look for the Name property."},
        @{"Name" = "image_path"; "DefaultValue" = "D:\Sources\install-prepped.wim";
          "Description" = "The destination of the generated image."},
        @{"Name" = "product_key";
          "Description" = "The product key for the selected OS. If the value is default_kms_key and the Windows image is
                           ServerStandard or ServerDatacenter (Core), the appropiate KMS key will be used."},
        @{"Name" = "extra_features";
          "Description" = "A comma separated array of extra features that will be enabled on the resulting image.
                           These features need to be present in the ISO file."},
        @{"Name" = "extra_capabilities";
          "Description" = "A comma separated array of extra capabilities that will be enabled on the resulting image.
                           These capabilities need to be present in the ISO file."},
        @{"Name" = "gold_image"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "It will stop the image generation after the updates are installed and cleaned."},
        @{"Name" = "gold_image_path";
          "Description" = "This is the full path of the already generated golden image.
                           It should be a valid VHDX path."},
        @{"Name" = "custom_resources_path";
          "Description" = "This is the full path of a folder with custom resources which will be used by
                           the custom scripts.
                           The resources found at this path will be copied recursively to the image
                           UnattendResources\CustomResources folder."},
        @{"Name" = "custom_scripts_path";
          "Description" = "This is the full path of the folder which can contain a set of PS scripts,
                           that will be copied and executed during the online generation part on the VM.
                           The PowerShell scripts, if existent, will be started by Logon.ps1 script,
                           at different moments during image generation.
                           The purpose of these scripts is to offer to the user a fully
                           customizable way of defining additional logic for tweaking the final image.
                           The scripts files can have the following names: RunBeforeWindowsUpdates.ps1,
                           RunAfterWindowsUpdates.ps1, RunBeforeSysprep.ps1, RunAfterSysprep.ps1.
                           The script names contain the information on when the script will be executed.
                           One can define only some of the hook scripts and it is not mandatory to define all of them.
                           If a script does not exist, it will not be executed."},
        @{"Name" = "administrator_password"; "GroupName" = "vm"; "DefaultValue" = "Pa`$`$w0rd";
          "Description" = "This will be the Administrator user's, so that AutoLogin can be performed on the instance,
                           in order to install the required products,
                           updates and perform the generation tasks like sysprep."},
        @{"Name" = "external_switch"; "GroupName" = "vm"; "DefaultValue" = "external";
          "Description" = "Used to specify the virtual switch the VM will be using.
                           If it is specified but it is not external or if the switch does not exist,
                           you will get an error message."},
        @{"Name" = "cpu_count"; "GroupName" = "vm"; "DefaultValue" = "1";
          "Description" = "The number of CPU cores assigned to the VM used to generate the image."},
        @{"Name" = "ram_size"; "GroupName" = "vm"; "DefaultValue" = "2147483648";
          "Description" = "RAM (in bytes) assigned to the VM used to generate the image."},
        @{"Name" = "disk_size"; "GroupName" = "vm"; "DefaultValue" = "64424509440";
          "Description" = "Disk space (in bytes) assigned to the boot disk for the VM used to generate the image."},
        @{"Name" = "drivers_path"; "GroupName" = "drivers";
          "Description" = "The location where additional drivers that are needed for the image are located."},
        @{"Name" = "install_updates"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, the latest updates will be downloaded and installed."},
        @{"Name" = "purge_updates"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, will run DISM with /resetbase option. This will reduce the size of
                           WinSXS folder, but after that Windows updates cannot be uninstalled."},
        @{"Name" = "unattend_xml_path"; "GroupName" = "sysprep"; "DefaultValue" = "UnattendTemplate.xml";
          "Description" = "The path to the Unattend XML template file."},
        @{"Name" = "persist_drivers_install"; "GroupName" = "sysprep"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "In case the hardware on which the image is generated will also be the hardware on
                           which the image will be deployed this can be set to true, otherwise the spawned
                           instance is prone to BSOD."},
        @{"Name" = "startlayout_path";
          "Description" = "If set, it will replace the system default start menu and taskbar layouts."},
        @{"Name" = "enable_custom_wallpaper"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "If set to true, a custom wallpaper will be set according to the values of configuration options
                           wallpaper_path and wallpaper_solid_color"},
        @{"Name" = "wallpaper_path";
          "Description" = "If set, it will replace the Cloudbase Solutions wallpaper to the one specified.
                           The wallpaper needs to be a valid .jpg/.jpeg image."},
        @{"Name" = "wallpaper_solid_color";
          "Description" = "If set, it will replace the Cloudbase Solutions wallpaper to a solid color.
                           Currently, the only allowed solid color is '0 0 0' (black).
                           If both wallpaper_path and wallpaper_solid_color are set,
                           the script will throw an error."},
        @{"Name" = "disable_first_logon_animation"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set, the animation displayed during the first login on Windows Client versions will be disabled."},
        @{"Name" = "extra_packages";
          "Description" = "A comma separated list of extra packages (referenced by filepath)
                           to slipstream into the underlying image.
                           This allows additional local packages, like security updates, to be added to the image."},
        @{"Name" = "extra_packages_ignore_errors"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "Ignore failures from DISM when installing extra_packages, such as when
                           updates are skipped which are not applicable to the image."},
        @{"Name" = "enable_shutdown_without_logon"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "Enables shutdown of the Windows instance from the logon console."},
        @{"Name" = "enable_ping_requests"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, firewall rules will be added to enable ping requests (ipv4 and ipv6)."},
        @{"Name" = "enable_active_mode"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, it will set the High Performance mode and some power mode
                           and registry tweaks to prevent the machine from sleeping / hibernating."},
        @{"Name" = "disable_secure_boot"; "GroupName" = "vm"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "If set to true, the secure boot firmware option will be disabled."},
        @{"Name" = "clean_updates_offline"; "GroupName" = "updates"; "DefaultValue" = $false; "AsBoolean" = $true;
          "Description" = "Clean up the updates / components by running a DISM Cleanup-Image command.
                           This is useful when updates or capabilities are installed offline."},
        @{"Name" = "clean_updates_online"; "GroupName" = "updates"; "DefaultValue" = $true; "AsBoolean" = $true;
          "Description" = "Clean up the updates / components by running a DISM Cleanup-Image command.
                           This is useful when updates or other packages are installed when the instance is running."},
        @{"Name" = "time_zone"; "GroupName" = "custom";
          "Description" = "Set a custom timezone for the Windows image."},
        @{"Name" = "ntp_servers"; "GroupName" = "custom";
          "Description" = "Set custom ntp servers(space separated) for the Windows image"}
    )
}

function Get-WindowsImageConfig {
     <#
    .SYNOPSIS
     This function reads the ini file given as a parameter and returns a dictionary of config options for the Windows
     image to be generated. If there are no values for a set of keys defined in Get-AvailableConfigOptions, the
     default values will be used instead.
     #>
    param([parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    if (!$fullConfigFilePath -or (-not (Test-Path $fullConfigFilePath))) {
        Write-Warning ("Config file {0} does not exist." -f $configFilePath)
    }
    $winImageConfig = @{}
    $availableConfigOptions = Get-AvailableConfigOptions
    foreach($availableConfigOption in $availableConfigOptions) {
        try {
            $groupName = "DEFAULT"
            $asBoolean = $false
            if ($availableConfigOption['GroupName']) {
                $groupName = $availableConfigOption['GroupName']
            }
            if ($availableConfigOption['AsBoolean']) {
                $asBoolean = $availableConfigOption['AsBoolean']
            }
            $value = Get-IniFileValue -Path $fullConfigFilePath -Section $groupName `
                                      -Key $availableConfigOption['Name'] `
                                      -Default $availableConfigOption['DefaultValue'] `
                                      -AsBoolean:$asBoolean
        } catch {
            $value = $availableConfigOption['DefaultValue']
        }
        $winImageConfig += @{$availableConfigOption['Name'] = $value}
    }
    return $winImageConfig
}
function Set-IniComment {
    param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Key,
        [parameter()]
        [string]$Section = "DEFAULT",
        [parameter(Mandatory=$false)]
        [string]$Description,
        [parameter(Mandatory=$true)]
        [string]$Path
    )

    $content = Get-Content $Path
    $index = 0
    $lines = @()
    $descriptionSplited = $Description -split '["\n\r"|"\r\n"|\n|\r]'
    foreach ($line in $descriptionSplited) {
        if ($line.trim()) {
            $lines += "# " + $line.trim()
        }
    }
    foreach ($line in $content) {
        if ($Description -and $line.StartsWith($Key) -and ($content[$index -1] -ne $lines)) {
            $content = $content[0..($index -1)], $lines, $content[$index..($content.Length -1)]
            break
        }
        $index += 1
    }
    Set-Content -Value $content -Path $ConfigFilePath -Encoding ASCII
}

function New-WindowsImageConfig {
    <#
    .SYNOPSIS
     This function creates a ini type config file with the options taken from the Get-WindowsImageConfig function.
     #>
    param([parameter(Mandatory=$true)]
        [string]$ConfigFilePath
    )
    if (Test-Path $ConfigFilePath) {
        Write-Warning "$ConfigFilePath exists and it will be rewritten."
        Remove-Item -Force $ConfigFilePath
    }
    New-Item -ItemType File -Path $ConfigFilePath | Out-Null

    $fullConfigFilePath = Resolve-Path $ConfigFilePath -ErrorAction SilentlyContinue
    $availableConfigOptions = Get-AvailableConfigOptions
    foreach($availableConfigOption in $availableConfigOptions) {
        try {
            $groupName = "DEFAULT"
            $value = $availableConfigOption['DefaultValue']
            if ($availableConfigOption['GroupName']) {
                $groupName = $availableConfigOption['GroupName']
            }
            if (!$availableConfigOption['AsBoolean'] -and !$value) {
                $value = '""'
            }
            Set-IniFileValue -Path $fullConfigFilePath -Section $groupName `
                             -Key $availableConfigOption['Name'] `
                             -Value $value | Out-Null
            Set-IniComment -Path $fullConfigFilePath -Key $availableConfigOption['Name'] `
                           -Description $availableConfigOption['Description']
        } catch {
            Write-Warning ("Config option {0} could not be written." -f @($availableConfigOption['Name']))
        }
    }
}

Export-ModuleMember Get-WindowsImageConfig, New-WindowsImageConfig
