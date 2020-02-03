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
Import-Module Dism
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$localResourcesDir = "$scriptPath\UnattendResources"
$kmsProductKeysFile = "$scriptPath\kms_product_keys.json"
Import-Module "$scriptPath\Config.psm1"
Import-Module "$scriptPath\UnattendResources\ini.psm1"

# Enforce Tls1.2, as GitHub and more websites require it.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$noHypervWarning = @"
The Hyper-V role is missing from this machine. In order to be able to finish
generating the image, you need to install the Hyper-V role.

You can do so by running the following commands from an elevated powershell
command prompt:
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart

Don't forget to reboot after you install the Hyper-V role.
"@

. "$scriptPath\Interop.ps1"

class PathShouldExistAttribute : System.Management.Automation.ValidateArgumentsAttribute {
    [void] Validate([object]$arguments, [System.Management.Automation.EngineIntrinsics]$engineIntrinsics) {
        if (!(Test-Path -Path $arguments)) {
            throw "Path ``$arguments`` not found."
        }
    }
}

function Write-Log {
    Param($messageToOut)
    Write-Host ("{0} - {1}" -f @((Get-Date), $messageToOut))
}

function Execute-Retry {
    Param(
        [parameter(Mandatory=$true)]
        $command,
        [int]$maxRetryCount=4,
        [int]$retryInterval=4
    )

    $currErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $retryCount = 0
    while ($true) {
        try {
            $res = Invoke-Command -ScriptBlock $command
            $ErrorActionPreference = $currErrorActionPreference
            return $res
        } catch [System.Exception] {
            $retryCount++
            if ($retryCount -ge $maxRetryCount) {
                $ErrorActionPreference = $currErrorActionPreference
                throw
            } else {
                if($_) {
                    Write-Warning $_
                }
                Start-Sleep $retryInterval
            }
        }
    }
}

function Is-Administrator {
    $wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
    $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdmin = $prp.IsInRole($adm)
    if (!$isAdmin) {
        throw "This cmdlet must be executed in an elevated administrative shell"
    }
}

function Get-WimInteropObject {
    Param(
        [parameter(Mandatory=$true)]
        [string]$WimFilePath
    )
    return (New-Object WIMInterop.WimFile -ArgumentList $WimFilePath)
}

function Get-WimFileImagesInfo {
    <#
    .SYNOPSIS
     This function retrieves a list of the Windows Editions from an ISO file.
    .DESCRIPTION
     This function reads the Images content of the WIM file that can be found
     on a mounted ISO and it returns an object for each Windows Edition, each
     object containing a list of properties.
    .PARAMETER WimFilePath
     Location of the install.wim file found on the mounted ISO image.
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$WimFilePath
    )
    PROCESS
    {
        $w = Get-WimInteropObject $WimFilePath
        return $w.Images
    }
}

function Create-ImageVirtualDisk {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [string]$VhdPath,
        [parameter(Mandatory=$true)]
        [long]$Size
    )

    Write-Log "Creating Virtual Disk Image: $VhdPath..."
    $v = [WIMInterop.VirtualDisk]::CreateVirtualDisk($VhdPath, $Size)
    try {
        $v.AttachVirtualDisk()
        $path = $v.GetVirtualDiskPhysicalPath()
        # -match creates an env variable called $Matches
        $path -match "\\\\.\\PHYSICALDRIVE(?<num>\d+)" | Out-Null
        $diskNum = $Matches["num"]
        $volumeLabel = "OS"

		Initialize-Disk -Number $diskNum -PartitionStyle GPT
		# EFI partition
		$systemPart = New-Partition -DiskNumber $diskNum -Size 200MB `
			-GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' `
			-AssignDriveLetter
		& format.com "$($systemPart.DriveLetter):" /FS:FAT32 /Q /Y | Out-Null
		if ($LASTEXITCODE) {
			throw "Format failed"
		}
		# MSR partition
		New-Partition -DiskNumber $diskNum -Size 128MB `
			-GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
		# Windows partition
		$windowsPart = New-Partition -DiskNumber $diskNum -UseMaximumSize `
			-GptType "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}" `
			-AssignDriveLetter

        Format-Volume -DriveLetter $windowsPart.DriveLetter `
            -FileSystem NTFS -NewFileSystemLabel $volumeLabel `
            -Force -Confirm:$false | Out-Null
        return @("$($systemPart.DriveLetter):", "$($windowsPart.DriveLetter):")
    } finally {
        Write-Log "Successfuly created disk: $VhdPath"
        $v.Close()
    }
}

function Apply-Image {
    Param(
        [parameter(Mandatory=$true)]
        [string]$winImagePath,
        [parameter(Mandatory=$true)]
        [string]$wimFilePath,
        [parameter(Mandatory=$true)]
        [int]$imageIndex
    )
    Write-Log ('Applying Windows image "{0}" in "{1}"' -f $wimFilePath, $winImagePath)
    #Expand-WindowsImage -ImagePath $wimFilePath -Index $imageIndex -ApplyPath $winImagePath
    # Use Dism in place of the PowerShell equivalent for better progress update
    # and for ease of interruption with CTRL+C
    & Dism.exe /apply-image /imagefile:${wimFilePath} /index:${imageIndex} /ApplyDir:${winImagePath}
    if ($LASTEXITCODE) { throw "Dism apply-image failed" }
}

function Create-BCDBootConfig {
    Param(
        [parameter(Mandatory=$true)]
        [string]$systemDrive,
        [parameter(Mandatory=$true)]
        [string]$windowsDrive,
        [parameter(Mandatory=$true)]
        [object]$image
    )

    Write-Log ("Create BCDBoot Config for {0}" -f @($image.ImageName))
    $bcdbootLocalPath = "bcdboot.exe"
    $bcdbootPath = "${windowsDrive}\windows\system32\bcdboot.exe"
    if (!(Test-Path $bcdbootPath)) {
        Write-Warning ('"{0}" not found, using online version' -f $bcdbootPath)
        $bcdbootPath = $bcdbootLocalPath
    }

    $ErrorActionPreference = "SilentlyContinue"
    # Note: older versions of bcdboot.exe don't have a /f argument
    if ($image.ImageVersion.Major -eq 6 -and $image.ImageVersion.Minor -lt 2) {
       $bcdbootOutput = & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v
       # Note(avladu): Retry using the local bcdboot path
       # when generating Win7 images on Win10 / Server 2k16 hosts
       if ($LASTEXITCODE) {
           Write-Log "Retrying with bcdboot.exe from host"
           $bcdbootOutput = & $bcdbootLocalPath ${windowsDrive}\windows /s ${systemDrive} /v /f UEFI
       }
    } else {
       $bcdbootOutput = & $bcdbootPath ${windowsDrive}\windows /s ${systemDrive} /v /f UEFI
    }
    if ($LASTEXITCODE) {
        $ErrorActionPreference = "Stop"
        throw "BCDBoot failed with error: $bcdbootOutput"
    }

    $ErrorActionPreference = "Stop"
    Write-Log "BCDBoot config has been created."
}

function Transform-Xml {
    Param(
        [parameter(Mandatory=$true)]
        [string]$xsltPath,
        [parameter(Mandatory=$true)]
        [string]$inXmlPath,
        [parameter(Mandatory=$true)]
        [string]$outXmlPath,
        [parameter(Mandatory=$true)]
        $xsltArgs
    )
    $xslt = New-Object System.Xml.Xsl.XslCompiledTransform($false)
    $xsltSettings = New-Object System.Xml.Xsl.XsltSettings($false, $true)
    $xslt.Load($xsltPath, $xsltSettings, (New-Object System.Xml.XmlUrlResolver))
    $outXmlFile = New-Object System.IO.FileStream($outXmlPath, `
        [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    $argList = New-Object System.Xml.Xsl.XsltArgumentList

    foreach ($k in $xsltArgs.Keys) {
        $argList.AddParam($k, "", $xsltArgs[$k])
    }
    $xslt.Transform($inXmlPath, $argList, $outXmlFile)
    $outXmlFile.Close()
}

function Generate-UnattendXml {
    Param(
        [parameter(Mandatory=$true)]
        [string]$inUnattendXmlPath,
        [parameter(Mandatory=$true)]
        [string]$outUnattendXmlPath,
        [parameter(Mandatory=$true)]
        [object]$image,
        [ValidatePattern("^$|^\S{5}-\S{5}-\S{5}-\S{5}-\S{5}")]
        [parameter(Mandatory=$false)]
        [string]$productKey,
        [parameter(Mandatory=$false)]
        $administratorPassword
    )

    Write-Log "Generate Unattend Xml :$outUnattendXmlPath..."
    $xsltArgs = @{}
    $xsltArgs["processorArchitecture"] = ([string]$image.ImageArchitecture).ToLower()
    $xsltArgs["imageName"] = $image.ImageName
    $xsltArgs["versionMajor"] = $image.ImageVersion.Major
    $xsltArgs["versionMinor"] = $image.ImageVersion.Minor
    $xsltArgs["installationType"] = $image.ImageInstallationType
    $xsltArgs["administratorPassword"] = $administratorPassword

    if ($productKey) {
        $xsltArgs["productKey"] = $productKey
    }

    Transform-Xml -xsltPath "$scriptPath\Unattend.xslt" -inXmlPath $inUnattendXmlPath `
        -outXmlPath $outUnattendXmlPath -xsltArgs $xsltArgs
    Write-Log "Xml was generated."
}

function Detach-VirtualDisk {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VhdPath
    )
    try {
        $v = [WIMInterop.VirtualDisk]::OpenVirtualDisk($VhdPath)
        $v.DetachVirtualDisk()
    } finally {
        if ($v) { $v.Close() }
    }
}

function Check-DismVersionForImage {
    Param(
        [Parameter(Mandatory=$true)]
        [object]$image
    )
    $dismVersion = New-Object System.Version `
        (Get-Command dism.exe).FileVersionInfo.ProductVersion
    if ($image.ImageVersion.CompareTo($dismVersion) -gt 0) {
        Write-Warning "The installed version of DISM is older than the Windows image"
    }
}

function Copy-CustomResources {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ResourcesDir,
        [string]$CustomResources,
        [string]$CustomScripts
        )

    Write-Log "Copy Custom Resources: $CustomResources..."
    if (!(Test-Path "$resourcesDir")) {
        New-Item -Type Directory $resourcesDir | Out-Null
    }
    if ($CustomResources) {
        if (!(Test-Path "$resourcesDir\CustomResources")) {
            New-Item -Type Directory "$resourcesDir\CustomResources" | Out-Null
        }
        Write-Log "Copying: $CustomResources $resourcesDir"
        # Custom resources can be multiple directories, split by ","
        $customResourcesSplit = $CustomResources.split(",")
        foreach ($customResource in $customResourcesSplit) {
            Copy-Item -Recurse "$customResource\*" "$resourcesDir\CustomResources"
        }
    }
    if ($CustomScripts) {
        if (!(Test-Path "$resourcesDir\CustomScripts")) {
            New-Item -Type Directory "$resourcesDir\CustomScripts" | Out-Null
        }
        Write-Log "Copying: $CustomScripts $resourcesDir"
        # Custom scripts can be multiple directories, split by ","
        $customScriptsSplit = $CustomScripts.split(",")
        foreach ($customScript in $customScriptsSplit) {
            Copy-Item -Recurse "$customScript\*" "$resourcesDir\CustomScripts"
        }
    }
    Write-Log "Custom Resources at: $ResourcesDir."
}

function Copy-UnattendResources {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [string]$imageInstallationType
    )

    Write-Log "Copy Unattend Resources: $imageInstallationType..."
    # Workaround to recognize the $resourcesDir drive. This seems a PowerShell bug
    Get-PSDrive | Out-Null

    if (!(Test-Path "$resourcesDir")) {
        New-Item -Type Directory $resourcesDir | Out-Null
    }
    Write-Log "Copying: $localResourcesDir $resourcesDir"
    Copy-Item -Recurse -Force "$localResourcesDir\*" $resourcesDir

    Write-Log "Resources have been copied."
}

function Generate-ConfigFile {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$resourcesDir,
        [Parameter(Mandatory=$true)]
        [hashtable]$values
    )

    Write-Log "Generate config file: $resourcesDir..."
    $configIniPath = "$resourcesDir\config.ini"
    Import-Module "$localResourcesDir\ini.psm1"
    foreach ($i in $values.GetEnumerator()) {
        Set-IniFileValue -Path $configIniPath -Section "DEFAULT" -Key $i.Key -Value $i.Value
    }
    Write-Log "Config file was generated."
}

function Add-DriversToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [string]$driversPath
    )
    Write-Log ('Adding drivers from "{0}" to image "{1}"' -f $driversPath, $winImagePath)
    Execute-Retry {
        & Dism.exe /image:${winImagePath} /Add-Driver /driver:${driversPath} /ForceUnsigned /recurse
        if ($LASTEXITCODE) {
            throw "Dism failed to add drivers from: $driversPath"
        }
    } -retryInterval 1
}

function Add-PackageToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [string]$packagePath,
        [Parameter(Mandatory=$false)]
        [boolean]$ignoreErrors
    )
    Write-Log ('Adding packages from "{0}" to image "{1}"' -f $packagePath, $winImagePath)
    & Dism.exe /image:${winImagePath} /Add-Package /Packagepath:${packagePath}
    if ($LASTEXITCODE -and !$ignoreErrors) {
        throw "Dism failed to add packages from: $packagePath"
    } elseif ($LASTEXITCODE) {
        Write-Log ("Dism failed to add packages from $packagePath. Skipping.")
    }
}

function Enable-FeaturesInImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [array]$featureNames
    )
    if ($featureNames) {
        $cmd = @(
        "Dism.exe",
        ("/image:{0}" -f ${winImagePath}),
        "/Enable-Feature"
        )
        foreach ($featureName in $featureNames) {
            $cmd += ("/FeatureName:{0}" -f $featureName)
        }

        Execute-Retry {
            & $cmd[0] $cmd[1..$cmd.Length]
            if ($LASTEXITCODE) { throw "Dism failed to enable features: $featureNames" }
        }
    }
}

function Add-CapabilitiesToImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [array]$capabilityNames
    )
    if ($capabilityNames) {
        $cmd = @(
        "Dism.exe",
        ("/image:{0}" -f ${winImagePath}),
        "/Add-Capability"
        )
        foreach ($capabilityName in $capabilityNames) {
            $cmd += ("/CapabilityName:{0}" -f $capabilityName)
        }

        Execute-Retry {
            & $cmd[0] $cmd[1..$cmd.Length]
            if ($LASTEXITCODE) { throw "Dism failed to add capabilities: $capabilityNames" }
        }
    }
}

function Check-EnablePowerShellInImage {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$true)]
        [object]$image
    )
    # Windows 2008 R2 Server Core does not have powershell enabled by default
    $v62 = New-Object System.Version 6, 2, 0, 0
    if ($image.ImageVersion.CompareTo($v62) -lt 0 `
            -and $image.ImageInstallationType -eq "Server Core") {
        Write-Log "Enabling PowerShell in the Windows image"
        $psFeatures = @("NetFx2-ServerCore",
                        "MicrosoftWindowsPowerShell",
                        "NetFx2-ServerCore-WOW64",
                        "MicrosoftWindowsPowerShell-WOW64"
                        )
        Enable-FeaturesInImage $winImagePath $psFeatures
    }
}

function Is-IsoFile {
    Param(
        [parameter(Mandatory=$true)]
        [string]$FilePath
    )
    return ([System.IO.Path]::GetExtension($FilePath) -eq ".iso")
}

function Is-ServerInstallationType {
    Param(
        [parameter(Mandatory=$true)]
        [object]$image
    )
    return ($image.ImageInstallationType -in @("Server", "Server Core"))
}

function Set-DotNetCWD {
    # Make sure the PowerShell and .Net CWD match
    [Environment]::CurrentDirectory = (Get-Location -PSProvider FileSystem).ProviderPath
}

function Get-PathWithoutExtension {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [int]$Depth = 0
    )
    # NOTE(avladu): Cleanup all the extensions
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    for($i = 0;$i -lt $Depth;$i++) {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
    }
    return Join-Path ([System.IO.Path]::GetDirectoryName($Path)) $fileName
}

function Resize-VHDImage {
    <#
    .SYNOPSIS
     This function resizes the VHD image to a minimum VHD size plus a FreeSpace parameter value buffer.
    .DESCRIPTION
     This function mounts the VHD given as parameter and retrieves the drive letter. After that it computes
     the actual size and the minimum supported size.
    .PARAMETER VirtualDiskPath
     The path to the VHD image  to resize.
    .PARAMETER FreeSpace
     This is the extra buffer parameter.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$VirtualDiskPath,
        [parameter(Mandatory=$false)]
        [Uint64]$FreeSpace=500MB
    )
    Write-Log "Shrinking VHD to minimum size"

    $vhdSize = (Get-VHD -Path $VirtualDiskPath).Size
    $vhdSizeGB = $vhdSize/1GB
    Write-Log "Initial VHD size is: $vhdSizeGB GB"

    $mountedVHD = Mount-VHD -Path $VirtualDiskPath -Passthru
    Get-PSDrive | Out-Null

    $Drive = ($mountedVHD | Get-Disk | Get-Partition | Get-Volume | `
        Sort-Object -Property Size -Descending | Select-Object -First 1).DriveLetter

    try {
        Optimize-Volume -DriveLetter $Drive -Defrag -ReTrim -SlabConsolidate

        $partitionInfo = Get-Partition -DriveLetter $Drive
        $partitionResizeInfo = Get-PartitionSupportedSize -DriveLetter $Drive
        $MinSize = $partitionResizeInfo.SizeMin
        $MaxSize = $partitionResizeInfo.SizeMax
        $CurrSize = $partitionInfo.Size/1GB
        Write-Log "Current partition size: $CurrSize GB"
        # Leave free space for making sure Sysprep finishes successfuly
        $newSizeGB = [int](($MinSize + $FreeSpace)/1GB) + 1
        $NewSize = $newSizeGB*1GB
        Write-Log "New partition size: $newSizeGB GB"

        if (($NewSize - $FreeSpace) -gt $MinSize) {
                $global:i = 0
                $global:sizeIncreased = 0
            try {
                $step = 100MB
                # Adding 10 retries means increasing the size to a max of 1.5GB,
                # which should be enough for the Resize-Partition to succeed.
                Execute-Retry {
                    $global:sizeIncreased = ($NewSize + ($step * $global:i))
                    Write-Log "Size increased: $sizeIncreased"
                    $global:i = $global:i + 1
                    Resize-Partition -DriveLetter $Drive -Size $global:sizeIncreased -ErrorAction "Stop"
                } -maxRetryCount 10
            } catch {
                Write-Log "Partition could not be resized using an incremental method"
                Write-Log "Trying to resize partition using a binary search method"
                $binaryTries = 0
                # For example, with 10 binary tries and a max min difference of 1TB space,
                # we will get 1024 / 1024 = 1 GB difference
                $binaryMaxTries = 10
                $MinSize = $global:sizeIncreased
                while (($MinSize -lt $MaxSize) -and ($binaryTries -lt $binaryMaxTries)) {
                    $desiredSize = $MinSize + ($MaxSize - $MinSize) / 2
                    Write-Log "Trying to decrease the partition to $desiredSize"
                    try {
                        Resize-Partition -DriveLetter $Drive -Size $desiredSize -ErrorAction "Stop"
                        Write-Log "Partition resized to $desiredSize. MaxSize becomes the desired size"
                        $MaxSize = $desiredSize
                    } catch {
                        Write-Log "Partition could not be resized to $desiredSize. MinSize becomes the desired size"
                        $MinSize = $desiredSize
                    }
                    $binaryTries ++
                }
            }
        }
    } finally {
        Dismount-VHD -Path $VirtualDiskPath
    }

    $vhdMinSize = (Get-VHD -Path $VirtualDiskPath).MinimumSize
    if ($vhdSize -gt $vhdMinSize) {
        Resize-VHD $VirtualDiskPath -ToMinimumSize
    }
    $FinalDiskSize = ((Get-VHD -Path $VirtualDiskPath).Size/1GB)
    Write-Log "Final disk size: $FinalDiskSize GB"
}

function Check-Prerequisites {
    $needsHyperV = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V
    if ($needsHyperV.State -ne "Enabled") {
        throw $noHypervWarning
    }
}

function Wait-ForVMShutdown {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    Write-Log "Waiting for $Name to finish sysprep."
    $isOff = (Get-VM -Name $Name).State -eq "Off"
    $vmMessages = @{}
    while ($isOff -eq $false) {
        Start-Sleep 1
        $vmState = (Get-VM -Name $Name).State
        $isOff =  $vmState -eq "Off"
        try {
            if ($vmState -ne "Running" -or `
                !(Get-VMIntegrationService $Name -Name "Key-Value Pair Exchange").Enabled) {
                continue
            }
            $currentVMMessages = Get-KVPData -VMName $Name
            if (!$currentVMMessages) {continue}
            foreach ($stage in $currentVMMessages.keys) {
                if (!$vmMessages[$stage]) {
                    Write-Log ("- - {0}: {1}" -f @($stage, $currentVMMessages[$stage]))
                }
            }
            $vmMessages = $currentVMMessages
        } catch {
            Write-Log "Could not retrieve VM runtime logs"
        }
    }
}

function Convert-KvpData($xmlData) {
   $data = @{}

   foreach ($xmlItem in $xmlData) {
      $key = ""
      $value = ""
      $xmlData = [Xml]$xmlItem
      foreach ($i in $xmlData.INSTANCE.PROPERTY) {
         if ($i.Name -eq "Name") {
            $key = $i.Value
         }
         if ($i.Name -eq "Data") {
            $value = $i.Value
         }
      }
      if ($key -like "ImageGenerationLog-*") {
         $key = $key.replace("ImageGenerationLog-","")
         $data[$key] = $value
      }
   }

   return $data
}

function Get-KVPData {
   param($VMName)
   $wmiNamespace = "root\virtualization\v2"
   $vm = Get-WmiObject -Namespace $wmiNamespace `
      -Query "Select * From Msvm_ComputerSystem Where ElementName=`'$VMName`'"
   if (!$vm) {return}

   $kvp = Get-WmiObject -Namespace $wmiNamespace `
      -Query "Associators of {$vm} Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_KvpExchangeComponent"
   if (!$kvp) {return}

   $kvpData = Convert-KvpData($kvp.GuestIntrinsicExchangeItems)
   return $kvpData
}

function Get-ImageInformation {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        [Parameter(Mandatory=$true)]
        [string]$ImageName
    )

    $ntDll = "$driveLetter\Windows\system32\ntdll.dll"
    if (Test-Path $ntDll) {
        $versionString = (Get-Item $ntDll).VersionInfo.ProductVersion
        $osVersion = $versionString.split('.')
        $imageVersion = @{
            "Major" = $osVersion[0];
            "Minor" = $osVersion[1];
        }
    } else {
        throw "Unable to determine OS Version"
    }

    if ((Get-Item $ntDll).Target -like "*amd64_microsoft-windows-ntdll*") {
        $imageArchitecture = "AMD64"
    } else {
        $imageArchitecture = "i386"
    }

    if ($imageName -notlike "*server*") {
        $imageInstallationType = "Client"
    } elseif ($imageName -like '*Core') {
        $imageInstallationType = "Server Core"
    } else {
        $imageInstallationType = "Server"
    }

    return @{
        "imageVersion" = $imageVersion;
        "imageArchitecture" = $imageArchitecture;
        "imageInstallationType" = $imageInstallationType;
    }
}

function Set-WindowsWallpaper {
    Param(
        [Parameter(Mandatory=$true)][PathShouldExist()]
        [string]$WinDrive,
        [Parameter(Mandatory=$false)]
        [string]$WallpaperPath,
        [Parameter(Mandatory=$false)]
        [string]$WallpaperSolidColor
    )

    Write-Log "Setting wallpaper..."
    $useWallpaperImage = $false
    $wallpaperGPOPath = Join-Path $localResourcesDir "GPO"

    if ($WallpaperPath -and $WallpaperSolidColor) {
        throw "WallpaperPath and WallpaperSolidColor cannot be set at the same time."
    }
    if ($WallpaperPath -or !($WallpaperSolidColor)) {
        if (!$WallpaperPath -or !(@('.jpg', '.jpeg') -contains `
                (Get-Item $windowsImageConfig.wallpaper_path -ErrorAction SilentlyContinue).Extension)) {
            $WallpaperPath = Join-Path $localResourcesDir "Wallpaper.jpg"
        }
        if (!(Test-Path $WallpaperPath)) {
            throw "Walpaper path ``$WallpaperPath`` does not exist."
        }
        $wallpaperDestinationFolder = Join-Path $winDrive "\Windows\web\Wallpaper\Cloud"
        if (!(Test-Path $wallpaperDestinationFolder)) {
           New-Item -Type Directory $wallpaperDestinationFolder | Out-Null
        }
        Copy-Item -Force $WallpaperPath "$wallpaperDestinationFolder\Wallpaper.jpg"
        Write-Log "Wallpaper copied to the image."

        # Note(avladu) if the image already has been booted and has a wallpaper, the
        # GPO will not be applied for the users who have already logged in.
        # The wallpaper can still be changed by replacing the cached one.
        $cachedWallpaperPartPath = "\Users\Administrator\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper*"
        $cachedWallpaperPath = Join-Path -ErrorAction SilentlyContinue $winDrive $cachedWallpaperPartPath
        if (Test-Path $cachedWallpaperPath) {
            $wallpaperPathFullName = (Get-Item $cachedWallpaperPath).FullName
            Remove-Item -Recurse -Force ((Get-Item $cachedWallpaperPath).DirectoryName + "\*")
            Copy-Item -Force $WallpaperPath $wallpaperPathFullName
            Write-Log "Cached wallpaper for user Administrator has been replaced."
        }
        $useWallpaperImage = $true
    }

    $windowsLocalGPOPath = Join-Path $winDrive "\Windows\System32\GroupPolicy"
    if (!(Test-Path $windowsLocalGPOPath)) {
       New-Item -Type Directory $windowsLocalGPOPath | Out-Null
    }
    Copy-Item -Recurse -Force "$wallpaperGPOPath\*" "$windowsLocalGPOPath\"
    $basePolicyRegistry = Join-Path $windowsLocalGPOPath "User/Registry.pol"
    $wallpaperPolicyRegistry = Join-Path $windowsLocalGPOPath "User/Registry-wallpaper.pol"
    $solidColorPolicyRegistry = Join-Path $windowsLocalGPOPath "User/Registry-solid-color.pol"

    if ($useWallpaperImage) {
        Move-Item -Force $wallpaperPolicyRegistry $basePolicyRegistry
        Remove-Item -Force $solidColorPolicyRegistry -ErrorAction SilentlyContinue
    } else {
        Move-Item -Force $solidColorPolicyRegistry $basePolicyRegistry
        Remove-Item -Force $wallpaperPolicyRegistry -ErrorAction SilentlyContinue
    }
    Write-Log "Wallpaper GPO copied to the image."

    Write-Log "Wallpaper was set."
}

function Reset-WindowsWallpaper {
    Param(
        [Parameter(Mandatory=$true)][PathShouldExist()]
        [string]$WinDrive
    )
    $wallpaperDestination = Join-Path $winDrive "\Windows\web\Wallpaper\Cloud\Wallpaper.jpg"
    Remove-Item -Force -ErrorAction SilentlyContinue $wallpaperDestination

    $cachedWallpaperPartPath = "\Users\Administrator\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper*"
    $cachedWallpaperPath = Join-Path -ErrorAction SilentlyContinue $winDrive $cachedWallpaperPartPath
    Remove-Item -Force -ErrorAction SilentlyContinue $cachedWallpaperPath

    $windowsLocalGPOPath = Join-Path $winDrive "\Windows\System32\GroupPolicy\User\Registry.pol"
    Remove-Item -Force -ErrorAction SilentlyContinue $windowsLocalGPOPath
}

function Get-TotalLogicalProcessors {
    $count = 0
    $cpus = Get-WmiObject Win32_Processor
    foreach ($cpu in $cpus) {
        $count += $cpu.NumberOfLogicalProcessors
    }
    return $count
}

function Map-KMSProductKey {
    param($ImageName, $ImageVersion)

    $productKeysMap = Get-Content -Encoding ASCII $kmsProductKeysFile | ConvertFrom-Json
    try {
        $ImageVersionBuild = $ImageVersion.Build
        if ($ImageVersion.Major -eq "6") {
            $ImageVersionBuild = 0
        }
        return ($productKeysMap | Select-Object -ExpandProperty "KMS" | `
            Select-Object -ExpandProperty ([string]$ImageVersion.Major) | `
            Select-Object -ExpandProperty ([string]$ImageVersion.Minor) | `
            Select-Object -ExpandProperty ([string]$ImageVersionBuild) | `
            Select-Object -ExpandProperty $ImageName)
    } catch {
        Write-Log "No valid KMS key found for image ${ImageName}"
    }
}

function Clean-WindowsUpdates {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$winImagePath,
        [Parameter(Mandatory=$false)]
        [boolean]$PurgeUpdates
    )
    Write-Log "Running offline dism Cleanup-Image..."
    if (([System.Environment]::OSVersion.Version.Major -gt 6) -or ([System.Environment]::OSVersion.Version.Minor -ge 2))
    {
        if (!$PurgeUpdates) {
            Dism.exe /image:${winImagePath} /Cleanup-Image /StartComponentCleanup
        } else {
            Dism.exe /image:${winImagePath} /Cleanup-Image /StartComponentCleanup /ResetBase
        }
        if ($LASTEXITCODE) {
            throw "Offline dism Cleanup-Image failed."
        } else {
            Write-Log "Offline dism Cleanup-Image completed."
        }
    }
}

function New-BaseWindowsImage {
    <#
    .SYNOPSIS
     This function generates a Windows image using Hyper-V  to instantiate the image in
     order to apply the updates.
    .DESCRIPTION
     This command requires Hyper-V to be enabled, a VMSwitch to be configured for external
     network connectivity if the updates are to be installed, which is highly recommended.
	 After the Hyper-V instance shuts down, the resulting VHDX is mounted and captured as
	 a WIM image for deployment.

     The list of parameters can be found in the Config.psm1 file.
    #>
    Param(
        [parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$ConfigFilePath
    )
    $windowsImageConfig = Get-WindowsImageConfig -ConfigFilePath $ConfigFilePath

    Write-Log "Windows online image generation started."
    Is-Administrator

    Check-Prerequisites
	
    if ($windowsImageConfig.external_switch) {
        $VMSwitch = Get-VMSwitch -Name $windowsImageConfig.external_switch -ErrorAction SilentlyContinue
        if (!$VMSwitch) {
            throw ("Selected vmswitch {0} does not exist" -f $windowsImageConfig.external_switch)
        }
        if ($VMSwitch.SwitchType -ne "External") {
            throw ("Selected switch {0} is not an external switch." -f $windowsImageConfig.external_switch)
        }
    }
	else {
		$VMSwitch = Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue
		
        if (!$VMSwitch) {
            throw "Default vmswitch does not exist"
        }
	}
	
    if ([int]$windowsImageConfig.cpu_count -gt [int](Get-TotalLogicalProcessors)) {
        throw "CpuCores larger then available (logical) CPU cores."
    }
	
	$imagePath = $windowsImageConfig.image_path

    if (Test-Path $imagePath) {
        Write-Log "Found already existing image file. Removing it..." -ForegroundColor Yellow
        Remove-Item -Force $imagePath
        Write-Log "Already existent image file has been removed." -ForegroundColor Yellow
    }

    try {		
		try {
			$mountedWindowsIso = $null
			if ($windowsImageConfig.wim_file_path.EndsWith('.iso')) {
				$windowsImageConfig.wim_file_path = get-command $windowsImageConfig.wim_file_path -erroraction ignore `
					| Select-Object -ExpandProperty Source
				if($windowsImageConfig.wim_file_path -eq $null){
					throw ("Unable to find source iso. Either specify the full path or add the folder containing the iso to the path variable")
				}
				$mountedWindowsIso = [WIMInterop.VirtualDisk]::OpenVirtualDisk($windowsImageConfig.wim_file_path)
				$mountedWindowsIso.AttachVirtualDisk()
				$devicePath = $mountedWindowsIso.GetVirtualDiskPhysicalPath()
				$basePath = ((Get-DiskImage -DevicePath $devicePath `
						| Get-Volume).DriveLetter) + ":"
				$windowsImageConfig.wim_file_path = "$($basePath)\Sources\install.wim"
			}
			
			Set-DotNetCWD
			
			$image = Get-WimFileImagesInfo -WimFilePath $windowsImageConfig.wim_file_path | `
				Where-Object { $_.ImageName -eq $windowsImageConfig.image_name }
			if (!$image) {
				throw ("Image {0} not found in WIM file {1}" -f @($windowsImageConfig.image_name, $windowsImageConfig.wim_file_path))
			}
			Check-DismVersionForImage $image
			
			try {
				$drives = Create-ImageVirtualDisk -VhdPath $imagePath -Size $windowsImageConfig.disk_size
				$winImagePath = "$($drives[1])\"
				$resourcesDir = "${winImagePath}UnattendResources"
				$outUnattendXmlPath = "${winImagePath}Unattend.xml"
				$xmlunattendPath = Join-Path $scriptPath $windowsImageConfig['unattend_xml_path']
				$xmlParams = @{'InUnattendXmlPath' = $xmlunattendPath;
							   'OutUnattendXmlPath' = $outUnattendXmlPath;
							   'Image' = $image;
							   'AdministratorPassword' = $windowsImageConfig.administrator_password;
				}
				if ($windowsImageConfig.product_key) {
					$productKey = $windowsImageConfig.product_key
					if ($productKey -eq "default_kms_key") {
						$productKey = Map-KMSProductKey $windowsImageConfig.image_name $image.ImageVersion
					}
					if ($productKey) {
						$xmlParams.Add('productKey', $productKey)
					}
				}
				Generate-UnattendXml @xmlParams
				Copy-UnattendResources -resourcesDir $resourcesDir -imageInstallationType $image.ImageInstallationType
				Copy-CustomResources -ResourcesDir $resourcesDir -CustomResources $windowsImageConfig.custom_resources_path `
									 -CustomScripts $windowsImageConfig.custom_scripts_path
				Copy-Item $ConfigFilePath "$resourcesDir\config.ini"
				if ($windowsImageConfig.enable_custom_wallpaper) {
					Set-WindowsWallpaper -WinDrive $winImagePath -WallpaperPath $windowsImageConfig.wallpaper_path `
						-WallpaperSolidColor $windowsImageConfig.wallpaper_solid_color
				}

				Apply-Image -winImagePath $winImagePath -wimFilePath $windowsImageConfig.wim_file_path `
					-imageIndex $image.ImageIndex
				
				if ($windowsImageConfig.startlayout_path) {
					Write-Log "Importing start layout..."
					Import-StartLayout -LayoutPath $windowsImageConfig.startlayout_path -MountPath $winImagePath
					Write-Log "Start layout imported into image."
				}
					
				Create-BCDBootConfig -systemDrive $drives[0] -windowsDrive $drives[1] -image $image
				Check-EnablePowerShellInImage $winImagePath $image

				if ($windowsImageConfig.drivers_path -and (Test-Path $windowsImageConfig.drivers_path)) {
					Add-DriversToImage $winImagePath $windowsImageConfig.drivers_path
				}
				if ($windowsImageConfig.extra_features) {
					Enable-FeaturesInImage $winImagePath $windowsImageConfig.extra_features
				}
				if ($windowsImageConfig.extra_packages) {
					foreach ($package in $windowsImageConfig.extra_packages.split(",")) {
						Add-PackageToImage $winImagePath $package -ignoreErrors $windowsImageConfig.extra_packages_ignore_errors
					}
				}
				if ($windowsImageConfig.extra_capabilities) {
					Add-CapabilitiesToImage $winImagePath $windowsImageConfig.extra_capabilities
				}
				if ($windowsImageConfig.clean_updates_offline) {
					Clean-WindowsUpdates $winImagePath -PurgeUpdates $windowsImageConfig.purge_updates
				}

				Optimize-Volume -DriveLetter $drives[1].replace(":","") -Defrag -ReTrim -SlabConsolidate
			} finally {
				if (Test-Path $imagePath) {
					Detach-VirtualDisk $imagePath
				}
			}		
		}
		finally {
			if($mountedWindowsIso){
				$mountedWindowsIso.DetachVirtualDisk()
			}
		}
			
		$VMName = "WindowsOnlineImage-Sysprep" + (Get-Random)	
		
		Write-Log "Creating VM $VMName attached to $VMSwitch"
		New-VM -Name $VMName -MemoryStartupBytes $windowsImageConfig.ram_size -SwitchName $VMSwitch.Name `
			-VhdPath $imagePath -Generation 2 | Out-Null
		Set-VMProcessor -VMname $VMName -count $windowsImageConfig.cpu_count | Out-Null
		
		Set-VMMemory -VMname $VMName -DynamicMemoryEnabled:$false | Out-Null
		$vmAutomaticCheckpointsEnabledWrapper = (Get-VM -Name $VMName) | Select-Object 'AutomaticCheckpointsEnabled' `
			-ErrorAction SilentlyContinue
		$vmAutomaticCheckpointsEnabled = $false
		if ($vmAutomaticCheckpointsEnabledWrapper) {
		   $vmAutomaticCheckpointsEnabled = $vmAutomaticCheckpointsEnabledWrapper.AutomaticCheckpointsEnabled
		}
		if ($vmAutomaticCheckpointsEnabled) {
		   Set-VM -VMName $VMName -AutomaticCheckpointsEnabled:$false
		}
		Write-Log "Starting $VMName"
		Start-VM $VMName | Out-Null
		Start-Sleep 5
		Wait-ForVMShutdown $VMName
		Remove-VM $VMName -Confirm:$false -Force
			
    } catch {
        Write-Log $_
        if ($windowsImageConfig.image_path -and (Test-Path $windowsImageConfig.image_path)) {
            Remove-Item -Force $windowsImageConfig.image_path -ErrorAction SilentlyContinue
        }
        Throw
    }
	
    Write-Log "Windows image generation finished. Image path: $($windowsImageConfig.image_path)"
}

Export-ModuleMember New-BaseWindowsImage, Get-WindowsImageConfig, New-WindowsImageConfig, Get-WimFileImagesInfo
