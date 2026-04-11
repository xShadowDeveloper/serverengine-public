# - - - - - PowerShell - - - - - #


# This prepares Windows Package Manager (WinGet) for automated software 
# deployment through ServerEngine. It ensures WinGet is properly installed, 
# configured, and functional for enterprise software management.
# Credits: Based on work from: https://github.com/asheroto/winget-install/blob/master/winget-install.ps1
#----------------------------------------------------------------------
# After successfully running this, you are ready to use 
# ServerEngine software deployment
#----------------------------------------------------------------------
# Requires Administrator privilegues

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm) {
    Write-Host "<WRITE-LOG = ""*Please run ServerEngine as Administrator.*"">"
    Write-Host "<WRITE-LOG = ""*If this was a remote execution please provide Administrator credentials.*"">"
    Write-Error "Warning: Not running as Administrator."
}

$Force = $false
$ForceClose = $false
$AlternateInstallMethod = $false
$Wait = $false
$NoExit = $false
$Version = $false
$Help = $false

if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Source -Full
    exit 0
}

if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $PSVersionTable
    Get-Host
}

if ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug']) {
    $DebugPreference = 'Continue'
    $ConfirmPreference = 'None'
}

$RunAsSystem = $false
if ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -match "NT AUTHORITY\\SYSTEM") {
    $RunAsSystem = $true
}

function Find-WinGet {
    try {
        $WinGetPathToResolve = Join-Path -Path $ENV:ProgramFiles -ChildPath 'WindowsApps\Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe'
        $ResolveWinGetPath = Resolve-Path -Path $WinGetPathToResolve -ErrorAction Stop | Sort-Object {
            [version]($_.Path -replace '^[^\d]+_((\d+\.)*\d+)_.*', '$1')
        }
        if ($ResolveWinGetPath) {
            $WinGetPath = $ResolveWinGetPath[-1].Path
        }
        $WinGet = Join-Path $WinGetPath 'winget.exe'
        if (Test-Path -Path $WinGet) {
            return $WinGet
        } else {
            return $null
        }
    } catch {
        return $null
    }
}

function Get-OSInfo {
    [CmdletBinding()]
    param ()

    try {
        $registryValues = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $releaseIdValue = $registryValues.ReleaseId
        $displayVersionValue = $registryValues.DisplayVersion
        $nameValue = $registryValues.ProductName
        $editionIdValue = $registryValues.EditionId
        $editionIdValue = $editionIdValue -replace "Server", ""

        try {
            $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        } catch {
            throw "Unable to run Get-CimInstance."
        }

        $nameValue = $osDetails.Caption
        $architecture = ($osDetails.OSArchitecture -replace "[^\d]").Trim()
        if ($architecture -eq "32") {
            $architecture = "x32"
        } elseif ($architecture -eq "64") {
            $architecture = "x64"
        }

        $versionValue = [System.Environment]::OSVersion.Version

        if ($osDetails.ProductType -eq 1) {
            $typeValue = "Workstation"
        } elseif ($osDetails.ProductType -eq 2 -or $osDetails.ProductType -eq 3) {
            $typeValue = "Server"
        } else {
            $typeValue = "Unknown"
        }

        $numericVersion = ($nameValue -replace "[^\d]").Trim()
        if ($numericVersion -ge 10 -and $osDetails.Caption -match "multi-session") {
            $typeValue = "Workstation"
        }

        $result = [PSCustomObject]@{
            ReleaseId      = $releaseIdValue
            DisplayVersion = $displayVersionValue
            Name           = $nameValue
            Type           = $typeValue
            NumericVersion = $numericVersion
            EditionId      = $editionIdValue
            Version        = $versionValue
            Architecture   = $architecture
        }

        return $result
    } catch {
        Write-Error "Unable to get OS version details."
        ExitWithDelay 1
    }
}

function Get-GitHubRelease {
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )

    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop
        $latestVersion = $response.tag_name
        $publishedAt = $response.published_at
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()
        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Unable to check for updates."
        exit 1
    }
}

function Get-WingetDownloadUrl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Match
    )

    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"
    $releases = Invoke-RestMethod -uri $uri -Method Get -ErrorAction Stop
    foreach ($release in $releases) {
        if ($release.name -match "preview") {
            continue
        }
        $data = $release.assets | Where-Object name -Match $Match
        if ($data) {
            return $data.browser_download_url
        }
    }
    $latestRelease = $releases | Select-Object -First 1
    $data = $latestRelease.assets | Where-Object name -Match $Match
    return $data.browser_download_url
}

function Get-WingetStatus {
    if ($RunAsSystem) {
        $wingetPath = Find-WinGet
        if ($null -ne $wingetPath) {
            $winget = & $wingetPath -v
        } else {
            $winget = $null
        }
    } else {
        $winget = Get-Command -Name winget -ErrorAction SilentlyContinue
    }

    if ($null -ne $winget -and $winget -notlike '*failed to run*') {
        return $true
    }

    return $false
}

function Handle-Error {
    param($ErrorRecord)

    $OriginalErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    if ($ErrorRecord.Exception.Message -match '0x80073D06') {
        Write-Warning "Higher version already installed."
        Write-Warning "That's okay, continuing..."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF0') {
        Write-Warning "Same version already installed."
        Write-Warning "That's okay, continuing..."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073D02') {
        Write-Warning "Resources modified are in-use. Try closing Windows Terminal / PowerShell / Command Prompt and try again."
        Write-Warning "Run the script with the -ForceClose parameter which will relaunch the script in conhost.exe."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF3') {
        Write-Warning "Problem with one of the prerequisites."
        Write-Warning "Try running the script again or with the -ForceClose parameter."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF9') {
        Write-Warning "Registering winget failed with error code 0x80073CF9."
        Write-Warning "The SYSTEM account may not work. Run using an Administrator account."
    } elseif ($ErrorRecord.Exception.Message -match 'Unable to connect to the remote server') {
        Write-Warning "Cannot connect to the Internet to download the required files."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match "The remote name could not be resolved") {
        Write-Warning "Cannot connect to the Internet to download the required files."
    } else {
        return $ErrorRecord
    }

    $ErrorActionPreference = $OriginalErrorActionPreference
}

function Get-CurrentProcess {
    $oldTitle = $host.ui.RawUI.WindowTitle
    $tempTitle = ([Guid]::NewGuid())
    $host.ui.RawUI.WindowTitle = $tempTitle
    Start-Sleep 1
    $currentProcess = Get-Process | Where-Object { $_.MainWindowTitle -eq $tempTitle }
    $currentProcess = [PSCustomObject]@{
        Name = $currentProcess.Name
        Id   = $currentProcess.Id
    }
    $host.ui.RawUI.WindowTitle = $oldTitle
    return $currentProcess
}

function ExitWithDelay {
    param (
        [int]$ExitCode,
        [int]$Seconds = 10
    )

    if ($Wait) {
        Write-Output "`nWaiting for $Seconds seconds before exiting..."
        Start-Sleep -Seconds $Seconds
    }

    if ($NoExit) {
        Write-Output "Script completed. Pausing indefinitely. Press any key to exit..."
        Read-Host
    }

    if ($MyInvocation.CommandOrigin -eq "Runspace") {
        Break
    } else {
        Exit $ExitCode
    }
}

function Import-GlobalVariable {
    [CmdletBinding()]
    param(
        [string]$VariableName
    )

    try {
        $globalValue = Get-Variable -Name $VariableName -ValueOnly -Scope Global -ErrorAction Stop
        Set-Variable -Name $VariableName -Value $globalValue -Scope Script
    } catch {}
}

function Test-AdminPrivileges {
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $true
    }
    return $false
}

Function New-TemporaryFile2 {
    $tempPath = [System.IO.Path]::GetTempPath()
    $tempFile = [System.IO.Path]::Combine($tempPath, [System.IO.Path]::GetRandomFileName())
    $null = New-Item -Path $tempFile -ItemType File -Force
    return $tempFile
}

function Path-ExistsInEnvironment {
    param (
        [string]$PathToCheck,
        [string]$Scope = 'Both'
    )

    $pathExists = $false
    if ($Scope -eq 'User' -or $Scope -eq 'Both') {
        $userEnvPath = $env:PATH
        if (($userEnvPath -split ';').Contains($PathToCheck)) {
            $pathExists = $true
        }
    }

    if ($Scope -eq 'System' -or $Scope -eq 'Both') {
        $systemEnvPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)
        if (($systemEnvPath -split ';').Contains($PathToCheck)) {
            $pathExists = $true
        }
    }

    return $pathExists
}

function Add-ToEnvironmentPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PathToAdd,
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'System')]
        [string]$Scope
    )

    if (-not (Path-ExistsInEnvironment -PathToCheck $PathToAdd -Scope $Scope)) {
        if ($Scope -eq 'System') {
            $systemEnvPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine)
            $systemEnvPath += ";$PathToAdd"
            [System.Environment]::SetEnvironmentVariable('PATH', $systemEnvPath, [System.EnvironmentVariableTarget]::Machine)
        } elseif ($Scope -eq 'User') {
            $userEnvPath = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User)
            $userEnvPath += ";$PathToAdd"
            [System.Environment]::SetEnvironmentVariable('PATH', $userEnvPath, [System.EnvironmentVariableTarget]::User)
        }
        if (-not ($env:PATH -split ';').Contains($PathToAdd)) {
            $env:PATH += ";$PathToAdd"
        }
    }
}

function Set-PathPermissions {
    param (
        [string]$FolderPath
    )

    $administratorsGroupSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $administratorsGroup = $administratorsGroupSid.Translate([System.Security.Principal.NTAccount])
    $acl = Get-Acl -Path $FolderPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $administratorsGroup,
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $FolderPath -AclObject $acl
}

function Test-VCRedistInstalled {
    $64BitOS = [System.Environment]::Is64BitOperatingSystem
    $64BitProcess = [System.Environment]::Is64BitProcess

    if ($64BitOS -and -not $64BitProcess) {
        Throw 'Please run PowerShell in the system native architecture.'
    }

    $registryPath = [string]::Format(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\{0}\Microsoft\VisualStudio\14.0\VC\Runtimes\X{1}',
        $(if ($64BitOS -and $64BitProcess) { 'WOW6432Node' } else { '' }),
        $(if ($64BitOS) { '64' } else { '86' })
    )

    $registryExists = Test-Path -Path $registryPath
    $majorVersion = if ($registryExists) {
        (Get-ItemProperty -Path $registryPath -Name 'Major').Major
    } else {
        0
    }

    $version = if ($registryExists) {
        (Get-ItemProperty -Path $registryPath -Name 'Version').Version
    } else {
        0
    }

    $dllPath = [string]::Format(
        '{0}\system32\concrt140.dll',
        $env:windir
    )
    $dllExists = [System.IO.File]::Exists($dllPath)

    return $registryExists -and $majorVersion -eq 14 -and $dllExists
}

function TryRemove {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        if (Test-Path -Path $FilePath) {
            Remove-Item -Path $FilePath -ErrorAction SilentlyContinue
        }
    } catch {}
}

function Install-NuGetIfRequired {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            try { 
                Install-PackageProvider -Name "NuGet" -Force -ForceBootstrap -ErrorAction SilentlyContinue | Out-Null 
            } catch {}
        }
    }
}

function Get-ManifestVersion {
    param(
        [Parameter(Mandatory)]
        [string]$Lib_Path
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Lib_Path)
    $entry = $zip.Entries | Where-Object { $_.FullName -eq "AppxManifest.xml" }
    if ($entry) {
        $stream = $entry.Open()
        $reader = New-Object System.IO.StreamReader($stream)
        [xml]$xml = $reader.ReadToEnd()
        $reader.Close()
        $zip.Dispose()
        $DownloadedLibVersion = $xml.Package.Identity.Version
        return $DownloadedLibVersion
    } else {
        Write-Error "AppxManifest.xml not found."
    }
}

function Get-InstalledLibVersion {
    param(
        [Parameter(Mandatory)]
        [string]$Lib_Name
    )

    $InstalledLib = Get-AppxPackage -Name "*$($Lib_Name)*" -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
    if ($InstalledLib) {
        $InstalledLibVersion = $InstalledLib.Version
        return $InstalledLibVersion
    } else {
        $InstalledLibVersion = $null
        return $InstalledLibVersion
    }
}

function Install-LibIfRequired {
    param(
        [Parameter(Mandatory)]
        [string]$Lib_Name,
        [Parameter(Mandatory)]
        [string]$Lib_Path
    )

    $InstalledLibVersion = Get-InstalledLibVersion -Lib_Name $Lib_Name
    $DownloadedLibVersion = Get-ManifestVersion -Lib_Path $Lib_Path
    if (!$InstalledLibVersion -or !$DownloadedLibVersion -or ($DownloadedLibVersion -gt $InstalledLibVersion)) {
        if ($RunAsSystem) {
            $null = Add-ProvisionedAppxPackage -Online -SkipLicense -PackagePath $Lib_Path
        } else {
            $null = Add-AppxPackage -Path $Lib_Path
        }
    }
}

Import-GlobalVariable -VariableName "Debug"
Import-GlobalVariable -VariableName "ForceClose"
Import-GlobalVariable -VariableName "Force"
Import-GlobalVariable -VariableName "AlternateInstallMethod"

Write-Host "<WRITE-LOG = ""*Checking WinGet Envirement...*"">"

if (-not (Test-AdminPrivileges)) {
    Write-Warning "Run the script as an Administrator."
    ExitWithDelay 1
}

$osVersion = Get-OSInfo
$arch = $osVersion.Architecture
$currentProcess = Get-CurrentProcess

if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -lt 10) {
    Write-Error "Requires Windows 10 or later."
    ExitWithDelay 1
}

if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10 -and $osVersion.ReleaseId -lt 1809) {
    Write-Error "Requires Windows 10 version 1809 or later."
    ExitWithDelay 1
}

if ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -lt 2019) {
    Write-Error "Requires Windows Server 2019 or newer."
    ExitWithDelay 1
}

if (Get-WingetStatus) {
    if ($Force -eq $false) {
        Write-Host "<WRITE-LOG = ""*WinGet is already installed.*"">"
        ExitWithDelay 0 5
    }
}

if ($ForceClose) {
    if ($currentProcess.Name -eq "WindowsTerminal") {
        Start-Sleep -Seconds 10
        $command = "cd '$pwd'; $($MyInvocation.Line)"
        if ($Force -and !($command -imatch '\s-Force\b')) { $command += " -Force" }
        if ($ForceClose -and !($command -imatch '\s-ForceClose\b')) { $command += " -ForceClose" }
        if ($Debug -and !($command -imatch '\s-Debug\b')) { $command += " -Debug" }
        if ([Environment]::Is64BitOperatingSystem) {
            if ([Environment]::Is64BitProcess) {
                Start-Process -FilePath "conhost.exe" -ArgumentList "powershell -ExecutionPolicy Bypass -Command &{$command}" -Verb RunAs
            } else {
                Start-Process -FilePath "$env:windir\sysnative\conhost.exe" -ArgumentList "powershell -ExecutionPolicy Bypass -Command &{$command}" -Verb RunAs
            }
        } else {
            Start-Process -FilePath "conhost.exe" -ArgumentList "powershell -ExecutionPolicy Bypass -Command &{$command}" -Verb RunAs
        }
        Stop-Process -id $currentProcess.Id
    }
}

try {
    if ($osVersion.NumericVersion -ne 2019 -and $AlternateInstallMethod -eq $false -and $RunAsSystem -eq $false) {
        try {
            Install-NuGetIfRequired
            Write-Host "<WRITE-LOG = ""*Installing Microsoft.WinGet.Client module...*"">"
            try { Install-Module -Name Microsoft.WinGet.Client -Force -AllowClobber -Repository PSGallery -ErrorAction SilentlyContinue *>&1 | Out-Null } catch { }
            Write-Host "<WRITE-LOG = ""*Installing WinGet...*"">"
            try { Repair-WinGetPackageManager -AllUsers -Force -Latest *>&1 | Out-Null } catch { }
        } catch {
            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) { throw $errorHandled }
        }
        Add-ToEnvironmentPath -PathToAdd "%LOCALAPPDATA%\Microsoft\WindowsApps" -Scope 'User'
    }

    if (($osVersion.Type -eq "Server" -and ($osVersion.NumericVersion -eq 2019)) -or $AlternateInstallMethod -or $RunAsSystem) {
        try {
            $winget_dependencies_path = New-TemporaryFile2
            $winget_dependencies_url = Get-WingetDownloadUrl -Match 'DesktopAppInstaller_Dependencies.zip'
            Write-Host "<WRITE-LOG = ""*Downloading WinGet dependencies...*"">"
            Invoke-WebRequest -Uri $winget_dependencies_url -OutFile $winget_dependencies_path
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($winget_dependencies_path)
            $matchingEntries = $zip.Entries | Where-Object { $_.FullName -match ".*$arch.appx" }
            if ($matchingEntries) {
                $matchingEntries | ForEach-Object {
                    $destPath = Join-Path ([System.IO.Path]::GetTempPath()) $_.Name
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $destPath, $true)
                    if ($_.Name -like '*.VCLibs.140.00.UWPDesktop*.appx') { $VCLibs_Path = $destPath }
                    if ($_.Name -like '*.UI.Xaml.2.8*.appx') { $UIXaml_Path = $destPath }
                }
                $zip.Dispose()
            } else {
                Write-Error "Dependency not found."
            }
            Write-Output "Installing VCLibs.140.00.UWPDesktop..."
            Install-LibIfRequired -Lib_Name 'VCLibs.140.00.UWPDesktop' -Lib_Path $VCLibs_Path
            Write-Output ""
            Write-Output "Installing UI.Xaml.2.8..."
            Install-LibIfRequired -Lib_Name 'UI.Xaml.2.8' -Lib_Path $UIXaml_Path
            TryRemove $winget_dependencies_path
            TryRemove $VCLibs_Path
            TryRemove $UIXaml_Path
        } catch {
            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) { throw $errorHandled }
        }

        try {
            $winget_license_path = New-TemporaryFile2
            $winget_license_url = Get-WingetDownloadUrl -Match "License1.xml"
            Write-Host "<WRITE-LOG = ""*Downloading winget license...*"">"
            Invoke-WebRequest -Uri $winget_license_url -OutFile $winget_license_path
            $winget_path = New-TemporaryFile2
            $winget_url = Get-WingetDownloadUrl -Match 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
            Write-Host "<WRITE-LOG = ""*Downloading WinGet...*"">"
            Invoke-WebRequest -Uri $winget_url -OutFile $winget_path
            Write-Host "<WRITE-LOG = ""*Installing WinGet...*"">"
            Add-AppxProvisionedPackage -Online -PackagePath $winget_path -LicensePath $winget_license_path | Out-Null
            TryRemove $winget_path
            TryRemove $winget_license_path
        } catch {
            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) { throw $errorHandled }
        }

        if (!(Test-VCRedistInstalled)) {
            $VCppRedistributable_Url = "https://aka.ms/vs/17/release/vc_redist.${arch}.exe"
            $VCppRedistributable_Path = New-TemporaryFile2
            Write-Output "Downloading Visual C++ Redistributable..."
            Invoke-WebRequest -Uri $VCppRedistributable_Url -OutFile $VCppRedistributable_Path
            $VCppRedistributableExe_Path = $VCppRedistributable_Path + ".exe"
            Rename-Item -Path $VCppRedistributable_Path -NewName $VCppRedistributableExe_Path
            Write-Output "Installing Visual C++ Redistributable..."
            Start-Process -FilePath $VCppRedistributableExe_Path -ArgumentList "/install", "/quiet", "/norestart" -Wait
            TryRemove $VCppRedistributableExe_Path
        } else {
            Write-Output "Visual C++ Redistributable is already installed."
        }

        Write-Host "<WRITE-LOG = ""*Fixing permissions for WinGet folder...*"">"
        $WinGetFolderPath = (Get-ChildItem -Path ([System.IO.Path]::Combine($env:ProgramFiles, 'WindowsApps')) -Filter "Microsoft.DesktopAppInstaller_*_${arch}__8wekyb3d8bbwe" | Sort-Object Name | Select-Object -Last 1).FullName
        if ($null -ne $WinGetFolderPath) {
            Set-PathPermissions -FolderPath $WinGetFolderPath
            Add-ToEnvironmentPath -PathToAdd $WinGetFolderPath -Scope 'System'
        } else {
            Write-Warning "winget folder path not found."
        }
    }

    Write-Host "<WRITE-LOG = ""*Registering WinGet...*"">"
	try {
    	if ($osVersion.NumericVersion -ne 2019 -and $RunAsSystem -eq $false) {
        	# First try the family name registration
        	try {
            	Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
        	} catch {
            	Write-Host "<WRITE-LOG = ""*Family name registration failed, trying alternative method...*"">"
            
            	# Find the actual package path and register it directly
            	$packagePath = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Directory -Filter "Microsoft.DesktopAppInstaller_*_*__8wekyb3d8bbwe" | 
            	               Sort-Object Name -Descending | 
                	           Select-Object -First 1 -ExpandProperty FullName
            
            	if ($packagePath) {
                	$manifestPath = Join-Path $packagePath "AppxManifest.xml"
                	if (Test-Path $manifestPath) {
                    	Write-Host "<WRITE-LOG = ""*Registering package from: $packagePath*"">"
                    	Add-AppxPackage -Register -DisableDevelopmentMode -RegisterPath $manifestPath -ErrorAction Stop
                	} else {
                    	throw "Manifest not found at $manifestPath"
                	}
            	} else {
                	throw "Could not find WinGet package installation directory"
            	}
        	}
    	}
    
    	# Verify registration was successful
    	$registered = Get-AppxPackage -Name "Microsoft.DesktopAppInstaller" -ErrorAction SilentlyContinue
    	if ($registered) {
        	Write-Host "<WRITE-LOG = ""*WinGet registered successfully.*"">"
    	} else {
        	Write-Warning "WinGet package may not be properly registered"
    	}
	} catch {
    	Write-Warning "Failed to register WinGet: $($_.Exception.Message)"
    
    	# Try one more method - repair using winget module if available
    	try {
        	Write-Host "<WRITE-LOG = ""*Attempting repair via Repair-WinGetPackageManager...*"">"
        	Import-Module Microsoft.WinGet.Client -ErrorAction SilentlyContinue
        	Repair-WinGetPackageManager -AllUsers -ErrorAction SilentlyContinue
    	} catch {
        	# Silently continue if this also fails
    	}
	}

    Write-Host "<WRITE-LOG = ""*WinGet installed.*"">"
    Write-Host "<WRITE-LOG = ""*Checking if WinGet is working..*"">"

    Start-Sleep -Seconds 3
    if (Get-WingetStatus -eq $true) {
        Write-Host "<WRITE-LOG = ""*WinGet is working.*"">"

        if ($RunAsSystem) {
            Write-Output "Restart may be required under SYSTEM context."
        }
    } else {
        if (Get-WingetStatus -ne $true) {
            Write-Warning "WinGet command not detected. Wait 1 minute or restart computer."
        }
    }

    ExitWithDelay 0
} catch {
    Write-Warning "See troubleshooting guide: https://github.com/asheroto/winget-install#troubleshooting"
    Write-Warning "Check for updates: $PowerShellGalleryName -CheckForUpdate"
    if ($_.Exception.Message -notmatch '0x80073D02') {
        if ($Debug) { Write-Warning "Line number : $($_.InvocationInfo.ScriptLineNumber)" }
        Write-Warning "Error: $($_.Exception.Message)`n"
    }
    ExitWithDelay 1
}

# SIG # Begin signature block
# MIIc1QYJKoZIhvcNAQcCoIIcxjCCHMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUKeP8EpyD15nyNcR/EwFS1k4C
# glOgghdDMIIEBTCCAu2gAwIBAgITFAAAAAIukB1TwGOSTQAAAAAAAjANBgkqhkiG
# 9w0BAQsFADAaMRgwFgYDVQQDEw9TZXJ2ZXJFbmdpbmUtQ0EwHhcNMjYwMzIxMTAw
# NDU4WhcNMjcwMzIxMTAxNDU4WjA/MRkwFwYDVQQDExBTZXJ2ZXJFbmdpbmUgTExD
# MSIwIAYJKoZIhvcNAQkBFhNjZW9Ac2VydmVyZW5naW5lLmNvMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs0CxL4QDnvoOI5CnSDWEYLe8WdMUb6lrJ7XM
# aCDo4F7X8qDT+1w9hQrh4kNljlbowSS1jlEwK3to75fpRljDzDGN6a6cm0WUW49c
# dL8iK3U/ryrBUjbf2Ln8o1Gs7wcwabK1c28u1p9TJBrNgkd4RImnlHoysOS5RbdS
# 2aakN+nrAa9K70ak72MSZVM9DMe1tzeWBs1LZ78hA8MC3KncRn6HpqrMvPz5gUZm
# 2SQJ/LEwrdjI4mVUX9P7CGkipfGJiWMDzh5cM1wf1/QhoGvr8sCjy5Y67HaA/cOD
# TU1yN5QUn5VH9kGAD9/JDG64CyI1GNVrjsCGXhXaT4llm53tIQIDAQABo4IBHTCC
# ARkwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1Ud
# DgQWBBTi3EGZG11SOoD+soLbyLIqMnOwUzAfBgNVHSMEGDAWgBStSs/V0ivjZHyV
# iFt4ptEbhKzQhTBEBgNVHR8EPTA7MDmgN6A1hjNmaWxlOi8vLy9XSU4tU1JWLUFa
# MS9DZXJ0RW5yb2xsL1NlcnZlckVuZ2luZS1DQS5jcmwwWwYIKwYBBQUHAQEETzBN
# MEsGCCsGAQUFBzAChj9maWxlOi8vLy9XSU4tU1JWLUFaMS9DZXJ0RW5yb2xsL1dJ
# Ti1TUlYtQVoxX1NlcnZlckVuZ2luZS1DQS5jcnQwDAYDVR0TAQH/BAIwADANBgkq
# hkiG9w0BAQsFAAOCAQEAV+xG1rHc8K79QN7jQZviYjgj8/Ca7S/htlJ5PCZYFEkZ
# nmALbuIbgFB4QQXwaCy9CxwJpsI0LQQIWNc27c1xuteuHIFIMdC5NPQ8ENR+n0h/
# 7T3Xtr/poGgOO6na7vGHKKZioXGhzM0pqurXK2rbyaKCwjxP1KRSri0IzDzRA/k4
# zbeBHNxIGpvSYK+eQWd7fbhY9U8fIO412YB0/0RheNg5qwfyTPNR3GPj0AkXTYLq
# GuKZW798r//N8iSHeS0B8ODOS8Q7g+TZUO/FGGjpdwIcLjpTGxzIWXVMaklUx7Mw
# 33TClGHbymLXZPo3ORlqrWe5Ii2h+245H5Qx7HN+nzCCBY0wggR1oAMCAQICEA6b
# GI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEk
# MCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAw
# MDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2u
# exuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKv
# aJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/gh
# YZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOt
# yU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCR
# cKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8
# oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m
# 1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y
# 1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkl
# iWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/E
# IFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOC
# ATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/n
# upiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB
# /wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqg
# OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEA
# cKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU
# 9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0Sb
# QyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1Rmpp
# VLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxY
# oA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0Vys
# GMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYw
# DQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNl
# cnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1
# OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4
# MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6
# c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3
# SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVST
# EG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpq
# umzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJ
# yUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/Gcal
# NeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8A
# w4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/n
# J0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA
# 6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2ba
# oD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNV
# HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAf
# BgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMG
# A1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCH
# xYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdh
# OP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDC
# vwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B
# 0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWG
# NqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRN
# ivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02Oo
# XN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy
# 4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2w
# L40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQt
# yRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2
# zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3
# DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFB
# MD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5
# NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5
# WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIg
# MjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDq
# rmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dn
# xk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5Kyyn
# eqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V
# 1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSy
# i5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77e
# pTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yep
# yekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A9
# 0/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtIt
# nj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1
# Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpF
# Hti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQC
# MAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9v
# U0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5
# NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQw
# OTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2
# Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGB
# vg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bO
# ySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAE
# cxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5i
# QMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwq
# xv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjt
# P+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMF
# zGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjF
# jLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8
# gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01
# c4IhSOxqt81nMYIE/DCCBPgCAQEwMTAaMRgwFgYDVQQDEw9TZXJ2ZXJFbmdpbmUt
# Q0ECExQAAAACLpAdU8Bjkk0AAAAAAAIwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcC
# AQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYB
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMdl6lXuMtEc
# NjJcUU+d83HY77ZnMA0GCSqGSIb3DQEBAQUABIIBAKxDiKuG3v/92bAW4f7R/t27
# MnCUp6VD296fxMvYTNG6ssvrHfMc2pQ2707bbm21UJOaZL/hD7xZkaed7ABDVtJ5
# b7vubO00xQxB/R2BBKzSS5e31crdlsCGkc88tZBZcLQIyn1w7Sl/ZNQ98cdhMyjj
# zOzD3ap2FYdOYE8Q5+M59lfly9iKGW8jVltMrK0L3yqNq64EP5k44SW2besVqDOK
# usICHT9p/Kohk3Q5gnxc4K5jA/HFIEHrcKLE+qzg7Zo6n7X3bYPfNWWxu8SaJxx6
# BWeIhgN9H3zMlXR17NTpkilIwNRFaJnoA4inKnnP6oM5WDKalfVPkzPMt/qxpgOh
# ggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqG
# SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMzI1MTczMDMwWjAvBgkqhkiG9w0B
# CQQxIgQgPUYgbo3nE1cvHj6ybB1EQ5Bn6VoHTNZZlkNIwqrp04gwDQYJKoZIhvcN
# AQEBBQAEggIAlh/BaRvO5QJNs1eCRnSDCLIE9VR6nUMGacqkQ56MpYSV5Wx93DST
# oEkc/SaLw0ZHSPmypab4e3uET3XT59r8r/FwWiC4yHc79/EpX4Uo/wW8ug2BqtL9
# I5zyrPp7Zg2Q5AUCT+c522mvhdrivdMbBL0rDVfTQWeP3GBysRalD/J0s+J85tXf
# CEGPQ4WEzyLQ2v2syTq2V30UNwriyeEIxu6QHAkVOBZV391y9AaRa6LbMDVk8kAI
# /GtPdadbn+vxhPO2txLT4H4aW1UI7h8Xudp6n6Clt6q2ynelAn86I7NrTQBR4BJ2
# Kjsiz0uNYBaL7ox2Cr/AAYrJsUNlKscuN7IHnplo2Fa6OoPh3W9OBXj4xtDyi9Tn
# 52gjlZe8B14LARwn9HO+AxBUmYqvRJD9qStftoOUdgX6TSbyt/QCtnSDgyiXf7KO
# ctc9uCJJKQgom/H6tvTBl6+p4UOMlUkuxuddi5jtBuOfrw54MlVqG+Kc30Z8ZATC
# U2mV//oiE1f4pmSz2PrQC2gHRDV3YTMtxJE5o/l9m0H7W7oC0tsydSy6SczbTjTM
# R5c2XMylEjMm+7kf/WByt/UT5/N/b3yWEq6UgE6QeNNLmywwdf01V7OyGjR2vAy5
# Nq8aHMJos0+KWVRGunGspT0SkSJFCTgMe1hMiXGlNyDrPr1GFzF8mww=
# SIG # End signature block
