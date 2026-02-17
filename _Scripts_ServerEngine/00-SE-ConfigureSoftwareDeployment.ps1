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

$Force = $true
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
