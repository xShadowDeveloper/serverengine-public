# Discover Installed Applications
#-------------------------------------------
function Write-Log {
    param($Message)
    Write-Host "<WRITE-LOG = `"*$Message*`">"
}

# Get Installed Programs (Win32)
Write-Host "`n=== Installed Win32 Programs (Control Panel) ===" -ForegroundColor Cyan
$logListWin32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName

foreach ($log in $logListWin32) {
    Write-Log $log
}
$logListWin32 | Format-Table -AutoSize

# Get Installed Microsoft Store (UWP) Apps
Write-Host "`n=== Installed Microsoft Store (UWP) Apps ===" -ForegroundColor Cyan
$logListUWP = Get-AppxPackage | 
    Select-Object Name, PackageFullName, Version | Sort-Object Name

foreach ($log in $logListUWP) {
    Write-Log $log
}
$logListUWP | Format-Table -AutoSize
