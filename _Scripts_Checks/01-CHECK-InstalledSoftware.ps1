# Discover Installed Applications
#-------------------------------------------

# Get Installed Programs (Win32)
Write-Host "`n=== Installed Win32 Programs (Control Panel) ===" -ForegroundColor Cyan
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize

# Get Installed Microsoft Store (UWP) Apps
Write-Host "`n=== Installed Microsoft Store (UWP) Apps ===" -ForegroundColor Cyan
Get-AppxPackage | 
Select-Object Name, PackageFullName, Version | Sort-Object Name | Format-Table -AutoSize
	
