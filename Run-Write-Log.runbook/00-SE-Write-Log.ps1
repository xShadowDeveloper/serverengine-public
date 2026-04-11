# Gather Useful Computer Information
#-----------------------------------------------------------

function Write-Log {
    param($Message)
    Write-Host "<WRITE-LOG = `"*$Message*`">"
}

Write-Log "Starting Computer Information Collection"

# OS Information
Write-Log "--- Operating System ---"
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Log "OS Name: $($osInfo.Caption)"
Write-Log "OS Version: $($osInfo.Version)"
Write-Log "OS Build: $($osInfo.BuildNumber)"
Write-Log "Architecture: $($osInfo.OSArchitecture)"
Write-Log "Install Date: $($osInfo.InstallDate)"
Write-Log "Last Boot Time: $($osInfo.LastBootUpTime)"
Write-Log "System Directory: $($osInfo.SystemDirectory)"

# System (Computer) Info
Write-Log "--- System ---"
$sysInfo = Get-CimInstance -ClassName Win32_ComputerSystem
Write-Log "Computer Name: $($sysInfo.Name)"
Write-Log "Domain: $($sysInfo.Domain)"
Write-Log "Role: $($sysInfo.Roles -join ', ')"
Write-Log "System Type: $($sysInfo.SystemType)"
Write-Log "Manufacturer: $($sysInfo.Manufacturer)"
Write-Log "Model: $($sysInfo.Model)"

# BIOS Serial Number (separate query to ensure accuracy)
Write-Log "--- System Serial ---"
$serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
Write-Log "Serial Number: $serial"

# CPU
Write-Log "--- Processor ---"
$cpu = Get-CimInstance -ClassName Win32_Processor
Write-Log "Name: $($cpu.Name)"
Write-Log "Manufacturer: $($cpu.Manufacturer)"
Write-Log "Cores: $($cpu.NumberOfCores)"
Write-Log "Logical Processors: $($cpu.NumberOfLogicalProcessors)"
Write-Log "Max Clock Speed: $($cpu.MaxClockSpeed) MHz"

# Memory
Write-Log "--- Memory (RAM) ---"
$mem = Get-CimInstance -ClassName Win32_PhysicalMemory
$totalGB = ($mem | Measure-Object -Property Capacity -Sum).Sum / 1GB
Write-Log "Total RAM: $([math]::Round($totalGB, 1)) GB"
Write-Log "Modules Installed: $($mem.Count)"

# Disk (C: only, as representative)
Write-Log "--- Disk (C:) ---"
$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
Write-Log "Drive: C:\"
Write-Log "Size: $([math]::Round($disk.Size / 1GB, 1)) GB"
Write-Log "Free Space: $([math]::Round($disk.FreeSpace / 1GB, 1)) GB"
Write-Log "File System: $($disk.FileSystem)"
Write-Log "Volume Label: $($disk.VolumeName)"

# BIOS Details
Write-Log "--- BIOS ---"
$bios = Get-CimInstance -ClassName Win32_BIOS
Write-Log "Vendor: $($bios.SMBIOSBIOSVendor)"
Write-Log "Version: $($bios.SMBIOSBIOSVersion)"
Write-Log "Release Date: $($bios.ReleaseDate)"

# Network (first enabled adapter)
Write-Log "--- Network (IPv4) ---"
$net = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | Select-Object -First 1
if ($net) {
    Write-Log "MAC Address: $($net.MACAddress)"
    Write-Log "IP Address: $(if ($net.IPAddress) { $net.IPAddress -join ', ' } else { 'None' })"
    Write-Log "Default Gateway: $(if ($net.DefaultIPGateway) { $net.DefaultIPGateway -join ', ' } else { 'None' })"
} else {
    Write-Log "No active IPv4 network adapters found"
}

Write-Log "Computer Information Collection Complete"
