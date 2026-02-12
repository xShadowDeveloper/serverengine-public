# Windows 11 Compatibility Check
# This script checks Windows 11 compatibility and generates 
# an HTML report on the desktop, you can change the location 
# to fileshare, see line 768
#---------------------------------------------------------------


# Windows 11 Compatibility Check Script with HTML Report
# This script checks Windows 11 compatibility and generates an HTML report on the desktop

# Function to create HTML report
function New-HTMLReport {
    param(
        [hashtable]$Results,
        [hashtable]$SystemInfo,
        [int]$Passed,
        [int]$Total
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows 11 Compatibility Report</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #2c3e50;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            border-radius: 15px;
            padding: 30px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        
        .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
        }
        
        .summary {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-item {
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            background: #f8f9fa;
        }
        
        .summary-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        

tesetgn: center;
            padding: 20px;
            border-radius: 10px;
            background: #f8f9fa;
        }
        
        .summary-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        

tesetgn: center;
            padding: 20px;
            border-radius: 10px;
            background: #f8f9fa;
        }
        
        .summary-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .summary-label {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        
        .checks-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .check-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        
        .check-card:hover {
            transform: translateY(-5px);
        }
        
        .check-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .check-title {
            font-size: 1.2em;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .status-badge {
            padding: 6px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .status-pass {
            background: #d4edda;
            color: #155724;
        }
        
        .status-fail {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status-warning {
            background: #fff3cd;
            color: #856404;
        }
        
        .check-details {
            color: #7f8c8d;
            font-size: 0.95em;
            line-height: 1.5;
        }
        
        .system-info {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .info-item {
            padding: 10px;
            border-bottom: 1px solid #ecf0f1;
        }
        
        .info-label {
            font-weight: bold;
            color: #2c3e50;
        }
        
        .info-value {
            color: #7f8c8d;
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            color: white;
            font-size: 0.9em;
        }
        
        .progress-bar {
            height: 10px;
            background: #ecf0f1;
            border-radius: 5px;
            margin: 20px 0;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 5px;
            transition: width 0.5s ease;
        }
        
        .progress-pass {
            background: linear-gradient(90deg, #28a745, #20c997);
        }
        
        .progress-warning {
            background: linear-gradient(90deg, #ffc107, #fd7e14);
        }
        
        .recommendation {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin-top: 15px;
            border-radius: 0 8px 8px 0;
        }
        
        @media (max-width: 768px) {
            .checks-grid {
                grid-template-columns: 1fr;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Windows 11 Compatibility Report</h1>
            <p class="subtitle">Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
        
        <div class="summary">
            <h2>Compatibility Summary</h2>
            <div class="progress-bar">
                <div class="progress-fill $(if ($Passed -eq $Total) { 'progress-pass' } else { 'progress-warning' })" style="width: $(($Passed/$Total)*100)%"></div>
            </div>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value" style="color: #28a745;">$Passed</div>
                    <div class="summary-label">Requirements Passed</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #dc3545;">$($Total - $Passed)</div>
                    <div class="summary-label">Requirements Failed</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #007bff;">$Total</div>
                    <div class="summary-label">Total Checks</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value" style="color: #6c757d;">$([math]::Round(($Passed/$Total)*100, 1))%</div>
                    <div class="summary-label">Compatibility Score</div>
                </div>
            </div>
"@

    # Add overall recommendation
    if ($Passed -eq $Total) {
        $html += @"
            <div class="recommendation">
                <strong>🎉 Excellent!</strong> Your device appears to meet all Windows 11 requirements. You should be able to upgrade without issues.
            </div>
"@
    } elseif ($Passed -ge ($Total * 0.7)) {
        $html += @"
            <div class="recommendation">
                <strong>⚠️ Good Compatibility</strong> Your device meets most Windows 11 requirements. Some features may require hardware updates.
            </div>
"@
    } else {
        $html += @"
            <div class="recommendation">
                <strong>❌ Limited Compatibility</strong> Your device may not be eligible for Windows 11. Consider hardware upgrades or check with your manufacturer.
            </div>
"@
    }

    $html += @"
        </div>
        
        <div class="checks-grid">
"@

    # Add check cards
    foreach ($check in $Results.GetEnumerator()) {
        $statusClass = if ($check.Value.Passed) { "status-pass" } else { "status-fail" }
        $statusText = if ($check.Value.Passed) { "PASS" } else { "FAIL" }
        
        $html += @"
            <div class="check-card">
                <div class="check-header">
                    <div class="check-title">$($check.Value.Name)</div>
                    <div class="status-badge $statusClass">$statusText</div>
                </div>
                <div class="check-details">
                    $($check.Value.Details -join "<br>")
                </div>
            </div>
"@
    }

    $html += @"
        </div>
        
        <div class="system-info">
            <h2>System Information</h2>
            <div class="info-grid">
"@

    # Add system information
    foreach ($info in $SystemInfo.GetEnumerator()) {
        $html += @"
                <div class="info-item">
                    <div class="info-label">$($info.Key):</div>
                    <div class="info-value">$($info.Value)</div>
                </div>
"@
    }

    $html += @"
            </div>
        </div>
        
        <div class="footer">
            <p>Report generated by Windows 11 Compatibility Checker</p>
            <p>For more information, visit: <a href="https://www.microsoft.com/en-us/windows/windows-11-specifications" style="color: white;">Microsoft Windows 11 Specifications</a></p>
        </div>
    </div>
</body>
</html>
"@

    return $html
}

# Enhanced UEFI Check Function
function Test-UEFI {
    try {
        $details = @()
        $detectionMethod = ""
        
        # Method 1: Check via firmware type (works on Windows 8/Server 2012 and newer)
        $firmwareType = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty PCSystemType
        if ($firmwareType -eq 2) {
            $details += "UEFI firmware detected (PCSystemType method)"
            $detectionMethod = "Firmware Type"
            return @{Passed = $true; Details = $details; Method = $detectionMethod}
        }
        
        # Method 2: Check Secure Boot status (indicates UEFI)
        $secureBoot = Get-CimInstance -Namespace "Root\StandardCimv2" -ClassName MSFT_SecureBoot -ErrorAction SilentlyContinue
        if ($secureBoot -and $secureBoot.SecureBootEnabled) {
            $details += "UEFI detected via Secure Boot status"
            $detectionMethod = "Secure Boot"
            return @{Passed = $true; Details = $details; Method = $detectionMethod}
        }
        
        # Method 3: Check via BIOS/firmware class
        $bios = Get-CimInstance -ClassName Win32_BIOS
        if ($bios.BIOSVersion -like "*UEFI*" -or $bios.Name -like "*UEFI*") {
            $details += "UEFI detected in BIOS information"
            $detectionMethod = "BIOS Information"
            return @{Passed = $true; Details = $details; Method = $detectionMethod}
        }
        
        # Method 4: Check registry (for older systems)
        $registryUEFI = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
        if ($registryUEFI -ne $null) {
            $details += "UEFI detected via registry method"
            $detectionMethod = "Registry"
            return @{Passed = $true; Details = $details; Method = $detectionMethod}
        }
        
        # Method 5: For VMs - check if it's a VM and use alternative detection
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        if ($computerSystem.Model -like "*Virtual*" -or $computerSystem.Manufacturer -like "*VMware*" -or $computerSystem.Manufacturer -like "*Microsoft*" -or $computerSystem.Manufacturer -like "*Parallels*") {
            $details += "Virtual Machine detected - using alternative UEFI detection"
            
            # For VMs, check if UEFI firmware is reported
            if ($computerSystem -match "UEFI" -or $bios.Description -like "*UEFI*") {
                $details += "UEFI detected in VM environment"
                $detectionMethod = "VM Detection"
                return @{Passed = $true; Details = $details; Method = $detectionMethod}
            }
            
            # Additional VM-specific check
            $baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
            if ($baseboard -and ($baseboard.Product -like "*UEFI*" -or $baseboard.Product -like "*EFI*")) {
                $details += "UEFI detected via VM baseboard information"
                $detectionMethod = "VM Baseboard"
                return @{Passed = $true; Details = $details; Method = $detectionMethod}
            }
        }
        
        $details += "Legacy BIOS detected - UEFI firmware is required for Windows 11"
        $detectionMethod = "Multiple Methods"
        return @{Passed = $false; Details = $details; Method = $detectionMethod}
        
    } catch {
        $details = @("Unable to check UEFI status: $($_.Exception.Message)")
        return @{Passed = $false; Details = $details; Method = "Error"}
    }
}

# Main script execution
Write-Host "Windows 11 Compatibility Check" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Generating compatibility report..." -ForegroundColor Yellow

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Initialize results
$results = @{}
$systemInfo = @{}
$totalChecks = 0
$passedChecks = 0

# Function to add check result
function Add-CheckResult {
    param($Name, $Passed, $Details)
    $results[$Name] = @{
        Name = $Name
        Passed = $Passed
        Details = $Details
    }
    $script:totalChecks++
    if ($Passed) { $script:passedChecks++ }
}

# Check TPM
try {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if ($tpm -and $tpm.TpmPresent) {
        $details = @(
            "TPM is present and enabled",
            "Version: $($tpm.ManufacturerVersionFull)",
            "Ready: $($tpm.TpmReady)"
        )
        Add-CheckResult -Name "TPM 2.0" -Passed $true -Details $details
    } else {
        Add-CheckResult -Name "TPM 2.0" -Passed $false -Details @("TPM 2.0 is required but not detected or enabled")
        Write-Host "<WRITE-LOG = ""*TPM 2.0 is required but not detected or enabled*"">"
    }
} catch {
    Add-CheckResult -Name "TPM 2.0" -Passed $false -Details @("Unable to check TPM: $($_.Exception.Message)")
    Write-Host "<WRITE-LOG = ""*TPM 2.0 is required but not detected or enabled*"">"
}

# Check Secure Boot via Registry (no admin needed)
try {
    $secureBoot = $false
    $details = @()
    
    # Method 1A: Check UEFI Secure Boot status
    $uefiSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue
    if ($uefiSecureBoot -and $uefiSecureBoot.UEFISecureBootEnabled -eq 1) {
        $secureBoot = $true
        $details += "Secure Boot is enabled (Registry method)"
    }
    
    # Method 1B: Alternative registry location
    elseif (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot") {
        $secureBootValues = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "*" -ErrorAction SilentlyContinue
        if ($secureBootValues -and $secureBootValues.Values -contains 1) {
            $secureBoot = $true
            $details += "Secure Boot is enabled (Alternative registry)"
        } else {
            $details += "Secure Boot registry key exists but not enabled"
        }
    }
    
    # Method 2: WMI/CIM query (may work without admin)
    try {
        $cimSecureBoot = Get-CimInstance -Namespace "Root\StandardCimv2" -ClassName MSFT_SecureBoot -ErrorAction SilentlyContinue
        if ($cimSecureBoot -and $cimSecureBoot.SecureBootEnabled) {
            $secureBoot = $true
            $details += "Secure Boot is enabled (WMI method)"
        }
    } catch {
        # WMI method failed, continue with other methods
    }
    
    if ($secureBoot) {
        Add-CheckResult -Name "Secure Boot" -Passed $true -Details $details
    } else {
        if ($details.Count -eq 0) {
            $details += "Secure Boot is disabled or not supported"
        }
        Add-CheckResult -Name "Secure Boot" -Passed $false -Details $details
        Write-Host "<WRITE-LOG = ""*Secure Boot is disabled or not supported*"">"
    }
} catch {
    Add-CheckResult -Name "Secure Boot" -Passed $false -Details @("Unable to check Secure Boot: $($_.Exception.Message)")
    Write-Host "<WRITE-LOG = ""*Secure Boot is disabled or not supported*"">"
}

# Check CPU

try {
    $cpu = Get-CimInstance -ClassName Win32_Processor
    $cpuName = $cpu.Name.Trim()
    $cores = $cpu.NumberOfCores
    $threads = $cpu.NumberOfLogicalProcessors
    $clockSpeed = [math]::Round($cpu.MaxClockSpeed / 1000, 2)
    $architecture = $cpu.AddressWidth
    $caption = $cpu.Caption
    
    # Enhanced CPU compatibility check with specific model support
    $isCompatible = $false
    $compatibilityMessage = ""
    $supportedCPUs = @()
    
    # Intel Core Processors (8th Gen and newer)
    $supportedCPUs += @(
        # Intel 8th/9th Gen
        "i3-8[0-9][0-9][0-9]", "i5-8[0-9][0-9][0-9]", "i7-8[0-9][0-9][0-9]", "i9-8[0-9][0-9][0-9]",
        "i3-9[0-9][0-9][0-9]", "i5-9[0-9][0-9][0-9]", "i7-9[0-9][0-9][0-9]", "i9-9[0-9][0-9][0-9]",
        
        # Intel 10th/11th Gen
        "i3-10[0-9][0-9][0-9]", "i5-10[0-9][0-9][0-9]", "i7-10[0-9][0-9][0-9]", "i9-10[0-9][0-9][0-9]",
        "i3-11[0-9][0-9][0-9]", "i5-11[0-9][0-9][0-9]", "i7-11[0-9][0-9][0-9]", "i9-11[0-9][0-9][0-9]",
        
        # Intel 12th/13th/14th Gen
        "i3-12[0-9][0-9][0-9]", "i5-12[0-9][0-9][0-9]", "i7-12[0-9][0-9][0-9]", "i9-12[0-9][0-9][0-9]",
        "i3-13[0-9][0-9][0-9]", "i5-13[0-9][0-9][0-9]", "i7-13[0-9][0-9][0-9]", "i9-13[0-9][0-9][0-9]",
        "i3-14[0-9][0-9][0-9]", "i5-14[0-9][0-9][0-9]", "i7-14[0-9][0-9][0-9]", "i9-14[0-9][0-9][0-9]",
        
        # Intel Xeon
        "Xeon.*E-21[0-9][0-9]", "Xeon.*E-22[0-9][0-9]", "Xeon.*E-23[0-9][0-9]", "Xeon.*E-24[0-9][0-9]",
        "Xeon W-12[0-9][0-9]", "Xeon W-13[0-9][0-9]", "Xeon W-14[0-9][0-9]", "Xeon W-15[0-9][0-9]",
        "Xeon.*Silver", "Xeon.*Gold", "Xeon.*Platinum",
        
        # AMD Ryzen 2000 series and newer
        "Ryzen 3 2[0-9][0-9][0-9]", "Ryzen 5 2[0-9][0-9][0-9]", "Ryzen 7 2[0-9][0-9][0-9]", "Ryzen 9 2[0-9][0-9][0-9]",
        "Ryzen 3 3[0-9][0-9][0-9]", "Ryzen 5 3[0-9][0-9][0-9]", "Ryzen 7 3[0-9][0-9][0-9]", "Ryzen 9 3[0-9][0-9][0-9]",
        "Ryzen 3 4[0-9][0-9][0-9]", "Ryzen 5 4[0-9][0-9][0-9]", "Ryzen 7 4[0-9][0-9][0-9]", "Ryzen 9 4[0-9][0-9][0-9]",
        "Ryzen 3 5[0-9][0-9][0-9]", "Ryzen 5 5[0-9][0-9][0-9]", "Ryzen 7 5[0-9][0-9][0-9]", "Ryzen 9 5[0-9][0-9][0-9]",
        "Ryzen 3 6[0-9][0-9][0-9]", "Ryzen 5 6[0-9][0-9][0-9]", "Ryzen 7 6[0-9][0-9][0-9]", "Ryzen 9 6[0-9][0-9][0-9]",
        "Ryzen 3 7[0-9][0-9][0-9]", "Ryzen 5 7[0-9][0-9][0-9]", "Ryzen 7 7[0-9][0-9][0-9]", "Ryzen 9 7[0-9][0-9][0-9]",
        "Ryzen 3 8[0-9][0-9][0-9]", "Ryzen 5 8[0-9][0-9][0-9]", "Ryzen 7 8[0-9][0-9][0-9]", "Ryzen 9 8[0-9][0-9][0-9]",
        "Ryzen 3 9[0-9][0-9][0-9]", "Ryzen 5 9[0-9][0-9][0-9]", "Ryzen 7 9[0-9][0-9][0-9]", "Ryzen 9 9[0-9][0-9][0-9]",
        
        # AMD Ryzen Threadripper
        "Threadripper 2[0-9][0-9][0-9]", "Threadripper 3[0-9][0-9][0-9]", "Threadripper 3[0-9][0-9][0-9]X",
        "Threadripper 4[0-9][0-9][0-9]", "Threadripper 5[0-9][0-9][0-9]", "Threadripper 7[0-9][0-9][0-9]",
        
        # AMD EPYC
        "EPYC 7[0-9][0-9][0-9]", "EPYC 7[0-9][0-9][0-9]X", "EPYC 9[0-9][0-9][0-9]", "EPYC 9[0-9][0-9][0-9]X",
        
        # Apple Silicon (for Windows on ARM)
        "Apple M[0-9]", "Apple M[0-9] Pro", "Apple M[0-9] Max", "Apple M[0-9] Ultra",
        
        # Qualcomm Snapdragon (Windows on ARM)
        "Snapdragon.*8[cx]", "Microsoft SQ[0-9]"
    )
    
    # Check if CPU matches supported patterns
    $isSupportedModel = $false
    foreach ($pattern in $supportedCPUs) {
        if ($cpuName -match $pattern) {
            $isSupportedModel = $true
            break
        }
    }
    
    # Virtualization support check
    $hasVirtualization = $null
    try {
        $vmMonitor = Get-CimInstance -Namespace "Root\Virtualization\V2" -ClassName Msvm_ComputerSystem -ErrorAction SilentlyContinue
        $secFeatures = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 | Select-Object -ExpandProperty SecondLevelAddressTranslationExtensions -ErrorAction SilentlyContinue
        $hasVirtualization = ($vmMonitor -ne $null) -or ($secFeatures -eq $true)
    } catch {
        # Virtualization check failed
        $hasVirtualization = $null
    }
    
    # Determine compatibility
    if ($isSupportedModel) {
        $isCompatible = $true
        $compatibilityMessage = "Supported model"
    } elseif ($cores -ge 2 -and $clockSpeed -ge 1.0 -and $architecture -eq 64) {
        $isCompatible = $true
        $compatibilityMessage = "Meets minimum requirements"
    } else {
        $isCompatible = $false
        $compatibilityMessage = "Does not meet requirements"
    }
    
    # Build details array
    $details = @(
        "Processor: $cpuName",
        "Cores: $cores",
        "Threads: $threads", 
        "Clock Speed: $clockSpeed GHz",
        "Architecture: $architecture-bit",
        "Compatibility: $compatibilityMessage"
    )
    
    # Add virtualization info if available
    if ($hasVirtualization -eq $true) {
        $details += "Virtualization: Supported"
    } elseif ($hasVirtualization -eq $false) {
        $details += "Virtualization: Not available"
    }
    
    # Add model support info
    if ($isSupportedModel) {
        $details += "Model Support: Officially supported"
    } else {
        $details += "Model Support: Check manufacturer compatibility"
    }
    
    Add-CheckResult -Name "Processor" -Passed $isCompatible -Details $details
    
} catch {
    Add-CheckResult -Name "Processor" -Passed $false -Details @("Unable to check processor: $($_.Exception.Message)")
    Write-Host "<WRITE-LOG = ""*Unable to check processor: $($_.Exception.Message)*"">"
}

# Check RAM
try {
    $ram = Get-CimInstance -ClassName Win32_ComputerSystem
    $totalRAM = [math]::Round($ram.TotalPhysicalMemory / 1GB, 2)
    
    $details = @("Installed RAM: $totalRAM GB")
    $ramCompatible = $totalRAM -ge 4
    Add-CheckResult -Name "Memory (RAM)" -Passed $ramCompatible -Details $details
} catch {
    Add-CheckResult -Name "Memory (RAM)" -Passed $false -Details @("Unable to check RAM: $($_.Exception.Message)")
    Write-Host "<WRITE-LOG = ""*Unable to check RAM: $($_.Exception.Message)*"">"
}

# Check Storage
try {
    $storage = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpace = [math]::Round($storage.FreeSpace / 1GB, 2)
    $totalSpace = [math]::Round($storage.Size / 1GB, 2)
    
    $details = @(
        "Total space: $totalSpace GB",
        "Free space: $freeSpace GB"
    )
    $storageCompatible = $freeSpace -ge 64
    Add-CheckResult -Name "Storage" -Passed $storageCompatible -Details $details
} catch {
    Add-CheckResult -Name "Storage" -Passed $false -Details @("Unable to check storage: $($_.Exception.Message)")
    Write-Host "<WRITE-LOG = ""*Unable to check storage: $($_.Exception.Message)*"">"
}

# Check UEFI
$uefiResult = Test-UEFI
Add-CheckResult -Name "UEFI Firmware" -Passed $uefiResult.Passed -Details $uefiResult.Details

# Check Graphics
try {
    $graphics = Get-CimInstance -ClassName Win32_VideoController | Where-Object {$_.Name -notlike "*Remote*"}
    $wddmCompatible = $false
    
    foreach ($controller in $graphics) {
        if ($controller.DriverVersion -and $controller.Name -notlike "*Remote*") {
            $wddmCompatible = $true
            break
        }
    }
    
    if ($wddmCompatible) {
        Add-CheckResult -Name "Graphics" -Passed $true -Details @("Compatible graphics adapter detected")
    } else {
        Add-CheckResult -Name "Graphics" -Passed $false -Details @("WDDM 2.0 compatible driver may be required")
        Write-Host "<WRITE-LOG = ""*WDDM 2.0 compatible driver may be required*"">"
    }
} catch {
    Add-CheckResult -Name "Graphics" -Passed $false -Details @("Unable to check graphics: $($_.Exception.Message)")
}

# Check Display
try {
    $display = Get-CimInstance -ClassName Win32_VideoController | Where-Object {$_.Name -notlike "*Remote*"}
    $horizontalResolution = 0
    
    foreach ($controller in $display) {
        if ($controller.CurrentHorizontalResolution -gt $horizontalResolution) {
            $horizontalResolution = $controller.CurrentHorizontalResolution
        }
    }
    
    $displayCompatible = $horizontalResolution -ge 720
    if ($displayCompatible) {
        Add-CheckResult -Name "Display" -Passed $true -Details @("Display resolution: ${horizontalResolution}p (meets requirements)")
    } else {
        Add-CheckResult -Name "Display" -Passed $false -Details @("Display resolution may not meet minimum requirements")
        Write-Host "<WRITE-LOG = ""*Display resolution may not meet minimum requirements*"">"
    }
} catch {
    Add-CheckResult -Name "Display" -Passed $false -Details @("Unable to check display: $($_.Exception.Message)")
}

# Gather system information
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $bios = Get-CimInstance -ClassName Win32_BIOS
    
    $systemInfo["Operating System"] = $os.Caption
    $systemInfo["OS Version"] = $os.Version
    $systemInfo["Manufacturer"] = $computer.Manufacturer
    $systemInfo["Model"] = $computer.Model
    $systemInfo["BIOS Version"] = $bios.SMBIOSBIOSVersion
    $systemInfo["Last Boot"] = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
    $systemInfo["Administrator"] = if ($isAdmin) { "Yes" } else { "No" }
} catch {
    Write-Warning "Unable to gather complete system information"
}

# Generate HTML report
$htmlContent = New-HTMLReport -Results $results -SystemInfo $systemInfo -Passed $passedChecks -Total $totalChecks

# Save to desktop
try {
    $isComp = "Not_Compatible"

    if($passedChecks -eq $totalChecks){
        $isComp = "Compatible"
        Write-Host "<WRITE-LOG = ""*Device is compatible with Windows 11*"">"
    }else{
        Write-Host "<WRITE-LOG = ""*Device is NOT compatible with Windows 11*"">"
    }

    $OutputPath = "$env:USERPROFILE\Desktop\"+$isComp+"-"+($computer).Name+".html"
    <# You can also save to fileshare instead just set $OutputPath as needed see ex.
    $OutputPath = "\\servername\share\"+$isComp+"-"+($computer).Name+".html"
    #>

    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "<WRITE-LOG = ""*Report saved to: $OutputPath*"">" -ForegroundColor Cyan
    
 
} catch {
    Write-Host "❌ Error saving report: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nCompatibility Summary: $passedChecks/$totalChecks requirements passed" -ForegroundColor $(if ($passedChecks -eq $totalChecks) { "Green" } else { "Yellow" })
