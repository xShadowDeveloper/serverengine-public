function Write-Log {
    param($Message)
    Write-Host "<WRITE-LOG = `"*$Message*`">"
}

try {
	$ramValues = @()
    # Collect RAM usage 5 times, 5 seconds apart
    1..5 | ForEach-Object {
    	$ram             = Get-WmiObject Win32_OperatingSystem
    	$totalRam        = [math]::Round($ram.TotalVisibleMemorySize / 1MB, 2)
    	$freeRam         = [math]::Round($ram.FreePhysicalMemory  / 1MB, 2)
    	$usedRam         = $totalRam - $freeRam
    	$ramUsagePercent = [math]::Round(($usedRam / $totalRam) * 100, 2)

        $ramValues += $ramUsagePercent
        Start-Sleep -Seconds 5
    }

    # Calculate and output the average
    $avgRam = [math]::Round(($ramValues | Measure-Object -Average).Average, 2)
    Write-Log "RAM Average Usage: $avgRam %"

    # Alert if average RAM exceeds 85%
    if ($avgRam -gt 85) {
        Write-Error "RAM usage too high: $avgRam %"
    }
}
catch {
    Write-Log "Unable to gather RAM Information: Device not supported."
}
