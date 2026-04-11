function Write-Log {
    param($Message)
    Write-Host "<WRITE-LOG = `"*$Message*`">"
}

try {
    $cpuValues = @()

    # Collect CPU usage 5 times, 5 seconds apart
    1..5 | ForEach-Object {
        $cpuSample = Get-Counter '\Processor(_Total)\% Processor Time'
        $cpuValue = $cpuSample.CounterSamples[0].CookedValue
        $cpuValues += $cpuValue
        Start-Sleep -Seconds 5
    }

    # Calculate and output the average
    $avgCpu = [math]::Round(($cpuValues | Measure-Object -Average).Average, 2)
    Write-Log "CPU Average Usage: $avgCpu %"

    # Alert if average CPU exceeds 85%
    if ($avgCpu -gt 85) {
        Write-Error "CPU usage too high: $avgCpu %"
    }

} catch {
    Write-Log "Unable to gather CPU Information: Device not supported."
}
