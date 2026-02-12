# Auto Disk Health & Cleanup
# Checks for low disk space and performs cleanup 
# (temp, recycle bin, update cache).
#---------------------------------------------------------------

$Threshold = 50  # Disk usage % limit
$Drives = Get-PSDrive -PSProvider 'FileSystem'

foreach ($Drive in $Drives) {
    try {
        $Usage = [math]::Round((($Drive.Used / ($Drive.Free + $Drive.Used)) * 100), 2)
        Write-Host "<WRITE-LOG = ""*Checking $($Drive.Name): $Usage% used*"">"

        if ($Usage -ge $Threshold) 
		{
            Write-Host "<WRITE-LOG = ""*Drive $($Drive.Name) exceeds threshold ($Usage%) - cleaning...*"">"
            
            # Clear temp files
            Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Empty recycle bin
            (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | 
                ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }

            # Clear Windows Update cache
            Stop-Service wuauserv -ErrorAction SilentlyContinue
            Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service wuauserv -ErrorAction SilentlyContinue
            
            Write-Host "<WRITE-LOG = ""*Cleanup completed for $($Drive.Name)*"">"
        }
    } Catch {
        Write-Host "Error processing $($Drive.Name): $_"
    }
}
