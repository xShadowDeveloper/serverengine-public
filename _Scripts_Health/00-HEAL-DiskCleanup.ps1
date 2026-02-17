# - - - - - PowerShell - - - - - #


# Auto Disk Health & Cleanup
# Checks for low disk space and performs cleanup 
# (temp, recycle bin, update cache).
#---------------------------------------------------------------

$Threshold = 50  # Disk usage % limit

Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    try {
        $Usage = [math]::Round((($_.Used / ($_.Free + $_.Used)) * 100), 2)
        Write-Host "<WRITE-LOG = ""*Checking $($_.Name): $Usage% used*"">"

        if ($Usage -ge $Threshold) {
            Write-Host "<WRITE-LOG = ""*Drive $($_.Name) exceeds threshold ($Usage%) - cleaning...*"">"
            
            # Clear temp files
            Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Empty recycle bin
            (New-Object -ComObject Shell.Application).NameSpace(0xA).Items() | 
                ForEach-Object { Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue }

            # Clear Windows Update cache
            Stop-Service wuauserv -ErrorAction SilentlyContinue
            Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
            Start-Service wuauserv -ErrorAction SilentlyContinue
            
            Write-Host "<WRITE-LOG = ""*Cleanup completed for $($_.Name)*"">"
        }
    } catch {
        Write-Host "Error processing $($_.Name): $_"
    }
}
