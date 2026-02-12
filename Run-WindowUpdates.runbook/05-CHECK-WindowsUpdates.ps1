# Check Windows Updates
#----------------------------------------------------------

# Import the module
Import-Module PSWindowsUpdate -Force
Write-Host "<WRITE-LOG = ""*PSWindowsUpdate module imported*"">"
Write-Host "<WRITE-LOG = ""*Searching for Windows Updates...*"">"
    
# Get available updates with error handling
try {
	$updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop
	$count = $updates.Count
	Write-Host "<WRITE-LOG = ""*Found $count Updates...*"">"
	$store = $updates
} catch {
	Write-Host "<WRITE-LOG = ""*ERROR: Failed to search for updates: $($_.Exception.Message)*"">"
	Write-Error "ERROR: Failed to search for updates: $($_.Exception.Message)"
}
