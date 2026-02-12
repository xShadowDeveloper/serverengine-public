# Self-Healing Service Monitor
# Restarts important services automatically if stopped.
#-----------------------------------------------------------------

$ServiceDownList = $store
Write-Host "<WRITE-LOG = ""*ServiceDownList: $ServiceDownList*"">"

foreach ($ServiceName in $ServiceDownList) {
	try{
		$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
		Restart-Service -Name $ServiceName -Force
		Start-Sleep 2
		$Service.Refresh()

		if ($Service.Status -eq 'Running') {
			Write-Host "<WRITE-LOG = ""*Service: $ServiceName restarted successfully.*"">"
		} else {
			Write-Host "<WRITE-LOG = ""*Service: $ServiceName failed to start.*"">"
		}
	}
}
