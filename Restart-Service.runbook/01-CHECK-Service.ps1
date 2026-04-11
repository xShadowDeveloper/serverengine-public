# Restart Service
#-----------------------------------------------------------------


	$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
	if ($null -eq $Service)
	{
		Write-Host "<WRITE-LOG = ""*Service: $ServiceName not found.*"">"
		continue 
	}

	if ($Service.Status -ne 'Running') 
	{
		Write-Host "<WRITE-LOG = ""*Service: $ServiceName is down! Starting...*"">"

		$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
		Start-Service -Name $ServiceName
		Start-Sleep 2
		$Service.Refresh()

		if ($Service.Status -eq 'Running') {
			Write-Host "<WRITE-LOG = ""*Service: $ServiceName started successfully.*"">"
		} else {
			Write-Host "<WRITE-LOG = ""*Service: $ServiceName failed to start.*"">"
		}
	}
	else {
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

