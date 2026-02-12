# Check Services and gather information
#-----------------------------------------------------------------

# Modify as needed
$CriticalServices = @(
    "Dnscache",
    "NTDS",
    "Netlogon",
    "LanmanWorkstation",
    "LanmanServer",
    "RpcSs",
    "W32Time",
    "NlaSvc",
    "WinDefend"
    )  

# Initialize $store as array
$store = @()

foreach ($ServiceName in $CriticalServices) 
{	
	$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
	if ($null -eq $Service)
	{
		Write-Host "<WRITE-LOG = ""*Service: $ServiceName not found.*"">"
		continue 
	}

	if ($Service.Status -ne 'Running') 
	{
		Write-Host "<WRITE-LOG = ""*Service: $ServiceName is down! Save to store...*"">"
		# Add service if down
		$store += $ServiceName
	}
	else {
		Write-Host "<WRITE-LOG = ""*Service: $ServiceName is running.*"">"
	}	
}
