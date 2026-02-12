# Install Windows Updates, exclude KBs if needed
#------------------------------------------------------------

$updates = $store
Write-Host "<WRITE-LOG = ""*Load Store: $store*"">"

# Search Windows Updates again if needed
<#$updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop#>

if ($updates.Count -gt 0) {
	Write-Host "<WRITE-LOG = ""*Found $($updates.Count) update(s) to install*"">"
        
	# Display update details
	$updates | ForEach-Object {
	Write-Host "<WRITE-LOG = ""*Update: $($_.Title) (KB$($_.KB))*"">"
	}

	Write-Host "<WRITE-LOG = ""*Installing Windows Updates...*"">"

    $scriptBlock = {
	    try {
            Import-Module PSWindowsUpdate -Force
                
			# Hide problematic updates (expand this list as needed)
		    $problematicKBs = @('KB5034439', 'KB5034441',  'KB5005463', 'KB4535680', 'KB5008876') # Add known problematic KBs here
	        foreach ($kb in $problematicKBs) {
                try {
					$update = Get-WindowsUpdate -KBArticleID $kb -ErrorAction SilentlyContinue
					    if ($update) {
                            Hide-WindowsUpdate -KBArticleID $kb -Confirm:$false
                            Write-Output "Hidden problematic update: KB$kb"
                        }
				} catch {
                        Write-Warning "Could not hide KB$kb : $($_.Exception.Message)"
				}
			}
                
			# Get and install updates
		    $updatesToInstall = Get-WindowsUpdate -MicrosoftUpdate -Install -AcceptAll -AutoReboot:$false -IgnoreReboot
        	        
		    # Stop any running PSWindowsUpdate scheduled tasks
	        $runningTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like '*PSWindowsUpdate*' -and $_.State -eq 'Running' }
            foreach ($task in $runningTasks) {
	            try {
                    Stop-ScheduledTask -TaskName $task.TaskName -Confirm:$false
				} catch {
			        Write-Warning "Could not stop task $($task.TaskName): $($_.Exception.Message)"
		        }
	        }     
		} catch {
	        Write-Error "Update installation failed: $($_.Exception.Message)"
		}
	} #end scriptBlock

	# Execute the update job
	try {
        $job = Invoke-WuJob -ComputerName $env:COMPUTERNAME -Script $scriptBlock -RunNow -Confirm:$false -ErrorAction Stop
		Write-Host "<WRITE-LOG = ""*Update job started successfully*"">"
	} catch {
		Write-Host "<WRITE-LOG = ""*ERROR: Failed to start update job: $($_.Exception.Message)*"">"
		Write-Error "ERROR: Failed to start update job: $($_.Exception.Message)"
	}

	# Monitor update progress
	Write-Host "<WRITE-LOG = ""*Monitoring update progress...*"">"
	$timeout = 3600 # 60 minute timeout
	$timer = 0
    $checkInterval = 30 # seconds
        
	while ($timer -lt $timeout) {
		$runningTasks = Get-ScheduledTask | Where-Object { 
		$_.TaskName -like '*PSWindowsUpdate*' -and $_.State -eq 'Running' 
		}
            
		if ($runningTasks.Count -eq 0) {
			Write-Host "<WRITE-LOG = ""*Windows Updates installation completed!*"">"
                
			# Check if reboot is required
		    $rebootRequired = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

	        if ($rebootRequired) {
                Write-Host "<WRITE-LOG = ""*System restart required*"">"
			} else {
				Write-Host "<WRITE-LOG = ""*No restart required*"">"
			}
		break
	    }
            
		# Progress update every 60 seconds
		if ($timer % 60 -eq 0) {
	        Write-Host "<WRITE-LOG = ""*Updates in progress... ($([math]::Round($timer/60)) minutes elapsed)*"">"
        }

		Start-Sleep -Seconds $checkInterval
	    $timer += $checkInterval
    }
	if ($timer -ge $timeout) {
        Write-Host "<WRITE-LOG = ""*WARNING: Update process timed out after $timeout seconds*"">"
	}
        
} else {
	Write-Host "<WRITE-LOG = ""*System is up to date.*"">"
}
