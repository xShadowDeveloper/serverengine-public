# File Downloader
#------------------------------------

function Download-File
{
    param (
        [string]$Link = "",
        [string]$TargetFolder = "",
        [string]$Filename = "",
    )

    # Set output ZIP path
    $TargetFile = Join-Path $TargetFolder $Filename

    if ($Link)
	{
	    # Download
		Start-BitsTransfer -Source $Link -Destination $TargetFile -ErrorAction Stop
		
		Write-Host "Downloaded file to $TargetFile"
		Start-Sleep -Seconds 2

    	# Extract and clean up, assuming it's a .zip file
    	if (Test-Path $TargetFile)
		{
        	Expand-Archive -Path $TargetFile -DestinationPath $TargetFolder -Force
        	Remove-Item -Path $TargetFile
        	Write-Host "Extracted archive to $Target and deleted zip"
    	}
		else{
        	show-Error "File was not found!"
    	}
    }
	else {
        show-Warning "Could not find download link."
        return
	}
}

Download-File -Link "https://files.com/PolicyDefinitions.zip" -TargetFolder ".\" -Filename "PolicyDefinitions.zip"
Download-File -Link "https://files.com/GPO_Templates.zip" -TargetFolder ".\" -Filename "GPO_Templates.zip"
