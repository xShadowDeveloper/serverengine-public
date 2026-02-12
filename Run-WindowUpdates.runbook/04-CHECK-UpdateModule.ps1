# Install/Update WU Moduel
#-----------------------------------------

Write-Host "<WRITE-LOG = ""*Checking PSWindowsUpdate module...*"">"
    
# Install PSWindowsUpdate module
$module = Get-Module -Name PSWindowsUpdate -ListAvailable
if (!$module) {
	Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Confirm:$false -SkipPublisherCheck
	Write-Host "<WRITE-LOG = ""*PSWindowsUpdate module installed successfully*"">"
} else {
	Write-Host "<WRITE-LOG = ""*PSWindowsUpdate module already installed*"">"
}
