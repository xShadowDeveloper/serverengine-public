# Install the Application Compatibility Feature on Demand on Server Core
#-----------------------------------------------------
# Requires Administrator previlegues

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm) 
{
    Write-Host "<WRITE-LOG = ""*Please run this script as Administrator.*"">"
    Write-Host "<WRITE-LOG = ""*If this was a remote execution please provide Administrator credentials.*"">"
    Write-Error "Warning: Not running as Administrator."
}
else {
	Add-WindowsCapability -Online -Name "ServerCore.AppCompatibility~~~~0.0.1.0"
	# You must reboot for the installation to take effect
}

