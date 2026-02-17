# Clear the Windows Update cache
#-------------------------------------------------

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm) {
    Write-Host "<WRITE-LOG = ""*Please run this script as Administrator.*"">"
    Show-Warning "Please run this script as Administrator."
    Write-Host "<WRITE-LOG = ""*If this was a remote execution please provide Administrator credentials.*"">"
    Write-Error "Warning: Not running as Administrator."
} else {
	Stop-Service wuauserv -Force
	Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse -Force
	Start-Service wuauserv
	Write-Host "Windows Update cache cleared!"
}

