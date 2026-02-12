# Remove some unwanted applications
#-----------------------------------------

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm)
{
	Write-Host "<WRITE-LOG = ""*Please run this script as Administrator.*"">"
    Write-Host "<WRITE-LOG = ""*If this was a remote execution please provide Administrator credentials.*"">"
    Write-Error "Warning: Not running as Administrator."
}
else {
	$apps = @(
  	"Microsoft.3DBuilder",
  	"Microsoft.BingWeather",
  	"Microsoft.MicrosoftSolitaireCollection",
  	"Microsoft.OfficeHub",
  	"Microsoft.SkypeApp",
  	"Microsoft.XboxApp",
  	"Microsoft.ZuneMusic",
  	"Microsoft.ZuneVideo"
	)
	foreach ($app in $apps)
	{
		Get-AppxPackage -Name $app | Remove-AppxPackage
	}
	Write-Host "Bloatware removed!"
}
