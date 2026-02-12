# Check Packageprovider NuGet
#---------------------------------------

Write-Host "<WRITE-LOG = ""*Checking for NuGet package provider...*"">"

# Install NuGet provider if not present
if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false -WhatIf:$false -ErrorAction SilentlyContinue
	Write-Host "<WRITE-LOG = ""*NuGet package provider installed successfully*"">"
} else {
    Write-Host "<WRITE-LOG = ""*NuGet package provider already available*"">"
}
