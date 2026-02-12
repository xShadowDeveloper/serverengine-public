# Check Internet Connection
#-----------------------------------------

$internet = (Test-Connection 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue)

if($internet)
{
	Write-Host "<WRITE-LOG = ""*Internet connection: Available*"">"
}
else{
	Write-Error "Internet connection: Unavailable"
}
