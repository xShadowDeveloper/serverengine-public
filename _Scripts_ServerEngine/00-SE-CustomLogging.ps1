<# You can send output information to ServerEngine Logs by
# using Write-Host with special indexing
#---------------------------------------------------------
# Start index must be:               Write-Host "<WRITE-LOG = ""*
# Between * the information          this is a test :)
# End Index must be:                 *"">"
#>

# Exmaple 1 (Log Text)
Write-Host "<WRITE-LOG = ""*this is a test :)*"">"

# Exmaple 2 (Log Variable)
$log = "this is another test :)"
Write-Host "<WRITE-LOG = ""*$log*"">"

#---------------------------------------------------------
# This can be really beneficial for quick bug research
#---------------------------------------------------------

