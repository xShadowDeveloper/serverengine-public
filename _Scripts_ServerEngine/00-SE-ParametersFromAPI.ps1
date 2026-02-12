# You can replace data/text in a script requested by the API
<#-----------------------------------------------------
# Ex. Variable = "Value" (called with API after the status variable)
# any variable after is indicated as dynamic parameters and
# you can use as many as you needed
#
# xTest1 = "someText"
# xTest2 = "verysomesome"
#>

# Exmaple 1 (Log Text)
Write-Host "<WRITE-LOG = ""*xTest1*"">"

# Exmaple 2 (Log Variable)
$log = "xTest2"
Write-Host "<WRITE-LOG = ""*$log*"">"

