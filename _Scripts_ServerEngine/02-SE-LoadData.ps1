# To access and load stored data from the script before
# use the $store variable like this:
#--------------------------------------------------
function Write-Log {
    param($Message)
    Write-Host "<WRITE-LOG = `"*$Message*`">"
}

# Example 1 (Load Text)
$example1 = $store

# Example 2 (Load Variable)
$example2 = $store

# Example 3 (Load Numeric Values)
$example3 = $store

# Example 4 (Load String List)

$userList = @()
$userList = $store -split ","
Write-Log $userList

#--------------------------------------------------
# Only use one example at a time 
#--------------------------------------------------
