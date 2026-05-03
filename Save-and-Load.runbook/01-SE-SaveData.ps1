# You can save data to the variable $store
# To use data on the next script using Runbooks
#--------------------------------------------------
function Write-Log {
    param($Message)
    Write-Host "<WRITE-LOG = `"*$Message*`">"
}

# Example 1 (Save Text)
$store = "This text was saved"

# Example 2 (Save Variable)
$message = "This variable was saved"
$store = $message

# Example 3 (Save Numeric Values)
$store = 1337

# Example 4 (Save SringList or Aarray as String)
$store = "c.orlando, m.muster"

Write-Log "Save: $store"
#--------------------------------------------------
# Check LoadData next for loading usage
#--------------------------------------------------
