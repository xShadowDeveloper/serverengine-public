# You can save data to the variable $store
# To use data on the next script using Runbooks
#--------------------------------------------------

# Example 1 (Save Text)
$store = "This text was saved"

# Example 2 (Save Variable)
$message = "This variable was saved"
$store = $message

# Example 3 (Save Numeric Values)
$store = 1337

# Example 4 (Save Mixed Data)
# In a loop initialze $store as array
$store = @()
foreach ($file in $fileList){
	$store += $file
}
#or all it once if you can
$store = @("John", 30, "Engineer", 75000.50)

#--------------------------------------------------
# Check LoadData next for loading usage
#--------------------------------------------------
