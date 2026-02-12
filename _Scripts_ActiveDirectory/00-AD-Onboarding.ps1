# Active Directory: User Onboarding
#-------------------------------------------

Import-Module ActiveDirectory

# Enable detailed debugging
$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"
Write-Host "Converting password to SecureString"
$SecurePassword = ConvertTo-SecureString 'xAccountPassword' -AsPlainText -Force
 
# Create new AD User
Write-Host "Creating New-ADUser..."

try {
    New-ADUser `
        -Name 'xName' `
        -GivenName 'xGivenName' `
        -Surname 'xSurname' `
        -DisplayName 'xDisplayName' `
        -SamAccountName 'xSamAccountName' `
        -UserPrincipalName 'xUserPrincipalName' `
        -EmailAddress 'xEmailAddress' `
        -Description 'xDescription' `
        -Department 'xDepartment' `
        -Office 'xOffice' `
        -Company 'xCompany' `
        -Title 'xTitle' `
        -OfficePhone 'xPhone' `
        -StreetAddress 'xStreetAddress' `
        -City 'xCity' `
        -PostalCode 'xPostalCode' `
        -State 'xState' `
        -Country 'xCountry' `
        -Path 'xPath' `
        -AccountPassword $SecurePassword `
        -Enabled $true `
        -Verbose
 
 
    $roleList = 'xGroups'
    $roles = $roleList -split ','
 
    foreach ($role in $roles) {
 
        if ($role -like 'Finance'){
            try {
                Add-ADGroupMember -Identity 'SG-FIN-Accountants' -Members 'xSamAccountName' -Verbose
                Add-ADGroupMember -Identity 'SG-FIN-AP-Team (Accounts Payable)' -Members 'xSamAccountName' -Verbose
                Add-ADGroupMember -Identity 'SG-FIN-AR-Team (Accounts Receivable)' -Members 'xSamAccountName' -Verbose
                Add-ADGroupMember -Identity 'SG-FIN-Payroll-Processors' -Members 'xSamAccountName' -Verbose
                Add-ADGroupMember -Identity 'SG-FIN-Financial-Analysts' -Members 'xSamAccountName' -Verbose
                Add-ADGroupMember -Identity 'SG-FIN-Budget-Managers' -Members 'xSamAccountName' -Verbose
            }
			catch 
			{
                Write-Host "<WRITE-LOG = ""*Failed to assign user to role $role*"">"
            }
        }

		if ($role -like 'HR'){
    		try {
        		Add-ADGroupMember -Identity 'SG-HR-Users' -Members 'xSamAccountName' -Verbose
        		Add-ADGroupMember -Identity 'SG-HR-HRIS' -Members 'xSamAccountName' -Verbose
        		Add-ADGroupMember -Identity 'SG-HR-Personnel-Files' -Members 'xSamAccountName' -Verbose
    		}
			catch 
			{
        		Write-Host "<WRITE-LOG = ""*Failed to assign user to role $role*"">"
    		}	
		}
        #Define more assignments here...
 
    }
    Write-Host "<WRITE-LOG = ""*User Onboarding completed!*"">"
    Write-Host "<WRITE-LOG = ""*User created: xName*"">"
    Write-Host "<WRITE-LOG = ""*Email: xUserPrincipalName*"">"
    Write-Host "<WRITE-LOG = ""*Login: xSamAccountName*"">"
    Write-Host "<WRITE-LOG = ""*Password: xAccountPassword*"">"
     
}
catch 
{
    Write-Error "AD User creation failed:" +$($_.Exception.Message)
}
