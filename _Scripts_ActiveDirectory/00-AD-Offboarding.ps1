# Active Directory: User Offboarding
#-------------------------------------------

Import-Module ActiveDirectory

# Domain
$DomainDN = (Get-ADDomain).DistinguishedName

# Offboarding OU
$OffboardingOU = "OU=Offboarding,OU=Company,$DomainDN"

# Groups that must NOT be removed
$ProtectedGroups = @("Domain Users") 

# Generate random password function
function Generate-RandomPassword {
    Add-Type -AssemblyName System.Web
    [System.Web.Security.Membership]::GeneratePassword(16, 4)
}

# Process users
Get-ADUser -SearchBase $OffboardingOU -Filter * -Properties MemberOf |
ForEach-Object 
{
    $User = $_
	# Only proceed if the user is enabled
	if ($User.Enabled) 
	{
    	# Remove from all groups except protected
    	$GroupsToRemove = $User.MemberOf | 
		ForEach-Object 
		{ 
        	(Get-ADGroup $_).SamAccountName 
    	} | Where-Object { $_ -notin $ProtectedGroups }

    	foreach ($Group in $GroupsToRemove) 
		{
        	Remove-ADGroupMember -Identity $Group -Members $User -Confirm:$false
    	}

    	# Reset password to random
    	$NewPassword = Generate-RandomPassword
    	Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)

    	# Disable account
    	Disable-ADAccount -Identity $User
		Write-Host "<WRITE-LOG = ""*$($User.SamAccountName) offboarding completed.*"">"
	}
}
