# Active Directory: Clone all groups from a reference user to another
#-------------------------------------------------

Import-Module ActiveDirectory

$sourceUser = "{sourceUser}" # sAMAccountName
$targetUser = "{targetUser}" # sAMAccountName

Get-ADUser -Identity $sourceUser -Properties MemberOf | 
Select-Object -ExpandProperty MemberOf |
ForEach-Object { 
	Add-ADGroupMember -Identity $_ -Members $targetUser 
}
Write-Host "$targetUser now has the same group memberships as $sourceUser."
