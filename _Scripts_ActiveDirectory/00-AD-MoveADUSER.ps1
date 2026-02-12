# Active Directory: Move AD Users based on Department ex. QUO-SYNC
#-------------------------------------------

Import-Module ActiveDirectory

# Domain
$DomainDN = (Get-ADDomain).DistinguishedName

# Source OU (Q.U.O. Sync folder)
$SourceOU = "OU=QUO-SYNC,$DomainDN"

# Department → Target OU mapping
$DepartmentOUs = @{
    "IT"        = "OU=IT,OU=Users,OU=Company,$DomainDN"
    "HR"        = "OU=HR,OU=Users,OU=Company,$DomainDN"
    "Finance"   = "OU=Finance,OU=Users,OU=Company,$DomainDN"
    "Marketing" = "OU=Marketing,OU=Users,OU=Company,$DomainDN"
}

# Move each user to respective OU
Get-ADUser -SearchBase $SourceOU -Filter * -Properties Department |
ForEach-Object {

    $User = $_
    if (-not $User.Department) {
        Write-Error "Skipping $($User.SamAccountName): No Department set"
    }
    if (-not $DepartmentOUs.ContainsKey($User.Department)) {
        Write-Error "Skipping $($User.SamAccountName): No OU mapped for department '$($User.Department)'"
    }
    $TargetOU = $DepartmentOUs[$User.Department]

    try {
        Move-ADObject -Identity $User.DistinguishedName -TargetPath $TargetOU
        Write-Host "Moved $($User.SamAccountName) to $TargetOU"
    }
    catch {
        Write-Error "Failed to move $($User.SamAccountName): $_"
    }
}
