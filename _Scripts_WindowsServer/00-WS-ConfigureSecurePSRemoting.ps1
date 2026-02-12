# Configures Windows PowerShell Remoting and WinRM for ServerEngine management
#----------------------------------------------------------------
# Requires Administrator previlegues

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm) 
{
    Write-Host "<WRITE-LOG = ""*Please run this script as Administrator.*"">"
    Write-Host "<WRITE-LOG = ""*If this was a remote execution please provide Administrator credentials.*"">"
    Write-Error "Warning: Not running as Administrator."
}
else {
	# Step 1 - Prepare Network Adapters
	Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private 2>$null

	# Step 2 - Enable Windows PowerShell Remoting
	Enable-PSRemoting -Force

	# Step 3 - Configure WinRM SSL with Self-Signed Certificate

	# Start WinRM service if not running
	if ((Get-Service WinRM).Status -ne 'Running') 
	{
    	Start-Service WinRM -ErrorAction Stop
    	Set-Service WinRM -StartupType Automatic -ErrorAction Stop
	}

	# Configure HTTPS listener
	winrm quickconfig -transport:https -force 2>$null

	# Check for existing certificate
	$hostname = hostname
	$existingCert = Get-ChildItem "Cert:\LocalMachine\My" | 
	    Where-Object { 
	        $_.Subject -eq "CN=$hostname" -and 
	        $_.Issuer -eq "CN=$hostname" -and
	        $_.HasPrivateKey -eq $true
	    } |
	    Sort-Object NotAfter -Descending |
	    Select-Object -First 1

	# Create new certificate only if needed
	if ($existingCert) 
	{
    	# Check if certificate is expired or expiring soon (within 30 days)
    	$daysUntilExpiry = ($existingCert.NotAfter - (Get-Date)).Days
    
    	if ($daysUntilExpiry -le 30) 
		{
        	Write-Host "Existing certificate expires in $daysUntilExpiry days. Creating new certificate..."
        	$cert = New-SelfSignedCertificate -DnsName $hostname `
                	-CertStoreLocation "Cert:\LocalMachine\My" `
                	-KeySpec KeyExchange -ErrorAction Stop
    	}
    	else {
        	Write-Host "Using existing valid certificate (expires in $daysUntilExpiry days)"
        	$cert = $existingCert
    	}
	}
	else {
    	Write-Output "No existing certificate found. Creating new certificate..."
    	$cert = New-SelfSignedCertificate -DnsName $hostname `
            	-CertStoreLocation "Cert:\LocalMachine\My" `
            	-KeySpec KeyExchange -ErrorAction Stop
	}

	# Remove any existing HTTPS listeners
	winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null

	# Create HTTPS listener with the certificate
	New-Item -Path "WSMan:\localhost\Listener" -Transport HTTPS `
         	-Address * -CertificateThumbprint $cert.Thumbprint -Force -ErrorAction Stop

	# Configure firewall (skip if rule already exists)
	$fwRule = (Get-NetFirewallRule -Name "WINRM-HTTPS-In-TCP" -ErrorAction SilentlyContinue)
	if (-not $fwRule) 
	{
    	New-NetFirewallRule -Name "WINRM-HTTPS-In-TCP" `
        	-DisplayName "Windows Remote Management (HTTPS-In)" `
        	-Enabled True -Direction Inbound -Protocol TCP `
        	-LocalPort 5986 -Action Allow -ErrorAction Stop
	}
	Write-Host "WinRM HTTPS successfully configured"
	Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
	Write-Host "Certificate Expires: $($cert.NotAfter.ToString('yyyy-MM-dd'))"
	Write-Host "<WRITE-LOG = ""*PowerShell Remoting successfully configured.*"">"
}

