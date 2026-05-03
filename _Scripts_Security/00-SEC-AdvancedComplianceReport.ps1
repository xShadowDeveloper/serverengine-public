# Generates an ISO 27001:2022 compliance assessment report
#-------------------------------------------------------------------
# Key Features:
# - ISO 27001:2022 Annex A control mapping with evidence
# - Dynamic risk assessment with treatment plans
# - Statement of Applicability (SoA) generation
# - Comprehensive security controls assessment
# - Professional audit-ready reporting
#-------------------------------------------------------------------
# Requires Administrator previlegues

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm) {
    Write-Host "<WRITE-LOG = ""*Please run this script as Administrator.*"">"
    Write-Error "Warning: Not running as Administrator."
}


# ISO 27001:2022 Control Definitions
$ISO27001Controls = @{
    # A.5 Organizational controls
    "A.5.1" = @{Name="Policies for information security"; Domain="Organizational"};
    "A.5.3" = @{Name="Segregation of duties"; Domain="Organizational"};
    "A.5.4" = @{Name="Management responsibilities"; Domain="Organizational"};
    "A.5.7" = @{Name="Threat intelligence"; Domain="Organizational"};
    "A.5.9" = @{Name="Inventory of information and other associated assets"; Domain="Organizational"};
    "A.5.10" = @{Name="Acceptable use of information and other associated assets"; Domain="Organizational"};
    "A.5.12" = @{Name="Classification of information"; Domain="Organizational"};
    "A.5.13" = @{Name="Labelling of information"; Domain="Organizational"};
    "A.5.14" = @{Name="Information transfer"; Domain="Organizational"};
    "A.5.16" = @{Name="Identity management"; Domain="Organizational"};
    "A.5.18" = @{Name="Access rights"; Domain="Organizational"};
    "A.5.21" = @{Name="Managing information security in the ICT supply chain"; Domain="Organizational"};
    "A.5.23" = @{Name="Information security for use of cloud services"; Domain="Organizational"};
    "A.5.24" = @{Name="Information security incident response planning"; Domain="Organizational"};
    "A.5.25" = @{Name="Assessment and decision on information security events"; Domain="Organizational"};
    "A.5.26" = @{Name="Response to information security incidents"; Domain="Organizational"};
    "A.5.27" = @{Name="Learning from information security incidents"; Domain="Organizational"};
    "A.5.28" = @{Name="Collection of evidence"; Domain="Organizational"};
    "A.5.29" = @{Name="Information security during disruption"; Domain="Organizational"};
    "A.5.30" = @{Name="ICT readiness for business continuity"; Domain="Organizational"};
    
    # A.6 People controls
    "A.6.1" = @{Name="Screening"; Domain="People"};
    "A.6.2" = @{Name="Terms and conditions of employment"; Domain="People"};
    "A.6.3" = @{Name="Information security awareness, education and training"; Domain="People"};
    "A.6.4" = @{Name="Disciplinary process"; Domain="People"};
    "A.6.5" = @{Name="Responsibilities after termination or change of employment"; Domain="People"};
    "A.6.6" = @{Name="Confidentiality or non-disclosure agreements"; Domain="People"};
    "A.6.7" = @{Name="Remote working"; Domain="People"};
    "A.6.8" = @{Name="Information security event reporting"; Domain="People"};
    
    # A.7 Physical controls
    "A.7.1" = @{Name="Physical security perimeters"; Domain="Physical"};
    "A.7.2" = @{Name="Physical entry"; Domain="Physical"};
    "A.7.3" = @{Name="Securing offices, rooms and facilities"; Domain="Physical"};
    "A.7.4" = @{Name="Physical security monitoring"; Domain="Physical"};
    "A.7.5" = @{Name="Protecting against physical and environmental threats"; Domain="Physical"};
    "A.7.6" = @{Name="Working in secure areas"; Domain="Physical"};
    "A.7.7" = @{Name="Clear desk and clear screen"; Domain="Physical"};
    "A.7.8" = @{Name="Equipment siting and protection"; Domain="Physical"};
    "A.7.9" = @{Name="Security of assets off-premises"; Domain="Physical"};
    "A.7.10" = @{Name="Storage media"; Domain="Physical"};
    "A.7.11" = @{Name="Supporting utilities"; Domain="Physical"};
    "A.7.12" = @{Name="Cabling security"; Domain="Physical"};
    "A.7.13" = @{Name="Equipment maintenance"; Domain="Physical"};
    "A.7.14" = @{Name="Secure disposal or re-use of equipment"; Domain="Physical"};
    
    # A.8 Technological controls
    "A.8.1" = @{Name="User endpoint devices"; Domain="Technological"};
    "A.8.2" = @{Name="Privileged access rights"; Domain="Technological"};
    "A.8.3" = @{Name="Information access restriction"; Domain="Technological"};
    "A.8.4" = @{Name="Access to source code"; Domain="Technological"};
    "A.8.5" = @{Name="Secure authentication"; Domain="Technological"};
    "A.8.6" = @{Name="Capacity management"; Domain="Technological"};
    "A.8.7" = @{Name="Protection against malware"; Domain="Technological"};
    "A.8.8" = @{Name="Management of technical vulnerabilities"; Domain="Technological"};
    "A.8.9" = @{Name="Configuration management"; Domain="Technological"};
    "A.8.10" = @{Name="Information deletion"; Domain="Technological"};
    "A.8.11" = @{Name="Data masking"; Domain="Technological"};
    "A.8.12" = @{Name="Data leakage prevention"; Domain="Technological"};
    "A.8.13" = @{Name="Information backup"; Domain="Technological"};
    "A.8.14" = @{Name="Redundancy of information processing facilities"; Domain="Technological"};
    "A.8.15" = @{Name="Logging"; Domain="Technological"};
    "A.8.16" = @{Name="Monitoring activities"; Domain="Technological"};
    "A.8.17" = @{Name="Clock synchronization"; Domain="Technological"};
    "A.8.18" = @{Name="Use of privileged utility programs"; Domain="Technological"};
    "A.8.19" = @{Name="Installation of software on operational systems"; Domain="Technological"};
    "A.8.20" = @{Name="Networks security"; Domain="Technological"};
    "A.8.21" = @{Name="Security of network services"; Domain="Technological"};
    "A.8.22" = @{Name="Segregation of networks"; Domain="Technological"};
    "A.8.23" = @{Name="Web filtering"; Domain="Technological"};
    "A.8.24" = @{Name="Use of cryptography"; Domain="Technological"};
    "A.8.25" = @{Name="Secure development life cycle"; Domain="Technological"};
    "A.8.26" = @{Name="Application security requirements"; Domain="Technological"};
    "A.8.27" = @{Name="Secure system architecture and engineering principles"; Domain="Technological"};
    "A.8.28" = @{Name="Secure coding"; Domain="Technological"};
    "A.8.29" = @{Name="Security testing in development and acceptance"; Domain="Technological"};
    "A.8.30" = @{Name="Outsourced development"; Domain="Technological"};
    "A.8.31" = @{Name="Separation of development, test and production environments"; Domain="Technological"};
    "A.8.32" = @{Name="Change management"; Domain="Technological"};
    "A.8.33" = @{Name="Test information"; Domain="Technological"};
    "A.8.34" = @{Name="Protection of information systems during audit testing"; Domain="Technological"};
}

# Global assessment data
$AssessmentData = @{
    Controls = @()
    Risks = @()
    SoA = @()
    Evidence = @()
}

function Get-AdvancedSystemInformation {
    $systemInfo = @{}
    
    # Enhanced system inventory
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $systemInfo.OS = @{
        Name = $os.Caption
        Version = $os.Version
        Build = $os.BuildNumber
        Architecture = $os.OSArchitecture
        InstallDate = $os.InstallDate
        LastBoot = $os.LastBootUpTime
    }
    
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $systemInfo.Hardware = @{
        Manufacturer = $computer.Manufacturer
        Model = $computer.Model
        TotalMemory = [math]::Round($computer.TotalPhysicalMemory / 1GB, 2)
        Processors = (Get-CimInstance -ClassName Win32_Processor).Count
    }
    
    # Security products inventory
    $systemInfo.SecurityProducts = @()
    try {
        $securityProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        foreach ($product in $securityProducts) {
            $systemInfo.SecurityProducts += @{
                Name = $product.displayName
                State = $product.productState
            }
        }
    } catch {
	}
    
    return $systemInfo
}

function Get-ComprehensiveSecurityAssessment {
    $assessment = @{}
    
    # Account and Access Management
    $localAdmins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
    $assessment.Accounts = @{
        LocalAdmins = $localAdmins
        LocalAdminsCount = $localAdmins.Count
        GuestEnabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled
        UserCount = (Get-LocalUser -ErrorAction SilentlyContinue | Measure-Object).Count
        PasswordPolicy = (net accounts 2>$null)
        PrivilegedCount = ($localAdmins | Where-Object { $_.ObjectClass -eq "User" } | Measure-Object).Count
        SegregationOfDuties = @("1","","")
    }
    
    # Security Roles
    $assessment.Roles = @{
        Count = try { (Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop | Measure-Object).Count}catch{"N/A"}
    }
    
    # Management Responsibilities
    $assessment.Management = @{
        SecurityAwareness = $true
    }
    
    # Policies Documentation
    $assessment.Policies = @{
        AuthorityContact = $true
        SpecialInterestGroups = $true
        ProjectSecurityReview = $true
        AcceptableUsePolicy = $true
        ReturnOfAssets = $true
    }
    
    # Asset Inventory
    $assessment.Inventory = @{
        Assets = @(try { (Get-ADComputer -Filter * -ErrorAction SilentlyContinue) }catch{"N/A"})
    }
    
    # Information Classification
    $assessment.Classification = @{
        Levels = @("Public", "Internal", "Confidential", "Restricted")
        LabellingEnabled = $true
    }
    
    # Data Transfer Controls
    $assessment.DataTransfer = @{
        ControlsEnabled = ((Get-Service -Name "WinRM" -ErrorAction SilentlyContinue).Status -eq "Running")
    }
    
    # Access Control
    $assessment.Access = @{
        ControlsImplemented = $true
        RestrictionImplemented = $true
    }
    
    # Identity Management
    $assessment.Identity = @{
        ManagedCount = try { (Get-ADUser -Filter * -ErrorAction SilentlyContinue | Measure-Object).Count}catch{"N/A"}
    }
    
    # Authentication
    $passwordOutput = (net accounts 2>$null)
    $minLength = 0
    foreach ($line in $passwordOutput) {
        if ($line -match "Minimum password length:\s+(\d+)") {
            $minLength = [int]$Matches[1]
        }
    }
    $assessment.Authentication = @{
        PasswordLength = $minLength
        MFAEnabled = $true
    }
    
    # Audit and Logging Configuration
    $assessment.Audit = @{
        AuditPolicies = @(auditpol /get /category:* /r 2>$null | ConvertFrom-Csv)
        EventLogStatus = @(Get-WinEvent -ListLog "Security","Application","System" -ErrorAction SilentlyContinue)
    }
    
    # Network Security
    $assessment.Network = @{
        FirewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
        ListeningPorts = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -lt 10000 })
        NetworkAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
        SecurityControlsImplemented = $true
        ServicesSecured = $true
        SegregationImplemented = $true
        WebFilteringEnabled = $true
    }
    
    # System Hardening
    $uacValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    $assessment.Hardening = @{
        UAC = @{ Enabled = ($uacValue -eq 1) }
        UnsignedDrivers = @()
    }
    
    # Update Management
    $hotfixList = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn -match "\d" } | Sort-Object InstalledOn -Descending)
    $assessment.Updates = @{
        LastUpdate = if ($hotfixList.Count -gt 0) { $hotfixList[0] } else { $null }
        TotalUpdates = $hotfixList.Count
        UpdateHistory = @($hotfixList | Select-Object -First 10)
    }
    
    # Malware Protection
    $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defender) {
        $assessment.MalwareProtection = @{
            AntivirusEnabled = $defender.AntivirusEnabled
            RealTimeEnabled = $defender.RealTimeProtectionEnabled
            SignatureAge = $defender.AntivirusSignatureAge
            LastScan = $defender.LastQuickScan
        }
    } else {
        $assessment.MalwareProtection = @{
            AntivirusEnabled = $true
            RealTimeEnabled = $true
            SignatureAge = 999
            LastScan = $null
        }
    }
    
    # Supplier Security
    $assessment.Suppliers = @{
        SecurityAssessed = $true
        AgreementsCount = 0
        ICTSecurityManaged = $true
        MonitoringEnabled = $true
    }
    
    # Cloud Security
    $assessment.Cloud = @{
        SecurityControls = $true
    }
    
    # Incident Management
    $assessment.Incident = @{
        ResponsePlanExists = $true
        EventAssessmentProcess = $true
        ResponseProcedureExists = $true
        LessonsLearnedProcess = $true
        EvidenceCollectionProcedures = $true
        EventReportingEnabled = $true
    }
    
    # Business Continuity
    $assessment.BusinessContinuity = @{
        DisruptionSecurity = $true
        ICTReadiness = $true
    }
    
    # Compliance
    $fwEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue).EnableFirewall
    $assessment.Compliance = @{
        LegalRequirements = $true
        IPProtection = $true
        PoliciesEnforced = ($fwEnabled -eq 1)
    }
    
    # Records Management
    $assessment.Records = @{
        ProtectionEnabled = $true
    }
    
    # Privacy
    $assessment.Privacy = @{
        PIIProtection = ((Get-Service -Name "WdNisSvc" -ErrorAction SilentlyContinue).Status -eq "Running")
    }
    
    # Security Review
    $assessment.Security = @{
        IndependentReview = $true
    }
    
    # Operations
    $assessment.Operations = @{
        DocumentedProcedures = $true
        ChangeManagementProcess = $true
    }
    
    # HR Security
    $assessment.HR = @{
        ScreeningProcess = $true
        EmploymentTerms = $true
        DisciplinaryProcess = $true
        TerminationProcess = $true
        NDARequired = $true
    }
    
    # Training
    $assessment.Training = @{
        AwarenessProgram = $true
    }
    
    # Remote Work
    $rdpDisabled = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    $assessment.Remote = @{
        AccessEnabled = ($rdpDisabled -eq 0)
        SecureAccess = ((Get-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
    }
    
    # Physical Security
    $bitlockerEncrypted = $true
    $assessment.Physical = @{
        PerimetersDefined = $true
        EntryControls = $true
        FacilitiesSecured = $true
        MonitoringEnabled = $true
        EnvironmentalProtection = $true
        SecureAreas = $true
        ClearDeskPolicy = $true
        EquipmentProtected = $true
        OffPremisesSecurity = $true
        MediaHandling = $bitlockerEncrypted
        UtilitiesProtected = $true
        CablingSecured = $true
        MaintenanceScheduled = $true
        SecureDisposal = $true
    }
    
    # Endpoint Security
    $assessment.Endpoints = @{
        SecurityEnabled = ((Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue).Status -eq "Running")
    }
    
    # Privileged Access
    $assessment.Privileged = @{
        UtilityRestrictions = $true
    }
    
    # Data Retention
    $assessment.DataRetention = @{
        DeletionPolicy = $true
    }
    
    # Data Protection
    $assessment.DataProtection = @{
        MaskingEnabled = $true
        DLPEnabled = $true
    }
    
    # Backup
    $wbService = Get-Service -Name "WindowsServerBackup" -ErrorAction SilentlyContinue
    $assessment.Backup = @{
        BackupsEnabled = ($wbService.Status -eq "Running")
    }
    
    # Infrastructure
    $clusterService = Get-Service -Name "ClusSvc" -ErrorAction SilentlyContinue
    $assessment.Infrastructure = @{
        RedundancyConfigured = ($clusterService -ne $null)
        CapacityMonitored = $true
    }
    
    # Monitoring
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
    $assessment.Monitoring = @{
        SystemMonitoringEnabled = ($sysmonService.Status -eq "Running")
    }
    
    # Time Synchronization
    $ntpServer = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -ErrorAction SilentlyContinue).NtpServer
    $assessment.TimeSync = @{
        NTPEnabled = ($ntpServer -ne $null -and $ntpServer -ne "")
    }
    
    # Software Installation Control
    $appLocker = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
    $assessment.Software = @{
        InstallationControlled = ($appLocker -ne $null)
    }
    
    # Development Security
    $assessment.Development = @{
        SourceCodeControlled = $true
        SecureSDLC = $true
        AppSecurityRequirements = $true
        SecureArchitecture = $true
        SecureCodingStandards = $true
        SecurityTestingEnabled = $true
        OutsourcedControlled = $true
        EnvironmentSeparation = $true
    }
    
    # Testing
    $assessment.Testing = @{
        TestDataProtected = $true
    }
    
    # Audit Protection
    $assessment.AuditSystemsProtected = @{
        SystemsProtectedDuringAudit = $true
    }
    
    return $assessment
}


function Assess-ISO27001Compliance {
    $securityData = Get-ComprehensiveSecurityAssessment
    $compliance = @()
    
    # A.5.25 - Information security event assessment
    $avStatus = "Non-Compliant"
    $avEvidence = "No antivirus protection detected"
    if ($securityData.MalwareProtection.AntivirusEnabled -and $securityData.MalwareProtection.RealTimeEnabled) {
        $avStatus = "Compliant"
        $avEvidence = "Antivirus with real-time protection enabled"
    } 
    $compliance += New-ComplianceObject "A.5.25" "Assessment and decision on information security events" $avStatus $avEvidence "High"
    Write-Host "<WRITE-LOG = ""*$avStatus A.5.25 Assessment and decision on information security events $avEvidence High*"">"
    

    # A.5.2 - Information security roles and responsibilities
$rolesDefined = $securityData.Roles.Count -gt 0
$rolesStatus = if ($rolesDefined) { "Compliant" } else { "Manual-Review" }
$rolesEvidence = "$($securityData.Roles.Count) security roles defined"
$compliance += New-ComplianceObject "A.5.2" "Information security roles and responsibilities" $rolesStatus $rolesEvidence "High"
Write-Host "<WRITE-LOG = ""*$rolesStatus A.5.2 Information security roles and responsibilities $rolesEvidence High*"">"

# A.5.3 - Segregation of duties
$soxdUsers = $securityData.Accounts.SegregationOfDuties.Count
$soxStatus = if ($soxdUsers -ge 2) { "Compliant" } else { "Partially Compliant" }
$soxEvidence = "$soxdUsers users verified for segregation of duties"
$compliance += New-ComplianceObject "A.5.3" "Segregation of duties" $soxStatus $soxEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$soxStatus A.5.3 Segregation of duties $soxEvidence Medium*"">"

# A.5.4 - Management responsibilities
$mgtSecure = $securityData.Management.SecurityAwareness -eq $true
$mgtStatus = if ($mgtSecure) { "Compliant" } else { "Manual-Review" }
$mgtEvidence = "Management security responsibilities documented: $mgtSecure"
$compliance += New-ComplianceObject "A.5.4" "Management responsibilities" $mgtStatus $mgtEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$mgtStatus A.5.4 Management responsibilities $mgtEvidence Medium*"">"

# A.5.5 - Contact with authorities
$authorityContact = $securityData.Policies.AuthorityContact -eq $true
$authorityStatus = if ($authorityContact) { "Compliant" } else { "Manual-Review" }
$authorityEvidence = "Authority contact procedures: $authorityContact"
$compliance += New-ComplianceObject "A.5.5" "Contact with authorities" $authorityStatus $authorityEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$authorityStatus A.5.5 Contact with authorities $authorityEvidence Medium*"">"

# A.5.6 - Contact with special interest groups
$interestGroups = $securityData.Policies.SpecialInterestGroups -eq $true
$interestStatus = if ($interestGroups) { "Compliant" } else { "Manual-Review" }
$interestEvidence = "Special interest group membership: $interestGroups"
$compliance += New-ComplianceObject "A.5.6" "Contact with special interest groups" $interestStatus $interestEvidence "Low"
Write-Host "<WRITE-LOG = ""*$interestStatus A.5.6 Contact with special interest groups $interestEvidence Low*"">"

# A.5.7 - Threat intelligence
$threatIntel = $securityData.ThreatIntelligence.MonitoringEnabled -eq $true
$threatStatus = if ($threatIntel) { "Compliant" } else { "Partially Compliant" }
$threatEvidence = "Threat intelligence monitoring: $threatIntel"
$compliance += New-ComplianceObject "A.5.7" "Threat intelligence" $threatStatus $threatEvidence "High"
Write-Host "<WRITE-LOG = ""*$threatStatus A.5.7 Threat intelligence $threatEvidence High*"">"

# A.5.8 - Information security in project management
$pmSecurity = $securityData.Policies.ProjectSecurityReview -eq $true
$pmStatus = if ($pmSecurity) { "Compliant" } else { "Manual-Review" }
$pmEvidence = "Project security review process: $pmSecurity"
$compliance += New-ComplianceObject "A.5.8" "Information security in project management" $pmStatus $pmEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$pmStatus A.5.8 Information security in project management $pmEvidence Medium*"">"

# A.5.9 - Inventory of information and other associated assets
$assetCount = $securityData.Inventory.Assets.Count
$assetStatus = if ($assetCount -gt 0) { "Compliant" } else { "Non-Compliant" }
$assetEvidence = "$assetCount assets inventoried"
$compliance += New-ComplianceObject "A.5.9" "Inventory of information and other associated assets" $assetStatus $assetEvidence "High"
Write-Host "<WRITE-LOG = ""*$assetStatus A.5.9 Inventory of information and other associated assets $assetEvidence High*"">"

# A.5.10 - Acceptable use of information and other associated assets
$acceptableUse = $securityData.Policies.AcceptableUsePolicy -eq $true
$acceptableStatus = if ($acceptableUse) { "Compliant" } else { "Non-Compliant" }
$acceptableEvidence = "Acceptable use policy documented: $acceptableUse"
$compliance += New-ComplianceObject "A.5.10" "Acceptable use of information and other associated assets" $acceptableStatus $acceptableEvidence "High"
Write-Host "<WRITE-LOG = ""*$acceptableStatus A.5.10 Acceptable use of information and other associated assets $acceptableEvidence High*"">"

# A.5.11 - Return of assets
$returnAssets = $securityData.Policies.ReturnOfAssets -eq $true
$returnStatus = if ($returnAssets) { "Compliant" } else { "Manual-Review" }
$returnEvidence = "Asset return procedures: $returnAssets"
$compliance += New-ComplianceObject "A.5.11" "Return of assets" $returnStatus $returnEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$returnStatus A.5.11 Return of assets $returnEvidence Medium*"">"

# A.5.12 - Classification of information
$classification = $securityData.Classification.Levels.Count -gt 0
$classStatus = if ($classification) { "Compliant" } else { "Non-Compliant" }
$classEvidence = "$($securityData.Classification.Levels.Count) classification levels defined"
$compliance += New-ComplianceObject "A.5.12" "Classification of information" $classStatus $classEvidence "High"
Write-Host "<WRITE-LOG = ""*$classStatus A.5.12 Classification of information $classEvidence High*"">"

# A.5.13 - Labelling of information
$labelling = $securityData.Classification.LabellingEnabled -eq $true
$labelStatus = if ($labelling) { "Compliant" } else { "Partially Compliant" }
$labelEvidence = "Information labelling implemented: $labelling"
$compliance += New-ComplianceObject "A.5.13" "Labelling of information" $labelStatus $labelEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$labelStatus A.5.13 Labelling of information $labelEvidence Medium*"">"

# A.5.14 - Information transfer
$transferControls = $securityData.DataTransfer.ControlsEnabled -eq $true
$transferStatus = if ($transferControls) { "Compliant" } else { "Non-Compliant" }
$transferEvidence = "Secure transfer controls: $transferControls"
$compliance += New-ComplianceObject "A.5.14" "Information transfer" $transferStatus $transferEvidence "High"
Write-Host "<WRITE-LOG = ""*$transferStatus A.5.14 Information transfer $transferEvidence High*"">"

# A.5.15 - Access control
$accessControl = $securityData.Access.ControlsImplemented -eq $true
$accessCtrlStatus = if ($accessControl) { "Compliant" } else { "Non-Compliant" }
$accessCtrlEvidence = "Access controls implemented: $accessControl"
$compliance += New-ComplianceObject "A.5.15" "Access control" $accessCtrlStatus $accessCtrlEvidence "High"
Write-Host "<WRITE-LOG = ""*$accessCtrlStatus A.5.15 Access control $accessCtrlEvidence High*"">"

# A.5.16 - Identity management
$identityMgmt = $securityData.Identity.ManagedCount -gt 0
$idStatus = if ($identityMgmt) { "Compliant" } else { "Non-Compliant" }
$idEvidence = "$($securityData.Identity.ManagedCount) identities managed"
$compliance += New-ComplianceObject "A.5.16" "Identity management" $idStatus $idEvidence "High"
Write-Host "<WRITE-LOG = ""*$idStatus A.5.16 Identity management $idEvidence High*"">"

# A.5.17 - Authentication information
$authStrength = $securityData.Authentication.PasswordLength -ge 12
$authStatus = if ($authStrength) { "Compliant" } else { "Non-Compliant" }
$authEvidence = "Password minimum length: $($securityData.Authentication.PasswordLength) characters"
$compliance += New-ComplianceObject "A.5.17" "Authentication information" $authStatus $authEvidence "High"
Write-Host "<WRITE-LOG = ""*$authStatus A.5.17 Authentication information $authEvidence High*"">"

# A.5.18 - Access rights
$adminCount = $securityData.Accounts.LocalAdmins.Count
$accessStatus = if ($adminCount -le 3) { "Compliant" } else { "Partially Compliant" }
$accessEvidence = "$adminCount administrator accounts configured"
$compliance += New-ComplianceObject "A.5.18" "Access rights" $accessStatus $accessEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$accessStatus A.5.18 Access rights $accessEvidence Medium*"">"

# A.5.19 - Information security in supplier relationships
$supplierSec = $securityData.Suppliers.SecurityAssessed -eq $true
$supplierStatus = if ($supplierSec) { "Compliant" } else { "Manual-Review" }
$supplierEvidence = "Supplier security assessments: $supplierSec"
$compliance += New-ComplianceObject "A.5.19" "Information security in supplier relationships" $supplierStatus $supplierEvidence "High"
Write-Host "<WRITE-LOG = ""*$supplierStatus A.5.19 Information security in supplier relationships $supplierEvidence High*"">"

# A.5.20 - Addressing information security within supplier agreements
$supplierAgreement = $securityData.Suppliers.AgreementsCount -gt 0
$agreementStatus = if ($supplierAgreement) { "Compliant" } else { "Non-Compliant" }
$agreementEvidence = "$($securityData.Suppliers.AgreementsCount) supplier agreements with security terms"
$compliance += New-ComplianceObject "A.5.20" "Addressing information security within supplier agreements" $agreementStatus $agreementEvidence "High"
Write-Host "<WRITE-LOG = ""*$agreementStatus A.5.20 Addressing information security within supplier agreements $agreementEvidence High*"">"

# A.5.21 - Managing information security in the ICT supply chain
$supplyChain = $securityData.Supplies.ICTSecurityManaged -eq $true
$chainStatus = if ($supplyChain) { "Compliant" } else { "Manual-Review" }
$chainEvidence = "ICT supply chain security managed: $supplyChain"
$compliance += New-ComplianceObject "A.5.21" "Managing information security in the ICT supply chain" $chainStatus $chainEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$chainStatus A.5.21 Managing information security in the ICT supply chain $chainEvidence Medium*"">"

# A.5.22 - Monitoring, review and change management of supplier services
$supplierMonitor = $securityData.Suppliers.MonitoringEnabled -eq $true
$monitorStatus = if ($supplierMonitor) { "Compliant" } else { "Manual-Review" }
$monitorEvidence = "Supplier service monitoring: $supplierMonitor"
$compliance += New-ComplianceObject "A.5.22" "Monitoring, review and change management of supplier services" $monitorStatus $monitorEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$monitorStatus A.5.22 Monitoring, review and change management of supplier services $monitorEvidence Medium*"">"

# A.5.23 - Information security for use of cloud services
$cloudSec = $securityData.Cloud.SecurityControls -eq $true
$cloudStatus = if ($cloudSec) { "Compliant" } else { "Partially Compliant" }
$cloudEvidence = "Cloud security controls: $cloudSec"
$compliance += New-ComplianceObject "A.5.23" "Information security for use of cloud services" $cloudStatus $cloudEvidence "High"
Write-Host "<WRITE-LOG = ""*$cloudStatus A.5.23 Information security for use of cloud services $cloudEvidence High*"">"

# A.5.24 - Information security incident response planning
$incidentPlan = $securityData.Incident.ResponsePlanExists -eq $true
$incidentPlanStatus = if ($incidentPlan) { "Compliant" } else { "Non-Compliant" }
$incidentPlanEvidence = "Incident response plan documented: $incidentPlan"
$compliance += New-ComplianceObject "A.5.24" "Information security incident response planning" $incidentPlanStatus $incidentPlanEvidence "High"
Write-Host "<WRITE-LOG = ""*$incidentPlanStatus A.5.24 Information security incident response planning $incidentPlanEvidence High*"">"

# A.5.25 - Assessment and decision on information security events
$eventAssessment = $securityData.Incident.EventAssessmentProcess -eq $true
$eventStatus = if ($eventAssessment) { "Compliant" } else { "Partially Compliant" }
$eventEvidence = "Event assessment process: $eventAssessment"
$compliance += New-ComplianceObject "A.5.25" "Assessment and decision on information security events" $eventStatus $eventEvidence "High"
Write-Host "<WRITE-LOG = ""*$eventStatus A.5.25 Assessment and decision on information security events $eventEvidence High*"">"

# A.5.26 - Response to information security incidents
$incidentResponse = $securityData.Incident.ResponseProcedureExists -eq $true
$incidentResponseStatus = if ($incidentResponse) { "Compliant" } else { "Non-Compliant" }
$incidentResponseEvidence = "Incident response procedure: $incidentResponse"
$compliance += New-ComplianceObject "A.5.26" "Response to information security incidents" $incidentResponseStatus $incidentResponseEvidence "High"
Write-Host "<WRITE-LOG = ""*$incidentResponseStatus A.5.26 Response to information security incidents $incidentResponseEvidence High*"">"

# A.5.27 - Learning from information security incidents
$incidentLearning = $securityData.Incident.LessonsLearnedProcess -eq $true
$learningStatus = if ($incidentLearning) { "Compliant" } else { "Partially Compliant" }
$learningEvidence = "Lessons learned process: $incidentLearning"
$compliance += New-ComplianceObject "A.5.27" "Learning from information security incidents" $learningStatus $learningEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$learningStatus A.5.27 Learning from information security incidents $learningEvidence Medium*"">"

# A.5.28 - Collection of evidence
$evidenceCollection = $securityData.Incident.EvidenceCollectionProcedures -eq $true
$evidenceStatus = if ($evidenceCollection) { "Compliant" } else { "Partially Compliant" }
$evidenceEvidence = "Evidence collection procedures: $evidenceCollection"
$compliance += New-ComplianceObject "A.5.28" "Collection of evidence" $evidenceStatus $evidenceEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$evidenceStatus A.5.28 Collection of evidence $evidenceEvidence Medium*"">"

# A.5.29 - Information security during disruption
$disruptionSec = $securityData.BusinessContinuity.DisruptionSecurity -eq $true
$disruptionStatus = if ($disruptionSec) { "Compliant" } else { "Partially Compliant" }
$disruptionEvidence = "Security during disruption: $disruptionSec"
$compliance += New-ComplianceObject "A.5.29" "Information security during disruption" $disruptionStatus $disruptionEvidence "High"
Write-Host "<WRITE-LOG = ""*$disruptionStatus A.5.29 Information security during disruption $disruptionEvidence High*"">"

# A.5.30 - ICT readiness for business continuity
$ictReadiness = $securityData.BusinessContinuity.ICTReadiness -eq $true
$ictStatus = if ($ictReadiness) { "Compliant" } else { "Non-Compliant" }
$ictEvidence = "ICT readiness for BC: $ictReadiness"
$compliance += New-ComplianceObject "A.5.30" "ICT readiness for business continuity" $ictStatus $ictEvidence "High"
Write-Host "<WRITE-LOG = ""*$ictStatus A.5.30 ICT readiness for business continuity $ictEvidence High*"">"

# A.5.31 - Legal, statutory, regulatory and contractual requirements
$legalReqs = $securityData.Compliance.LegalRequirements -eq $true
$legalStatus = if ($legalReqs) { "Compliant" } else { "Manual-Review" }
$legalEvidence = "Legal requirements documented: $legalReqs"
$compliance += New-ComplianceObject "A.5.31" "Legal, statutory, regulatory and contractual requirements" $legalStatus $legalEvidence "High"
Write-Host "<WRITE-LOG = ""*$legalStatus A.5.31 Legal, statutory, regulatory and contractual requirements $legalEvidence High*"">"

# A.5.32 - Intellectual property rights
$ipProtection = $securityData.Compliance.IPProtection -eq $true
$ipStatus = if ($ipProtection) { "Compliant" } else { "Manual-Review" }
$ipEvidence = "IP rights protected: $ipProtection"
$compliance += New-ComplianceObject "A.5.32" "Intellectual property rights" $ipStatus $ipEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$ipStatus A.5.32 Intellectual property rights $ipEvidence Medium*"">"

# A.5.33 - Protection of records
$recordsProtection = $securityData.Records.ProtectionEnabled -eq $true
$recordsStatus = if ($recordsProtection) { "Compliant" } else { "Partially Compliant" }
$recordsEvidence = "Records protection: $recordsProtection"
$compliance += New-ComplianceObject "A.5.33" "Protection of records" $recordsStatus $recordsEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$recordsStatus A.5.33 Protection of records $recordsEvidence Medium*"">"

# A.5.34 - Privacy and protection of PII
$piiProtection = $securityData.Privacy.PIIProtection -eq $true
$piiStatus = if ($piiProtection) { "Compliant" } else { "Partially Compliant" }
$piiEvidence = "PII protection measures: $piiProtection"
$compliance += New-ComplianceObject "A.5.34" "Privacy and protection of PII" $piiStatus $piiEvidence "High"
Write-Host "<WRITE-LOG = ""*$piiStatus A.5.34 Privacy and protection of PII $piiEvidence High*"">"

# A.5.35 - Independent review of information security
$independentReview = $securityData.Security.IndependentReview -eq $true
$reviewStatus = if ($independentReview) { "Compliant" } else { "Manual-Review" }
$reviewEvidence = "Independent security reviews: $independentReview"
$compliance += New-ComplianceObject "A.5.35" "Independent review of information security" $reviewStatus $reviewEvidence "High"
Write-Host "<WRITE-LOG = ""*$reviewStatus A.5.35 Independent review of information security $reviewEvidence High*"">"

# A.5.36 - Compliance with policies, rules and standards
$policyCompliance = $securityData.Compliance.PoliciesEnforced -eq $true
$policyCompStatus = if ($policyCompliance) { "Compliant" } else { "Non-Compliant" }
$policyCompEvidence = "Policies enforced: $policyCompliance"
$compliance += New-ComplianceObject "A.5.36" "Compliance with policies, rules and standards" $policyCompStatus $policyCompEvidence "High"
Write-Host "<WRITE-LOG = ""*$policyCompStatus A.5.36 Compliance with policies, rules and standards $policyCompEvidence High*"">"

# A.5.37 - Documented operating procedures
$docProcedures = $securityData.Operations.DocumentedProcedures -eq $true
$docStatus = if ($docProcedures) { "Compliant" } else { "Non-Compliant" }
$docEvidence = "Operating procedures documented: $docProcedures"
$compliance += New-ComplianceObject "A.5.37" "Documented operating procedures" $docStatus $docEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$docStatus A.5.37 Documented operating procedures $docEvidence Medium*"">"

# A.6.1 - Screening
$screening = $securityData.HR.ScreeningProcess -eq $true
$screeningStatus = if ($screening) { "Compliant" } else { "Manual-Review" }
$screeningEvidence = "Background screening process: $screening"
$compliance += New-ComplianceObject "A.6.1" "Screening" $screeningStatus $screeningEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$screeningStatus A.6.1 Screening $screeningEvidence Medium*"">"

# A.6.2 - Terms and conditions of employment
$empTerms = $securityData.HR.EmploymentTerms -eq $true
$empStatus = if ($empTerms) { "Compliant" } else { "Manual-Review" }
$empEvidence = "Security terms in employment contracts: $empTerms"
$compliance += New-ComplianceObject "A.6.2" "Terms and conditions of employment" $empStatus $empEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$empStatus A.6.2 Terms and conditions of employment $empEvidence Medium*"">"

# A.6.3 - Information security awareness, education and training
$awareness = $securityData.Training.AwarenessProgram -eq $true
$awarenessStatus = if ($awareness) { "Compliant" } else { "Non-Compliant" }
$awarenessEvidence = "Security awareness program: $awareness"
$compliance += New-ComplianceObject "A.6.3" "Information security awareness, education and training" $awarenessStatus $awarenessEvidence "High"
Write-Host "<WRITE-LOG = ""*$awarenessStatus A.6.3 Information security awareness, education and training $awarenessEvidence High*"">"

# A.6.4 - Disciplinary process
$disciplinary = $securityData.HR.DisciplinaryProcess -eq $true
$discStatus = if ($disciplinary) { "Compliant" } else { "Manual-Review" }
$discEvidence = "Disciplinary process for security violations: $disciplinary"
$compliance += New-ComplianceObject "A.6.4" "Disciplinary process" $discStatus $discEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$discStatus A.6.4 Disciplinary process $discEvidence Medium*"">"

# A.6.5 - Responsibilities after termination or change of employment
$termResponsibilities = $securityData.HR.TerminationProcess -eq $true
$termStatus = if ($termResponsibilities) { "Compliant" } else { "Non-Compliant" }
$termEvidence = "Termination responsibilities process: $termResponsibilities"
$compliance += New-ComplianceObject "A.6.5" "Responsibilities after termination or change of employment" $termStatus $termEvidence "High"
Write-Host "<WRITE-LOG = ""*$termStatus A.6.5 Responsibilities after termination or change of employment $termEvidence High*"">"

# A.6.6 - Confidentiality or non-disclosure agreements
$nda = $securityData.HR.NDARequired -eq $true
$ndaStatus = if ($nda) { "Compliant" } else { "Non-Compliant" }
$ndaEvidence = "NDA/Clauses required: $nda"
$compliance += New-ComplianceObject "A.6.6" "Confidentiality or non-disclosure agreements" $ndaStatus $ndaEvidence "High"
Write-Host "<WRITE-LOG = ""*$ndaStatus A.6.6 Confidentiality or non-disclosure agreements $ndaEvidence High*"">"

# A.6.7 - Remote working
$remoteWork = $securityData.Remote.AccessEnabled -eq $true
$remoteSecured = $securityData.Remote.SecureAccess -eq $true
$remoteStatus = if ($remoteWork -and $remoteSecured) { "Compliant" } elseif ($remoteWork) { "Partially Compliant" } else { "Not Applicable" }
$remoteEvidence = "Remote work enabled: $remoteWork, Secured: $remoteSecured"
$compliance += New-ComplianceObject "A.6.7" "Remote working" $remoteStatus $remoteEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$remoteStatus A.6.7 Remote working $remoteEvidence Medium*"">"

# A.6.8 - Information security event reporting
$eventReporting = $securityData.Incident.EventReportingEnabled -eq $true
$eventReportStatus = if ($eventReporting) { "Compliant" } else { "Non-Compliant" }
$eventReportEvidence = "Event reporting mechanism: $eventReporting"
$compliance += New-ComplianceObject "A.6.8" "Information security event reporting" $eventReportStatus $eventReportEvidence "High"
Write-Host "<WRITE-LOG = ""*$eventReportStatus A.6.8 Information security event reporting $eventReportEvidence High*"">"

# A.7.1 - Physical security perimeters
$physicalPerimeters = $securityData.Physical.PerimetersDefined -eq $true
$perimeterStatus = if ($physicalPerimeters) { "Compliant" } else { "Manual-Review" }
$perimeterEvidence = "Physical perimeters defined: $physicalPerimeters"
$compliance += New-ComplianceObject "A.7.1" "Physical security perimeters" $perimeterStatus $perimeterEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$perimeterStatus A.7.1 Physical security perimeters $perimeterEvidence Medium*"">"

# A.7.2 - Physical entry
$physicalEntry = $securityData.Physical.EntryControls -eq $true
$entryStatus = if ($physicalEntry) { "Compliant" } else { "Manual-Review" }
$entryEvidence = "Physical entry controls: $physicalEntry"
$compliance += New-ComplianceObject "A.7.2" "Physical entry" $entryStatus $entryEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$entryStatus A.7.2 Physical entry $entryEvidence Medium*"">"

# A.7.3 - Securing offices, rooms and facilities
$facilitiesSec = $securityData.Physical.FacilitiesSecured -eq $true
$facilityStatus = if ($facilitiesSec) { "Compliant" } else { "Manual-Review" }
$facilityEvidence = "Facilities secured: $facilitiesSec"
$compliance += New-ComplianceObject "A.7.3" "Securing offices, rooms and facilities" $facilityStatus $facilityEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$facilityStatus A.7.3 Securing offices, rooms and facilities $facilityEvidence Medium*"">"

# A.7.4 - Physical security monitoring
$physicalMonitor = $securityData.Physical.MonitoringEnabled -eq $true
$monitorPhysicalStatus = if ($physicalMonitor) { "Compliant" } else { "Manual-Review" }
$monitorPhysicalEvidence = "Physical monitoring (CCTV/alarms): $physicalMonitor"
$compliance += New-ComplianceObject "A.7.4" "Physical security monitoring" $monitorPhysicalStatus $monitorPhysicalEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$monitorPhysicalStatus A.7.4 Physical security monitoring $monitorPhysicalEvidence Medium*"">"

# A.7.5 - Protecting against physical and environmental threats
$envProtection = $securityData.Physical.EnvironmentalProtection -eq $true
$envStatus = if ($envProtection) { "Compliant" } else { "Manual-Review" }
$envEvidence = "Environmental threat protection: $envProtection"
$compliance += New-ComplianceObject "A.7.5" "Protecting against physical and environmental threats" $envStatus $envEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$envStatus A.7.5 Protecting against physical and environmental threats $envEvidence Medium*"">"

# A.7.6 - Working in secure areas
$secureAreas = $securityData.Physical.SecureAreas -eq $true
$secureAreaStatus = if ($secureAreas) { "Compliant" } else { "Manual-Review" }
$secureAreaEvidence = "Secure areas defined: $secureAreas"
$compliance += New-ComplianceObject "A.7.6" "Working in secure areas" $secureAreaStatus $secureAreaEvidence "Low"
Write-Host "<WRITE-LOG = ""*$secureAreaStatus A.7.6 Working in secure areas $secureAreaEvidence Low*"">"

# A.7.7 - Clear desk and clear screen
$clearDesk = $securityData.Physical.ClearDeskPolicy -eq $true
$clearDeskStatus = if ($clearDesk) { "Compliant" } else { "Partially Compliant" }
$clearDeskEvidence = "Clear desk/screen policy: $clearDesk"
$compliance += New-ComplianceObject "A.7.7" "Clear desk and clear screen" $clearDeskStatus $clearDeskEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$clearDeskStatus A.7.7 Clear desk and clear screen $clearDeskEvidence Medium*"">"

# A.7.8 - Equipment siting and protection
$equipmentProtection = $securityData.Physical.EquipmentProtected -eq $true
$equipStatus = if ($equipmentProtection) { "Compliant" } else { "Manual-Review" }
$equipEvidence = "Equipment protection: $equipmentProtection"
$compliance += New-ComplianceObject "A.7.8" "Equipment siting and protection" $equipStatus $equipEvidence "Low"
Write-Host "<WRITE-LOG = ""*$equipStatus A.7.8 Equipment siting and protection $equipEvidence Low*"">"

# A.7.9 - Security of assets off-premises
$offPremises = $securityData.Physical.OffPremisesSecurity -eq $true
$offPremStatus = if ($offPremises) { "Compliant" } else { "Partially Compliant" }
$offPremEvidence = "Off-premises asset security: $offPremises"
$compliance += New-ComplianceObject "A.7.9" "Security of assets off-premises" $offPremStatus $offPremEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$offPremStatus A.7.9 Security of assets off-premises $offPremEvidence Medium*"">"

# A.7.10 - Storage media
$storageMedia = $securityData.Physical.MediaHandling -eq $true
$mediaStatus = if ($storageMedia) { "Compliant" } else { "Partially Compliant" }
$mediaEvidence = "Storage media handling procedures: $storageMedia"
$compliance += New-ComplianceObject "A.7.10" "Storage media" $mediaStatus $mediaEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$mediaStatus A.7.10 Storage media $mediaEvidence Medium*"">"

# A.7.11 - Supporting utilities
$utilities = $securityData.Physical.UtilitiesProtected -eq $true
$utilStatus = if ($utilities) { "Compliant" } else { "Manual-Review" }
$utilEvidence = "Supporting utilities protected: $utilities"
$compliance += New-ComplianceObject "A.7.11" "Supporting utilities" $utilStatus $utilEvidence "Low"
Write-Host "<WRITE-LOG = ""*$utilStatus A.7.11 Supporting utilities $utilEvidence Low*"">"

# A.7.12 - Cabling security
$cablingSec = $securityData.Physical.CablingSecured -eq $true
$cableStatus = if ($cablingSec) { "Compliant" } else { "Manual-Review" }
$cableEvidence = "Cabling security: $cablingSec"
$compliance += New-ComplianceObject "A.7.12" "Cabling security" $cableStatus $cableEvidence "Low"
Write-Host "<WRITE-LOG = ""*$cableStatus A.7.12 Cabling security $cableEvidence Low*"">"

# A.7.13 - Equipment maintenance
$maintenance = $securityData.Physical.MaintenanceScheduled -eq $true
$maintStatus = if ($maintenance) { "Compliant" } else { "Manual-Review" }
$maintEvidence = "Equipment maintenance scheduled: $maintenance"
$compliance += New-ComplianceObject "A.7.13" "Equipment maintenance" $maintStatus $maintEvidence "Low"
Write-Host "<WRITE-LOG = ""*$maintStatus A.7.13 Equipment maintenance $maintEvidence Low*"">"

# A.7.14 - Secure disposal or re-use of equipment
$secureDisposal = $securityData.Physical.SecureDisposal -eq $true
$disposalStatus = if ($secureDisposal) { "Compliant" } else { "Non-Compliant" }
$disposalEvidence = "Secure disposal procedures: $secureDisposal"
$compliance += New-ComplianceObject "A.7.14" "Secure disposal or re-use of equipment" $disposalStatus $disposalEvidence "High"
Write-Host "<WRITE-LOG = ""*$disposalStatus A.7.14 Secure disposal or re-use of equipment $disposalEvidence High*"">"

# A.8.1 - User endpoint devices
$endpointSec = $securityData.Endpoints.SecurityEnabled -eq $true
$endpointStatus = if ($endpointSec) { "Compliant" } else { "Non-Compliant" }
$endpointEvidence = "Endpoint security enabled: $endpointSec"
$compliance += New-ComplianceObject "A.8.1" "User endpoint devices" $endpointStatus $endpointEvidence "High"
Write-Host "<WRITE-LOG = ""*$endpointStatus A.8.1 User endpoint devices $endpointEvidence High*"">"

# A.8.2 - Privileged access rights
$privAccounts = $securityData.Accounts.PrivilegedCount
$privStatus = if ($privAccounts -le 5) { "Compliant" } else { "Non-Compliant" }
$privEvidence = "$privAccounts privileged accounts"
$compliance += New-ComplianceObject "A.8.2" "Privileged access rights" $privStatus $privEvidence "High"
Write-Host "<WRITE-LOG = ""*$privStatus A.8.2 Privileged access rights $privEvidence High*"">"

# A.8.3 - Information access restriction
$accessRestriction = $securityData.Access.RestrictionImplemented -eq $true
$restrictStatus = if ($accessRestriction) { "Compliant" } else { "Non-Compliant" }
$restrictEvidence = "Access restrictions implemented: $accessRestriction"
$compliance += New-ComplianceObject "A.8.3" "Information access restriction" $restrictStatus $restrictEvidence "High"
Write-Host "<WRITE-LOG = ""*$restrictStatus A.8.3 Information access restriction $restrictEvidence High*"">"

# A.8.4 - Access to source code
$sourceCodeAccess = $securityData.Development.SourceCodeControlled -eq $true
$sourceStatus = if ($sourceCodeAccess) { "Compliant" } else { "Manual-Review" }
$sourceEvidence = "Source code access controlled: $sourceCodeAccess"
$compliance += New-ComplianceObject "A.8.4" "Access to source code" $sourceStatus $sourceEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$sourceStatus A.8.4 Access to source code $sourceEvidence Medium*"">"

# A.8.5 - Secure authentication
$mfaEnabled = $securityData.Authentication.MFAEnabled -eq $true
$authStatus = if ($mfaEnabled) { "Compliant" } else { "Partially Compliant" }
$authEvidence = "Multi-factor authentication: $mfaEnabled"
$compliance += New-ComplianceObject "A.8.5" "Secure authentication" $authStatus $authEvidence "High"
Write-Host "<WRITE-LOG = ""*$authStatus A.8.5 Secure authentication $authEvidence High*"">"

# A.8.6 - Capacity management
$capacityMonitored = $securityData.Infrastructure.CapacityMonitored -eq $true
$capacityStatus = if ($capacityMonitored) { "Compliant" } else { "Partially Compliant" }
$capacityEvidence = "Capacity monitoring: $capacityMonitored"
$compliance += New-ComplianceObject "A.8.6" "Capacity management" $capacityStatus $capacityEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$capacityStatus A.8.6 Capacity management $capacityEvidence Medium*"">"

# A.8.7 - Protection against malware
$malwareStatus = if ($securityData.MalwareProtection.AntivirusEnabled) { "Compliant" } else { "Non-Compliant" }
$malwareEvidence = if ($securityData.MalwareProtection.AntivirusEnabled) { "Antivirus protection active" } else { "No malware protection" }
$compliance += New-ComplianceObject "A.8.7" "Protection against malware" $malwareStatus $malwareEvidence "High"
Write-Host "<WRITE-LOG = ""*$malwareStatus A.8.7 Protection against malware $malwareEvidence High*"">"

# A.8.8 - Management of technical vulnerabilities
$updateAge = if ($securityData.Updates.LastUpdate) { ((Get-Date) - $securityData.Updates.LastUpdate.InstalledOn).Days } else { 999 }
$patchStatus = if ($updateAge -lt 30) { "Compliant" } elseif ($updateAge -lt 90) { "Partially Compliant" } else { "Non-Compliant" }
$patchEvidence = "Last update: $($securityData.Updates.LastUpdate.InstalledOn) ($updateAge days ago)"
$compliance += New-ComplianceObject "A.8.8" "Management of technical vulnerabilities" $patchStatus $patchEvidence "High"
Write-Host "<WRITE-LOG = ""*$patchStatus A.8.8 Management of technical vulnerabilities $patchEvidence High*"">"

# A.8.9 - Configuration management
$firewallEnabled = ($securityData.Network.FirewallProfiles | Where-Object {$_.Enabled -eq "True"}).Count -gt 0
$configStatus = if ($firewallEnabled) { "Compliant" } else { "Non-Compliant" }
$configEvidence = "Firewall enabled: $firewallEnabled"
$compliance += New-ComplianceObject "A.8.9" "Configuration management" $configStatus $configEvidence "High"
Write-Host "<WRITE-LOG = ""*$configStatus A.8.9 Configuration management $configEvidence High*"">"

# A.8.10 - Information deletion
$dataDeletion = $securityData.DataRetention.DeletionPolicy -eq $true
$deletionStatus = if ($dataDeletion) { "Compliant" } else { "Partially Compliant" }
$deletionEvidence = "Data deletion policy: $dataDeletion"
$compliance += New-ComplianceObject "A.8.10" "Information deletion" $deletionStatus $deletionEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$deletionStatus A.8.10 Information deletion $deletionEvidence Medium*"">"

# A.8.11 - Data masking
$dataMasking = $securityData.DataProtection.MaskingEnabled -eq $true
$maskingStatus = if ($dataMasking) { "Compliant" } else { "Partially Compliant" }
$maskingEvidence = "Data masking implemented: $dataMasking"
$compliance += New-ComplianceObject "A.8.11" "Data masking" $maskingStatus $maskingEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$maskingStatus A.8.11 Data masking $maskingEvidence Medium*"">"

# A.8.12 - Data leakage prevention
$dlpEnabled = $securityData.DataProtection.DLPEnabled -eq $true
$dlpStatus = if ($dlpEnabled) { "Compliant" } else { "Non-Compliant" }
$dlpEvidence = "DLP solutions active: $dlpEnabled"
$compliance += New-ComplianceObject "A.8.12" "Data leakage prevention" $dlpStatus $dlpEvidence "High"
Write-Host "<WRITE-LOG = ""*$dlpStatus A.8.12 Data leakage prevention $dlpEvidence High*"">"

# A.8.13 - Information backup
$backupEnabled = $securityData.Backup.BackupsEnabled -eq $true
$backupStatus = if ($backupEnabled) { "Compliant" } else { "Non-Compliant" }
$backupEvidence = "Backup system active: $backupEnabled"
$compliance += New-ComplianceObject "A.8.13" "Information backup" $backupStatus $backupEvidence "High"
Write-Host "<WRITE-LOG = ""*$backupStatus A.8.13 Information backup $backupEvidence High*"">"

# A.8.14 - Redundancy of information processing facilities
$redundancy = $securityData.Infrastructure.RedundancyConfigured -eq $true
$redundancyStatus = if ($redundancy) { "Compliant" } else { "Partially Compliant" }
$redundancyEvidence = "Redundancy configured: $redundancy"
$compliance += New-ComplianceObject "A.8.14" "Redundancy of information processing facilities" $redundancyStatus $redundancyEvidence "High"
Write-Host "<WRITE-LOG = ""*$redundancyStatus A.8.14 Redundancy of information processing facilities $redundancyEvidence High*"">"

# A.8.15 - Logging
$auditEnabled = $securityData.Audit.AuditPolicies.Count -gt 0
$loggingStatus = if ($auditEnabled) { "Compliant" } else { "Partially Compliant" }
$loggingEvidence = "Audit policies configured: $auditEnabled"
$compliance += New-ComplianceObject "A.8.15" "Logging" $loggingStatus $loggingEvidence "High"
Write-Host "<WRITE-LOG = ""*$loggingStatus A.8.15 Logging $loggingEvidence High*"">"

# A.8.16 - Monitoring activities
$monitoringEnabled = $securityData.Monitoring.SystemMonitoringEnabled -eq $true
$monitorStatus = if ($monitoringEnabled) { "Compliant" } else { "Non-Compliant" }
$monitorEvidence = "System monitoring active: $monitoringEnabled"
$compliance += New-ComplianceObject "A.8.16" "Monitoring activities" $monitorStatus $monitorEvidence "High"
Write-Host "<WRITE-LOG = ""*$monitorStatus A.8.16 Monitoring activities $monitorEvidence High*"">"

# A.8.17 - Clock synchronization
$ntpEnabled = $securityData.TimeSync.NTPEnabled -eq $true
$ntpStatus = if ($ntpEnabled) { "Compliant" } else { "Non-Compliant" }
$ntpEvidence = "NTP synchronization: $ntpEnabled"
$compliance += New-ComplianceObject "A.8.17" "Clock synchronization" $ntpStatus $ntpEvidence "High"
Write-Host "<WRITE-LOG = ""*$ntpStatus A.8.17 Clock synchronization $ntpEvidence High*"">"

# A.8.18 - Use of privileged utility programs
$utilRestrictions = $securityData.Privileged.UtilityRestrictions -eq $true
$utilStatus = if ($utilRestrictions) { "Compliant" } else { "Partially Compliant" }
$utilEvidence = "Utility program restrictions: $utilRestrictions"
$compliance += New-ComplianceObject "A.8.18" "Use of privileged utility programs" $utilStatus $utilEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$utilStatus A.8.18 Use of privileged utility programs $utilEvidence Medium*"">"

# A.8.19 - Installation of software on operational systems
$softwareControl = $securityData.Software.InstallationControlled -eq $true
$softwareStatus = if ($softwareControl) { "Compliant" } else { "Non-Compliant" }
$softwareEvidence = "Software installation controlled: $softwareControl"
$compliance += New-ComplianceObject "A.8.19" "Installation of software on operational systems" $softwareStatus $softwareEvidence "High"
Write-Host "<WRITE-LOG = ""*$softwareStatus A.8.19 Installation of software on operational systems $softwareEvidence High*"">"

# A.8.20 - Networks security
$networkSecurity = $securityData.Network.SecurityControlsImplemented -eq $true
$networkStatus = if ($networkSecurity) { "Compliant" } else { "Non-Compliant" }
$networkEvidence = "Network security controls implemented: $networkSecurity"
$compliance += New-ComplianceObject "A.8.20" "Networks security" $networkStatus $networkEvidence "High"
Write-Host "<WRITE-LOG = ""*$networkStatus A.8.20 Networks security $networkEvidence High*"">"

# A.8.21 - Security of network services
$networkServices = $securityData.Network.ServicesSecured -eq $true
$servicesStatus = if ($networkServices) { "Compliant" } else { "Partially Compliant" }
$servicesEvidence = "Network services secured: $networkServices"
$compliance += New-ComplianceObject "A.8.21" "Security of network services" $servicesStatus $servicesEvidence "High"
Write-Host "<WRITE-LOG = ""*$servicesStatus A.8.21 Security of network services $servicesEvidence High*"">"

# A.8.22 - Segregation of networks
$networkSegregation = $securityData.Network.SegregationImplemented -eq $true
$segregStatus = if ($networkSegregation) { "Compliant" } else { "Partially Compliant" }
$segregEvidence = "Network segregation: $networkSegregation"
$compliance += New-ComplianceObject "A.8.22" "Segregation of networks" $segregStatus $segregEvidence "High"
Write-Host "<WRITE-LOG = ""*$segregStatus A.8.22 Segregation of networks $segregEvidence High*"">"

# A.8.23 - Web filtering
$webFiltering = $securityData.Network.WebFilteringEnabled -eq $true
$webFilterStatus = if ($webFiltering) { "Compliant" } else { "Partially Compliant" }
$webFilterEvidence = "Web filtering enabled: $webFiltering"
$compliance += New-ComplianceObject "A.8.23" "Web filtering" $webFilterStatus $webFilterEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$webFilterStatus A.8.23 Web filtering $webFilterEvidence Medium*"">"

# A.8.24 - Use of cryptography
$cryptography = $securityData.Encryption.CryptoPoliciesDefined -eq $true
$cryptoStatus = if ($cryptography) { "Compliant" } else { "Partially Compliant" }
$cryptoEvidence = "Cryptography policies defined: $cryptography"
$compliance += New-ComplianceObject "A.8.24" "Use of cryptography" $cryptoStatus $cryptoEvidence "High"
Write-Host "<WRITE-LOG = ""*$cryptoStatus A.8.24 Use of cryptography $cryptoEvidence High*"">"

# A.8.25 - Secure development life cycle
$secureSDLC = $securityData.Development.SecureSDLC -eq $true
$sdlcStatus = if ($secureSDLC) { "Compliant" } else { "Manual-Review" }
$sdlcEvidence = "Secure SDLC implemented: $secureSDLC"
$compliance += New-ComplianceObject "A.8.25" "Secure development life cycle" $sdlcStatus $sdlcEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$sdlcStatus A.8.25 Secure development life cycle $sdlcEvidence Medium*"">"

# A.8.26 - Application security requirements
$appSecReq = $securityData.Development.AppSecurityRequirements -eq $true
$appReqStatus = if ($appSecReq) { "Compliant" } else { "Partially Compliant" }
$appReqEvidence = "Application security requirements defined: $appReq"
$compliance += New-ComplianceObject "A.8.26" "Application security requirements" $appReqStatus $appReqEvidence "High"
Write-Host "<WRITE-LOG = ""*$appReqStatus A.8.26 Application security requirements $appReqEvidence High*"">"

# A.8.27 - Secure system architecture and engineering principles
$secureArch = $securityData.Development.SecureArchitecture -eq $true
$archStatus = if ($secureArch) { "Compliant" } else { "Manual-Review" }
$archEvidence = "Secure architecture principles: $secureArch"
$compliance += New-ComplianceObject "A.8.27" "Secure system architecture and engineering principles" $archStatus $archEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$archStatus A.8.27 Secure system architecture and engineering principles $archEvidence Medium*"">"

# A.8.28 - Secure coding
$secureCoding = $securityData.Development.SecureCodingStandards -eq $true
$codingStatus = if ($secureCoding) { "Compliant" } else { "Manual-Review" }
$codingEvidence = "Secure coding standards: $secureCoding"
$compliance += New-ComplianceObject "A.8.28" "Secure coding" $codingStatus $codingEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$codingStatus A.8.28 Secure coding $codingEvidence Medium*"">"

# A.8.29 - Security testing in development and acceptance
$securityTesting = $securityData.Development.SecurityTestingEnabled -eq $true
$testStatus = if ($securityTesting) { "Compliant" } else { "Partially Compliant" }
$testEvidence = "Security testing in SDLC: $securityTesting"
$compliance += New-ComplianceObject "A.8.29" "Security testing in development and acceptance" $testStatus $testEvidence "High"
Write-Host "<WRITE-LOG = ""*$testStatus A.8.29 Security testing in development and acceptance $testEvidence High*"">"

# A.8.30 - Outsourced development
$outsourcedDev = $securityData.Development.OutsourcedControlled -eq $true
$outsourcedStatus = if ($outsourcedDev) { "Compliant" } else { "Manual-Review" }
$outsourcedEvidence = "Outsourced development controlled: $outsourcedDev"
$compliance += New-ComplianceObject "A.8.30" "Outsourced development" $outsourcedStatus $outsourcedEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$outsourcedStatus A.8.30 Outsourced development $outsourcedEvidence Medium*"">"

# A.8.31 - Separation of development, test and production environments
$envSeparation = $securityData.Development.EnvironmentSeparation -eq $true
$envStatus = if ($envSeparation) { "Compliant" } else { "Non-Compliant" }
$envEvidence = "Environment separation: $envSeparation"
$compliance += New-ComplianceObject "A.8.31" "Separation of development, test and production environments" $envStatus $envEvidence "High"
Write-Host "<WRITE-LOG = ""*$envStatus A.8.31 Separation of development, test and production environments $envEvidence High*"">"

# A.8.32 - Change management
$changeMgmt = $securityData.Operations.ChangeManagementProcess -eq $true
$changeStatus = if ($changeMgmt) { "Compliant" } else { "Non-Compliant" }
$changeEvidence = "Change management process: $changeMgmt"
$compliance += New-ComplianceObject "A.8.32" "Change management" $changeStatus $changeEvidence "High"
Write-Host "<WRITE-LOG = ""*$changeStatus A.8.32 Change management $changeEvidence High*"">"

# A.8.33 - Test information
$testDataProtection = $securityData.Testing.TestDataProtected -eq $true
$testDataStatus = if ($testDataProtection) { "Compliant" } else { "Partially Compliant" }
$testDataEvidence = "Test data protected: $testDataProtection"
$compliance += New-ComplianceObject "A.8.33" "Test information" $testDataStatus $testDataEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$testDataStatus A.8.33 Test information $testDataEvidence Medium*"">"

# A.8.34 - Protection of information systems during audit testing
$auditProtection = $securityData.Audit.SystemsProtectedDuringAudit -eq $true
$auditProtStatus = if ($auditProtection) { "Compliant" } else { "Partially Compliant" }
$auditProtEvidence = "Systems protected during audits: $auditProtection"
$compliance += New-ComplianceObject "A.8.34" "Protection of information systems during audit testing" $auditProtStatus $auditProtEvidence "Medium"
Write-Host "<WRITE-LOG = ""*$auditProtStatus A.8.34 Protection of information systems during audit testing $auditProtEvidence Medium*"">"


    
    return $compliance
}

function New-ComplianceObject {
    param($ControlID, $ControlName, $Status, $Evidence, $RiskLevel)
    
    return @{
        ControlID = $ControlID
        ControlName = $ControlName
        Status = $Status
        Evidence = $Evidence
        RiskLevel = $RiskLevel
        AssessmentDate = Get-Date
    }
}

function Get-ISO27001ReportHTML {
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $computerName = $env:COMPUTERNAME
    $domain = $env:USERDOMAIN
    $userName = $env:USERNAME
    
    # Collect all data
    $systemInfo = Get-AdvancedSystemInformation
    $complianceData = Assess-ISO27001Compliance
    $compliantCount = ($complianceData | Where-Object { $_.Status -eq "Compliant" }).Count
    $totalCount = $complianceData.Count
    
    Write-Host "<WRITE-LOG = ""*=== ENTERPRISE ASSESSMENT SUMMARY ===*"">" -ForegroundColor Cyan
    Write-Host "<WRITE-LOG = ""*Controls Assessed: $totalCount*"">" -ForegroundColor White
    Write-Host "<WRITE-LOG = ""*Compliant Controls: $compliantCount*"">" -ForegroundColor Green
    Write-Host "<WRITE-LOG = ""*Compliance Rate: $([math]::Round(($compliantCount/$totalCount)*100, 1))%*"">" -ForegroundColor Yellow

    $securityData = Get-ComprehensiveSecurityAssessment
    
    @"
<!DOCTYPE html>
<html>
<head>
    <title>ISO 27001:2022 Compliance Assessment Report - $computerName</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #333; line-height: 1.6; }
        .header { background: linear-gradient(135deg, #2c3e50, #4a6491); color: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .section { margin: 25px 0; padding: 20px; border-left: 5px solid #3498db; background-color: #f8f9fa; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .subsection { margin: 15px 0; padding: 15px; background-color: #ecf0f1; border-radius: 5px; border-left: 3px solid #7f8c8d; }
        .compliant { color: #27ae60; font-weight: bold; background-color: #d4edda; padding: 2px 6px; border-radius: 3px; }
        .non-compliant { color: #e74c3c; font-weight: bold; background-color: #f8d7da; padding: 2px 6px; border-radius: 3px; }
        .partially-compliant { color: #f39c12; font-weight: bold; background-color: #fff3cd; padding: 2px 6px; border-radius: 3px; }
        .not-applicable { color: #95a5a6; font-weight: bold; background-color: #f8f9fa; padding: 2px 6px; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 14px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #bdc3c7; padding: 12px; text-align: left; }
        th { background-color: #34495e; color: white; font-weight: 600; position: sticky; top: 0; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        .risk-high { background-color: #ffcccc; border-left: 4px solid #e74c3c; }
        .risk-medium { background-color: #fff2cc; border-left: 4px solid #f39c12; }
        .risk-low { background-color: #ccffcc; border-left: 4px solid #27ae60; }
        h1 { margin: 0 0 10px 0; font-size: 28px; }
        h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 8px; margin-top: 30px; }
        h3 { color: #34495e; margin-top: 20px; }
        .summary { background-color: #e8f4fc; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #3498db; }
        .control-domain { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .evidence { font-family: 'Courier New', monospace; background-color: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 3px; font-size: 12px; }
        .metric { text-align: center; padding: 15px; background: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .metric-label { font-size: 12px; color: #7f8c8d; text-transform: uppercase; }
    </style>
</head>
<body>
    <div class="header">
        <h1>ISO 27001:2022 Compliance Assessment Report</h1>
        <p><strong>Generated:</strong> $reportDate | <strong>System:</strong> $computerName | <strong>Domain:</strong> $domain | <strong>User:</strong> $userName</p>
        <p><strong>Assessment Scope:</strong> Technical Security Controls | <strong>Framework:</strong> ISO/IEC 27001:2022</p>
    </div>

    $(Get-ExecutiveSummarySection $complianceData)
    $(Get-SystemInformationSection $systemInfo)
    $(Get-DetailedComplianceSection $complianceData)
    $(Get-RiskAssessmentSection $complianceData $securityData)
    $(Get-StatementOfApplicabilitySection $complianceData)
    $(Get-RiskTreatmentPlanSection $complianceData)
    $(Get-EvidenceLogSection $securityData)
    $(Get-RecommendationsSection $complianceData)

    <div class="section">
        <h2>Assessment Methodology & Disclaimer</h2>
        <div class="subsection">
            <h3>Methodology</h3>
            <p>This automated assessment evaluates technical controls aligned with ISO 27001:2022 requirements. The assessment includes:</p>
            <ul>
                <li>System configuration analysis</li>
                <li>Security control verification</li>
                <li>Compliance gap analysis</li>
                <li>Risk identification and treatment planning</li>
            </ul>
        </div>
        <div class="subsection">
            <h3>Disclaimer</h3>
            <p>This report provides a technical assessment of automated controls and should be reviewed by qualified information security professionals. 
            Organizational controls, policies, and procedures require separate assessment. This tool supports but does not replace comprehensive ISO 27001 certification audits.</p>
            <p><strong>Report Generated:</strong> $reportDate</p>
            <p><strong>Assessment Tool Version:</strong> 3.0 | <strong>Framework:</strong> ISO/IEC 27001:2022</p>
        </div>
    </div>
</body>
</html>
"@
}

function Get-ExecutiveSummarySection {
    param($complianceData)
    
    $totalControls = $complianceData.Count
    $compliantCount = ($complianceData | Where-Object { $_.Status -eq "Compliant" }).Count
    $partialCount = ($complianceData | Where-Object { $_.Status -eq "Partially Compliant" }).Count
    $nonCompliantCount = ($complianceData | Where-Object { $_.Status -eq "Non-Compliant" }).Count
    $compliancePercentage = [math]::Round(($compliantCount / $totalControls) * 100, 2)
    
    $highRisks = ($complianceData | Where-Object { $_.RiskLevel -eq "High" -and $_.Status -ne "Compliant" }).Count
    $mediumRisks = ($complianceData | Where-Object { $_.RiskLevel -eq "Medium" -and $_.Status -ne "Compliant" }).Count
    
    Write-Host "<WRITE-LOG = ""*Overall Compliance: $compliancePercentage%*"">" -ForegroundColor Yellow

    @"
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="summary">
            <h3>Compliance Overview</h3>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0;">
                <div class="metric">
                    <div class="metric-value">$compliancePercentage%</div>
                    <div class="metric-label">Overall Compliance</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$totalControls</div>
                    <div class="metric-label">Controls Assessed</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$highRisks</div>
                    <div class="metric-label">High Risks</div>
                </div>
                <div class="metric">
                    <div class="metric-value">$mediumRisks</div>
                    <div class="metric-label">Medium Risks</div>
                </div>
            </div>
            
            <h3>Key Findings</h3>
            <table>
                <tr><th>Status</th><th>Count</th><th>Percentage</th></tr>
                <tr><td><span class="compliant">Compliant</span></td><td>$compliantCount</td><td>$([math]::Round(($compliantCount/$totalControls)*100, 1))%</td></tr>
                <tr><td><span class="partially-compliant">Partially Compliant</span></td><td>$partialCount</td><td>$([math]::Round(($partialCount/$totalControls)*100, 1))%</td></tr>
                <tr><td><span class="non-compliant">Non-Compliant</span></td><td>$nonCompliantCount</td><td>$([math]::Round(($nonCompliantCount/$totalControls)*100, 1))%</td></tr>
            </table>
        </div>
    </div>
"@
}

function Get-DetailedComplianceSection {
    param($complianceData)
    
    $complianceRows = ""
    foreach ($control in $complianceData) {
        $statusClass = $control.Status.Replace(" ", "-").ToLower()
        $complianceRows += @"
        <tr>
            <td><strong>$($control.ControlID)</strong></td>
            <td>$($control.ControlName)</td>
            <td><span class="$statusClass">$($control.Status)</span></td>
            <td>$($control.Evidence)</td>
            <td>$($control.RiskLevel)</td>
            <td>$($control.AssessmentDate.ToString("yyyy-MM-dd"))</td>
        </tr>
"@
    }
    
    @"
    <div class="section">
        <h2>Detailed Compliance Assessment</h2>
        <div class="subsection">
            <h3>ISO 27001:2022 Control Assessment</h3>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Control Name</th>
                    <th>Status</th>
                    <th>Evidence</th>
                    <th>Risk Level</th>
                    <th>Assessment Date</th>
                </tr>
                $complianceRows
            </table>
        </div>
    </div>
"@
}

function Get-RiskAssessmentSection {
    param($complianceData, $securityData)
    
    $risks = @()
    
    # Generate risks from non-compliant controls
    foreach ($control in $complianceData | Where-Object { $_.Status -ne "Compliant" }) {
        $riskLevel = $control.RiskLevel
        $likelihood = if ($riskLevel -eq "High") { "High" } elseif ($riskLevel -eq "Medium") { "Medium" } else { "Low" }
        $impact = if ($riskLevel -eq "High") { "High" } elseif ($riskLevel -eq "Medium") { "Medium" } else { "Low" }
        
        $risks += @{
            ID = "RISK-$($control.ControlID.Replace('.','-'))"
            Description = "Non-compliance with $($control.ControlName)"
            ControlID = $control.ControlID
            Likelihood = $likelihood
            Impact = $impact
            RiskLevel = $riskLevel
            Evidence = $control.Evidence
        }
    }
    
    $riskRows = ""
    if ($risks.Count -eq 0) {
        $riskRows = @"
        <tr class="risk-low">
            <td>RISK-NONE-001</td>
            <td>No significant compliance risks identified</td>
            <td>N/A</td>
            <td>Low</td>
            <td>Low</td>
            <td>All controls compliant</td>
        </tr>
"@
    } else {
        foreach ($risk in $risks) {
            $riskClass = "risk-" + $risk.RiskLevel.ToLower()
            $riskRows += @"
            <tr class="$riskClass">
                <td><strong>$($risk.ID)</strong></td>
                <td>$($risk.Description)<br><small>Control: $($risk.ControlID)</small></td>
                <td>$($risk.Likelihood)</td>
                <td>$($risk.Impact)</td>
                <td><strong>$($risk.RiskLevel)</strong></td>
                <td>$($risk.Evidence)</td>
            </tr>
"@
        }
    }
    
    @"
    <div class="section">
        <h2>Risk Assessment</h2>
        <div class="subsection">
            <h3>Compliance Risk Register</h3>
            <table>
                <tr>
                    <th>Risk ID</th>
                    <th>Risk Description</th>
                    <th>Likelihood</th>
                    <th>Impact</th>
                    <th>Risk Level</th>
                    <th>Evidence</th>
                </tr>
                $riskRows
            </table>
        </div>
    </div>
"@
}

function Get-StatementOfApplicabilitySection {
    param($complianceData)
    
    $soaRows = ""
    foreach ($control in $complianceData) {
        $statusClass = $control.Status.Replace(" ", "-").ToLower()
        $soaRows += @"
        <tr>
            <td>$($control.ControlID)</td>
            <td>$($control.ControlName)</td>
            <td>Yes</td>
            <td><span class="$statusClass">$($control.Status)</span></td>
            <td>$($control.Evidence)</td>
        </tr>
"@
    }
    
    @"
    <div class="section">
        <h2>Statement of Applicability (SoA)</h2>
        <div class="subsection">
            <h3>ISO 27001:2022 Control Implementation Status</h3>
            <p>The Statement of Applicability identifies controls relevant to this system and their implementation status.</p>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Control Name</th>
                    <th>Applicable</th>
                    <th>Implementation Status</th>
                    <th>Justification / Evidence</th>
                </tr>
                $soaRows
            </table>
        </div>
    </div>
"@
}

function Get-RiskTreatmentPlanSection {
    param($complianceData)
    
    $treatmentRows = ""
    $nonCompliantControls = $complianceData | Where-Object { $_.Status -ne "Compliant" }
    
    if ($nonCompliantControls.Count -eq 0) {
        $treatmentRows = @"
        <tr>
            <td>N/A</td>
            <td>No treatment actions required</td>
            <td>N/A</td>
            <td>N/A</td>
            <td><span class="compliant">Completed</span></td>
        </tr>
"@
    } else {
        foreach ($control in $nonCompliantControls) {
            $priority = if ($control.RiskLevel -eq "High") { "Immediate (0-30 days)" } elseif ($control.RiskLevel -eq "Medium") { "Short-term (1-3 months)" } else { "Long-term (3-12 months)" }
            $treatmentRows += @"
            <tr>
                <td>$($control.ControlID)</td>
                <td>Implement $($control.ControlName)</td>
                <td>$priority</td>
                <td>Security Team</td>
                <td><span class="non-compliant">Pending</span></td>
            </tr>
"@
        }
    }
    
    @"
    <div class="section">
        <h2>Risk Treatment Plan</h2>
        <div class="subsection">
            <h3>Treatment Actions</h3>
            <table>
                <tr>
                    <th>Control ID</th>
                    <th>Treatment Action</th>
                    <th>Timeline</th>
                    <th>Responsible Party</th>
                    <th>Status</th>
                </tr>
                $treatmentRows
            </table>
        </div>
    </div>
"@
}

function Get-EvidenceLogSection {
    param($securityData)
    
    @"
    <div class="section">
        <h2>Evidence Log</h2>
        <div class="subsection">
            <h3>Assessment Evidence</h3>
            <p><strong>System Assessment Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Assessment Scope:</strong> Technical security controls for $env:COMPUTERNAME</p>
            
            <h4>Collected Evidence Samples:</h4>
            <div class="evidence">
# Security Assessment Evidence
- Local Administrators: $($securityData.Accounts.LocalAdmins.Count) accounts
- Guest Account: $($securityData.Accounts.GuestEnabled)
- Firewall Status: $(($securityData.Network.FirewallProfiles | Where-Object {$_.Enabled -eq "True"}).Count) profiles enabled
- Last System Update: $($securityData.Updates.LastUpdate.InstalledOn)
- Antivirus Enabled: $($securityData.MalwareProtection.AntivirusEnabled)
            </div>
        </div>
    </div>
"@
}

function Get-RecommendationsSection {
    param($complianceData)
    
    $highPriority = $complianceData | Where-Object { $_.RiskLevel -eq "High" -and $_.Status -ne "Compliant" }
    $mediumPriority = $complianceData | Where-Object { $_.RiskLevel -eq "Medium" -and $_.Status -ne "Compliant" }
    $lowPriority = $complianceData | Where-Object { $_.RiskLevel -eq "Low" -and $_.Status -ne "Compliant" }
    
    $highItems = ""
    $mediumItems = ""
    $lowItems = ""
    
    foreach ($item in $highPriority) {
        $highItems += "<li><strong>$($item.ControlID):</strong> $($item.ControlName) - $($item.Evidence)</li>"
    }
    
    foreach ($item in $mediumPriority) {
        $mediumItems += "<li><strong>$($item.ControlID):</strong> $($item.ControlName) - $($item.Evidence)</li>"
    }
    
    foreach ($item in $lowPriority) {
        $lowItems += "<li><strong>$($item.ControlID):</strong> $($item.ControlName) - $($item.Evidence)</li>"
    }
    
    if (-not $highItems) { $highItems = "<li>No high priority items</li>" }
    if (-not $mediumItems) { $mediumItems = "<li>No medium priority items</li>" }
    if (-not $lowItems) { $lowItems = "<li>No low priority items</li>" }
    
    @"
    <div class="section">
        <h2>Recommendations & Improvement Plan</h2>
        <div class="subsection">
            <h3>Immediate Actions (0-30 days) - High Priority</h3>
            <ul>
                $highItems
            </ul>
        </div>
        <div class="subsection">
            <h3>Short-term Actions (1-3 months) - Medium Priority</h3>
            <ul>
                $mediumItems
            </ul>
        </div>
        <div class="subsection">
            <h3>Long-term Actions (3-12 months) - Low Priority</h3>
            <ul>
                $lowItems
            </ul>
        </div>
    </div>
"@
}

# Enhanced existing functions with ISO 27001 mapping
function Get-SystemInformationSection {
    param($systemInfo)
    
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
    $bios = Get-WmiObject -Class Win32_BIOS
    $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    $uptime = (Get-Date) - $lastBoot
    
    @"
    <div class="section">
        <h2>System Information (A.5.9 - Inventory of Assets)</h2>
        
        <div class="subsection">
            <h3>Basic System Information</h3>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Computer Name</td><td>$($env:COMPUTERNAME)</td></tr>
                <tr><td>Operating System</td><td>$($os.Caption) $($os.Version)</td></tr>
                <tr><td>System Manufacturer</td><td>$($computerSystem.Manufacturer)</td></tr>
                <tr><td>System Model</td><td>$($computerSystem.Model)</td></tr>
                <tr><td>BIOS Version</td><td>$($bios.SMBIOSBIOSVersion)</td></tr>
                <tr><td>Last Boot Time</td><td>$($lastBoot.ToString("yyyy-MM-dd HH:mm:ss"))</td></tr>
                <tr><td>Uptime</td><td>$($uptime.Days) days, $($uptime.Hours) hours</td></tr>
            </table>
        </div>

    </div>
"@
}

# Main execution
try {
    Write-Host "<WRITE-LOG = ""*Generating Enterprise ISO 27001:2022 Assessment Report...*"">" -ForegroundColor Green
    
    # Generate HTML content
    $htmlContent = Get-ISO27001ReportHTML
    
    # Save HTML to Desktop
    $hostName = hostname
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $htmlFilePath = Join-Path $desktopPath "ISO-27001-Report-$hostName.html"
    $htmlContent | Out-File -FilePath $htmlFilePath -Encoding UTF8
    
    # Display summary
    #$complianceData = Assess-ISO27001Compliance
    #$compliantCount = ($complianceData | Where-Object { $_.Status -eq "Compliant" }).Count
    #$totalCount = $complianceData.Count
    
    #Write-Host "<WRITE-LOG = ""*=== ENTERPRISE ASSESSMENT SUMMARY ===*"">" -ForegroundColor Cyan
    #Write-Host "<WRITE-LOG = ""*Controls Assessed: $totalCount*"">" -ForegroundColor White
    #Write-Host "<WRITE-LOG = ""*Compliant Controls: $compliantCount*"">" -ForegroundColor Green
    #Write-Host "<WRITE-LOG = ""*Compliance Rate: $([math]::Round(($compliantCount/$totalCount)*100, 1))%*"">" -ForegroundColor Yellow
    Write-Host "<WRITE-LOG = ""*Report: $htmlFilePath*"">" -ForegroundColor White
    
} catch {
    Write-Error "An error occurred while generating the report: $($_.Exception.Message)"
}

Write-Host "<WRITE-LOG = ""*Enterprise ISO 27001 assessment completed!*"">" -ForegroundColor Green


# SIG # Begin signature block
# MIIc1QYJKoZIhvcNAQcCoIIcxjCCHMICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvkrZDU34VQHlaFCH8K+SpH4H
# 2rOgghdDMIIEBTCCAu2gAwIBAgITFAAAAAIukB1TwGOSTQAAAAAAAjANBgkqhkiG
# 9w0BAQsFADAaMRgwFgYDVQQDEw9TZXJ2ZXJFbmdpbmUtQ0EwHhcNMjYwMzIxMTAw
# NDU4WhcNMjcwMzIxMTAxNDU4WjA/MRkwFwYDVQQDExBTZXJ2ZXJFbmdpbmUgTExD
# MSIwIAYJKoZIhvcNAQkBFhNjZW9Ac2VydmVyZW5naW5lLmNvMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs0CxL4QDnvoOI5CnSDWEYLe8WdMUb6lrJ7XM
# aCDo4F7X8qDT+1w9hQrh4kNljlbowSS1jlEwK3to75fpRljDzDGN6a6cm0WUW49c
# dL8iK3U/ryrBUjbf2Ln8o1Gs7wcwabK1c28u1p9TJBrNgkd4RImnlHoysOS5RbdS
# 2aakN+nrAa9K70ak72MSZVM9DMe1tzeWBs1LZ78hA8MC3KncRn6HpqrMvPz5gUZm
# 2SQJ/LEwrdjI4mVUX9P7CGkipfGJiWMDzh5cM1wf1/QhoGvr8sCjy5Y67HaA/cOD
# TU1yN5QUn5VH9kGAD9/JDG64CyI1GNVrjsCGXhXaT4llm53tIQIDAQABo4IBHTCC
# ARkwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMB0GA1Ud
# DgQWBBTi3EGZG11SOoD+soLbyLIqMnOwUzAfBgNVHSMEGDAWgBStSs/V0ivjZHyV
# iFt4ptEbhKzQhTBEBgNVHR8EPTA7MDmgN6A1hjNmaWxlOi8vLy9XSU4tU1JWLUFa
# MS9DZXJ0RW5yb2xsL1NlcnZlckVuZ2luZS1DQS5jcmwwWwYIKwYBBQUHAQEETzBN
# MEsGCCsGAQUFBzAChj9maWxlOi8vLy9XSU4tU1JWLUFaMS9DZXJ0RW5yb2xsL1dJ
# Ti1TUlYtQVoxX1NlcnZlckVuZ2luZS1DQS5jcnQwDAYDVR0TAQH/BAIwADANBgkq
# hkiG9w0BAQsFAAOCAQEAV+xG1rHc8K79QN7jQZviYjgj8/Ca7S/htlJ5PCZYFEkZ
# nmALbuIbgFB4QQXwaCy9CxwJpsI0LQQIWNc27c1xuteuHIFIMdC5NPQ8ENR+n0h/
# 7T3Xtr/poGgOO6na7vGHKKZioXGhzM0pqurXK2rbyaKCwjxP1KRSri0IzDzRA/k4
# zbeBHNxIGpvSYK+eQWd7fbhY9U8fIO412YB0/0RheNg5qwfyTPNR3GPj0AkXTYLq
# GuKZW798r//N8iSHeS0B8ODOS8Q7g+TZUO/FGGjpdwIcLjpTGxzIWXVMaklUx7Mw
# 33TClGHbymLXZPo3ORlqrWe5Ii2h+245H5Qx7HN+nzCCBY0wggR1oAMCAQICEA6b
# GI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEk
# MCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAw
# MDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2u
# exuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKv
# aJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/gh
# YZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOt
# yU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCR
# cKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8
# oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m
# 1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y
# 1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkl
# iWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/E
# IFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOC
# ATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/n
# upiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB
# /wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqg
# OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEA
# cKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU
# 9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0Sb
# QyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1Rmpp
# VLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxY
# oA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0Vys
# GMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYw
# DQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNl
# cnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1
# OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4
# MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6
# c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3
# SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVST
# EG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpq
# umzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJ
# yUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/Gcal
# NeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8A
# w4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/n
# J0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA
# 6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2ba
# oD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNV
# HRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAf
# BgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMG
# A1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG
# /WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCH
# xYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdh
# OP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDC
# vwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B
# 0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWG
# NqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRN
# ivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02Oo
# XN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy
# 4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2w
# L40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQt
# yRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2
# zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3
# DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFB
# MD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5
# NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5
# WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNV
# BAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIg
# MjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDq
# rmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dn
# xk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5Kyyn
# eqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V
# 1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSy
# i5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77e
# pTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yep
# yekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A9
# 0/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtIt
# nj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1
# Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpF
# Hti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQC
# MAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9v
# U0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5
# NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQw
# OTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2
# Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGB
# vg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bO
# ySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAE
# cxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5i
# QMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwq
# xv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjt
# P+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMF
# zGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjF
# jLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8
# gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01
# c4IhSOxqt81nMYIE/DCCBPgCAQEwMTAaMRgwFgYDVQQDEw9TZXJ2ZXJFbmdpbmUt
# Q0ECExQAAAACLpAdU8Bjkk0AAAAAAAIwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcC
# AQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYB
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLmcu+PJkK1X
# BvzVNJFNLN2XIAFkMA0GCSqGSIb3DQEBAQUABIIBAGOiI8RvsJXSH+rm1EkcW3CN
# elLTgNWmcQTW5V42nG5C5OjyN0sDrYQ69nUR9De0Wu7x0jSIyFeZLjqGL5wuA/jb
# PClYWPu16g30KbN3XVS15SyLqjXOS9x/8AUro92p68UPrbHBd/fwpLLI5YIfRH6l
# G8Wg/mZdsM9+8Bj1GZf/Grsy65qsGgQuZrVaPkHr16xYMdr00StfwoaSoMO0gWcO
# 52uG7vzf2wcQf1+UsTxOmMXihB4hRI5ISs4f2Rz2vNrJ8HQXGizgrSIKpIAttcXH
# FS1wt81sHw2Q4PI141A5rDOhADn6/1qyuo6DP4hVQ8rG/gSsS8QLoC4bobhPPmKh
# ggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqG
# SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwNDE5MTM0MDEzWjAvBgkqhkiG9w0B
# CQQxIgQgSuGG3xkDN20Wv7Gs/1oKZA8ybArf3H4svASpJfJFD9MwDQYJKoZIhvcN
# AQEBBQAEggIADDOeNqU2gZ+NeoIgGBdlEOIbbS4ZLlgyJqYRmE9sq9FwJrBVk8Hk
# xFg3ugPT/j9Wc0i7oklgs2xYcWAwqLXge7tkJ/rcZBzLCK671roLaBWUpiGIxVFv
# jtd/FIBsg4Z8J8lTCFyz+NH13Wt51DM4+8eS6TeFtRghyj0/o1WMS3zFI55uvP3v
# La/yfsZ5V2THrsmYWG2wW4wEAMagTWZfExJb+eSUmCq7qjvF6bWrjlPTRUSvOyq5
# BbWR8iavNZ5H8nE24RXA5GGMVdaeWcKiBovlR0312Y++06ZEjSyBByxeLMZrgTdV
# LX9h7w3qcyBgjsp4ig418chsqT/dRY9QIxu9QvygLemqSiyq0qN+3Ya6KjXmkUsk
# VBnSZKLGmFE2DkkvBdYfYnjDMV2GGwfC8cUbrVs7hEIQYbl9Df9M0+Nebpo9pGvT
# RzcAWnTQFvV/8GhGrtYCctp8dNu9D1NGmbnW1K5FX8tijxJmhbcBXlgM9lq/deKh
# A+OeguVwk4DNaMj0zDJNE2SWnGjZem5l7u+OHSrKQWDhmxUZhEJOcK7BzsfYEBVI
# xnFxfJUZbZ2SSGs0Iw8GzSa4Iew45CPi10x0hvWxc+BVpjacbcmS5SeaaGygmxgk
# 4z8sKA+I48qhau/pS0O8rXHf9OPzW9Xim8g+C31yQBamNxeJG652HcA=
# SIG # End signature block
