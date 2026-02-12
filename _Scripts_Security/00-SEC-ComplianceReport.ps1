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
    }
    
    return $systemInfo
}

function Get-ComprehensiveSecurityAssessment {
    $assessment = @{}
    
    # Account and Access Management
    $assessment.Accounts = @{
        LocalAdmins = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)
        GuestEnabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled
        UserCount = (Get-LocalUser).Count
        PasswordPolicy = net accounts
    }
    
    # Audit and Logging Configuration
    $assessment.Audit = @{
        AuditPolicies = auditpol /get /category:* /r | ConvertFrom-Csv
        EventLogStatus = Get-WinEvent -ListLog "Security","Application","System" -ErrorAction SilentlyContinue
    }
    
    # Network Security
    $assessment.Network = @{
        FirewallProfiles = Get-NetFirewallProfile
        ListeningPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -lt 10000}
        NetworkAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
    }
    
    # System Hardening
    $assessment.Hardening = @{
        UAC = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -ErrorAction SilentlyContinue
        UnsignedDrivers = Get-WmiObject -Class Win32_PnPSignedDriver | Where-Object {$_.IsSigned -eq $false}
    }
    
    # Update Management
    $assessment.Updates = @{
        LastUpdate = Get-HotFix | Where-Object { $_.InstalledOn -match "\d" } | Sort-Object InstalledOn -Descending | Select-Object -First 1 -ErrorAction SilentlyContinue
        TotalUpdates = (Get-HotFix).Count
        UpdateHistory = Get-HotFix | Where-Object { $_.InstalledOn -match "\d" } | Sort-Object InstalledOn -Descending | Select-Object -First 10 -ErrorAction SilentlyContinue
    }
    
    # Malware Protection
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $assessment.MalwareProtection = @{
                AntivirusEnabled = $defender.AntivirusEnabled
                RealTimeEnabled = $defender.RealTimeProtectionEnabled
                SignatureAge = $defender.AntivirusSignatureAge
                LastScan = $defender.LastQuickScan
            }
        }
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
    
    # A.5.18 - Access rights
    $adminCount = $securityData.Accounts.LocalAdmins.Count
    $accessStatus = if ($adminCount -le 3) { "Compliant" } else { "Partially Compliant" }
    $accessEvidence = "$adminCount administrator accounts configured"
    $compliance += New-ComplianceObject "A.5.18" "Access rights" $accessStatus $accessEvidence "Medium"
    Write-Host "<WRITE-LOG = ""*$accessStatus A.5.18 Access rights $accessEvidence Medium*"">"
    
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
    
    # A.8.15 - Logging
    $auditEnabled = $securityData.Audit.AuditPolicies.Count -gt 0
    $loggingStatus = if ($auditEnabled) { "Compliant" } else { "Partially Compliant" }
    $loggingEvidence = "Audit policies configured: $auditEnabled"
    $compliance += New-ComplianceObject "A.8.15" "Logging" $loggingStatus $loggingEvidence "Medium"
    Write-Host "<WRITE-LOG = ""*$loggingStatus A.8.15 Logging $loggingEvidence Medium*"">"
    
    # A.8.20 - Networks security
    $networkStatus = if ($firewallEnabled) { "Compliant" } else { "Non-Compliant" }
    $networkEvidence = "Network security controls implemented"
    $compliance += New-ComplianceObject "A.8.20" "Networks security" $networkStatus $networkEvidence "High"
    Write-Host "<WRITE-LOG = ""*$networkStatus A.8.20 Networks security $networkEvidence High*"">"
    
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
    $htmlFilePath = Join-Path $desktopPath "ISO-27001-2022-Report-$hostName-$timestamp.html"
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
