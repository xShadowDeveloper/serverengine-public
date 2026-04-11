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
    } catch {
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQ2/IINqHX6m1ULvuZ1cs0txl
# cmigghdDMIIEBTCCAu2gAwIBAgITFAAAAAIukB1TwGOSTQAAAAAAAjANBgkqhkiG
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
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAH4Vm243RCR
# PJql6Latl+I2k3KJMA0GCSqGSIb3DQEBAQUABIIBAHZdziNhB//5Axoh07WCGwfK
# 9Kp65pfpkkEbjO2eER0GMwSNF84rYzbp7PEG29HzB+PcuTnnyhUSZXEd3hrBoeyI
# juXzXPSw2NSe4xFqbXn6okoXncKu+4IwvGEr9Pc8dtFNlm+azm4D7qy2wkfLCHUc
# C3zK6K655xHXUNsxKoUGxVGg5OHzZQWNLiPHGcjhG08Wa+un7lulIc93WTdQrVsH
# 7FMnQG9vHR96sodhQODWGpWGxDpUswK+RPjH249grO9nAMMPeFfrsmqT9rU+7L5A
# 3D9XSsBaWwbmFWtQHaGtsMg8bfpMtqOWxalz8qlZfmTQ+Ji6IC9Y0ws4fkzGJOmh
# ggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsGCSqG
# SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMzI1MTczMDQ3WjAvBgkqhkiG9w0B
# CQQxIgQgEqCY9kGMdecjwQWqib1MpipOA+BeMlCP0CSzmzBxB9EwDQYJKoZIhvcN
# AQEBBQAEggIAVM4rmqSFlIjWhoyizqteiUtpgUKN/HXu1SOhYu7VWloHqq4lbKmK
# LZcdRZXxZTG4tToo9Vj3pJPfsESmBPalG/wwPGMlt71pOtMbfxCSPqojRGVbaEb1
# o3PGfFg7lsKpOwaOsJY65FZk1zIntDF/kN4sRhkurTvp2j76g9rdIPsN6FJHfht9
# ytfu+CB1OpvUVBnDQd0gupw3x9+qyHwdTw1OazxzbY2EkEUEWTAxYlY66LisSuVw
# O8tin/0w/9RgOQqpyQbcbCjC1ns+wlLN6HgPadMAelyeT1GAz4QUYh7vxDacYMJn
# BwGLBRvPeIYV13GnNdiaM3BNuL5knpFwBNa1a6VNZyVxPetupdNN3ymXyXaN/M7G
# omziwth6mZy2go0Q+7s32CHyayWnh2wv+I6bcqbktK37/R5JgKpdqpwJBCdfg2rK
# G2z6kFhWAAEl1N8hcfRhHKq74VNO4OmSwN0x5JCJPyxvF5gX16JUMpf5bdQw+ufl
# CmlKHcgeRETYEU+iv1LqYzCLbgxIM25uU2jc5HtDBF3M14xc8NJw+wH/424mjg5t
# 0NVyFpqNfsnms/4enFOXzSr4SNG+3wFNhMfQ5Xn+vEIjITvS8cTVSNTwb6PP6WrE
# xP8c5NjJiZjlIzgWEqx1a+OJFaJJRaQeHpzYyQSAGTvGZs+63qjumjc=
# SIG # End signature block
