# - - - - - PowerShell - - - - - #


# Remove additional unwanted bloatware including Family and Get Started apps
#-----------------------------------------

$isadm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isadm) {
    Write-Host "<WRITE-LOG = ""*Please run this script as Administrator.*"">"
    Write-Host "<WRITE-LOG = ""*If this was a remote execution please provide Administrator credentials.*"">"
    Write-Error "Warning: Not running as Administrator."
} else {
    $apps = @(
        "Microsoft.3DBuilder",
        "Microsoft.BingNews",
        "Microsoft.BingSearch",
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.OfficeHub",
        "Microsoft.SkypeApp",
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Clipchamp.Clipchamp",               # Clipchamp video editor
        "Microsoft.WindowsFeedbackHub",      # Feedback Hub
        "Microsoft.GetHelp",                 # Get Help app
        "Microsoft.Getstarted",              # Get Started app (onboarding)
        "Microsoft.GamingApp",               # Gaming services app
        "Microsoft.MSPaint",                 # Paint 3D and classic Paint (MSPaint)
        "Microsoft.YourPhone",               # Phone Link app
        "MicrosoftCorporationII.QuickAssist",# Quick Assist
        "Microsoft.WindowsSoundRecorder",   # Sound Recorder
        "Microsoft.MicrosoftStickyNotes",   # Sticky Notes
        "Microsoft.MixedReality.Portal",     # Mixed Reality Portal
        "microsoft.windowscommunicationsapps",  # Mail and Calendar app package name
        "Microsoft.WindowsMaps",             # Maps app
		"MicrosoftCorporationII.MicrosoftFamily"  # Microsoft Family app
    )

    foreach ($app in $apps) {
       Get-AppxPackage -Name $app -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Remove-AppxPackage $_ -ErrorAction Stop
                Write-Host "<WRITE-LOG = ""*Removed app: $($app)*"">"
            } catch {
                Write-Warning "Failed to remove app '$($app)': $_"
            }
       }
    }
    Write-Host "<WRITE-LOG = ""*Bloatware removal completed!*"">"
}
