# ============================================================
# Invoke-IOCChecker.ps1
# Author: Q'Lae Mann
# Description: Accepts a list of suspicious IP addresses and
#              queries the AbuseIPDB threat intelligence API
#              for reputation data. Flags IPs above a defined
#              confidence threshold and exports findings to CSV
#              for documentation and SIEM correlation.
# Use Case:    Threat hunting, alert triage, post-incident IOC
#              validation, proactive environment sweeping
# API Docs:    https://www.abuseipdb.com/api
# ============================================================

# ---------- CONFIGURATION ----------
$APIKey            = $APIKey = $env:ABUSEIPDB_API_KEY  # Free tier available at abuseipdb.com
$ConfidenceThresh  = 50     # Flag IPs with abuse confidence >= this value (0-100)
$LookbackDays      = 30     # How far back AbuseIPDB checks reports
$ReportPath        = ".\IOC_Report_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"

# IOC list — populate from threat intel feed, SIEM export, or paste manually
$SuspiciousIPs = @(
    "66.94.112.214",   # Example: IP from failed login investigation
    "185.220.101.45",  # Example: Known Tor exit node
    "198.199.80.61"    # Example: Flagged in threat intel feed
)
# -----------------------------------

Write-Host "`n[*] Starting IOC Check against AbuseIPDB..." -ForegroundColor Cyan
Write-Host "[*] Evaluating $($SuspiciousIPs.Count) IP(s)"
Write-Host "[*] Confidence threshold : $ConfidenceThresh%`n"

$Results = foreach ($IP in $SuspiciousIPs) {

    Write-Host "[~] Querying: $IP" -ForegroundColor Yellow

    try {
        # Build the API request
        $Headers  = @{ "Key" = $APIKey; "Accept" = "application/json" }
        $Endpoint = "https://api.abuseipdb.com/api/v2/check"
        $Params   = @{ ipAddress = $IP; maxAgeInDays = $LookbackDays; verbose = $true }

        $Response = Invoke-RestMethod -Uri $Endpoint -Headers $Headers -Body $Params -Method GET

        $Data = $Response.data

        # Determine flag status
        $IsFlagged = $Data.abuseConfidenceScore -ge $ConfidenceThresh

        if ($IsFlagged) {
            Write-Host "  [!] FLAGGED - Confidence: $($Data.abuseConfidenceScore)% | Country: $($Data.countryCode) | Reports: $($Data.totalReports)" -ForegroundColor Red
        } else {
            Write-Host "  [+] Clean   - Confidence: $($Data.abuseConfidenceScore)% | Country: $($Data.countryCode)" -ForegroundColor Green
        }

        # Return structured result object
        [PSCustomObject]@{
            IPAddress          = $IP
            AbuseConfidence    = $Data.abuseConfidenceScore
            Flagged            = if ($IsFlagged) { 'YES' } else { 'NO' }
            CountryCode        = $Data.countryCode
            ISP                = $Data.isp
            Domain             = $Data.domain
            TotalReports       = $Data.totalReports
            LastReportedAt     = $Data.lastReportedAt
            UsageType          = $Data.usageType
            IsTor              = $Data.isTor
            IsWhitelisted      = $Data.isWhitelisted
            CheckedAt          = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }

    } catch {
        Write-Warning "  Failed to query $IP : $_"

        [PSCustomObject]@{
            IPAddress       = $IP
            AbuseConfidence = 'ERROR'
            Flagged         = 'ERROR'
            CountryCode     = 'N/A'
            ISP             = 'N/A'
            Domain          = 'N/A'
            TotalReports    = 'N/A'
            LastReportedAt  = 'N/A'
            UsageType       = 'N/A'
            IsTor           = 'N/A'
            IsWhitelisted   = 'N/A'
            CheckedAt       = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
    }

    # Respect API rate limits (free tier = 1000 requests/day)
    Start-Sleep -Milliseconds 500
}

# Summary
$FlaggedCount = ($Results | Where-Object { $_.Flagged -eq 'YES' }).Count
Write-Host "`n[*] Summary: $FlaggedCount of $($SuspiciousIPs.Count) IPs flagged above $ConfidenceThresh% confidence threshold`n"

# Export to CSV
$Results | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "[+] Report exported to: $ReportPath`n" -ForegroundColor Cyan

# ---------- ANALYST NOTES ----------
# Workflow integration ideas:
#   - Feed IPs directly from Detect-FailedLogins.ps1 output
#   - Pull IOC list from daily threat intel brief
#   - Schedule as a morning sweep via Windows Task Scheduler
#   - Pipe flagged IPs directly into a SIEM alert or ticket
#
# AbuseIPDB free tier: 1,000 checks/day, 30-day lookback
# Register at https://www.abuseipdb.com to get your API key
# -----------------------------------
