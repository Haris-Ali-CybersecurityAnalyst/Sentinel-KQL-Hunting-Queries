# Microsoft Sentinel — KQL Threat Hunting Queries

Kusto Query Language (KQL) queries for proactive threat hunting in Microsoft Sentinel, organized by hunting hypothesis rather than by log source.

## Hunts

### Hunt 1: Unusual Sign-In Locations
```kql
SigninLogs
| where ResultType == 0
| summarize Countries = make_set(LocationDetails.countryOrRegion) by UserPrincipalName
| where array_length(Countries) > 1
```
Hypothesis: an account is being used from more than one country in the lookback window without a business reason (e.g. no travel/VPN policy).

### Hunt 2: Suspicious OAuth App Consent
```kql
AuditLogs
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, AppName, Result
```
Hypothesis: a malicious or over-permissioned third-party app was granted consent — common in phishing-for-consent attacks.

### Hunt 3: Impossible Travel Combined with Risky Sign-In
```kql
SigninLogs
| where RiskLevelDuringSignIn != "none"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, RiskLevelDuringSignIn
| sort by TimeGenerated desc
```
Hypothesis: correlating Entra ID risk scoring with sign-in geography surfaces compromised accounts faster than either signal alone.

### Hunt 4: Mass File Download / Potential Exfiltration
```kql
OfficeActivity
| where Operation == "FileDownloaded"
| summarize DownloadCount = count() by UserId, bin(TimeGenerated, 1h)
| where DownloadCount > 50
```
Hypothesis: an account downloading an abnormal volume of files in a short window may indicate data staging before exfiltration.

### Hunt 5: PowerShell Down-Level Logging Bypass Attempts
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine contains "powershell" and CommandLine contains "-version 2"
```
Hypothesis: adversaries downgrade PowerShell to v2 to evade Script Block Logging (which only exists in v3+).

## How I use these
Each hunt is run on a schedule (weekly/monthly depending on data volume), and any hits are triaged using the process in [`01-SOC-Analyst-Playbooks`](../01-SOC-Analyst-Playbooks).
