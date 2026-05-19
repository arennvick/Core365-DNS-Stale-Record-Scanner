# Core365-DNS-StaleRecord-Scanner

A production-ready PowerShell tool that scans **all AD DNS forward + reverse zones** and detects stale records left behind by a decommissioned Domain Controller. It generates a **modern HTML dashboard report** (search + export) and can optionally remove those stale records safely.

> Brand: **core365.cloud**  > Author: **Antonio Rennvick Annoson**  > Blog: https://blog.core365.cloud

---

## Why this tool exists (real-world problem)
When a Domain Controller is demoted or decommissioned, DNS often retains stale references across many zones (forward and reverse). If you have **dozens or hundreds** of zones, manually checking the “Name Servers” tab or hunting old SRV/PTR entries becomes slow and risky.

This tool lets you:
- scan everything in one run
- see exactly what is stale (by zone + record type)
- export evidence for change/audit
- optionally remove records (or preview removals via WhatIf)

---

## Features
- Scans **all zones** on a target DNS server (defaults to PDC Emulator)
- Detects stale record types:
  - **NS, A, AAAA, SRV, CNAME, PTR**
- Three modes:
  - **Scan** (default): report only
  - **WhatIf**: preview removals, no changes
  - **Remove**: deletes matching records
- Modern HTML dashboard:
  - summary cards
  - record-type breakdown badges
  - searchable table with **clear (✕)**
  - export table to CSV
  - status badges (Found / WhatIf / Removed / Error)

---

## Requirements
- Windows PowerShell 5.1+ or PowerShell 7+ (recommended: 5.1 on management servers)
- RSAT modules:
  - `DnsServer`
  - `ActiveDirectory`
- Permissions:
  - DNS admin rights to query/remove records

> Tip: Run PowerShell **as Administrator** when scanning zones that require elevated access.

---

## Download
- GitHub: **(add your repo link here)**

---

## Usage

### 1) Scan only (safe)
```powershell
.\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local"
```

### 2) Include IP matching (recommended)
```powershell
.\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local" -OldIPAddress "10.10.10.10"
```

### 3) WhatIf preview (no changes)
```powershell
.\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local" -OldIPAddress "10.10.10.10" -WhatIf
```

### 4) Remove stale records (change DNS)
```powershell
.\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local" -OldIPAddress "10.10.10.10" -RemoveRecords
```

### 5) Target a specific DNS server
```powershell
.\Core365-DNS-StaleRecord-Scanner.ps1 -OldNameServerFQDN "oldAD01.core365.local" -DnsServerName "ad01"
```

---

## Output
- Creates an HTML report in the script folder by default:
  - `Core365-DNS-StaleRecord-Scanner_Report_YYYY-MM-DD_HHMMSS.html`
- Click **Export CSV** in the report to save table data.

---

## Sample Reports (sanitised)
Included in this package:
- `Core365_DNS_StaleRecord_Scanner_Report_SCAN.html`
- `Core365_DNS_StaleRecord_Scanner_Report_REMOVE.html`
- `Core365_DNS_StaleRecord_Scanner_Report_SCAN_CONFIRM_CLEAN.html`

---

## Notes / Safety
- Always run **Scan** first.
- Then run **WhatIf** to validate the tool is matching the correct records.
- Use **Remove** only after verifying results.

---

## Licence
MIT (recommended). Update as needed.
