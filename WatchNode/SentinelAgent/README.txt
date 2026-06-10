════════════════════════════════════════════════════════════════
  CORENEST SIEM — Windows Agent Installation Guide
════════════════════════════════════════════════════════════════

REQUIREMENTS
  • Windows 10 / 11 / Server 2016 or newer
  • PowerShell 5.1+ (built into Windows 10/11)
  • Administrator privileges

CONTENTS
  watchnode.exe   — Sentinel agent binary
  install.ps1     — Automated installer script
  config.yaml     — Configuration file (reference only)
  README.txt      — This file

────────────────────────────────────────────────────────────────
  QUICK INSTALL (Recommended)
────────────────────────────────────────────────────────────────

1. Extract this folder to your Desktop or Downloads.

2. Right-click on install.ps1 and choose:
   "Run with PowerShell"

   OR open PowerShell as Administrator and run:

   cd "C:\Users\YourName\Desktop\SentinelAgent"
   .\install.ps1 -ServerIP "YOUR_SERVER_IP"

   Replace YOUR_SERVER_IP with the Sentinel server address
   provided by your security team.

3. The installer will:
   ✓ Copy the agent to C:\Program Files\SentinelAgent\
   ✓ Write the configuration with your server IP
   ✓ Install it as a Windows service (auto-start on boot)
   ✓ Start the service immediately

4. The agent appears in the Sentinel dashboard within 30 seconds.

────────────────────────────────────────────────────────────────
  SILENT INSTALL (for bulk deployment)
────────────────────────────────────────────────────────────────

  .\install.ps1 -ServerIP "1.2.3.4" -Silent

  Optional parameters:
    -ServerIP    Server IP or hostname (required)
    -ServerPort  Port number (default: 50051)
    -Token       Enrollment token (default: sentinel-enroll-secret-2024)
    -Silent      Skip interactive prompts

────────────────────────────────────────────────────────────────
  MANAGE THE SERVICE
────────────────────────────────────────────────────────────────

  Check status   : Get-Service SentinelAgent
  Stop           : Stop-Service SentinelAgent
  Start          : Start-Service SentinelAgent
  Restart        : Restart-Service SentinelAgent

  View in Services app: Press Win+R, type services.msc
  Look for "CoreNest SIEM Agent"

────────────────────────────────────────────────────────────────
  UNINSTALL
────────────────────────────────────────────────────────────────

  Run as Administrator:
  .\install.ps1 -Uninstall

  This stops the service, removes it, and deletes the files.

────────────────────────────────────────────────────────────────
  FIREWALL NOTE
────────────────────────────────────────────────────────────────

  The agent connects OUTBOUND to your server on port 50051 (TCP).
  No inbound ports need to be opened on the Windows machine.
  If your server has a firewall, make sure port 50051 is open.

════════════════════════════════════════════════════════════════
