.SYNOPSIS
  Pull last N days of IIS SMTP W3C logs from a remote server and export SMTP source IP activity.

.DESCRIPTION
  - Prompts for SMTP server FQDN
  - Prompts for credentials
  - Mounts the remote C$ share temporarily
  - Reads SMTP W3C logs
  - Aggregates by IP and date
  - Performs reverse DNS lookup
  - Produces multiple output files useful for SMTP relay lockdown analysis

.PARAMETER DaysBack
  Number of days of SMTP log data to process.
  Default: 30

.PARAMETER OutputFolder
  Folder where output files will be written.
  Default: SMTP_Output under the script folder

.PARAMETER RemoteLogPath
  Path under C$ where SMTP logs are stored.
  Default: inetpub\logs\SMTPSVC1

.EXAMPLE
  .\Get-SMTPSourceIPs.ps1 -DaysBack 60 -OutputFolder C:\Temp\SMTP
