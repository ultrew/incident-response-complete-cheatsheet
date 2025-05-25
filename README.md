# 🛡️ Incident Response - Essential Tools & Websites

This document provides a categorized list of essential websites and tools used by incident responders for rapid investigation, triage, and threat intelligence, imp log sources/fields (splunk).

---

## 🔍 Threat Intelligence & IOC Analysis

| Tool | Description |
|------|-------------|
| [VirusTotal](https://www.virustotal.com/) | Scan files, URLs, domains, and IPs with multiple antivirus engines. |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Sandbox for dynamic malware analysis and behavior tracking. |
| [Any.Run](https://any.run/) | Interactive malware analysis in a sandbox environment. |
| [ThreatMiner](https://www.threatminer.org/) | IOC lookup and contextual threat intelligence platform. |
| [Robtex](https://www.robtex.com/) | DNS, IP, ASN, and routing intelligence tool. |
| [OTX AlienVault](https://otx.alienvault.com/) | Threat intelligence platform with open IOC feeds. |
| [Censys](https://search.censys.io/) | Search engine for discovering internet-connected devices. |
| [Shodan](https://www.shodan.io/) | Intelligence on exposed devices, ports, services. |

---

## 🌐 Domain, IP, & WHOIS Lookups

| Tool | Description |
|------|-------------|
| [URLScan.io](https://urlscan.io/) | Visual and metadata analysis of URLs. |
| [WhoisXML API](https://www.whoisxmlapi.com/) | WHOIS, subdomains, DNS, and email leak data. |
| [DomainTools](https://www.domaintools.com/) | WHOIS history, DNS records, domain reputation. |
| [AbuseIPDB](https://www.abuseipdb.com/) | Community-powered IP abuse reports. |
| [IPinfo.io](https://ipinfo.io/) | IP geolocation, ASN, VPN/proxy detection. |

---

## 🧪 File Analysis & Sandboxing

| Tool | Description |
|------|-------------|
| [Joe Sandbox](https://www.joesandbox.com/) | Static and dynamic malware analysis reports. |
| [Intezer Analyze](https://analyze.intezer.com/) | Detects reused malware code and threat families. |
| [ReversingLabs](https://www.reversinglabs.com/) | Deep file inspection and reputation data. |
| [Triage](https://tria.ge/) | Sandbox that provides behavior reports and IOC extraction. |
| [MalShare](https://malshare.com/) | Public malware repository searchable by hash. |
| [VirusBay](https://www.virusbay.io/) | Community-based malware sharing platform (requires login). |

---

## 🧠 MITRE ATT&CK & TTP Mapping

| Tool | Description |
|------|-------------|
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary tactics, techniques, and procedures knowledge base. |
| [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) | Visualize and map techniques from incident data. |

---

## 📊 Log Analysis & Memory Forensics

| Tool | Description |
|------|-------------|
| [Velociraptor](https://www.velociraptor.app/) | Endpoint visibility and IR agent with query language. |
| [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/) | Diagnostic tools like Procmon, Autoruns, TCPView. |
| [Loggly](https://www.loggly.com/) | Centralized log management and analysis. |
| [Splunk](https://www.splunk.com/) | Industry-standard SIEM and log analytics platform. |

---

## 🌐 Community & Research

| Tool | Description |
|------|-------------|
| [Reddit - r/BlueTeamSec](https://www.reddit.com/r/blueteamsec/) | Cyber defense discussions and alerts. |
| [The DFIR Report](https://thedfirreport.com/) | Detailed write-ups of real-world intrusions. |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) | Open malware family classification and samples. |
| [Twitter/X](https://twitter.com/) | Real-time IOC tracking from trusted infosec accounts. |

---

## 📂 File & Hash Lookup

| Tool | Description |
|------|-------------|
| [VirusTotal](https://www.virustotal.com/) | Search by file hash (MD5/SHA1/SHA256). |
| [Triage](https://tria.ge/) | Malware hash and sandbox reports. |
| [MalShare](https://malshare.com/) | Upload or search known malicious hashes. |

---

## 🗃️ Important Log Sources (Splunk) (A–Z)

| Log Source                | Purpose / Use Case                                                        | Details / Examples                                                                                   |
|---------------------------|---------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Active Directory Logs      | User logon activity, group membership changes, privilege escalation       | Logs related to Kerberos authentication, user creation/deletion, group changes, domain attacks     |
| AWS CloudTrail             | Tracks all user and API activity within AWS environment                   | Records API calls: user logins, EC2 actions, S3 access, IAM changes                                |
| Azure Activity Logs        | Monitors subscription-level events and admin actions                     | Tracks RBAC changes, key vault access, VM start/stop events                                        |
| DNS Logs                   | Tracks domain resolutions to detect beaconing, C2 traffic, typo-squatting | Internal DNS resolution logs, detects lookups to malicious IPs or C2 domains                       |
| EDR Logs                   | Endpoint behavior, process creation, malware detection                    | Shows malicious behavior, file access, process trees, detections (CrowdStrike, SentinelOne, etc.)  |
| Firewall Logs              | Ingress/egress traffic, denied connections, lateral movement detection    | Tracks allowed/denied traffic, geo-based access, rule hits (Palo Alto, Fortinet, Cisco ASA, etc.)  |
| Linux Syslog / Audit Logs  | General logging for services, auth, cron, kernel activities               | Auth logins, sudo usage, file access, command execution (/var/log/auth.log, /var/log/audit/audit.log) |
| PowerShell Logs            | Detects script execution, encoded commands, recon activity                | Logs script executions, module loads, fileless malware indicators                                  |
| Proxy Logs                 | User internet access, URL categorization, malware delivery attempts      | Outbound web traffic, detects C2 communication, malware downloads (Blue Coat, Squid, etc.)        |
| Windows Event Logs         | System, Security, Application logs including logons, process, service changes | Logon/logoff events, privilege use, object access, service changes                                 |

---

## 🧾 Key Fields to Monitor (Splunk) (A–Z by Log Source)

| Log Source           | Key Fields to Monitor                                            |
|----------------------|-----------------------------------------------------------------|
| Active Directory     | user, event_id, group, timestamp, source_ip                      |
| AWS CloudTrail       | eventName, userIdentity, sourceIPAddress, requestParameters, eventTime |
| DNS Logs             | query_name, response_code, query_type, client_ip, timestamp      |
| EDR Logs             | hostname, process_name, parent_process, cmdline, timestamp, user |
| Firewall Logs        | src_ip, dest_ip, src_port, dest_port, action, protocol           |
| Linux Syslog         | facility, severity, timestamp, hostname, process, message        |
| PowerShell Logs      | script_block_text, command_line, user, host_application, timestamp|
| Proxy Logs           | user, url, http_status, timestamp, method, user_agent            |
| Windows Event Logs   | event_id, user, process_name, logon_type, timestamp, source_ip   |

---

## 📁 File Version 1.1
- **Author:** [Tanishq Nama]
- **Last Updated:** 25th May, 2025

---
