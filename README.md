# Ransomware Incident Response Capstone

## Cyber Preparedness & Ransomware Threat Assessment

**AfricaHackon Academy Capstone — September 2026**

**Scenario:** OmniRoute Logistics vs. The Gentlemen Ransomware-as-a-Service threat

This portfolio project demonstrates how I approach ransomware preparedness from both a **technical** and **business-risk** perspective.

The capstone connected adversary behavior to enterprise exposure, mapped the attack path to **MITRE ATT&CK**, developed layered prevention, detection, response, and recovery controls, and translated the findings into a **board-ready first-24-hour response strategy**.

> **Project context:** This was a collaborative Squad 4 capstone. My portfolio highlights the detection-engineering and incident-response components represented on my resume while preserving the team nature of the original work.

---

## Portfolio Artifacts

* 📄 [Case Study](https://github.com/dredarsenic/ransomware-incident-response-capstone/blob/main/Case_Study.pdf)
* 📘 [Capstone Report](https://github.com/dredarsenic/ransomware-incident-response-capstone/blob/main/Squad_4_OmniRoute_Report.pdf)
* 📊 [Executive Presentation](https://github.com/dredarsenic/ransomware-incident-response-capstone/blob/main/Squad_4_OmniRoute_Deck.pptx)
---

## Scenario

OmniRoute Logistics is a multinational logistics scenario operating across **42 countries**, serving **1,800+ enterprise clients**, and processing **600,000+ shipment records per day**.

The threat assessment focused on **The Gentlemen**, a financially motivated ransomware group whose behavior in the scenario included:

* Fortinet edge exploitation
* Valid-account abuse
* Lateral movement
* Defense evasion
* Data exfiltration
* Ransomware deployment
* Recovery inhibition

### Central Question

> **How can OmniRoute stop an initial intrusion from becoming a ransomware attack that disrupts global logistics operations?**

---

## What the Project Covered

* Adversary characterization and ransomware threat modeling
* Business-impact and consequence analysis
* MITRE ATT&CK TTP mapping
* NIST CSF 2.0-aligned preparedness strategy
* Identity, segmentation, EDR/Sysmon, logging, backup, and recovery controls
* Sysmon detection engineering using **Event IDs 1 and 11**
* First-24-hour ransomware containment and recovery protection
* Prioritized **0–7 day, 30-day, 90-day, and 12-month** resilience roadmap
* Executive-style presentation and live panel defense

---

## My Contribution

My resume summarizes this project as follows:

* Collaborated on a board-ready cyber preparedness assessment for a multinational logistics scenario facing **The Gentlemen Ransomware-as-a-Service threat**
* Mapped ransomware tactics, techniques, and procedures to **MITRE ATT&CK** and helped develop layered detection, containment, incident response, and recovery recommendations
* Performed detection-engineering analysis using **Sysmon Event ID 1 (ProcessCreate)** and **Event ID 11 (FileCreate)** to evaluate scheduled-task persistence, process masquerading, command-line context, parent processes, hashes, and persistence artifacts
* Helped develop and defend a prioritized **first-24-hour ransomware response strategy** during a live executive-style panel presentation

---

## Threat Model

The Gentlemen was assessed as a **Cyber Breach & Organisational Disruption** adversary because the attack path goes beyond initial compromise.

The scenario demonstrated how an initial foothold could expand through identity abuse, remote administration, persistence, defense evasion, data theft, encryption, and recovery disruption.

### Key Enterprise Risks

* **Fortinet edge exposure** — vulnerable or exposed FortiGate/FortiProxy systems can become an entry point
* **Identity compromise** — stolen VPN, domain, or privileged credentials can allow deeper access
* **Lateral movement** — RDP, WMI, PowerShell, SMB, and administrative paths can spread compromise
* **Persistence** — scheduled tasks, registry Run keys, and valid accounts can survive reboot or partial cleanup
* **Defense evasion** — EDR impairment and logging changes can reduce visibility during the intrusion
* **Double extortion** — data theft plus encryption creates both operational and confidentiality pressure
* **Recovery inhibition** — backup or recovery disruption can extend downtime and weaken negotiating leverage

---

## Selected MITRE ATT&CK Mapping

| Technique     | Behavior                          | Defensive Focus                                                                    |
| ------------- | --------------------------------- | ---------------------------------------------------------------------------------- |
| **T1190**     | Exploit Public-Facing Application | Patch and harden Fortinet systems, restrict admin exposure, monitor edge activity  |
| **T1078.002** | Valid Domain Accounts             | MFA, PAM, separate admin accounts, abnormal login monitoring                       |
| **T1059.001** | PowerShell                        | Command-line logging, PowerShell telemetry, least privilege                        |
| **T1047**     | WMI                               | Restrict remote WMI, monitor `wmiprvse.exe` process chains                         |
| **T1053.005** | Scheduled Task/Job                | Sysmon EID 1 + EID 11, Task Scheduler telemetry                                    |
| **T1562.001** | Impair Defenses                   | EDR tamper protection, vulnerable-driver blocking, EDR health monitoring           |
| **T1484.001** | Group Policy Modification         | Controlled GPO changes, domain controller protection, directory-service monitoring |
| **T1021.001** | RDP                               | MFA, jump hosts, restricted admin paths, RDP logon monitoring                      |
| **T1486**     | Data Encrypted for Impact         | Segmentation, application control, ransomware behavior detection                   |
| **T1490**     | Inhibit System Recovery           | Immutable/offline backups, separate recovery credentials, backup monitoring        |

---

## Detection Engineering: Sysmon EID 1 + EID 11

A key technical exercise examined scheduled-task persistence using the following suspicious pattern:

```text
OriginalFileName = schtasks.exe
Task name        = WindowsUpdateService
Trigger          = ONSTART
Payload          = C:\ProgramData\svchost.exe
```

### Why Event ID 1 Matters

**Sysmon Event ID 1 — ProcessCreate** provides the execution context needed to understand how the scheduled task was created.

Important fields include:

* `Image`
* `OriginalFileName`
* `CommandLine`
* `ParentImage`
* `ParentCommandLine`
* `User`
* `ParentUser`
* `IntegrityLevel`
* `Hashes`
* `ProcessGuid`
* `ParentProcessGuid`
* Session and logon context

`OriginalFileName` is especially useful when a legitimate utility is renamed because the visible filename may change while the embedded metadata still identifies the original executable.

### Why Event ID 11 Matters

**Sysmon Event ID 11 — FileCreate** provides a second signal by confirming that a task artifact was actually written to a scheduled-task directory.

This is important because an attacker does not have to create a task using `schtasks.exe`. PowerShell, COM, APIs, or custom tooling could create the same persistence artifact.

### Correlation Logic

Confidence increases when multiple signals line up:

1. EID 1 shows a process creating the scheduled task
2. `OriginalFileName` identifies `schtasks.exe` even if the binary is renamed
3. The command line references `WindowsUpdateService`, `ONSTART`, and `C:\ProgramData\svchost.exe`
4. Parent-process or session context points to PowerShell, WMI, remote administration, or privileged execution
5. EID 11 confirms creation of the scheduled-task artifact

> **Key lesson:** Do not rely on a single filename or single event. Correlate process, user/session, command-line, hash, and persistence-artifact telemetry.

---

## First 24 Hours: Response Strategy

The response plan prioritized **containment before restoration**.

| Window     | Priority         | Example Actions                                                                            |
| ---------- | ---------------- | ------------------------------------------------------------------------------------------ |
| **0–2h**   | Secure the edge  | Restrict Fortinet management access, preserve logs/configs, begin scoping                  |
| **2–6h**   | Cut off access   | Revoke sessions, rotate VPN/admin credentials, disable compromised accounts                |
| **6–12h**  | Protect recovery | Lock down backup controls, protect Tier-0 identity, separate recovery credentials          |
| **12–18h** | Contain movement | Restrict RDP/WMI/WinRM/SMB, isolate affected hosts and segments                            |
| **18–24h** | Hunt the chain   | Hunt scheduled tasks, registry persistence, GPO abuse, exfiltration, and EDR-health issues |

> **Core principle:** Contain first. Do not restore until identity, management systems, and backups are trusted.

---

## Preparedness Strategy

The recommended posture was **Architectural Resilience**: assume prevention can fail and design the environment so that one compromise does not easily become enterprise-wide disruption.

The strategy emphasized four practical outcomes:

1. **Harden the edge and identity**
   Patching, MFA, credential hygiene, and privileged-access controls

2. **Detect early**
   Fortinet, EDR, Sysmon, AD/GPO, PowerShell/WMI, and outbound-traffic visibility

3. **Limit movement**
   Segmentation, administrative boundaries, jump hosts, and restricted remote administration

4. **Recover cleanly**
   Immutable/offline backups, separate recovery credentials, restore testing, and clean-room procedures

---

## Roadmap

The capstone translated the threat assessment into a staged implementation plan:

### 0–7 Days

* Review internet-facing Fortinet exposure
* Rotate credentials
* Hunt for signs of prior compromise

### 8–30 Days

* Centralize logs
* Validate EDR coverage and health
* Deploy Sysmon to critical systems
* Review privileged access and GPOs

### 31–60 Days

* Restrict lateral-movement paths
* Test ATT&CK-aligned detections
* Validate host-isolation procedures

### 61–90 Days

* Run clean recovery exercises
* Conduct a ransomware tabletop exercise
* Measure RTO/RPO

### 3–6 Months

* Expand segmentation
* Strengthen privileged-access controls
* Reduce standing privilege

### 6–12 Months

* Expand immutable backup coverage
* Make purple-team, recovery, and resilience testing routine

---

## Skills Demonstrated

`Ransomware Threat Modeling` · `MITRE ATT&CK` · `Sysmon` · `Detection Engineering` · `Incident Response` · `Threat Hunting` · `EDR` · `Identity Security` · `Network Segmentation` · `Backup & Recovery` · `NIST CSF 2.0` · `NIST SP 800-61` · `Executive Communication`

---

## Team Attribution

The original capstone report credits the following **Squad 4** members:

* Grace Weyama
* Andrew Kiema
* **Arcel Mukadi Kabamba**
* Benard Emmanuel Kariuki
* David Mwangi
* Denis Kyalo Ndemwa
* Gatanna Gachiri Waruinge
* Joseph Kirutu
* Tiffany Murithi

---

## References

The original report includes the full reference list.

Primary frameworks and sources included:

* MITRE ATT&CK Enterprise
* NIST Cybersecurity Framework (CSF) 2.0
* NIST SP 800-61 Rev. 3
* CISA #StopRansomware guidance
* CISA Known Exploited Vulnerabilities catalog
* Fortinet PSIRT guidance for CVE-2024-55591
* Microsoft Sysmon documentation
* Threat intelligence sources cited in the original report

---

## Disclaimer

OmniRoute is an academic scenario used to demonstrate cyber preparedness, detection engineering, incident response, and resilient recovery thinking.

This repository is a **portfolio project** and is not a production security assessment of a real organization.
