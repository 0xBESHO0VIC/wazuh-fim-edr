# EDR Basics: File Integrity Monitoring (FIM) using Wazuh

## 📋 Overview

This project demonstrates a practical implementation of **File Integrity Monitoring (FIM)** using **Wazuh** as an open-source EDR/SIEM solution. The lab simulates real-world unauthorized file activity on a Windows endpoint and walks through the full detection lifecycle — from configuring the Wazuh agent and manager, enabling real-time syscheck monitoring on a sensitive directory, simulating file creation/modification/deletion, and analyzing the resulting alerts in the Wazuh dashboard.

Beyond the basic FIM setup, this project also includes a **custom correlation rule** that detects a high-risk pattern: a single file being added, modified, and deleted within a short time window — a common indicator of data tampering or anti-forensics activity. This correlated event is escalated to a **Critical severity alert**, mapped to the MITRE ATT&CK framework.

---

## 🎯 Objective

Detect and investigate unauthorized file changes on a Windows machine using Wazuh File Integrity Monitoring (FIM):
- Monitor a sensitive directory for unauthorized modifications
- Simulate an attack by creating, modifying, and deleting a file
- Analyze the resulting alerts in the Wazuh dashboard
- Build a custom rule to detect suspicious tampering patterns

---

## 🛠️ Environment

| Component | Details |
|---|---|
| Wazuh Manager | Linux server |
| Wazuh Agent | Windows 10 Pro |
| Wazuh Version | v4.14.5 |
| Interface | Wazuh Dashboard (Kibana-based) |

---

## ⚙️ Configuration Steps

### 1. Install Wazuh Agent on Windows
```powershell
Start-Service WazuhSvc
```

### 2. Configure FIM for the Windows Agent (Shared Config)
Agent-specific FIM settings must be placed in the **shared agent configuration** file on the manager (not in `ossec.conf`, which only applies to the manager itself):

```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" realtime="yes">C:\Users\Public\Documents</directories>
  </syscheck>
</agent_config>
```

> 💡 **Key lesson learned:** `realtime="yes"` enables instant detection of file changes instead of waiting for the default scheduled scan (every 12 hours / 600s frequency).

### 3. Apply the configuration
```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/agent_control -r -u <agent_id>
```

### 4. Verify the agent received the new config
```bash
sudo /var/ossec/bin/agent_control -i <agent_id>
```
Confirm the **Shared file hash** has changed and **Status: Active**.

---

## 💥 Attack Simulation

On the Windows machine (PowerShell as Administrator):

```powershell
echo "Sensitive data" > C:\Users\Public\Documents\important.txt
Start-Sleep -Seconds 5

echo "Unauthorized modification detected" >> C:\Users\Public\Documents\important.txt
Start-Sleep -Seconds 5

Remove-Item C:\Users\Public\Documents\important.txt -Force
```

> 💡 **Key lesson learned:** Adding a short delay between actions is important — if events happen too quickly, Wazuh's real-time monitor may only capture the first event in the sequence.

---

## 🔍 Detection & Analysis

Alerts were viewed in **Wazuh Dashboard → File Integrity Monitoring → Events**, filtered with:

```
syscheck.path:*important* AND (syscheck.event:"added" OR syscheck.event:"modified" OR syscheck.event:"deleted")
```

### Detected Events

| Event Type | Rule ID | Rule Level | Description |
|---|---|---|---|
| File Added | 554 | 5 | File added to the system |
| File Modified | 550 | 7 | Integrity checksum changed |
| File Deleted | 553 | 7 | File deleted |

Each event included forensic details: timestamp, MD5/SHA1/SHA256 hashes, responsible user account, and Windows permission data.

---

## 🚨 Custom Correlation Rule: Critical Tampering Detection

To move beyond isolated low-severity alerts, a custom rule was created to detect the **full add → modify → delete sequence** on the same file within a short timeframe — a pattern consistent with data tampering or anti-forensics behavior.

**File:** `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="local,syscheck,">

  <rule id="100100" level="14" frequency="3" timeframe="120">
    <if_matched_group>syscheck_file</if_matched_group>
    <description>CRITICAL: File added, modified, and deleted within 2 minutes - possible tampering/anti-forensics activity.</description>
    <group>syscheck,syscheck_entry_added,syscheck_entry_modified,syscheck_entry_deleted,</group>
    <mitre>
      <id>T1070</id>
    </mitre>
  </rule>

</group>
```

| Parameter | Value | Meaning |
|---|---|---|
| `level` | 14 | Critical severity |
| `frequency` | 3 | Number of related events required |
| `timeframe` | 120 | Time window in seconds (2 minutes) |
| MITRE ATT&CK | T1070 | Indicator Removal |

After applying the rule and restarting the manager, the same attack simulation triggered a single **Critical** alert instead of three separate low-level events — reducing noise and surfacing the real threat.

---

## 📸 Screenshots

> *(Add your screenshots in a `screenshots/` folder and reference them below)*

- `screenshots/01-fim-config.png` – FIM configuration in `agent.conf`
- `screenshots/02-added-event.png` – File Added alert
- `screenshots/03-modified-event.png` – File Modified alert
- `screenshots/04-deleted-event.png` – File Deleted alert
- `screenshots/05-critical-alert.png` – Custom Critical correlation alert

---

## 🧠 Observation

During this hands-on lab, Wazuh's FIM proved how critical real-time visibility is for SOC analysts. By monitoring a sensitive directory, every file creation, modification, and deletion was logged with precise details — timestamps, file hashes, user identity, and permission changes.

Key takeaways:
- **Early detection** – Real-time monitoring caught file changes within seconds, drastically reducing the window an attacker has to operate undetected.
- **Forensic depth** – Hash comparisons (before/after) make it easy to confirm whether file content was actually altered, not just touched.
- **Accountability** – Capturing the responsible user account for every change helps trace actions back to a specific identity.
- **Compliance alignment** – FIM alerts mapped directly to frameworks like PCI DSS, HIPAA, GDPR, and NIST 800-53.
- **Detection engineering matters** – Out-of-the-box rules are a great starting point, but writing custom correlation rules (like the add→modify→delete detector above) is what turns raw logs into actionable, high-confidence alerts.

---

## 🧩 Skills Demonstrated

- Wazuh agent deployment and management
- File Integrity Monitoring (FIM) configuration
- Real-time vs. scheduled syscheck monitoring
- Wazuh Discover / FIM dashboard analysis (DQL queries)
- Custom detection rule writing (frequency-based correlation)
- MITRE ATT&CK technique mapping
- Security incident investigation workflow

---

## 📚 References
- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK – T1070: Indicator Removal](https://attack.mitre.org/techniques/T1070/)
