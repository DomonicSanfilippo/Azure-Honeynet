# Azure Honeynet and Live SOC

This project demonstrates an end-to-end security monitoring and incident-response workflow in Microsoft Azure. I built an intentionally exposed honeynet with Windows, Linux, and SQL workloads; centralized the resulting telemetry in Log Analytics and Microsoft Sentinel; developed KQL-based detections and workbooks; investigated malicious activity; and hardened the environment to measure the effect of remediation.

> **Security note:** The workloads were intentionally exposed only in a controlled lab environment for educational testing and were secured after data collection.

![Azure honeynet architecture](https://github.com/user-attachments/assets/29aa40bf-0cfb-4cc2-86b8-743741aa9cfe)

## Key Results

- Reduced recorded Microsoft Sentinel incidents from **23 to 0** after hardening
- Reduced recorded security alerts from **3 to 0**
- Reduced malicious network-flow records from **273 to 0**
- Reduced Linux syslog volume by **99.59%** and Windows security-event volume by **42.26%**
- Built KQL workbooks for Windows RDP failures, Linux SSH failures, SQL authentication failures, and malicious network flows

## Technologies and Skills

| Area | Technologies and Techniques |
| --- | --- |
| Cloud and SIEM | Microsoft Azure, Microsoft Sentinel, Log Analytics, Microsoft Defender for Cloud |
| Systems and Network | Windows, Linux, SQL Server, RDP, SSH, Network Security Groups, Azure flow logs |
| Detection and Analysis | KQL, analytics rules, workbooks, GeoIP enrichment, Event Viewer, Linux authentication logs |
| Security Operations | Log collection, alert triage, incident investigation, attack simulation, remediation, before-and-after analysis |

## Implementation

### 1. Build the Lab Environment

I deployed Windows and Linux virtual machines in a dedicated Azure resource group, installed SQL Server and SQL Server Management Studio, and created a separate attack VM for controlled testing.

![Windows and Linux virtual machines](https://github.com/user-attachments/assets/14f8b001-f67a-4c76-be4c-a57b2e85f5a9)

<details>
<summary>Additional environment screenshots</summary>

![Remote Desktop access to the Windows VM](https://github.com/user-attachments/assets/dc6c0883-7ea6-4e23-a38c-6c09b82283e0)

![Attack VM](https://github.com/user-attachments/assets/3389783c-e314-4e23-a38c-6c09b82283e0)

</details>

### 2. Create Controlled Exposure

To generate security telemetry, I temporarily allowed unrestricted inbound traffic through the lab NSGs and disabled the Windows host firewall. This exposed the test workloads to RDP, SSH, SQL authentication, and internet-sourced network activity.

![NSG configured to allow inbound traffic](https://github.com/user-attachments/assets/4ad4ab20-9e29-431a-ad2f-f893ec77b234)

<details>
<summary>Windows firewall validation and configuration</summary>

![Testing Windows VM connectivity](https://github.com/user-attachments/assets/5e3b6d3f-3ad3-4825-b9de-bb0fb31e66b6)

![Windows Defender Firewall configuration](https://github.com/user-attachments/assets/9c49feee-d586-4062-954d-cfc7b3cfaa6e)

</details>

### 3. Enable and Validate Host Logging

I enabled Windows audit logging for application-generated events and configured SQL Server to record successful and failed login attempts.

```cmd
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
```

I then generated failed SQL, RDP, and SSH authentication attempts and verified the resulting records in Windows Event Viewer and `/var/log/auth.log` on Linux.

![SQL Server login auditing](https://github.com/user-attachments/assets/0a4a6b80-3dc4-4053-aa85-92938fb8dd26)

<details>
<summary>Authentication testing and log validation</summary>

![Failed SQL login test](https://github.com/user-attachments/assets/669d99f8-a64e-4667-bdaf-1fcf76997728)

![Failed SQL login recorded in Event Viewer](https://github.com/user-attachments/assets/eeb63a58-2291-4b61-b562-e30c9773767c)

![SSH connectivity to the Linux VM](https://github.com/user-attachments/assets/fbcddbca-267b-4dfb-bc89-e1cce0b502a7)

![Controlled authentication testing from the attack VM](https://github.com/user-attachments/assets/db8287e3-b18b-4185-8edb-86a585915d30)

![Failed SSH authentication test](https://github.com/user-attachments/assets/3b0bd1bd-eba8-4b97-b08a-c350fcac2bc0)

![Windows event-log investigation](https://github.com/user-attachments/assets/971b4ce8-e465-4973-8a81-d90aa6419041)

![Linux authentication-log analysis](https://github.com/user-attachments/assets/3b694f03-b9aa-44ee-98b6-48f1239a6803)

</details>

### 4. Centralize Telemetry in Azure

I created a Log Analytics workspace and connected Microsoft Sentinel for centralized collection and investigation. I also:

- Created a GeoIP watchlist to enrich source IP addresses with location data
- Enabled Microsoft Defender for Cloud protection for servers and SQL workloads
- Configured Windows event-log and Linux syslog data-collection rules
- Enabled network flow logging for network-traffic analysis

![Log Analytics workspace](https://github.com/user-attachments/assets/1515f960-af95-4705-939a-a30eabfbe468)

<details>
<summary>Sentinel, Defender, and data-collection screenshots</summary>

![Microsoft Sentinel GeoIP watchlist](https://github.com/user-attachments/assets/f7451363-061f-4556-af35-4d71815103cd)

![Microsoft Defender for Cloud configuration](https://github.com/user-attachments/assets/8abb385e-b67a-41af-b6bf-019d87e671dd)

![Azure data-collection rules](https://github.com/user-attachments/assets/5ad81e7c-5140-465c-80ee-62645b8258ec)

</details>

### 5. Build KQL Workbooks and Detection Rules

I used KQL and the GeoIP watchlist to develop workbooks that visualized:

- Windows RDP authentication failures using Event ID 4625
- Linux SSH authentication failures
- SQL Server authentication failures using Event ID 18456
- Malicious inbound network flows allowed by NSG rules

| Workbook | Preview |
| --- | --- |
| Windows security events | ![Windows security event workbook](https://github.com/user-attachments/assets/f612fd87-bf92-478f-9138-cd1d07104465) |
| Malicious network flows | ![Malicious network-flow workbook](https://github.com/user-attachments/assets/6b04eb12-e425-454a-94d1-417ef35f71fb) |
| SQL authentication failures | ![SQL authentication workbook](https://github.com/user-attachments/assets/4c2ed9f7-4175-4f04-ae4e-880c09d61ce7) |
| Linux SSH failures | ![Linux SSH workbook](https://github.com/user-attachments/assets/fae2ebbd-a633-4367-8f30-c4b6443eedb7) |

I imported custom Sentinel analytics rules, validated that failed authentication activity generated detections, and opened the resulting Windows brute-force incident for investigation.

![Sentinel analytics rules](https://github.com/user-attachments/assets/85b12905-6469-45b2-9eff-3d34703afd6f)

![Windows brute-force incident investigation](https://github.com/user-attachments/assets/7252c745-a5a8-4544-965f-8c9a80d40206)

### 6. Harden the Environment

After investigating the activity, I reduced the attack surface by changing the Windows and Linux NSG inbound rules from unrestricted sources to **My IP address** only.

![NSG restricted to My IP address](https://github.com/user-attachments/assets/b7d98bc9-5957-407d-9245-518e5837aa7e)

## Before-and-After Results

The before- and after-hardening measurements were collected on May 21–22, 2024.

| Metric | Before Hardening | After Hardening | Change |
| --- | ---: | ---: | ---: |
| Windows security events (`SecurityEvent`) | 7,833 | 4,523 | 42.26% decrease |
| Linux syslog records (`Syslog`) | 725 | 3 | 99.59% decrease |
| Security alerts (`SecurityAlert`) | 3 | 0 | 100% decrease |
| Security incidents (`SecurityIncident`) | 23 | 0 | 100% decrease |
| Malicious network-flow records (`AzureNetworkAnalytics_CL`) | 273 | 0 | 100% decrease |

`SecurityEvent` includes routine Windows audit activity, so it was not expected to fall to zero. The most meaningful post-hardening outcomes were that recorded alerts, incidents, and malicious network-flow records fell to zero during the measurement period.

## Repository Contents

- [Sentinel analytics rules](./Sentinel-Analytics-Rules%28KQL%20Alert%20Queries%29.json)
- [Windows RDP failed-authentication workbook](./windows-rdp-auth-fail.json)
- [Linux SSH failed-authentication workbook](./linux-ssh-auth-fail.json)
- [SQL Server failed-authentication workbook](./mssql-auth-fail.json)
- [Malicious NSG flow workbook](./nsg-malicious-allowed-in.json)
- [GeoIP watchlist data](./geoip-summarized.csv)
- [Windows event-log XPath configuration](./Xpath.txt)

## Conclusion

This project demonstrates a complete defensive-security workflow: deploying and instrumenting cloud workloads, generating and collecting telemetry, developing KQL-based detections and visualizations, investigating a Sentinel incident, applying network hardening, and validating the effect of remediation with before-and-after data.
