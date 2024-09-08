## BUILDING A LIVE SOC + HONEYNET IN AZURE
This project demonstrates setting up and configuring a honeynet in Microsoft Azure. It includes creating virtual machines, configuring security settings, deploying a SQL database, and integrating Microsoft Sentinel for security monitoring and incident response.

![001](https://github.com/user-attachments/assets/29aa40bf-0cfb-4cc2-86b8-743741aa9cfe)


## Step 1: Environment Setup
To begin, I initiate the setup by creating two virtual machines: one running on a Windows operating system and the other on Linux. These virtual machines are strategically placed within the same resource group, ensuring efficient management and allocation of resources. This approach facilitates streamlined monitoring, maintenance, and resource utilization across both platforms.

![002](https://github.com/user-attachments/assets/14f8b001-f67a-4c76-be4c-a57b2e85f5a9)


## Step 2: Adjusting Network Security Groups (NSGs)
After deploying both VM instances, I proceed to the inbound security rules, specifically the Network Security Group (NSG), to remove the Remote Desktop Protocol (RDP) port restriction in order to gather information. I opt to allow 'any' inbound traffic temporarily, thereby opening up both Windows and Linux VMs to potential vulnerabilities. This decision grants unrestricted access to incoming traffic, which may pose security risks but enables comprehensive data collection and analysis.

![003](https://github.com/user-attachments/assets/4ad4ab20-9e29-431a-ad2f-f893ec77b234)


## Step 3: Disabling Windows Firewall
I start by pinging the public IP of my Windows VM to verify whether the firewall is still enabled. Upon confirming its status, I proceed to disable the firewall. This action is taken to ensure unhindered communication and accessibility to the Windows VM, facilitating seamless interaction and troubleshooting as needed.

![004](https://github.com/user-attachments/assets/5e3b6d3f-3ad3-4825-b9de-bb0fb31e66b6)


## Step 4: Accessing Windows VM via Remote Desktop
I achieve this by accessing the Windows VM through Remote Desktop. This remote connection enables me to interact with the VM's desktop interface directly, allowing me to make necessary adjustments, such as disabling the firewall, in a convenient and efficient manner.

![005](https://github.com/user-attachments/assets/dc6c0883-7ea6-4e50-a6ca-8b5ff5fadca8)


## Step 5: Disabling Windows Firewall via Advanced Settings
I proceed to access the Advanced Windows Defender Firewall settings on the Windows VM to disable the firewall entirely. By doing so, I intentionally expose the VM to potential threats from the internet, removing any protective barriers that the firewall previously provided. This action is taken for specific testing or troubleshooting purposes, acknowledging the heightened vulnerability of the system to external risks.

![006](https://github.com/user-attachments/assets/9c49feee-d586-4062-954d-cfc7b3cfaa6e)


## Step 6: Setting up SQL Database
After setting up the SQL database, configuring default settings and permissions, and assigning the current profile, I proceed with the installation process. Next, I download SQL Server Management Studio (SSMS) and configure it accordingly, as outlined in the provided Microsoft Learn documentation. Additionally, I navigate to the registry editor and make the necessary adjustments in the specified registry location to enable the desired functionality.




## Step 7: Enabling SQL Edit Functionality
To enable the edit function of SQL, I execute the command in the command prompt:

auditpol /set /subcategory:"application generated" /success:enable /failure:enable

Following this, I launch SQL Server Management Studio and log in using the sa (System Administrator) or admin account. Within SSMS, I access the properties of the Windows VM and configure security options. Specifically, I enable the feature to log both failed and successful logins for enhanced monitoring and auditing purposes.

![008](https://github.com/user-attachments/assets/0a4a6b80-3dc4-4053-aa85-92938fb8dd26)


## Step 8: Simulating Unauthorized Access
With deliberate intent, I enter incorrect credentials, both username and password, when attempting to log in to the SQL Server. This action is performed to simulate a failed login attempt, allowing for testing of the system's response to unauthorized access and validating the effectiveness of the configured security measures, such as auditing and logging of login attempts.

![009](https://github.com/user-attachments/assets/669d99f8-a64e-4667-bdaf-1fcf76997728)


## Step 9: Monitoring Failed Login Attempts
Upon entering the incorrect credentials for SQL Server, Event Viewer promptly notifies me of the failed login attempt. This notification serves as an essential alert, indicating that the security measures configured within the system are functioning as intended, effectively capturing and recording unauthorized access attempts for further analysis and mitigation.

![010](https://github.com/user-attachments/assets/eeb63a58-2291-4b61-b562-e30c9773767c)


## Step 10: Security Testing on Linux VM
With everything configured correctly on the Windows side, I shift my focus to the Linux VM. First, I conduct a ping test to verify connectivity, which yields a successful result. With confirmation of network connectivity, I proceed to establish an SSH (Secure Shell) connection to the Linux VM from my Windows VM. This allows me to securely access the command-line interface of the Linux VM, enabling further configuration and management tasks as needed.

![012](https://github.com/user-attachments/assets/fbcddbca-267b-4dfb-bc89-e1cce0b502a7)


## Step 11: Setting up Attack VM
Having established our SQL database, along with the virtual machines (Linux and Windows) and intentionally weakened the Network Security Groups (NSGs), we move on to the next phase by setting up an attack VM. This specialized virtual machine is specifically designed and configured to simulate various cyber attacks, providing a controlled environment for testing the effectiveness of our security measures and identifying potential vulnerabilities within our system.

![013](https://github.com/user-attachments/assets/3389783c-e314-4e23-a38c-6c09b82283e0)


## Step 12: Testing Unauthorized Access from Attack VM
From my attack VM, I initiate a Remote Desktop Protocol (RDP) session to my Windows VM. In this session, I deliberately input fake login credentials to simulate an unauthorized access attempt. This action allows me to monitor the logs generated from the interaction between my attacker VM and Windows VM, providing valuable insights for later analysis.

Subsequently, I download SQL Server Management Studio (SSMS) on my attack VM and attempt to sign in to the Windows VM using incorrect credentials. This intentional misuse of credentials further simulates a potential security breach, enabling me to assess how effectively the system detects and responds to such unauthorized login attempts originating from the attacker VM.

![014](https://github.com/user-attachments/assets/db8287e3-b18b-4185-8edb-86a585915d30)


## Step 13: Testing Unauthorized Access on Linux VM
Continuing with the testing, I establish an SSH connection from my attacker VM to my Linux VM using fake credentials. This action replicates a scenario where an unauthorized user attempts to gain access to the Linux system using invalid login information. By doing so, I can analyze the system logs to observe how the Linux VM handles and logs such unauthorized access attempts, further strengthening our understanding of the system's security posture and potential vulnerabilities.

![015](https://github.com/user-attachments/assets/3b0bd1bd-eba8-4b97-b08a-c350fcac2bc0)


## Step 14: Analyzing Logs and Incidents
Returning to my Windows VM, I initiate another Remote Desktop session to conduct further investigation. Within the Windows Event Viewer, specifically in the application and security tabs, I analyze the logs to identify and review the attempted logons that were triggered during the simulated attacks from the attacker VM. By examining these logs, I can gain valuable insights into the nature of the attempted intrusions, their origin, and any potential security implications for the system. This analysis aids in understanding the effectiveness of the implemented security measures and informs any necessary adjustments or enhancements to bolster the system's defenses against future attacks.

![016](https://github.com/user-attachments/assets/971b4ce8-e465-4973-8a81-d90aa6419041)


## Step 15: Analyzing Linux Authentication Logs
Switching from the VMs to my main desktop, I utilize the terminal to SSH into my Linux VM for further analysis. Navigating to the appropriate directory with the command cd /var/log, I access the logs where authentication-related information is stored.

To specifically focus on password-related logs, I execute the command cat auth.log | grep password. This command filters the contents of the authentication log (auth.log) to display only entries containing the keyword "password", allowing me to pinpoint and scrutinize relevant log entries related to authentication attempts on the Linux VM. This meticulous examination provides valuable insights into any unauthorized access attempts and aids in assessing the effectiveness of the security measures implemented on the Linux system.

![017](https://github.com/user-attachments/assets/3b694f03-b9aa-44ee-98b6-48f1239a6803)


## Step 16: Enhancing Monitoring Capabilities
Observing numerous attempted logon attempts from various sources, I recognize the importance of robust log management and analysis. To enhance our monitoring capabilities and gain deeper insights into system activities, I proceed to create a Log Analytics workspace.

This workspace will serve as a centralized hub for collecting, analyzing, and visualizing log data from multiple sources, including our virtual machines. By consolidating logs in a single location and leveraging advanced analytics tools, we can effectively detect anomalies, identify security threats, and generate actionable insights to strengthen our overall cybersecurity posture.

![018](https://github.com/user-attachments/assets/1515f960-af95-4705-939a-a30eabfbe468)


## Step 17: Setting up Microsoft Sentinel
After setting up the Log Analytics workspace, I proceed to create a Microsoft Sentinel instance within the RG-lab resource group. Within Sentinel, I create a new watchlist named "geoip." This watchlist is designed to store geographical IP information for analysis and correlation with incoming log data.

To populate the "geoip" watchlist, I upload a pre-configured GeoIP CSV file containing relevant geographical data associated with IP addresses. This data will enable Sentinel to enrich log entries with geographic information, facilitating enhanced threat detection and response capabilities by correlating IP addresses with their corresponding geographical locations.

![019](https://github.com/user-attachments/assets/f7451363-061f-4556-af35-4d71815103cd)


## Step 18: Configuring Microsoft Defender for Cloud
Continuing with the setup, I proceed to configure Microsoft Defender for Cloud. Within Defender for Cloud, I enable protection for servers and SQL Servers across our virtual machines. In the data collection tab, I ensure that all relevant events are enabled to provide comprehensive visibility into system activities.

Additionally, I configure SQL Server designation within the Defender plan to specifically tailor the protection measures for our SQL databases. To ensure continuous monitoring and analysis of security events, I enable continuous export, allowing for the seamless transfer of security data to external monitoring and analysis tools for further investigation and response.

![020](https://github.com/user-attachments/assets/8abb385e-b67a-41af-b6bf-019d87e671dd)


## Step 19: Configuring Data Collection Rulesets
To facilitate comprehensive logging and monitoring, I create a storage account within the RG-Lab resource group. In this storage account, I configure flow logs to capture network traffic data from both the Windows and Linux VMs.

Next, I successfully configure data collection rulesets to retrieve logs from both Windows and Linux environments. Within the data source settings, I add new rulesets specifically tailored for Windows event logs and Linux syslogs. These rulesets define the parameters for collecting and forwarding log data from the respective operating systems to the storage account for centralized storage and analysis.

![021](https://github.com/user-attachments/assets/5ad81e7c-5140-465c-80ee-62645b8258ec)


## Step 20: Customizing Workbooks
I delete existing default workbooks to replace with customized ones focused on:

### **Windows Security Events**

![022](https://github.com/user-attachments/assets/f612fd87-bf92-478f-9138-cd1d07104465)

### **Malicious Network Flows**

![023](https://github.com/user-attachments/assets/6b04eb12-e425-454a-94d1-417ef35f71fb)

### **SQL Server Authentication Attempts**

![024](https://github.com/user-attachments/assets/4c2ed9f7-4175-4f04-ae4e-880c09d61ce7)

### **Linux SSH Authentication Failures**

![025](https://github.com/user-attachments/assets/fae2ebbd-a633-4367-8f30-c4b6443eedb7)

These workbooks visualize relevant security events, enriched with geographic information, to aid in threat detection and response.

## Step 21: Importing Sentinel Analytics Rules
Continuing by importing the Sentinel-Analytics-Rules(KQL Alert Queries).json file into the analytics section for further analysis and enhancement of our detection capabilities.

![026](https://github.com/user-attachments/assets/85b12905-6469-45b2-9eff-3d34703afd6f)


## Step 22: Testing Security Measures
I conduct a test simulation for Failed logon attempts, revealing an average of 24 alerts per day. Additionally, I initiate an investigation within the Incidents tab to delve deeper into the detected security incidents.

![027](https://github.com/user-attachments/assets/7252c745-a5a8-4544-965f-8c9a80d40206)


## Step 23: Incident Response and Hardening
Entering the Analytics responses section, I engage in incident response activities, prioritizing patching to address vulnerabilities identified during the investigation. Noticing vulnerabilities in the Linux security groups, I promptly adjust the network settings for both Linux and Windows VMs to limit access to 'My IP address' only. This proactive measure aims to mitigate risks associated with attempted brute-forcing or unauthorized RDP access, bolstering the overall security posture of the environment.

![028](https://github.com/user-attachments/assets/b7d98bc9-5957-407d-9245-518e5837aa7e)


## Step 24: Metrics Before and After Hardening
### **Before Hardening**

| Start Time: 2024-05-21

| Metric | Count |
| --- | --- |
| SecurityEvent | 7833 |
| Syslog | 725 |
| SecurityAlert | 3 |
| SecurityIncident | 23 |
| AzureNetworkAnalytics_CL | 273 |

### **After Hardening**

| Stop Time: 2024-05-22

| Metric | Count |
| --- | --- |
| SecurityEvent | 4523 |
| Syslog | 3 |
| SecurityAlert | 0 |
| SecurityIncident | 0 |
| AzureNetworkAnalytics_CL | 0 |

### **Percentage Change in Metrics**

| Metric | Before Hardening | After Hardening | Percentage Change (%) |
| --- | --- | --- | --- |
| SecurityEvent | 7394 | 4523 | -38.83% |
| Syslog | 725 | 3 | -99.59% |
| SecurityAlert | 4 | 0 | -100% |
| SecurityIncident | 8 | 0 | -100% |
| AzureNetworkAnalytics_CL | 249 | 0 | -100% |

## Step 25: Conclusion 
This project demonstrates the setup of a live SOC and honeynet in Azure, involving virtual machine deployment, security configuration, and incident response integration. Through deliberate security testing and monitoring, we showcased the effectiveness of implemented measures, emphasizing the importance of proactive security practices in cloud environments.
