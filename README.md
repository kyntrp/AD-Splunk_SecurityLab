# Active Directory Security Lab: Logging & Threat Detection with Splunk


Project Overview
This lab focuses on configuring Active Directory (AD) in a controlled environment and integrating Splunk for security monitoring. The objective is to simulate authentication and administrative activity, specifically testing account creation and deletion tactics (T1136.001) alongside brute-force attacks. By leveraging Splunk, the lab aims to analyze logs for signs of unauthorized access attempts, privilege escalations, and anomalous logon behaviors, providing insights into detection strategies and forensic investigation techniques.


# Lab Setup Environment:
🔹 Virtual Machines (VMs)

•	Windows Server 2022 (Domain Controller) – Hosts the Active Directory (AD) environment, managing authentication, user accounts, and group policies.

•	Windows 10 (Client Machine) – Simulates a standard user workstation, interacting with AD for login events and administrative activities.

•	Kali Linux (Attacker Machine) – Used for simulating attacks, such as Bruteforce etc.

•	Ubuntu Server (Splunk Host) – Acts as the centralized log collection and analysis server, hosting Splunk for security monitoring and threat detection.


🔹 Splunk SIEM Integration

•	Splunk Server– Collects Windows Security Logs and Active Directory event logs for analysis.

•	Forwarders & Indexers – Used to send logs from the Domain Controller and Client Machine to Splunk for centralized monitoring.


🔹 Security Logging & Monitoring

•	Group Policy Configurations – Define audit policies to log authentication events, privilege escalations, and failed logins.

•	Sysmon Integration – Provides granular process-level telemetry for tracking adversary activity beyond standard Windows logs.

•	Splunk Queries (SPL) – Used for detecting anomalies in authentication patterns, lateral movement, and administrative abuse.


This setup will allow for real-time log analysis, threat hunting, and incident response simulations based on Active Directory events.


![image](https://github.com/user-attachments/assets/f5771d31-c247-42be-9393-233ca75baf27)


# Steps:


Setup Splunk :
Using the Host PC. Go to splunk (www.splunk.com), sign up then download free trial Splunk Enterprise for Linux(.deb)

Now we will setup a shared folder from host to VMs. Go to Ubuntu Server, install virtualbox guest addition iso (`sudo apt-get install virtualbox-guest-additions-iso`)
and  virtualbox guest utils (`sudo apt-get install virtualbox-guest-utils`)
This driver will let us use a ‘Shared Folder’ and access vboxsf group.
Reboot after done installing.
Setup shared folder in your VM client.
Add user in the vboxsf group(`sudo adduser <username> vboxsf`)

(I’m Using Oracle Virtualbox so it may be different on how I setup mine. Just google it or youtube on how to setup shared folder in your VM software)

![image](https://github.com/user-attachments/assets/acfb5420-090e-44ce-a1c0-542d9440a503)



Create a directory named ‘share’ (`mkdir share`) then mount our shared folder to it 
(`sudo mount -t vboxsf -o uid=1000,gid=1000 <shared folder name>  share/`)
Relogin then verify if the mounting of shared folder is successful. 

![image](https://github.com/user-attachments/assets/bf5c69cb-09cb-4ba5-befa-700db4df28ae)



To install splunk, type : `sudo dpkg -i <name of splunk in directory>`



Go to splunk directory to verify the installation (/opt/splunk)

![image](https://github.com/user-attachments/assets/a49295ec-ccfb-4766-9b5d-2f98b74ad848)

Go to bin (cd bin) – this is where the binaries the splunk can use.
To run the installer, type : ./splunk start 
Then accept the license agreement.

![image](https://github.com/user-attachments/assets/324826b0-da11-4b7a-a971-bd765003c8f3)


Lastly, type `sudo ./splunk enable boot-start -user <username>` - this command will automatically run the splunk everytime we login the user.




