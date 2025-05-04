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
Setup shared folder in your VM client and put the Splunk Enterprise for Linux that downloaded earlier
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

Go to bin (`cd bin`) – this is where the binaries the splunk can use.
To run the installer, type : `./splunk start`
Then accept the license agreement.

![image](https://github.com/user-attachments/assets/324826b0-da11-4b7a-a971-bd765003c8f3)


Lastly, type `sudo ./splunk enable boot-start -user <username>` - this command will automatically run the splunk everytime we login the user.





Next, I will install the Splunk Universal Forwarder in our Windows Server and Windows target PC.

In windows10, try to access our splunk server. Go to browser then type the IP of our server then add the port 8000 (it’s the default port used by splunk) 
In my case, it’s 10.0.2.14:8000

![image](https://github.com/user-attachments/assets/c7b6ed0c-7fde-448f-a93a-5d25c5969da3)


Go to www.splunk.com again, login the user created earlier then go to free trial download and look for Universal Forwarder then click ‘Get My Free Download’. Make sure to select the correct operating system for your device.
![image](https://github.com/user-attachments/assets/bf58b2fc-9a9d-4b1e-84ce-3116020becae)

Once done downloading, double click it to start then fill the required fields.
![image](https://github.com/user-attachments/assets/7e42beb9-10b0-4e4a-a5e7-57835c9e50e1)


Skip the deployment server. In the Receiving indexer. Put the Ubuntu Server IP and put the default port 9997.

![image](https://github.com/user-attachments/assets/e8b74775-2882-48e3-a717-6d66cfe48c7c)


While waiting to finish the installation of Splunk Universal Forwarder, Download Sysmon :
![image](https://github.com/user-attachments/assets/db282e2f-82d3-411e-8fe5-dd5f80bdbbb6)

Also download Sysmon olaf config (sysmonconfig.xml) :
![image](https://github.com/user-attachments/assets/4baf8de5-2ab7-4fed-a870-ea3377b061c1)

![image](https://github.com/user-attachments/assets/b4bb5c36-0291-4fd7-bb67-137e7016131b)


Go to downloads then extract the Sysmon that downloaded earlier. Start Windows Powershell as Administrator, change directory to the Sysmon folder we extracted then type  : 
.\Sysmon64.exe -i <insert the location of Sysmon config> 
Then click ‘Agree’

![image](https://github.com/user-attachments/assets/5dc136b8-3106-487b-b4e5-17da2f804c1b)

![image](https://github.com/user-attachments/assets/74f87fae-ce4c-418b-8719-5057aaca35c7)


![image](https://github.com/user-attachments/assets/8c4d285f-9dda-4ae2-bfa6-951f3a851c3a)



Now go back to the splunk installation.


![image](https://github.com/user-attachments/assets/35880e06-7293-493a-9cbb-95bb7846015e)



We need to instruct our Splunk Forwarder on what we want to send to our splunk server,
Create a new file in Notepad as Administrator.
Put this inside the file :

[WinEventLog://Application]

index = endpoint

disabled = false


[WinEventLog://Security]

index = endpoint

disabled = false


[WinEventLog://System]

index = endpoint

disabled = false


[WinEventLog://Microsoft-Windows-Sysmon/Operational]

index = endpoint

disabled = false

renderXml = true

source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational



![image](https://github.com/user-attachments/assets/3440136e-bd06-4059-9d79-de924c7710bf)

Save the file as ‘inputs.conf’   here : C:\Program Files\SplunkUniversalForwarder\etc\system\local

Now go to’  Services.msc then look for Splunk Forwader, double click it then select the ‘Log On’ tab then select ‘Local System Account’


![image](https://github.com/user-attachments/assets/e5148eaf-79a0-4cb7-978f-c1dee30bac41)


Once done, restart the Splunk Forwarder to apply the changes made.

![image](https://github.com/user-attachments/assets/94765f53-b1e0-4e87-acfa-b03030cdd4fc)

Login to Splunk webpage. Then go to settings > indexes

![image](https://github.com/user-attachments/assets/69a6b338-5e09-4ddb-96d4-bb656fdb350e)

Create new index named ‘endpoint’

![image](https://github.com/user-attachments/assets/935d2923-e64a-4e2e-93fb-7f1d1a1dd3a1)

Click the ‘settings’ again then select ‘Forwarding and receiving. Click ‘Configure receiving’ then create new Receiving Port then put the default port 9997

![image](https://github.com/user-attachments/assets/b68b6599-41f9-4cf7-9406-6f29aa63e8a4)

![image](https://github.com/user-attachments/assets/c0411b33-6881-40e0-9783-9883e4b9ada6)

Verify if we can now receive data. Go to apps, select ‘Search & Reporting’. 
In search box, type : ‘index=endpoint’ then check if there are events coming through.

![image](https://github.com/user-attachments/assets/65423268-d698-4370-b9b1-a59a7eb5d6b6)





