# Active Directory Security Lab: Logging & Threat Detection with Splunk


# Project Overview

This lab focuses on configuring Active Directory (AD) in a controlled environment and integrating Splunk for security monitoring. The objective is to simulate authentication and administrative activity, specifically testing account creation and deletion tactics (T1136.001) alongside brute-force attacks. By leveraging Splunk, the lab aims to analyze logs for signs of unauthorized access attempts, privilege escalations, and anomalous logon behaviors, providing insights into detection strategies and forensic investigation techniques.


# Lab Setup Environment:
🔹 Virtual Machines (VMs)

•	Windows Server 2022 (Domain Controller) – Hosts the Active Directory (AD) environment, managing authentication, user accounts, and group policies.

•	Windows 10 (Client Machine) – Simulates a standard user workstation, interacting with AD for login events and administrative activities.

•	Kali Linux (Attacker Machine) – Used for simulating brute-force attacks.

•	Ubuntu Server (Splunk Server) – Acts as the centralized log collection and analysis server, hosting Splunk for security monitoring and threat detection.


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
```.\Sysmon64.exe -i ..\<Name of Sysmon config> ```
Then click ‘Agree’

![image](https://github.com/user-attachments/assets/5dc136b8-3106-487b-b4e5-17da2f804c1b)

![image](https://github.com/user-attachments/assets/74f87fae-ce4c-418b-8719-5057aaca35c7)


![image](https://github.com/user-attachments/assets/8c4d285f-9dda-4ae2-bfa6-951f3a851c3a)



Now go back to the splunk installation.


![image](https://github.com/user-attachments/assets/35880e06-7293-493a-9cbb-95bb7846015e)



We need to instruct our Splunk Forwarder on what we want to send to our splunk server,
Create a new file in Notepad as Administrator.
Put this inside the file :
```
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
```


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



Setup Windows Server Active Directory:
Manage > Add Roles and Features

![image](https://github.com/user-attachments/assets/b85bb7d4-bfcc-4940-9b40-f31e0fa8cc76)


Select ‘Role-based or feature-based installation.

![image](https://github.com/user-attachments/assets/29930bca-b4ea-4ff9-93b6-b72ff11ab890)

Proceed to next panel. Click next. In ‘Server Roles’, hit the checkbox of ‘Active Directory Domain Services’.

![image](https://github.com/user-attachments/assets/a0aed42d-fe7c-4229-958a-4a105f15e9d9)


Keep clicking ‘Next’ until we get ‘Install’. Once the installation done, close the panel then click the flag icon beside manage. Click ‘ Promote this server to domain controller’


![image](https://github.com/user-attachments/assets/f9bea1b3-7cb7-44e1-afbf-7ba4a2079d30)


Add new forest then input your domain name. (The domain name must have a top level domain example : 
Domain.Sample)

![image](https://github.com/user-attachments/assets/106a1c95-3371-4483-9f6e-07da8cfcc564)


Leave everything default then set a password. Keep clicking ‘Next’. It will do a 'Prerequisites Check' then
You can ‘Install’ it. Once the setup is completed, the server will automatically restart.

![image](https://github.com/user-attachments/assets/a3e70541-4065-4f87-b95a-53ecf8db9aa3)


Now we will create a user under the domain. In Server Manager, click ‘tools’ then select ‘Active Directory Users and Computer.

![image](https://github.com/user-attachments/assets/b4a68a95-2ea6-417a-bf32-b7cab98770de)

Right click the domain, click ‘New’ > select ‘Organizational Unit’

![image](https://github.com/user-attachments/assets/11c06ef6-8621-4b0a-b606-933dd8914cb8)



Create your organizational Unit that mimics the real-world scenario.  in my case. I created  an ‘IT’ and ‘HR’. add user in each organization. Me, I created ‘Jenny Smith’ with a username of ‘jsmith’ in IT then ‘Terry Smith’ with a username of ‘tsmith’ in HR organization. Also put any password you want in both account.
Since we are in the lab environment. Make sure to uncheck the ‘User must change password at next logon’ 



Now go back to the windows 10 machine then join it to our newly created domain.
Go to  ‘Advance system settings’, click ‘Computer Name’ tab then click ‘Change’

![image](https://github.com/user-attachments/assets/02ee0b93-0e25-4003-ac87-15e799005846) ![image](https://github.com/user-attachments/assets/abcad7a7-c349-4def-8413-91845be9c2aa)


Select ‘Domain’ then input the name of domain you create. (in your ipv4 network adapter properties, put the  IP of your windows server or domain controller in the ‘preferred DNS server’ so we can join the PC to our domain) 
when you proceed in entering in domain, a login prompt will appear. Login the windows server administrator account.
Once you done joining the domain. The computer will require a restart to apply the changes made


![image](https://github.com/user-attachments/assets/f7e20db0-669d-499e-8397-7f23e5038b2a)  ![image](https://github.com/user-attachments/assets/fde133f4-5be3-40a3-8ac7-4c760ec98291)


Once the restart is done, you can now login the created account in domain into the windows10.


Now go to Kali Linux to start setting up an attack.
Open the Terminal,
Update and update repositories by typing `‘sudo apt-get update && sudo apt-get upgrade -y’`
Create new directory ‘ad-project’ (`mkdir ad-project`) all of the files that we will use to attack will be put in this directory.
Install crowbar (`sudo apt-get install -y crowbar`). I will be using this for a bruteforce attack.
Note : Please don’t target asset that you don’t have permission to do so. Only use this for educational purposes and use this for your lab or machine that you own.


![image](https://github.com/user-attachments/assets/bea21566-9b65-420d-b15f-73039369da75)



Once the installation is done, go to the wordlists directory (`cd /usr/share/wordlists/`)
Use gunzip to extract the rockyou file (`sudo gunzip rockyou.txt.gz`)
Then copy it to the created folder (`cp rockyou.txt ~/Desktop/ad-project`)

![image](https://github.com/user-attachments/assets/e4e51b43-edd6-46f1-af63-fdd974dc68a9)


Get only the first 20 lines then put it in a new text file (`head -n 20 rockyou.txt > passwords.txt`)

![image](https://github.com/user-attachments/assets/026cb3fd-825f-4c74-9709-47a021228683)


Edit the ‘password.txt’ then put the password of the users that we created ealier in the domain.


Now go back to the windows machine then enable the remote desktop. Go to ‘This PC > properties > scroll down and look for ‘Advanced system settings’. Click the remote tab then select ‘Allow remote connections to this computer’ > click ‘Select Users..

![image](https://github.com/user-attachments/assets/da6ee5d6-978d-4dfc-a11c-ca46372034e9)


Click on ‘Add..’ then input the username of 2 users created earlier. ‘check name’ then ‘OK’


# Attack Simulation
**1. Brute-Force Attack**

Back to our Kali Linux machine. Type crowbar -h in the terminal to see the options that can be use. (You can also use other bruteforce attack software like hydra or crackmapexec.)
Since we already open the remote desktop in windows pc, we can use this command:
`crowbar -b rdp -u <username> -C passwords.txt -s <ip addr>`  in my case, i used `crowbar -b rdp -u tsmith -C passwords.txt -s 10.0.2.10/32`

Here's a sample of what you see when you run the command :

![image](https://github.com/user-attachments/assets/a3027ece-f779-41b1-a9de-38fa1a56150f)


Now, go to splunk to check what telemetry are created.
Copy the text I put in search box and set the time in 'Last 15 minutes'.

![image](https://github.com/user-attachments/assets/152d8980-5158-49cc-acef-b691950cf610)

In the left side. In the ‘INTERESTING FIELDS’ click the Eventcode and you will see a event ID 4625

![image](https://github.com/user-attachments/assets/0b3a2901-7989-4081-aa00-6bca3898d6c2)

![image](https://github.com/user-attachments/assets/9b99b07c-e47d-4e93-b9a6-8e83cb98d1f7)

All of this failed login attempt happen pretty much at the same time which can be a clear indication of a bruteforce attack.

**2. Account Creation & Deletion (T1136.001)**

Now let’s try AtomicRedTeam to our machine.

First, open powershell as administrator then type  ‘Set-ExecutionPolicy Bypass CurrentUser’ then press ‘y’

![image](https://github.com/user-attachments/assets/d1f69d3d-3ee4-4373-8952-ad9118aba89a)


Go to windows Security then ‘Add or remove exclusions’ then add the Drive C.

We need to do this because Windows Security will automatically block the AtomicRedTeam.

![image](https://github.com/user-attachments/assets/62bf645d-d180-449f-b929-e8f89e97e5bb)


Type this on the powershell :
`IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);`

`Install-AtomicRedTeam -getAtomics`

![image](https://github.com/user-attachments/assets/84f77b97-6fb5-4024-b235-fe1f8ac167ab)



If this appear. Press ‘Y’
![image](https://github.com/user-attachments/assets/fe815f8c-c105-4201-b57c-bdaef906fc1e)



Once the installation is done, head into C:\AtomicRedTeam\atomics
You’ll see a bunch of technique ID aligned to MITRE ATT&CK framework. 
You can check all of this in https://attack.mitre.org/


![image](https://github.com/user-attachments/assets/4e6b0855-706f-46a3-9881-e84e3dc14046)


Now lets try one of this. Type : Invoke-AtomicTest T1136.001
As you can see below. It will create a username ‘NewLocalUser’ and also delete it.

![image](https://github.com/user-attachments/assets/4560f1af-1ada-4076-88d7-6582fab34391)


Now let’s check again our splunk for detection. Search ‘NewLocalUser’ in the last 15mins.

![image](https://github.com/user-attachments/assets/ba9369b1-0a9c-46c8-a375-d108b176a655)

It shows that our splunk capture the force creation of account and also delete it.
Now, go try the other 'Atomics' and make sure to check what it does in the mitre webpage.







