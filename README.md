# Bug Bounty

Overview
---------
1. - [Web Requests](#1---web-requests)
2. - [Online Resources](#2---online-resources)
3. - [HTML Injection](#3---html-injection)
4. - [Cross-Site Scripting (XSS)](#4---cross-site-scripting-xss)

   
#1. - Web Requests
-----------------------------------------

- Curl

```
$ curl -v <URL>
$ curl -IL <URL>
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

#2. - Online Resources
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

#2. - Sensitive Data Exposure
-----------------------------------------

- Source Code

```
Right-click -> View page source
OR
CTRL + U
```

#3. - HTML Injection
-----------------------------------------

- Hyperlink

```
<a href="http://www.google.com">Click Me</a>
```

#4. - Cross-Site Scripting (XSS)
-----------------------------------------

*Reflected XSS	= Occurs when user input is displayed on the page after processing (e.g., search result or error message).*

*Stored XSS = Occurs when user input is stored in the back end database and then displayed upon retrieval (e.g., posts or comments).*

*DOM XSS	= Occurs when user input is directly shown in the browser and is written to an HTML DOM object (e.g., vulnerable username or page title).*

- DOM XSS

```
#"><img src=/ onerror=alert(document.cookie)>
```
