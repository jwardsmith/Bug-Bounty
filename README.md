# Bug Bounty

Overview
---------
1. - [Web Requests](#1---web-requests)
   
#1. - Web Requests
-----------------------------------------

- Curl

```
$ curl -v <URL>
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' <URL>
curl <URL>/search.php?search=test
curl -X POST -d 'username=admin&password=admin' <URL>
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' <URL>
```
