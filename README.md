# Wiz Scripts


## WizCLI ASCI Table Summary
```
ubuntu:~$ python3 wiz-table-summary.py "$(./wizcli docker scan -i wizio.azurecr.io/sensor:v1 -f json)"
           _            _ _
 __      _(_)____   ___| (_)
 \ \ /\ / / |_  /  / __| | |
  \ V  V /| |/ /  | (__| | |
   \_/\_/ |_/___|  \___|_|_|
 SUCCESS  Ready to scan Docker image wizio.azurecr.io/sensor:v1                 
 SUCCESS  Scanned Docker image                                                  82bf7ba60a419800c66931e16ace83c13b996683d2c (5s)
 SUCCESS  Docker image scan analysis ready                                      
+---------+-----------------+------------------+----------+---------------+--------------------------------------------------------------+------------+---------------------------+
| Package | Package Version |  Vulnerability   | Severity | Fixed Version |                            Source                            | CVSS Score | CVSS Exploitability Score |
+---------+-----------------+------------------+----------+---------------+--------------------------------------------------------------+------------+---------------------------+
|  libc6  |  2.36-9+deb12u3 |                  |          |               |                                                              |            |                           |
|         |                 | CVE-2019-1010022 |   LOW    |      None     | https://security-tracker.debian.org/tracker/CVE-2019-1010022 |    9.8     |            3.9            |
|         |                 | CVE-2019-1010023 |   LOW    |      None     | https://security-tracker.debian.org/tracker/CVE-2019-1010023 |    8.8     |            2.8            |
|         |                 | CVE-2019-1010024 |   LOW    |      None     | https://security-tracker.debian.org/tracker/CVE-2019-1010024 |    5.3     |            3.9            |
|         |                 | CVE-2019-1010025 |   LOW    |      None     | https://security-tracker.debian.org/tracker/CVE-2019-1010025 |    5.3     |            3.9            |
|         |                 |  CVE-2019-9192   |   LOW    |      None     |  https://security-tracker.debian.org/tracker/CVE-2019-9192   |    7.5     |            3.9            |
|         |                 |  CVE-2010-4756   |   LOW    |      None     |  https://security-tracker.debian.org/tracker/CVE-2010-4756   |     4      |             8             |
|         |                 |  CVE-2018-20796  |   LOW    |      None     |  https://security-tracker.debian.org/tracker/CVE-2018-20796  |    7.5     |            3.9            |
+---------+-----------------+------------------+----------+---------------+--------------------------------------------------------------+------------+---------------------------+

Wiz Vulnerability Summary:
CRITICAL Count: 0
HIGH Count: 0
MEDIUM Count: 0
LOW Count: 7

Wiz Report URL:
"https://app.wiz.io/reports/cicd-scans#~(cicd_scan~'00d51330-72d1-4ea2-b197-8f7eeb6c5442)"
```
