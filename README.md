# IPDump
## A python utility for quickly generating reports for IP Addresses, Websites and domains.

Current features:
- Geolocation Information
- SSL Certificate Fetching
- WHOIS Information
- Portscanning
- Import-able

## Requirements
To use IPDump, you will need Python 3.

Additionally, you will need to install some additional dependencies:
```
pip3 install -r requirements.txt
```

## Usage
```
./ipdump.py -h
usage: ipdump.py [-h] [-l] [-c] [-a] [-p] [-i] [-s] [-w] [-n WORKERS]
                 [-r RANGE]
                 host

positional arguments:
  host                  The hostname/IP Address, URL or Domain of the target

optional arguments:
  -h, --help            show this help message and exit
  -l, --no-logging      Disable logging
  -c, --no-color        Disable colored logging
  -a, --all             Run all tools on the given target
  -p, --port-scan       Enable portscanning on the target
  -i, --ip-info         Fetch information from api-ip.com (contains
                        geographical info)
  -s, --ssl-cert        Retrieves the SSL Certificate of the host
  -w, --whois           Fetch whois information from arin.net (contains domain
                        ownership info)
  -n WORKERS, --workers WORKERS
                        Number of workers for portscanning
  -r RANGE, --range RANGE
                        Range of ports to scan formatted as START-END

```

## Examples: 

### Getting IP Geolocation Information
```
./ipdump.py 91.7.125.52 -i 
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Requesting information from http://ip-api.com/json/
[+] Response from http://ip-api.com/json/:
status       : success
continent    : Europe
continentCode: EU
country      : Germany
countryCode  : DE
region       : NW
regionName   : North Rhine-Westphalia
city         : Kempen
district     : 
zip          : 47906
lat          : 51.3643
lon          : 6.4186
timezone     : Europe/Berlin
currency     : EUR
isp          : Deutsche Telekom AG
org          : Deutsche Telekom AG
as           : AS3320 Deutsche Telekom AG
asname       : DTAG
reverse      : p5B077D34.dip0.t-ipconnect.de
mobile       : False
proxy        : False
query        : 91.7.125.52
[+] Report for 91.7.125.52 completed

```

### Getting SSL Certificates
```
./ipdump.py google.com -s
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Certificate: 
subject             : ((('countryName', 'US'),), (('stateOrProvinceName', 'California'),), (('localityName', 'Mountain View'),), (('organizationName', 'Google LLC'),), (('commonName', '*.google.com'),))
issuer              : ((('countryName', 'US'),), (('organizationName', 'Google Trust Services'),), (('commonName', 'GTS CA 1O1'),))
version             : 3
serialNumber        : C5D40BA32A0CF5570800000000287A46
notBefore           : Jan  7 15:47:12 2020 GMT
notAfter            : Mar 31 15:47:12 2020 GMT
subjectAltName      : (('DNS', '*.google.com'), ('DNS', '*.android.com'), ('DNS', '*.appengine.google.com'), ('DNS', '*.cloud.google.com'), ('DNS', '*.crowdsource.google.com'), ('DNS', '*.g.co'), ('DNS', '*.gcp.gvt2.com'), ('DNS', '*.gcpcdn.gvt1.com'), ('DNS', '*.ggpht.cn'), ('DNS', '*.gkecnapps.cn'), ('DNS', '*.google-analytics.com'), ('DNS', '*.google.ca'), ('DNS', '*.google.cl'), ('DNS', '*.google.co.in'), ('DNS', '*.google.co.jp'), ('DNS', '*.google.co.uk'), ('DNS', '*.google.com.ar'), ('DNS', '*.google.com.au'), ('DNS', '*.google.com.br'), ('DNS', '*.google.com.co'), ('DNS', '*.google.com.mx'), ('DNS', '*.google.com.tr'), ('DNS', '*.google.com.vn'), ('DNS', '*.google.de'), ('DNS', '*.google.es'), ('DNS', '*.google.fr'), ('DNS', '*.google.hu'), ('DNS', '*.google.it'), ('DNS', '*.google.nl'), ('DNS', '*.google.pl'), ('DNS', '*.google.pt'), ('DNS', '*.googleadapis.com'), ('DNS', '*.googleapis.cn'), ('DNS', '*.googlecnapps.cn'), ('DNS', '*.googlecommerce.com'), ('DNS', '*.googlevideo.com'), ('DNS', '*.gstatic.cn'), ('DNS', '*.gstatic.com'), ('DNS', '*.gstaticcnapps.cn'), ('DNS', '*.gvt1.com'), ('DNS', '*.gvt2.com'), ('DNS', '*.metric.gstatic.com'), ('DNS', '*.urchin.com'), ('DNS', '*.url.google.com'), ('DNS', '*.wear.gkecnapps.cn'), ('DNS', '*.youtube-nocookie.com'), ('DNS', '*.youtube.com'), ('DNS', '*.youtubeeducation.com'), ('DNS', '*.youtubekids.com'), ('DNS', '*.yt.be'), ('DNS', '*.ytimg.com'), ('DNS', 'android.clients.google.com'), ('DNS', 'android.com'), ('DNS', 'developer.android.google.cn'), ('DNS', 'developers.android.google.cn'), ('DNS', 'g.co'), ('DNS', 'ggpht.cn'), ('DNS', 'gkecnapps.cn'), ('DNS', 'goo.gl'), ('DNS', 'google-analytics.com'), ('DNS', 'google.com'), ('DNS', 'googlecnapps.cn'), ('DNS', 'googlecommerce.com'), ('DNS', 'source.android.google.cn'), ('DNS', 'urchin.com'), ('DNS', 'www.goo.gl'), ('DNS', 'youtu.be'), ('DNS', 'youtube.com'), ('DNS', 'youtubeeducation.com'), ('DNS', 'youtubekids.com'), ('DNS', 'yt.be'))
OCSP                : ('http://ocsp.pki.goog/gts1o1',)
caIssuers           : ('http://pki.goog/gsr2/GTS1O1.crt',)
crlDistributionPoints: ('http://crl.pki.goog/GTS1O1.crl',)
[+] Report for google.com completed
```


### Getting Website WHOIS Information
```
./ipdump.py github.com -w
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Sending whois query to whois.arin.net
[+] Response from whois.arin.net:

#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2019, American Registry for Internet Numbers, Ltd.
#


#
# Query terms are ambiguous.  The query is assumed to be:
#     "n 140.82.118.3"
#
# Use "?" to get help.
#

NetRange:       140.82.112.0 - 140.82.127.255
CIDR:           140.82.112.0/20
NetName:        GITHU
NetHandle:      NET-140-82-112-0-1
Parent:         NET140 (NET-140-0-0-0-0)
NetType:        Direct Assignment
OriginAS:       AS36459
Organization:   GitHub, Inc. (GITHU)
RegDate:        2018-04-25
Updated:        2019-06-20
Ref:            https://rdap.arin.net/registry/ip/140.82.112.0


OrgName:        GitHub, Inc.
OrgId:          GITHU
Address:        88 Colin P Kelly Jr Street
City:           San Francisco
StateProv:      CA
PostalCode:     94107
Country:        US
RegDate:        2012-10-22
Updated:        2014-04-26
Comment:        https://github.com
Comment:        Please contact us directly for matters pertaining to abuse.
Comment:        Urgent matters including DDoS are handled 24x7.
Ref:            https://rdap.arin.net/registry/entity/GITHU


OrgAbuseHandle: GITHU1-ARIN
OrgAbuseName:   GitHub Abuse
OrgAbusePhone:  +1-415-857-5430 
OrgAbuseEmail:  abuse@github.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/GITHU1-ARIN

OrgNOCHandle: GITHU-ARIN
OrgNOCName:   GitHub Ops
OrgNOCPhone:  +1-415-735-4488 
OrgNOCEmail:  hostmaster@github.com
OrgNOCRef:    https://rdap.arin.net/registry/entity/GITHU-ARIN

OrgTechHandle: GITHU-ARIN
OrgTechName:   GitHub Ops
OrgTechPhone:  +1-415-735-4488 
OrgTechEmail:  hostmaster@github.com
OrgTechRef:    https://rdap.arin.net/registry/entity/GITHU-ARIN


#
# ARIN WHOIS data and services are subject to the Terms of Use
# available at: https://www.arin.net/resources/registry/whois/tou/
#
# If you see inaccuracies in the results, please report at
# https://www.arin.net/resources/registry/whois/inaccuracy_reporting/
#
# Copyright 1997-2019, American Registry for Internet Numbers, Ltd.
#


[+] Report for github.com completed
```

### Portscanning a Server
```
./ipdump.py imap.gmail.com -p -r 900-1000
[+] WARNING: I am not liable for any damage (including criminal charges) which may arise from use of this software. For more information see the LICENSE file included with this software.

[+] Portscanning imap.gmail.com for open ports in the range 900-1000
    +-------+------------------------------+-----------+--------------------------------------------------+
    | Port  | Protocol                     | Transport | Description                                      |
    +-------+------------------------------+-----------+--------------------------------------------------+
    | 993   | imaps                        | tcp       | IMAP over TLS protocol                           |
    | 995   | pop3s                        | tcp       | POP3 over TLS protocol                           |
    +-------+------------------------------+-----------+--------------------------------------------------+
[+] Portscan finished
[+] Report for imap.gmail.com completed
```

### Importing

`example.py` illustrates how to import IPDump and carry out a simple portscan

```
# Import the Dumper class
from ipdump import Dumper

# Create a Dumper with the target "imap.gmail.com"
dumper = Dumper("imap.gmail.com")

# Print status message
print("Open Ports: ", end="")

# For each open port, print it to the console
dumper.get_open_ports(start=1, end=1000, callback=lambda portinfo: print(portinfo.port, end=" "), timeout=1)

# Print a newline, to write PS1 on a newline
print("")
```

yielding the following output:
```
./example.py 
Open Ports: 25 465 587 995 993 
```
