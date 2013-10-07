http_extend
===========

"HTTP-Monitoring" Tool for Zabbix

This tool can be utilized to gather behavioral measurement data or configuration data of webservers/appplication servers.
It can be used as an external check for the zabbix monitoring system.
This tool is written in c, therefore it creates very minimal overhead when Zabbix calls this tool as "External check".

Zabbix is already capable to monitor via the http protocol - the reasons for using this tool are:
 * Zabbix web scenarios cannot be executed on proxies
 * Zabbix is not capable to parse a value out of a website
 * Zabbix is not capable to set a host header
 * Zabbix is not capable to ignore ssl errors


Compile and Install
-------------------

Install the tool on zabbix-proxies, zabbix-servers or zabbix-nodes

Prerequisites:
 * C-compiler
 * GNU Make
 * Libpcre and Libpcre-Dev
 * Libcurl and Libcurl-Dev
 * libssl and libssl-dev

On Ubuntu just do
(This will install the binary 'mysql_extend' to /etc/zabbix/externalscripts):
```
git clone git://github.com/digitalmediacenter/http_extend.git http_extend
cd http_extend
sudo apt-get install libpcre3 libpcre3-dev gcc-4.4 libcurl3 libcurl4-openssl-dev
make
# Install to /etc/zabbix/externalscripts
CC=gcc-4.4 make install
# Install to /usr/local/bin
make INSTALLDIR=/usr/local/bin install
```

Usage
-----

Features:
```
$ ./http_extend 

http_extend,1.x fetch http urls and extract values
http_extend [-?] [-V] [-v] [-u URL] [-r PCRE-REGEX]

  -?              print this help and exit
  -V              print version and exit

  -v              set verbose flag (repeat for more output)
  -l              follow location redirects
  -i              ignore ssl certificat verification
  -f              fail request on curl errors (receive buffer of 5242880 bytes exceded, http-errors, ..)
  -s              provide only the status of the request (zabbix values: 1 = OK, 0 = NOT OK, )
  -m              provide the total delivery time of the request in seconds (zabbix values: >0.0 = OK (seconds), 0.0 = NOT OK)
  -c              check ssl certificate and return days until expire
  -u URL          Specify the url to fetch
  -t mseconds     Timeout of curl request in 1/1000 seconds (default: 5000 milliseconds)
  -r PCRE-REGEX   Specify the matching regex
  -h HOSTNAME     Specify the host header

```

Examples:
```
./http_extend -h
# Parse apache server status and gain "Total Accesses" value
./http_extend -v -u "https://www.foobar.org/server-status?auto" -r "Total Accesses: (\d+)"
# Check if string "Impressum" is in the response and return "1", otherwise return "0"
./http_extend -v -l -t 5000 -u 'http://10.1.1.1:80/men/shirts' -r '(Impressum)' -s -h www.foobarshop.de
# Check if header value "X-Cache-Lookup: HIT from" is set and return "1", 
# otherwise return "0" (show whole answer for debugging purposes)
./http_extend  -l -u http://foobar.com/ -r '(X-Cache-Lookup: HIT from)' -s  -t 100000 -vvv -a
# Get days until the SSL certificate expires
./http_extend -c -u https://goobar.org:443
```

Gather data from a apache-server-status page and add it as an measure to zabbix.
```
Description........: Apache Requests
Type...............: External check
Key Zabbix 1.8.....: http_extend[-t 5000 -u "https://{HOSTNAME}/server-status?auto" -r "Total Accesses: (\d+)"]
Key Zabbix 2.0.....: http_extend[-t,5000,-u,"https://{HOSTNAME}/server-status?auto",-r,"Total Accesses: (\d+)"]
Type of information: Numeric (unsigned)
Data type..........: Decimal
Update interval....: 300
Store value........: Delta (speed per second)
```

Check a website on a host behind a loadbalancer by setting the hostheader.
```
Description........: Check for "Impressum"
Type...............: External check
Key Zabbix 1.8.....: http_extend[-l -t {$TIMEOUT} -u 'http://{IPADDRESS}:80/men/shirts' -r '(Impressum)' -s -h www.foobarshop.de]
Key Zabbix 2.0.....: http_extend[-l,-t,{$TIMEOUT},-u,'http://{IPADDRESS}:80/men/shirts',-r,'(Impressum)',-s,-h,www.foobarshop.de]
Type of information: Numeric (unsigned)
Data type..........: Decimal
Update interval....: 300
Store value........: As is
Show value.........: Service state
```

The first matching regex group is printed to STDOUT. All other output is printed to STDERR.

See also subfolder "zabbix_templates/".

Tips / Good to know
-------------------

Timeout:

Maybe you have t increase timeout in Zabbix server configuration for external check:
```
Default:  3 seconds
Max:     30 seconds
```

More information can be found in documentation: https://www.zabbix.com/documentation/2.0/manual/appendix/config/zabbix_server

Missing features
----------------
- [ ] Fetch the remaining days of validness of ssl certificates
- [ ] Measure Time-To-First-Byte

Licence and Authors
-------------------

Additional authors are very welcome - just submit your patches as pull requests.

 * Marc Schoechlin <marc.schoechlin@dmc.de>
 * Andreas Heil <andreas.heil@dmc.de>

License - see: LICENSE.txt
