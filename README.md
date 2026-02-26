# check_zone_dnssec
Check DNSSEC at all nameservers for a zone

check_zone_dnssec.py
A command line tool to verify DNSSEC reponses at each authoritative
server for a signed zone.

Query each nameserver address for a zone and determine whether
DNSSEC signed responses for a given record and type within the
zone are correct.

This program assumes the parent zone has a valid DS record installed.
It first queries and authenticates that DS record from the root down.
Optionally, the program can be provided the actual DS record data it
should use instead of querying it from the DNS. This option is useful
for pre-delegation testing.

It then individually queries each nameserver for the zone. For each
nameserver, it queries the DNSKEY RRset, verifies the self signature(s)
on that set, matches the DS RRset to the KSKs. It then queries the
specified record name and type within the zone and authenticates its
signature.

Optionally, the program can be told to query specific additional
nameserver names or addresses not published in the NS RRset for the 
zone, or even omit querying the NS RRSet entirely.

The --nxdomain and --nodata options can be used to test signed NXDOMAIN
and NODATA responses respectively.

This program is useful for checking that _every_ authoritative server
for a target zone is responding with correctly signed answers.

Pre-requisites:
- Python 3
- [dnspython module](http://www.dnspython.org/) (included with most Linux/*BSD distributions)
- [python-cryptography](https://cryptography.io/en/latest/) for DNSSEC support
- [my resolve.py library](https://github.com/shuque/resolve)


### Installation

Install check_zone_dnssec.py:

* pip3 install git+https://github.com/shuque/check_zone_dnssec.git@v1.0.9


### Usage

```
usage: check_zone_dnssec.py [-h] [-v] [--nxdomain | --nodata] [--percent_ok N]
                            [-4 | -6] [--bufsize N] [--addnsname NSNAMES]
                            [--addnsip NSIPS] [--nonsquery] [--nsid]
                            [--dsdata DSDATA] [--resolvers IP [IP ...]]
                            [--text] [--timeout N] [--retries N]
                            zone recname rectype

Version 1.0.9
Query all nameserver addresses for a given zone and validate DNSSEC

positional arguments:
  zone                  DNS zone name
  recname               Record name in the zone
  rectype               Record type for that name

options:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  --nxdomain            Expect NXDOMAIN response
  --nodata              Expect NODATA response
  --percent_ok N        Percentage success threshold (default: 100)
  -4                    Query IPv4 nameserver addresses only
  -6                    Query IPv6 nameserver addresses only
  --bufsize N           Set EDNS buffer size in octets (default: 1420)
  --addnsname NSNAMES   Additional NS names to query (comma separated)
  --addnsip NSIPS       Additional NS IP addresses to query (comma separated)
  --nonsquery           Don't query zone's NS set (default: False)
  --nsid                Send and record NSID EDNS option
  --dsdata DSDATA       Use specified DS rdata string (default: None)
  --resolvers IP [IP ...]
                        Use specified resolver addresses (default: ['8.8.8.8',
                        '1.1.1.1'])
  --text                Emit abbreviated text output (default is json)
  --timeout N           Query timeout in secs (default: 4)
  --retries N           Number of UDP retries (default: 1)
```

### Example Runs

Check the positive www.salesforce.com CNAME response in the
salesforce.com zone:

```
$ check_zone_dnssec.py salesforce.com www.salesforce.com CNAME
{
  "zone": "salesforce.com.",
  "recname": "www.salesforce.com.",
  "rectype": "CNAME",
  "timestamp": "2026-01-05T02:06:47GMT",
  "success": true,
  "server_count_total": 12,
  "server_count_good": 12,
  "server_good_percent": "100.00",
  "servers": [
    {
      "nsname": "udns1.salesforce.com.",
      "ip": "2001:502:2eda::8",
      "dnssec": true
    },
    {
      "nsname": "udns1.salesforce.com.",
      "ip": "156.154.100.8",
      "dnssec": true
    },
    {
      "nsname": "udns2.salesforce.com.",
      "ip": "2001:502:ad09::8",
      "dnssec": true
    },
    {
      "nsname": "udns2.salesforce.com.",
      "ip": "156.154.101.8",
      "dnssec": true
    },
    {
      "nsname": "udns3.salesforce.com.",
      "ip": "2610:a1:1009::8",
      "dnssec": true
    },
    {
      "nsname": "udns3.salesforce.com.",
      "ip": "156.154.102.8",
      "dnssec": true
    },
    {
      "nsname": "udns4.salesforce.com.",
      "ip": "2610:a1:1010::8",
      "dnssec": true
    },
    {
      "nsname": "udns4.salesforce.com.",
      "ip": "156.154.103.8",
      "dnssec": true
    },
    {
      "nsname": "pch1.salesforce-dns.com.",
      "ip": "2620:171:809::1",
      "dnssec": true
    },
    {
      "nsname": "pch1.salesforce-dns.com.",
      "ip": "206.223.122.1",
      "dnssec": true
    },
    {
      "nsname": "pch2.salesforce-dns.com.",
      "ip": "2620:171:80a::1",
      "dnssec": true
    },
    {
      "nsname": "pch2.salesforce-dns.com.",
      "ip": "199.184.183.1",
      "dnssec": true
    }
  ]
}

```

Check the signed NXDOMAIN responses for the non-existent domain
'foo.nxd79.huque.com' at the huque.com zone:

```
$ check_zone_dnssec.py --nxdomain huque.com foo.nxd79.huque.com A
{
  "zone": "huque.com.",
  "recname": "foo.nxd79.huque.com.",
  "rectype": "A",
  "timestamp": "2026-01-05T02:10:10GMT",
  "success": true,
  "server_count_total": 10,
  "server_count_good": 10,
  "server_good_percent": "100.00",
  "servers": [
    {
      "nsname": "adns1.dnsrakuda.com.",
      "ip": "2600:1f18:6296:8902::c0de",
      "dnssec": true
    },
    {
      "nsname": "adns1.dnsrakuda.com.",
      "ip": "3.225.161.117",
      "dnssec": true
    },
    {
      "nsname": "adns2.dnsrakuda.com.",
      "ip": "2600:1f14:990:2e01::bad",
      "dnssec": true
    },
    {
      "nsname": "adns2.dnsrakuda.com.",
      "ip": "52.88.78.179",
      "dnssec": true
    },
    {
      "nsname": "adns1.nnn.upenn.edu.",
      "ip": "2607:f470:1001::ad:1",
      "dnssec": true
    },
    {
      "nsname": "adns1.nnn.upenn.edu.",
      "ip": "128.91.2.53",
      "dnssec": true
    },
    {
      "nsname": "adns2.nnn.upenn.edu.",
      "ip": "2607:f470:1002::ad:2",
      "dnssec": true
    },
    {
      "nsname": "adns2.nnn.upenn.edu.",
      "ip": "128.91.254.53",
      "dnssec": true
    },
    {
      "nsname": "adns3.nnn.upenn.edu.",
      "ip": "2607:f470:1003::ad:3",
      "dnssec": true
    },
    {
      "nsname": "adns3.nnn.upenn.edu.",
      "ip": "128.91.251.53",
      "dnssec": true
    }
  ]
}

```
