# check_zone_dnssec
Check DNSSEC at all nameservers for a zone

check_zone_dnssec.py
A command line too to verify DNSSEC reponses at each authoritative
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

This program is useful for checking that _every_ authoritative server
for a target zone is responding with correctly signed answers.

Pre-requisites:
- Python 3
- [dnspython module](http://www.dnspython.org/) (included with most Linux/*BSD distributions)
- [python-cryptography](https://cryptography.io/en/latest/) for DNSSEC support
- [my resolve.py library](https://github.com/shuque/resolve)


### Installation

Install the pre-requisite python cryptography package:

* pip3 install "cryptography>=3.0"

Install the dnspython package:

* pip3 install dnspython

Install resolve:

* pip3 install git+https://github.com/shuque/resolve.git@v0.6.6

Install check_zone_dnssec.py:

* pip3 install git+https://github.com/shuque/check_zone_dnssec.git@v1.0.0


### Usage

```
$ check_zone_dnssec.py -h
usage: check_zone_dnssec.py [-h] [-v] [--percent_ok N] [-4 | -6] [--bufsize N]
                            [--nsid] [--dsdata DSDATA]
                            [--resolvers IP [IP ...]] [--text] [--timeout N]
                            [--retries N]
                            zone recname rectype

Version 1.0.1
Query all nameserver addresses for a given zone and validate DNSSEC

positional arguments:
  zone                  DNS zone name
  recname               Record name in the zone
  rectype               Record type for that name

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  --percent_ok N        Percentage success threshold (default: 100)
  -4                    Use IPv4 transport only
  -6                    Use IPv6 transport only
  --bufsize N           Set EDNS buffer size in octets (default: 1420)
  --nsid                Send and record NSID EDNS option
  --dsdata DSDATA       Use specified DS rdata string (default: None)
  --resolvers IP [IP ...]
                        Use specified resolver addresses (default: ['8.8.8.8',
                        '1.1.1.1'])
  --text                Emit abbreviated text output (default is json)
  --timeout N           Query timeout in secs (default: 5)
  --retries N           Number of UDP retries (default: 1)
```
