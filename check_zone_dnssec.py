#!/usr/bin/env python3
#

"""
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

"""

import sys
import argparse
import time
import json
import dns.name
import dns.resolver
import dns.message
import dns.query
import dns.edns
import dns.exception

from reslib.prefs import Prefs
from reslib.cache import RootZone
from reslib.query import Query
from reslib.exception import ResError
from reslib.dnssec import check_self_signature, ds_rr_matches_dnskey
from reslib.dnssec import key_cache, load_keys, validate_all
from reslib.lookup import initialize_dnssec, resolve_name


__version__ = "1.0.0"
__description__ = f"""\
Version {__version__}
Query all nameserver addresses for a given zone and validate DNSSEC"""

DEFAULT_TIMEOUT = 4
DEFAULT_RETRIES = 1
DEFAULT_EDNS_BUFSIZE = 1420
DEFAULT_IP_RRTYPES = [dns.rdatatype.AAAA, dns.rdatatype.A]
DEFAULT_PERCENT_OK = 100


# We default to some public validating DNS resolvers for looking up the NS names
# and addresses. Ideally, you should only talk to resolver that you have a secured
# channel to, but since DNSSEC does not really depend on the security of nameserver
# names and addresses, this is okay.
RESOLVER_LIST = ['8.8.8.8', '1.1.1.1']

def query_type(qtype):
    """Check qtype argument value is well formed"""
    try:
        dns.rdatatype.from_text(qtype)
    except Exception as catchall_except:
        raise ValueError(f"invalid query type: {qtype}") from catchall_except
    return qtype.upper()


def process_arguments(arguments=None):
    """Process command line arguments"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__description__,
        allow_abbrev=False)
    parser.add_argument("zone", help="DNS zone name")
    parser.add_argument("recname", help="Record name in the zone")
    parser.add_argument("rectype", help="Record type for that name")

    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase output verbosity")
    parser.add_argument("--percent_ok", type=int, metavar='N',
                        default=DEFAULT_PERCENT_OK,
                        help="Percentage success threshold (default: %(default)d)")
    ip_rrtypes = parser.add_mutually_exclusive_group()
    ip_rrtypes.add_argument("-4", dest='ip_rrtypes',
                            action='store_const', const=[dns.rdatatype.A],
                            default=DEFAULT_IP_RRTYPES,
                            help="Query IPv4 nameserver addresses only")
    ip_rrtypes.add_argument("-6", dest='ip_rrtypes',
                            action='store_const', const=[dns.rdatatype.AAAA],
                            default=DEFAULT_IP_RRTYPES,
                            help="Query IPv6 nameserver addresses only")
    parser.add_argument("--bufsize", type=int, metavar='N',
                        default=DEFAULT_EDNS_BUFSIZE,
                        help="Set EDNS buffer size in octets (default: %(default)d)")
    parser.add_argument("--nsid", dest='nsid', action='store_true',
                        help="Send and record NSID EDNS option")
    parser.add_argument("--dsdata",
                        default=None,
                        help="Use specified DS rdata string (default: %(default)s)")
    parser.add_argument("--resolvers",
                        default=RESOLVER_LIST, metavar="IP", nargs='+',
                        help="Use specified resolver addresses (default: %(default)s)")
    parser.add_argument("--text", dest='text', action='store_true',
                        help="Emit abbreviated text output (default is json)")
    parser.add_argument("--timeout", type=int, metavar='N',
                        default=DEFAULT_TIMEOUT,
                        help="Query timeout in secs (default: %(default)d)")
    parser.add_argument("--retries", type=int, metavar='N',
                        default=DEFAULT_RETRIES,
                        help="Number of UDP retries (default: %(default)d)")

    if arguments is not None:
        return parser.parse_args(args=arguments)
    return parser.parse_args()


def send_query(
    message,
    where,
    timeout = None,
    retries = 0,
    port = 53,
    source = None,
    source_port = 0,
):
    """Send UDP DNS query with retries and TCP fallback."""

    while True:
        try:
            response = dns.query.udp(
                message,
                where,
                timeout,
                port,
                source,
                source_port,
                ignore_unexpected=True,
                raise_on_truncation=True,
            )
        except dns.exception.Timeout as timed_out:
            if retries > 0:
                retries -= 1
                continue
            raise dns.exception.Timeout from timed_out
        except dns.message.Truncated:
            response = dns.query.tcp(
                message,
                where,
                timeout,
                port,
                source,
                source_port,
            )
            return (response, True)
        else:
            return (response, False)


def get_resolver(addresses=None, dnssec_ok=False, timeout=DEFAULT_TIMEOUT):
    """return an appropriately configured Resolver object"""

    res = dns.resolver.Resolver()
    res.set_flags(dns.flags.RD | dns.flags.AD | dns.flags.CD)
    res.lifetime = timeout
    if dnssec_ok:
        res.use_edns(edns=0, ednsflags=dns.flags.DO, payload=CONFIG.payload)
    if addresses is not None:
        res.nameservers = addresses
    return res


def get_ds_data_from_dns(zone):
    """
    Get secured DS recordset data from the DNS. Returns a dns.rrset.RRset class.
    """

    query = Query(zone, 'DS', 'IN')
    resolve_name(query, RootZone, addResults=query)
    if not query.is_secure():
        raise ValueError(f'{zone}/DS returned insecure answer')
    for entry in query.full_answer_rrset:
        if entry.rrname == zone and entry.rrtype == dns.rdatatype.DS:
            return entry.rrset
    raise ValueError(f'{zone}/DS not found')


def get_ds_data_from_string(zonename, ds_string):
    """
    Get DS data from a textual rdata string. Returns a dns.rrset.RRset class.
    """

    try:
        ds_data = dns.rrset.from_text(zonename,
                                      86400,
                                      dns.rdataclass.IN,
                                      dns.rdatatype.DS,
                                      ds_string)
    except dns.exception.DNSException as bad_ds_data:
        raise ValueError("badly formatted DS data") from bad_ds_data
    return ds_data


def get_ns_list(resolver, zone):
    """Query and return list of nameservers for given zone"""

    msg = resolver.resolve(zone, dns.rdatatype.NS).response
    rrset = msg.get_rrset(msg.answer, zone, dns.rdataclass.IN, dns.rdatatype.NS)
    ns_list = [x.target for x in rrset.to_rdataset()]
    return sorted(ns_list)

def get_addresses(resolver, name, ip_rrtypes):
    """Get list of addresses for given domain name"""

    address_list = []
    for rrtype in ip_rrtypes:
        msg = resolver.resolve(name, rrtype).response
        rrset = msg.get_rrset(msg.answer, name, dns.rdataclass.IN, rrtype)
        for entry in rrset.to_rdataset():
            address_list.append(entry.address)
    return address_list


def get_response(rrname, rrtype, address):
    """
    Query RRset at given address and return DNS response message and \
    possibly an error (e.g. a timeout).
    """

    options = []
    if CONFIG.nsid:
        options.append(dns.edns.GenericOption(dns.edns.NSID, b''))
    msg = dns.message.make_query(rrname, rrtype, dns.rdataclass.IN,
                                 use_edns=True, want_dnssec=True,
                                 options=options, payload=CONFIG.bufsize)
    try:
        response, _ = send_query(msg, address,
                                 timeout=CONFIG.timeout,
                                 retries=CONFIG.retries)
    except dns.exception.Timeout:
        return None, "query timed out"
    return response, None


def get_rrset_and_signature(message, rrname, rrtype):
    """Get RRset and signature for name and type from DNS message"""

    rrset = message.get_rrset(message.answer,
                              rrname, dns.rdataclass.IN, rrtype)
    rrsig = message.get_rrset(message.answer,
                              rrname, dns.rdataclass.IN, dns.rdatatype.RRSIG,
                               covers=rrtype)
    return rrset, rrsig


def ds_rrset_matches_ksk_set(ds_set, ksk_set):
    """Return list of DS record and matching DNSKEY pairs"""

    match_list = []
    for ds_rdata in ds_set:
        for key in ksk_set:
            if key.zone_flag and ds_rr_matches_dnskey(ds_rdata, key):
                match_list.append([str(ds_rdata), str(key)])
    return match_list


class ZoneChecker:
    """Zone class"""

    result = {}              # result dictionary
    nslist = None            # list of nameserver names

    def __init__(self, zonename, recname, rectype, dsdata=None):
        self.name = zonename
        self.recname = recname
        self.rectype = rectype
        self.resolver = get_resolver(addresses=CONFIG.resolvers, dnssec_ok=False)
        if dsdata:
            self.dsdata = get_ds_data_from_string(zonename, dsdata)
        else:
            self.dsdata = get_ds_data_from_dns(self.name)
        self.get_nameservers()
        self.timestamp = None
        self.init_result()

    def init_result(self):
        """Initialize result dictionary"""
        self.result['zone'] = self.name.to_text()
        self.result['recname'] = self.recname.to_text()
        self.result['rectype'] = dns.rdatatype.to_text(self.rectype)
        self.result['timestamp'] = None
        self.result['success'] = False
        if CONFIG.verbose:
            self.result['dsdata'] = [str(x) for x in self.dsdata]
        self.result['server_count_total'] = 0
        self.result['server_count_good'] = 0
        self.result['server_good_percent'] = 0
        self.result['servers'] = []

    def get_nameservers(self):
        """Obtain nameserver list"""
        self.nslist = get_ns_list(self.resolver, self.name)

    def check_nameservers(self):
        """Check nameservers"""
        self.result['timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%S%Z", time.gmtime(time.time()))
        for nsname in self.nslist:
            alist = get_addresses(self.resolver, nsname, CONFIG.ip_rrtypes)
            for nsaddress in alist:
                self.result['server_count_total'] += 1
                entry = {}
                entry['nsname'] = nsname.to_text()
                entry['ip'] = nsaddress
                if not self.check_dnskey(entry):
                    self.result['servers'].append(entry)
                    continue
                self.check_record(entry)
                self.result['servers'].append(entry)

    def check_dnskey(self, entry):
        """Check DNSKEY at a single nameserver address"""
        msg, err = get_response(self.name, dns.rdatatype.DNSKEY, entry['ip'])
        if err:
            entry['dnssec'] = False
            entry['error'] = err
            return False

        dnskey_set, dnskey_sig = get_rrset_and_signature(msg,
                                                         self.name,
                                                         dns.rdatatype.DNSKEY)
        if CONFIG.nsid:
            for option in msg.options:
                if option.otype == dns.edns.NSID:
                    entry['nsid'] = option.nsid.decode()

        if not dnskey_set:
            entry['dnssec'] = False
            entry['error'] = "Non existent DNSKEY RRset"
            return False
        if not dnskey_sig:
            entry['dnssec'] = False
            entry['error'] = "Missing DNSKEY signature"
            return False
        try:
            keylist, ksklist = check_self_signature(dnskey_set, dnskey_sig)
            if CONFIG.verbose:
                entry['dnskey'] = [str(x) for x in keylist]
                entry['ksk'] = [str(x) for x in ksklist]
        except ResError as err:
            entry['dnssec'] = False
            entry['error'] = str(err)
            return False
        ds_match_list = ds_rrset_matches_ksk_set(self.dsdata, ksklist)
        if not ds_match_list:
            entry['dnssec'] = False
            entry['error'] = "DS did not match any DNSKEY"
            return False
        if CONFIG.verbose:
            entry['dsmatch'] = ds_match_list
        key_cache.install(self.name, load_keys(dnskey_set)[0])
        return True

    def check_record(self, entry):
        """Check data record at single nameserver address"""
        msg, err = get_response(self.recname, self.rectype, entry['ip'])
        if err:
            entry['dnssec'] = False
            entry['error'] = err
            return
        rec_set, rec_sig = get_rrset_and_signature(msg, self.recname, self.rectype)
        if not rec_set:
            entry['dnssec'] = False
            entry['error'] = "Non existent record"
            return
        if CONFIG.verbose:
            entry['record'] = {}
            entry['record']['rdataset'] = [str(x) for x in rec_set]
        if not rec_sig:
            entry['dnssec'] = False
            entry['error'] = "Missing record signature"
            return
        if CONFIG.verbose:
            entry['record']['sigs'] = [str(x) for x in rec_sig]
        try:
            verified, failed = validate_all(rec_set, rec_sig)
        except ResError as err:
            entry['dnssec'] = False
            entry['error'] = str(err)
            return
        if not verified:
            entry['dnssec'] = False
            entry['error'] = "No valid record signatures found: " + str(failed)
        else:
            entry['dnssec'] = True
            self.result['server_count_good'] += 1
            if CONFIG.verbose:
                entry['record']['signer'] = [str(x) for x in verified]

    def return_status(self):
        """Return status as a JSON string"""
        percent = 100.0 * self.result['server_count_good'] / self.result['server_count_total']
        self.result['server_good_percent'] = "{:.2f}".format(percent)
        if percent >= CONFIG.percent_ok:
            self.result["success"] = True
        return json.dumps(self.result, indent=2)

    def print_status(self):
        """Print Status"""
        if CONFIG.text:
            for entry in self.result['servers']:
                prefix = "DNSSEC SUCCESS" if entry['dnssec'] else "DNSSEC FAILED"
                print(prefix, entry['nsname'], entry['ip'],
                      entry['error'] if 'error' in entry else "")
        else:
            print(self.return_status())


if __name__ == '__main__':

    CONFIG = process_arguments()
    ZONENAME = dns.name.from_text(CONFIG.zone)
    RECNAME = dns.name.from_text(CONFIG.recname)
    RECTYPE = dns.rdatatype.from_text(CONFIG.rectype)

    Prefs.DNSSEC = True
    initialize_dnssec()

    CHECKER = ZoneChecker(ZONENAME, RECNAME, RECTYPE, dsdata=CONFIG.dsdata)
    CHECKER.check_nameservers()
    CHECKER.print_status()
    if CHECKER.result['success']:
        sys.exit(0)
    sys.exit(1)
