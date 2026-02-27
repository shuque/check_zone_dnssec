#!/usr/bin/env python3

"""
Unit tests for check_zone_dnssec.py

All tests avoid hitting the network — DNS calls are mocked throughout.
"""

import io
import json
import unittest
from unittest.mock import patch, MagicMock, call

import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.rrset
import dns.flags
import dns.message
import dns.resolver
import dns.query
import dns.edns
import dns.exception

from check_zone_dnssec import (
    query_type,
    process_arguments,
    send_query,
    get_resolver,
    get_ds_data_from_dns,
    get_ds_data_from_string,
    get_ns_list,
    get_addresses_for_type,
    get_addresses,
    get_response,
    get_rrset_and_signature,
    ds_rrset_matches_ksk_set,
    ZoneChecker,
    DEFAULT_TIMEOUT,
    DEFAULT_RETRIES,
    DEFAULT_EDNS_BUFSIZE,
    DEFAULT_IP_RRTYPES,
    DEFAULT_NSID,
    DEFAULT_PERCENT_OK,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config(**overrides):
    """Return a MagicMock config with sensible defaults."""
    cfg = MagicMock()
    defaults = dict(
        resolvers=['8.8.8.8'],
        timeout=4,
        bufsize=1420,
        retries=1,
        verbose=0,
        nsid=False,
        percent_ok=100,
        ip_rrtypes=[dns.rdatatype.AAAA, dns.rdatatype.A],
        nonsquery=False,
        nsnames=None,
        nsips=None,
        dsdata=None,
        nxdomain=False,
        nodata=False,
        text=False,
    )
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(cfg, k, v)
    return cfg


def make_checker(config=None, **config_overrides):
    """Build a ZoneChecker with DNS calls mocked out."""
    if config is None:
        config = make_config(**config_overrides)
    zone = dns.name.from_text('example.com.')
    recname = dns.name.from_text('example.com.')
    rectype = dns.rdatatype.SOA
    with patch('check_zone_dnssec.get_ds_data_from_dns') as mock_ds, \
         patch('check_zone_dnssec.get_ns_list') as mock_ns:
        mock_ds.return_value = MagicMock()
        mock_ns.return_value = [
            dns.name.from_text('ns1.example.com.'),
            dns.name.from_text('ns2.example.com.'),
        ]
        checker = ZoneChecker(zone, recname, rectype, config=config)
    return checker


# ===========================================================================
# 1. query_type()
# ===========================================================================

class TestQueryType(unittest.TestCase):

    def test_valid_types(self):
        self.assertEqual(query_type('A'), dns.rdatatype.A)
        self.assertEqual(query_type('AAAA'), dns.rdatatype.AAAA)
        self.assertEqual(query_type('SOA'), dns.rdatatype.SOA)
        self.assertEqual(query_type('MX'), dns.rdatatype.MX)
        self.assertEqual(query_type('NS'), dns.rdatatype.NS)
        self.assertEqual(query_type('TXT'), dns.rdatatype.TXT)

    def test_invalid_type(self):
        with self.assertRaises(ValueError):
            query_type('BOGUS')

    def test_case_insensitive(self):
        self.assertEqual(query_type('a'), dns.rdatatype.A)
        self.assertEqual(query_type('aaaa'), dns.rdatatype.AAAA)


# ===========================================================================
# 2. process_arguments()
# ===========================================================================

class TestProcessArguments(unittest.TestCase):

    def test_positional_args(self):
        args = process_arguments(['example.com', 'www.example.com', 'A'])
        self.assertEqual(args.zone, dns.name.from_text('example.com'))
        self.assertEqual(args.recname, dns.name.from_text('www.example.com'))
        self.assertEqual(args.rectype, dns.rdatatype.A)

    def test_defaults(self):
        args = process_arguments(['example.com', 'example.com', 'SOA'])
        self.assertEqual(args.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(args.retries, DEFAULT_RETRIES)
        self.assertEqual(args.bufsize, DEFAULT_EDNS_BUFSIZE)
        self.assertEqual(args.ip_rrtypes, DEFAULT_IP_RRTYPES)
        self.assertEqual(args.nsid, DEFAULT_NSID)
        self.assertEqual(args.percent_ok, DEFAULT_PERCENT_OK)
        self.assertFalse(args.nxdomain)
        self.assertFalse(args.nodata)
        self.assertFalse(args.text)
        self.assertFalse(args.nonsquery)
        self.assertIsNone(args.nsnames)
        self.assertIsNone(args.nsips)
        self.assertIsNone(args.dsdata)
        self.assertEqual(args.verbose, 0)

    def test_ipv4_only(self):
        args = process_arguments(['example.com', 'example.com', 'SOA', '-4'])
        self.assertEqual(args.ip_rrtypes, [dns.rdatatype.A])

    def test_ipv6_only(self):
        args = process_arguments(['example.com', 'example.com', 'SOA', '-6'])
        self.assertEqual(args.ip_rrtypes, [dns.rdatatype.AAAA])

    def test_nxdomain_flag(self):
        args = process_arguments([
            'example.com', 'nonexist.example.com', 'A', '--nxdomain'])
        self.assertTrue(args.nxdomain)
        self.assertFalse(args.nodata)

    def test_nodata_flag(self):
        args = process_arguments([
            'example.com', 'example.com', 'LOC', '--nodata'])
        self.assertFalse(args.nxdomain)
        self.assertTrue(args.nodata)

    def test_nxdomain_nodata_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            process_arguments([
                'example.com', 'example.com', 'A',
                '--nxdomain', '--nodata'])

    def test_ipv4_ipv6_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            process_arguments(['example.com', 'example.com', 'A', '-4', '-6'])

    def test_optional_flags(self):
        args = process_arguments([
            'example.com', 'example.com', 'SOA',
            '--verbose', '--nsid', '--nonsquery', '--text',
            '--timeout', '10', '--retries', '3', '--bufsize', '4096',
            '--percent_ok', '90',
            '--dsdata', '12345 8 2 AABB',
            '--addnsname', 'ns3.example.com',
            '--addnsip', '192.0.2.99',
            '--resolvers', '9.9.9.9', '1.0.0.1',
        ])
        self.assertEqual(args.verbose, 1)
        self.assertTrue(args.nsid)
        self.assertTrue(args.nonsquery)
        self.assertTrue(args.text)
        self.assertEqual(args.timeout, 10)
        self.assertEqual(args.retries, 3)
        self.assertEqual(args.bufsize, 4096)
        self.assertEqual(args.percent_ok, 90)
        self.assertEqual(args.dsdata, '12345 8 2 AABB')
        self.assertEqual(args.nsnames, 'ns3.example.com')
        self.assertEqual(args.nsips, '192.0.2.99')
        self.assertEqual(args.resolvers, ['9.9.9.9', '1.0.0.1'])


# ===========================================================================
# 3. send_query()
# ===========================================================================

class TestSendQuery(unittest.TestCase):

    def _make_message(self):
        return dns.message.make_query('example.com.', 'A')

    @patch('dns.query.udp')
    def test_success_first_try(self, mock_udp):
        mock_response = MagicMock()
        mock_udp.return_value = mock_response
        response, is_tcp = send_query(self._make_message(), '8.8.8.8',
                                       timeout=4)
        self.assertIs(response, mock_response)
        self.assertFalse(is_tcp)

    @patch('dns.query.udp')
    def test_timeout_then_success(self, mock_udp):
        mock_response = MagicMock()
        mock_udp.side_effect = [dns.exception.Timeout(), mock_response]
        response, is_tcp = send_query(self._make_message(), '8.8.8.8',
                                       timeout=4, retries=1)
        self.assertIs(response, mock_response)
        self.assertFalse(is_tcp)
        self.assertEqual(mock_udp.call_count, 2)

    @patch('dns.query.udp')
    def test_timeout_exhausted(self, mock_udp):
        mock_udp.side_effect = dns.exception.Timeout()
        with self.assertRaises(dns.exception.Timeout):
            send_query(self._make_message(), '8.8.8.8',
                       timeout=4, retries=0)

    @patch('dns.query.udp')
    def test_timeout_exhausted_with_retries(self, mock_udp):
        mock_udp.side_effect = [dns.exception.Timeout(),
                                dns.exception.Timeout()]
        with self.assertRaises(dns.exception.Timeout):
            send_query(self._make_message(), '8.8.8.8',
                       timeout=4, retries=1)
        self.assertEqual(mock_udp.call_count, 2)

    @patch('dns.query.tcp')
    @patch('dns.query.udp')
    def test_truncation_tcp_fallback(self, mock_udp, mock_tcp):
        mock_udp.side_effect = dns.message.Truncated()
        mock_tcp_response = MagicMock()
        mock_tcp.return_value = mock_tcp_response
        response, is_tcp = send_query(self._make_message(), '8.8.8.8',
                                       timeout=4)
        self.assertIs(response, mock_tcp_response)
        self.assertTrue(is_tcp)


# ===========================================================================
# 4. get_resolver()
# ===========================================================================

class TestGetResolver(unittest.TestCase):

    def test_default(self):
        res = get_resolver()
        self.assertEqual(res.lifetime, DEFAULT_TIMEOUT)
        self.assertTrue(res.flags & dns.flags.RD)
        self.assertTrue(res.flags & dns.flags.AD)
        self.assertTrue(res.flags & dns.flags.CD)

    def test_with_addresses(self):
        res = get_resolver(addresses=['9.9.9.9', '1.0.0.1'])
        self.assertEqual(res.nameservers, ['9.9.9.9', '1.0.0.1'])

    def test_with_dnssec_ok(self):
        res = get_resolver(dnssec_ok=True, payload=4096)
        self.assertTrue(res.edns >= 0)
        self.assertTrue(res.ednsflags & dns.flags.DO)
        self.assertEqual(res.payload, 4096)

    def test_custom_timeout(self):
        res = get_resolver(timeout=10)
        self.assertEqual(res.lifetime, 10)


# ===========================================================================
# 5. get_ds_data_from_string()
# ===========================================================================

class TestGetDsDataFromString(unittest.TestCase):

    def test_valid_ds(self):
        zonename = dns.name.from_text('example.com.')
        ds_string = '370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C'
        result = get_ds_data_from_string(zonename, ds_string)
        self.assertIsInstance(result, dns.rrset.RRset)
        self.assertEqual(result.rdtype, dns.rdatatype.DS)
        self.assertEqual(result.name, zonename)

    def test_malformed_ds(self):
        zonename = dns.name.from_text('example.com.')
        with self.assertRaises(ValueError) as ctx:
            get_ds_data_from_string(zonename, 'not-valid-ds-data')
        self.assertIn('badly formatted', str(ctx.exception))


# ===========================================================================
# 6. get_ds_data_from_dns()
# ===========================================================================

class TestGetDsDataFromDns(unittest.TestCase):

    @patch('check_zone_dnssec.resolve_name')
    @patch('check_zone_dnssec.Query')
    def test_secure_answer(self, MockQuery, mock_resolve):
        zone = dns.name.from_text('example.com.')
        mock_query = MockQuery.return_value
        mock_query.is_secure.return_value = True
        mock_rrset = MagicMock()
        mock_entry = MagicMock()
        mock_entry.rrname = zone
        mock_entry.rrtype = dns.rdatatype.DS
        mock_entry.rrset = mock_rrset
        mock_query.full_answer_rrset = [mock_entry]

        result = get_ds_data_from_dns(zone)
        self.assertIs(result, mock_rrset)

    @patch('check_zone_dnssec.resolve_name')
    @patch('check_zone_dnssec.Query')
    def test_insecure_answer(self, MockQuery, mock_resolve):
        zone = dns.name.from_text('example.com.')
        mock_query = MockQuery.return_value
        mock_query.is_secure.return_value = False

        with self.assertRaises(ValueError) as ctx:
            get_ds_data_from_dns(zone)
        self.assertIn('insecure', str(ctx.exception))

    @patch('check_zone_dnssec.resolve_name')
    @patch('check_zone_dnssec.Query')
    def test_ds_not_found(self, MockQuery, mock_resolve):
        zone = dns.name.from_text('example.com.')
        mock_query = MockQuery.return_value
        mock_query.is_secure.return_value = True
        # No matching entry in full_answer_rrset
        other_entry = MagicMock()
        other_entry.rrname = dns.name.from_text('other.com.')
        other_entry.rrtype = dns.rdatatype.DS
        mock_query.full_answer_rrset = [other_entry]

        with self.assertRaises(ValueError) as ctx:
            get_ds_data_from_dns(zone)
        self.assertIn('not found', str(ctx.exception))


# ===========================================================================
# 7. get_ns_list()
# ===========================================================================

class TestGetNsList(unittest.TestCase):

    def test_returns_sorted(self):
        resolver = MagicMock()
        zone = dns.name.from_text('example.com.')

        ns_names = [
            dns.name.from_text('ns2.example.com.'),
            dns.name.from_text('ns1.example.com.'),
            dns.name.from_text('ns3.example.com.'),
        ]
        mock_rrset = MagicMock()
        mock_rrset.to_rdataset.return_value = [
            MagicMock(target=n) for n in ns_names
        ]
        mock_msg = MagicMock()
        mock_msg.get_rrset.return_value = mock_rrset
        resolver.resolve.return_value = MagicMock(response=mock_msg)

        result = get_ns_list(resolver, zone)
        self.assertEqual(len(result), 3)
        # Verify sorted order
        self.assertEqual(result[0], dns.name.from_text('ns1.example.com.'))
        self.assertEqual(result[1], dns.name.from_text('ns2.example.com.'))
        self.assertEqual(result[2], dns.name.from_text('ns3.example.com.'))


# ===========================================================================
# 8. get_addresses_for_type() / get_addresses()
# ===========================================================================

class TestGetAddresses(unittest.TestCase):

    def _mock_resolve_with_addresses(self, resolver, addresses, rrtype):
        """Set up resolver to return addresses for a given type."""
        mock_rrset = MagicMock()
        mock_rrset.to_rdataset.return_value = [
            MagicMock(address=a) for a in addresses
        ]
        mock_msg = MagicMock()
        mock_msg.get_rrset.return_value = mock_rrset
        resolver.resolve.return_value = MagicMock(response=mock_msg)

    def test_direct_answer(self):
        resolver = MagicMock()
        name = dns.name.from_text('ns1.example.com.')
        self._mock_resolve_with_addresses(resolver, ['192.0.2.1'], dns.rdatatype.A)
        result = get_addresses_for_type(resolver, name, dns.rdatatype.A)
        self.assertEqual(result, ['192.0.2.1'])

    def test_no_answer(self):
        resolver = MagicMock()
        name = dns.name.from_text('ns1.example.com.')
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = get_addresses_for_type(resolver, name, dns.rdatatype.AAAA)
        self.assertEqual(result, [])

    def test_cname_chase(self):
        resolver = MagicMock()
        name = dns.name.from_text('alias.example.com.')
        target = dns.name.from_text('real.example.com.')

        # First call: returns CNAME (no A rrset, then CNAME rrset)
        cname_rrset = MagicMock()
        cname_rrset.to_rdataset.return_value = [MagicMock(target=target)]
        mock_msg_cname = MagicMock()
        mock_msg_cname.get_rrset.side_effect = [None, cname_rrset]

        # Second call: returns A record
        a_rrset = MagicMock()
        a_rrset.to_rdataset.return_value = [MagicMock(address='192.0.2.10')]
        mock_msg_a = MagicMock()
        mock_msg_a.get_rrset.return_value = a_rrset

        resolver.resolve.side_effect = [
            MagicMock(response=mock_msg_cname),
            MagicMock(response=mock_msg_a),
        ]

        result = get_addresses_for_type(resolver, name, dns.rdatatype.A)
        self.assertEqual(result, ['192.0.2.10'])

    def test_get_addresses_both_rrtypes(self):
        resolver = MagicMock()
        name = dns.name.from_text('ns1.example.com.')

        # AAAA response
        aaaa_rrset = MagicMock()
        aaaa_rrset.to_rdataset.return_value = [MagicMock(address='2001:db8::1')]
        mock_msg_aaaa = MagicMock()
        mock_msg_aaaa.get_rrset.return_value = aaaa_rrset

        # A response
        a_rrset = MagicMock()
        a_rrset.to_rdataset.return_value = [MagicMock(address='192.0.2.1')]
        mock_msg_a = MagicMock()
        mock_msg_a.get_rrset.return_value = a_rrset

        resolver.resolve.side_effect = [
            MagicMock(response=mock_msg_aaaa),
            MagicMock(response=mock_msg_a),
        ]

        result = get_addresses(resolver, name,
                               [dns.rdatatype.AAAA, dns.rdatatype.A])
        self.assertEqual(len(result), 2)
        self.assertIn('2001:db8::1', result)
        self.assertIn('192.0.2.1', result)


# ===========================================================================
# 9. get_response()
# ===========================================================================

class TestGetResponse(unittest.TestCase):

    @patch('check_zone_dnssec.send_query')
    def test_success(self, mock_send):
        mock_resp = MagicMock()
        mock_send.return_value = (mock_resp, False)
        response, err = get_response('example.com.', dns.rdatatype.A, '8.8.8.8')
        self.assertIs(response, mock_resp)
        self.assertIsNone(err)

    @patch('check_zone_dnssec.send_query')
    def test_timeout(self, mock_send):
        mock_send.side_effect = dns.exception.Timeout()
        response, err = get_response('example.com.', dns.rdatatype.A, '8.8.8.8')
        self.assertIsNone(response)
        self.assertEqual(err, "query timed out")

    @patch('check_zone_dnssec.send_query')
    def test_nsid_option_included(self, mock_send):
        mock_send.return_value = (MagicMock(), False)
        get_response('example.com.', dns.rdatatype.A, '8.8.8.8', nsid=True)
        # Inspect the message passed to send_query
        msg = mock_send.call_args[0][0]
        nsid_options = [o for o in msg.options if o.otype == dns.edns.NSID]
        self.assertEqual(len(nsid_options), 1)

    @patch('check_zone_dnssec.send_query')
    def test_nsid_option_absent(self, mock_send):
        mock_send.return_value = (MagicMock(), False)
        get_response('example.com.', dns.rdatatype.A, '8.8.8.8', nsid=False)
        msg = mock_send.call_args[0][0]
        nsid_options = [o for o in msg.options if o.otype == dns.edns.NSID]
        self.assertEqual(len(nsid_options), 0)


# ===========================================================================
# 10. get_rrset_and_signature()
# ===========================================================================

class TestGetRrsetAndSignature(unittest.TestCase):

    def test_both_present(self):
        mock_rrset = MagicMock()
        mock_sig = MagicMock()
        msg = MagicMock()
        msg.get_rrset.side_effect = [mock_rrset, mock_sig]
        rrset, sig = get_rrset_and_signature(
            msg, dns.name.from_text('example.com.'), dns.rdatatype.A)
        self.assertIs(rrset, mock_rrset)
        self.assertIs(sig, mock_sig)

    def test_rrset_only_no_sig(self):
        mock_rrset = MagicMock()
        msg = MagicMock()
        msg.get_rrset.side_effect = [mock_rrset, None]
        rrset, sig = get_rrset_and_signature(
            msg, dns.name.from_text('example.com.'), dns.rdatatype.A)
        self.assertIs(rrset, mock_rrset)
        self.assertIsNone(sig)

    def test_empty_answer(self):
        msg = MagicMock()
        msg.get_rrset.return_value = None
        rrset, sig = get_rrset_and_signature(
            msg, dns.name.from_text('example.com.'), dns.rdatatype.A)
        self.assertIsNone(rrset)
        self.assertIsNone(sig)


# ===========================================================================
# 11. ds_rrset_matches_ksk_set()
# ===========================================================================

class TestDsRrsetMatchesKskSet(unittest.TestCase):

    @patch('check_zone_dnssec.ds_rr_matches_dnskey')
    def test_matching_pair(self, mock_match):
        mock_match.return_value = True
        ds_rdata = MagicMock()
        ksk = MagicMock(zone_flag=True)
        result = ds_rrset_matches_ksk_set([ds_rdata], [ksk])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], [str(ds_rdata), str(ksk)])

    @patch('check_zone_dnssec.ds_rr_matches_dnskey')
    def test_no_match(self, mock_match):
        mock_match.return_value = False
        ds_rdata = MagicMock()
        ksk = MagicMock(zone_flag=True)
        result = ds_rrset_matches_ksk_set([ds_rdata], [ksk])
        self.assertEqual(result, [])

    @patch('check_zone_dnssec.ds_rr_matches_dnskey')
    def test_non_zone_key_skipped(self, mock_match):
        """Keys without zone_flag set should never match."""
        mock_match.return_value = True
        ds_rdata = MagicMock()
        ksk = MagicMock(zone_flag=False)
        result = ds_rrset_matches_ksk_set([ds_rdata], [ksk])
        self.assertEqual(result, [])
        mock_match.assert_not_called()


# ===========================================================================
# 12. ZoneChecker — initialization
# ===========================================================================

class TestZoneCheckerInit(unittest.TestCase):

    def test_basic_init(self):
        checker = make_checker()
        self.assertEqual(checker.name, dns.name.from_text('example.com.'))
        self.assertEqual(checker.result['zone'], 'example.com.')
        self.assertEqual(checker.result['recname'], 'example.com.')
        self.assertEqual(checker.result['rectype'], 'SOA')
        self.assertFalse(checker.result['success'])
        self.assertEqual(checker.result['server_count_total'], 0)
        self.assertEqual(checker.result['server_count_good'], 0)
        self.assertEqual(checker.result['servers'], [])

    @patch('check_zone_dnssec.get_ds_data_from_string')
    @patch('check_zone_dnssec.get_ds_data_from_dns')
    @patch('check_zone_dnssec.get_ns_list')
    def test_dsdata_from_string(self, mock_ns, mock_ds_dns, mock_ds_str):
        mock_ns.return_value = []
        mock_ds_str.return_value = MagicMock()
        config = make_config(dsdata='370 13 2 AABB')
        zone = dns.name.from_text('example.com.')
        ZoneChecker(zone, zone, dns.rdatatype.SOA, config=config)
        mock_ds_str.assert_called_once()
        mock_ds_dns.assert_not_called()

    @patch('check_zone_dnssec.get_ds_data_from_dns')
    @patch('check_zone_dnssec.get_ns_list')
    def test_dsdata_from_dns(self, mock_ns, mock_ds_dns):
        mock_ns.return_value = []
        mock_ds_dns.return_value = MagicMock()
        config = make_config(dsdata=None)
        zone = dns.name.from_text('example.com.')
        ZoneChecker(zone, zone, dns.rdatatype.SOA, config=config)
        mock_ds_dns.assert_called_once()

    @patch('check_zone_dnssec.get_ds_data_from_dns')
    @patch('check_zone_dnssec.get_ns_list')
    def test_additional_nsnames(self, mock_ns, mock_ds):
        mock_ns.return_value = [dns.name.from_text('ns1.example.com.')]
        mock_ds.return_value = MagicMock()
        config = make_config(nsnames='ns3.example.com,ns4.example.com')
        zone = dns.name.from_text('example.com.')
        checker = ZoneChecker(zone, zone, dns.rdatatype.SOA, config=config)
        names = [n.to_text() for n in checker.nslist]
        self.assertIn('ns3.example.com.', names)
        self.assertIn('ns4.example.com.', names)

    @patch('check_zone_dnssec.get_ds_data_from_dns')
    @patch('check_zone_dnssec.get_ns_list')
    def test_additional_ips(self, mock_ns, mock_ds):
        mock_ns.return_value = []
        mock_ds.return_value = MagicMock()
        config = make_config(nsips='192.0.2.50,192.0.2.51')
        zone = dns.name.from_text('example.com.')
        checker = ZoneChecker(zone, zone, dns.rdatatype.SOA, config=config)
        self.assertEqual(checker.iplist, ['192.0.2.50', '192.0.2.51'])

    @patch('check_zone_dnssec.get_ds_data_from_dns')
    @patch('check_zone_dnssec.get_ns_list')
    def test_nonsquery_skips_ns_lookup(self, mock_ns, mock_ds):
        mock_ds.return_value = MagicMock()
        config = make_config(nonsquery=True)
        zone = dns.name.from_text('example.com.')
        checker = ZoneChecker(zone, zone, dns.rdatatype.SOA, config=config)
        mock_ns.assert_not_called()
        self.assertEqual(checker.nslist, [])

    def test_instances_have_independent_state(self):
        """Verify no shared mutable state between instances."""
        c1 = make_checker()
        c2 = make_checker()
        c1.result['servers'].append({'test': True})
        self.assertEqual(len(c2.result['servers']), 0)
        c1.nslist.append('extra')
        self.assertNotIn('extra', c2.nslist)


# ===========================================================================
# 13. ZoneChecker.check_record() — dispatch logic
# ===========================================================================

class TestZoneCheckerCheckRecord(unittest.TestCase):

    def _make_msg(self, rcode_val=dns.rcode.NOERROR):
        msg = MagicMock()
        msg.rcode.return_value = rcode_val
        return msg

    @patch('check_zone_dnssec.get_response')
    def test_unexpected_rcode_with_nxdomain(self, mock_get):
        """nxdomain expected but got NOERROR."""
        checker = make_checker(nxdomain=True)
        mock_get.return_value = (self._make_msg(dns.rcode.NOERROR), None)
        entry = {'ip': '192.0.2.1'}
        checker.check_record(entry)
        self.assertFalse(entry['dnssec'])
        self.assertIn('Unexpected rcode', entry['error'])

    @patch('check_zone_dnssec.get_response')
    def test_unexpected_rcode_servfail(self, mock_get):
        """NOERROR expected but got SERVFAIL."""
        checker = make_checker(nxdomain=False)
        mock_get.return_value = (self._make_msg(dns.rcode.SERVFAIL), None)
        entry = {'ip': '192.0.2.1'}
        checker.check_record(entry)
        self.assertFalse(entry['dnssec'])
        self.assertIn('Unexpected rcode', entry['error'])

    @patch('check_zone_dnssec.get_response')
    def test_dispatches_to_nxdomain(self, mock_get):
        checker = make_checker(nxdomain=True)
        mock_get.return_value = (self._make_msg(dns.rcode.NXDOMAIN), None)
        entry = {'ip': '192.0.2.1'}
        with patch.object(checker, 'check_record_nxdomain') as mock_nx:
            checker.check_record(entry)
            mock_nx.assert_called_once()

    @patch('check_zone_dnssec.get_response')
    def test_dispatches_to_nodata(self, mock_get):
        checker = make_checker(nodata=True)
        mock_get.return_value = (self._make_msg(dns.rcode.NOERROR), None)
        entry = {'ip': '192.0.2.1'}
        with patch.object(checker, 'check_record_nodata') as mock_nd:
            checker.check_record(entry)
            mock_nd.assert_called_once()

    @patch('check_zone_dnssec.get_response')
    def test_dispatches_to_noerror(self, mock_get):
        checker = make_checker()
        mock_get.return_value = (self._make_msg(dns.rcode.NOERROR), None)
        entry = {'ip': '192.0.2.1'}
        with patch.object(checker, 'check_record_noerror') as mock_ne:
            checker.check_record(entry)
            mock_ne.assert_called_once()


# ===========================================================================
# 14. ZoneChecker.check_record_noerror()
# ===========================================================================

class TestZoneCheckerCheckRecordNoerror(unittest.TestCase):

    @patch('check_zone_dnssec.validate_all')
    @patch('check_zone_dnssec.get_rrset_and_signature')
    def test_valid_signed_record(self, mock_get_rr, mock_validate):
        checker = make_checker()
        mock_rrset = MagicMock()
        mock_sig = MagicMock()
        mock_get_rr.return_value = (mock_rrset, mock_sig)
        mock_validate.return_value = (['signer1'], [])
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_noerror(entry, msg)
        self.assertTrue(entry['dnssec'])
        self.assertEqual(checker.result['server_count_good'], 1)

    @patch('check_zone_dnssec.get_rrset_and_signature')
    def test_missing_record(self, mock_get_rr):
        checker = make_checker()
        mock_get_rr.return_value = (None, MagicMock())
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_noerror(entry, msg)
        self.assertFalse(entry['dnssec'])
        self.assertIn('Non existent record', entry['error'])

    @patch('check_zone_dnssec.get_rrset_and_signature')
    def test_missing_signature(self, mock_get_rr):
        checker = make_checker()
        mock_get_rr.return_value = (MagicMock(), None)
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_noerror(entry, msg)
        self.assertFalse(entry['dnssec'])
        self.assertIn('Missing record signature', entry['error'])

    @patch('check_zone_dnssec.validate_all')
    @patch('check_zone_dnssec.get_rrset_and_signature')
    def test_invalid_signature(self, mock_get_rr, mock_validate):
        checker = make_checker()
        mock_get_rr.return_value = (MagicMock(), MagicMock())
        mock_validate.return_value = ([], ['failed_sig'])
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_noerror(entry, msg)
        self.assertFalse(entry['dnssec'])
        self.assertIn('No valid record signatures', entry['error'])
        self.assertEqual(checker.result['server_count_good'], 0)

    @patch('check_zone_dnssec.validate_all')
    @patch('check_zone_dnssec.get_rrset_and_signature')
    def test_validate_raises(self, mock_get_rr, mock_validate):
        from reslib.exception import ResError
        checker = make_checker()
        mock_get_rr.return_value = (MagicMock(), MagicMock())
        mock_validate.side_effect = ResError("crypto error")
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_noerror(entry, msg)
        self.assertFalse(entry['dnssec'])
        self.assertIn('crypto error', entry['error'])

    @patch('check_zone_dnssec.validate_all')
    @patch('check_zone_dnssec.get_rrset_and_signature')
    def test_verbose_output(self, mock_get_rr, mock_validate):
        checker = make_checker(verbose=1)
        mock_rrset = MagicMock()
        mock_rrset.__iter__ = MagicMock(return_value=iter([MagicMock()]))
        mock_sig = MagicMock()
        mock_sig.__iter__ = MagicMock(return_value=iter([MagicMock()]))
        mock_get_rr.return_value = (mock_rrset, mock_sig)
        mock_validate.return_value = ([MagicMock()], [])
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_noerror(entry, msg)
        self.assertTrue(entry['dnssec'])
        self.assertIn('record', entry)
        self.assertIn('rdataset', entry['record'])
        self.assertIn('sigs', entry['record'])
        self.assertIn('signer', entry['record'])


# ===========================================================================
# 14b. ZoneChecker.check_record_nxdomain() / check_record_nodata()
# ===========================================================================

class TestZoneCheckerCheckRecordNxdomainNodata(unittest.TestCase):

    @patch('check_zone_dnssec.authenticate_nxdomain')
    def test_nxdomain_secure(self, mock_auth):
        checker = make_checker(nxdomain=True)
        checker.query = MagicMock()
        checker.query.is_secure.return_value = True
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_nxdomain(entry, msg)
        self.assertTrue(entry['dnssec'])
        self.assertEqual(checker.result['server_count_good'], 1)

    @patch('check_zone_dnssec.authenticate_nxdomain')
    def test_nxdomain_insecure(self, mock_auth):
        checker = make_checker(nxdomain=True)
        checker.query = MagicMock()
        checker.query.is_secure.return_value = False
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_nxdomain(entry, msg)
        self.assertFalse(entry['dnssec'])
        self.assertEqual(checker.result['server_count_good'], 0)

    @patch('check_zone_dnssec.authenticate_nodata')
    def test_nodata_secure(self, mock_auth):
        checker = make_checker(nodata=True)
        checker.query = MagicMock()
        checker.query.is_secure.return_value = True
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_nodata(entry, msg)
        self.assertTrue(entry['dnssec'])
        self.assertEqual(checker.result['server_count_good'], 1)

    @patch('check_zone_dnssec.authenticate_nodata')
    def test_nodata_insecure(self, mock_auth):
        checker = make_checker(nodata=True)
        checker.query = MagicMock()
        checker.query.is_secure.return_value = False
        msg = MagicMock()
        entry = {'ip': '192.0.2.1'}
        checker.check_record_nodata(entry, msg)
        self.assertFalse(entry['dnssec'])
        self.assertEqual(checker.result['server_count_good'], 0)


# ===========================================================================
# 15. ZoneChecker.return_status() / print_status()
# ===========================================================================

class TestZoneCheckerStatus(unittest.TestCase):

    def test_full_success(self):
        checker = make_checker()
        checker.result['server_count_total'] = 4
        checker.result['server_count_good'] = 4
        output = json.loads(checker.return_status())
        self.assertTrue(output['success'])
        self.assertEqual(output['server_good_percent'], '100.00')

    def test_partial_failure_below_threshold(self):
        checker = make_checker(percent_ok=100)
        checker.result['server_count_total'] = 4
        checker.result['server_count_good'] = 3
        output = json.loads(checker.return_status())
        self.assertFalse(output['success'])
        self.assertEqual(output['server_good_percent'], '75.00')

    def test_partial_success_custom_threshold(self):
        checker = make_checker(percent_ok=50)
        checker.result['server_count_total'] = 4
        checker.result['server_count_good'] = 2
        output = json.loads(checker.return_status())
        self.assertTrue(output['success'])
        self.assertEqual(output['server_good_percent'], '50.00')

    def test_zero_percent(self):
        checker = make_checker()
        checker.result['server_count_total'] = 3
        checker.result['server_count_good'] = 0
        output = json.loads(checker.return_status())
        self.assertFalse(output['success'])
        self.assertEqual(output['server_good_percent'], '0.00')

    def test_print_status_json(self):
        checker = make_checker()
        checker.result['server_count_total'] = 1
        checker.result['server_count_good'] = 1
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            checker.print_status()
            output = json.loads(mock_out.getvalue())
        self.assertTrue(output['success'])

    def test_print_status_text_success(self):
        checker = make_checker(text=True)
        checker.result['server_count_total'] = 1
        checker.result['server_count_good'] = 1
        checker.result['servers'] = [
            {'nsname': 'ns1.example.com.', 'ip': '192.0.2.1', 'dnssec': True}
        ]
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            checker.print_status()
            line = mock_out.getvalue().strip()
        self.assertTrue(line.startswith('DNSSEC SUCCESS'))
        self.assertIn('ns1.example.com.', line)

    def test_print_status_text_failure(self):
        checker = make_checker(text=True)
        checker.result['server_count_total'] = 1
        checker.result['server_count_good'] = 0
        checker.result['servers'] = [
            {'nsname': 'ns1.example.com.', 'ip': '192.0.2.1',
             'dnssec': False, 'error': 'some error'}
        ]
        with patch('sys.stdout', new_callable=io.StringIO) as mock_out:
            checker.print_status()
            line = mock_out.getvalue().strip()
        self.assertTrue(line.startswith('DNSSEC FAILED'))
        self.assertIn('some error', line)


if __name__ == '__main__':
    unittest.main()
