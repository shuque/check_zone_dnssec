# Unit Test Plan for check_zone_dnssec.py

All tests avoid hitting the network — DNS calls are mocked throughout.

## 1. `query_type()`
- **Valid type**: `"A"`, `"AAAA"`, `"SOA"`, `"MX"` — returns the correct `dns.rdatatype` integer.
- **Invalid type**: `"BOGUS"` — raises `ValueError`.

## 2. `process_arguments()`
- **Positional args**: Verify `zone`, `recname`, `rectype` are parsed into the correct types (`dns.name.Name`, rdatatype int).
- **Defaults**: Verify default values for `timeout`, `retries`, `bufsize`, `ip_rrtypes`, `nsid`, `percent_ok`, `nxdomain`, `nodata`, `text`.
- **`-4` / `-6` mutual exclusion**: Verify each sets the correct `ip_rrtypes`.
- **`--nxdomain` / `--nodata` mutual exclusion**: Verify each sets its flag, and both together are rejected.
- **Optional flags**: `--verbose`, `--nsid`, `--nonsquery`, `--text`, `--dsdata`, `--addnsname`, `--addnsip`, `--resolvers`.

## 3. `send_query()`
- **Success on first try**: Mock `dns.query.udp` to return a response; verify `(response, False)`.
- **Timeout then success (retry)**: First `udp` call raises `Timeout`, second succeeds; verify retry works.
- **Timeout exhausted**: All `udp` calls raise `Timeout`; verify `Timeout` is raised after retries are spent.
- **Truncation → TCP fallback**: `udp` raises `Truncated`; mock `dns.query.tcp` to return response; verify `(response, True)`.

## 4. `get_resolver()`
- **Default**: Returns resolver with RD+AD+CD flags, correct lifetime.
- **With addresses**: `nameservers` is set to the provided list.
- **With `dnssec_ok=True`**: EDNS is enabled with DO flag and the specified payload.

## 5. `get_ds_data_from_string()`
- **Valid DS rdata**: Returns an `RRset` of the correct type and content.
- **Malformed DS rdata**: Raises `ValueError`.

## 6. `get_ds_data_from_dns()`
- **Secure answer**: Mock `resolve_name` to populate a secure query with a DS entry; verify the RRset is returned.
- **Insecure answer**: Mock an insecure response; verify `ValueError("insecure answer")`.
- **DS not found**: Mock a secure response with no DS in the answer; verify `ValueError("not found")`.

## 7. `get_ns_list()`
- Mock `resolver.resolve()` to return a message with an NS RRset containing several names; verify the returned list is sorted.

## 8. `get_addresses_for_type()` / `get_addresses()`
- **Direct A/AAAA answer**: Mock resolve to return addresses; verify the list.
- **CNAME chase**: First resolve returns a CNAME, second returns an A record; verify the final address.
- **NoAnswer**: Mock `dns.resolver.NoAnswer`; verify empty list returned.
- **`get_addresses()` with both rrtypes**: Verify AAAA and A results are combined.

## 9. `get_response()`
- **Success**: Mock `send_query` to return a response; verify `(response, None)`.
- **Timeout**: Mock `send_query` to raise `Timeout`; verify `(None, "query timed out")`.
- **NSID option**: Verify the outgoing message includes the NSID option when `nsid=True`.

## 10. `get_rrset_and_signature()`
- Construct a `dns.message.Message` with an answer section containing both an RRset and its RRSIG; verify both are extracted.
- Message with RRset but no RRSIG; verify `rrsig` is `None`.
- Empty answer section; verify both are `None`.

## 11. `ds_rrset_matches_ksk_set()`
- **Matching pair**: Provide a DS and a DNSKEY that match; verify the pair appears in the result.
- **No match**: Provide mismatched DS and DNSKEY; verify empty result.

## 12. `ZoneChecker` — initialization
- Mock `get_ds_data_from_dns`, `get_ns_list`, and the resolver to construct a `ZoneChecker` instance. Verify `result` dict is initialized with correct zone/recname/rectype and zeroed counters.
- Verify `--dsdata` path calls `get_ds_data_from_string` instead of `get_ds_data_from_dns`.

## 13. `ZoneChecker.check_record()` — dispatch logic
- **Unexpected rcode with `--nxdomain`**: Response has NOERROR when NXDOMAIN expected; verify error entry.
- **Unexpected rcode without `--nxdomain`**: Response has SERVFAIL; verify error entry.
- **Timeout from `get_response`**: Verify error entry.
- **Dispatch to `check_record_nxdomain`**: When `nxdomain=True` and rcode is NXDOMAIN.
- **Dispatch to `check_record_nodata`**: When `nodata=True` and rcode is NOERROR.
- **Dispatch to `check_record_noerror`**: Default path.

## 14. `ZoneChecker.check_record_noerror()`
- **Valid signed record**: Mock a response with RRset + valid RRSIG; mock `validate_all` to return a verified signer; verify `dnssec=True` and `server_count_good` incremented.
- **Missing record**: No RRset in answer; verify error.
- **Missing signature**: RRset present but no RRSIG; verify error.
- **Invalid signature**: `validate_all` returns no verified signers; verify error.

## 15. `ZoneChecker.return_status()` / `print_status()`
- **100% success**: Verify `success=True` and correct percentage string.
- **Partial success below threshold**: Verify `success=False`.
- **Custom `--percent_ok`**: 50% threshold with 1 of 2 good; verify `success=True`.
- **`--text` output**: Verify the abbreviated text format.
- **JSON output**: Verify valid JSON with expected keys.

## Test file structure

All tests go in `test_check_zone_dnssec.py` using `unittest` with `unittest.mock.patch` for mocking DNS calls. Tests are grouped into `TestCase` classes mirroring the sections above (e.g., `TestQueryType`, `TestProcessArguments`, `TestSendQuery`, `TestZoneChecker`, etc.).


## Running tests

```
python3 -m unittest test_check_zone_dnssec -v
```
