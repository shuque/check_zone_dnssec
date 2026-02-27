# check_zone_dnssec — Code Review

*Version 1.0.9, commit b02ba4c234f98487552af9d1361716d4b59a7d80*

**Purpose:** A CLI tool that queries every authoritative nameserver for a DNS zone and validates that DNSSEC-signed responses are correct. It ensures *all* servers for a zone return properly signed answers.

## Workflow

1. **Obtain the DS record** — Either fetched and authenticated from the DNS (root down) via the `reslib` library, or provided manually via `--dsdata` for pre-delegation testing.
2. **Discover nameservers** — Queries the NS RRset for the zone (unless `--nonsquery`), resolves each NS name to addresses, and optionally includes additional names/IPs.
3. **For each nameserver address:**
   - Queries the DNSKEY RRset, verifies the self-signature, and matches the DS to a KSK.
   - Queries the target record (`recname`/`rectype`) and validates the RRSIG.
   - For `--nxdomain` or `--nodata`, authenticates the denial-of-existence response instead.
4. **Reports results** — JSON by default (or abbreviated text with `--text`), including per-server pass/fail and an overall success percentage.

## Key components in `check_zone_dnssec.py`

| Component | Lines | Role |
|---|---|---|
| `process_arguments()` | 79–143 | argparse setup with all CLI options |
| `send_query()` | 146–185 | UDP query with retry + TCP fallback on truncation |
| `get_resolver()` | 188–199 | Configures a `dns.resolver.Resolver` |
| `get_ds_data_from_dns()` | 202–214 | Fetches DS via `reslib` recursive resolver |
| `get_ds_data_from_string()` | 217–230 | Parses DS from CLI-provided rdata string |
| `get_ns_list()` | 233–239 | Queries NS RRset for the zone |
| `get_addresses()` | 267–275 | Resolves NS names to A/AAAA addresses |
| `get_response()` | 278–298 | Sends a DNSSEC-enabled query to a single address |
| `ZoneChecker` class | 323–567 | Core logic — orchestrates checks and collects results |
| `ZoneChecker.check_dnskey()` | 419–465 | DNSKEY validation + DS matching |
| `ZoneChecker.check_record_noerror()` | 499–528 | Validates positive response RRSIGs |
| `ZoneChecker.check_record_nxdomain()` | 530–538 | Validates signed NXDOMAIN (NSEC/NSEC3) |
| `ZoneChecker.check_record_nodata()` | 540–548 | Validates signed NODATA responses |
| `__main__` block | 569–581 | Entry point |

## Dependencies

- **dnspython** (`>=2.6.0`) — DNS protocol library
- **cryptography** (`>=3.0`) — Crypto primitives for DNSSEC verification
- **resolve** (author's own `reslib`) — Recursive resolution, DNSSEC authentication, key caching

## Packaging

- Uses `pyproject.toml` with setuptools; version is read dynamically from `__version__` in the script.
- Installed as a script (`script-files`), not a console entry point.

## Tests

- `tests.py` — A basic functional test that checks `example.com/SOA` against live DNS.
- `test_check_zone_dnssec.py` — An untracked test file also present in the repo.

## Design notes

- **Exit code**: returns 0 on success, 1 on failure — suitable for use in CI/monitoring pipelines.
- **`--percent_ok`**: allows partial success (e.g., 90% of servers passing is acceptable), useful for degraded environments.
- **NSID support**: can record the NSID EDNS option from each server for operational debugging.
