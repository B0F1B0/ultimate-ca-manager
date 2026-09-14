"""Regression tests for the SSRF cloud-metadata/loopback guard (utils/ssrf_protection).

The guard must not be evadable via:
  * the unspecified address (0.0.0.0 / ::), which routes to loopback on most OSes; or
  * an IPv4-mapped IPv6 encoding of a denied IPv4 target
    (e.g. ::ffff:169.254.169.254 for the cloud metadata service).
It must keep ALLOWING public and RFC1918-private literal IPs — this narrow guard permits
those by design (UCM is commonly pointed at internal infra).
"""
import pytest
from utils.ssrf_protection import validate_url_not_cloud_metadata


@pytest.mark.parametrize("url", [
    "https://0.0.0.0/",                    # unspecified -> loopback
    "https://[::]/",                       # unspecified -> loopback
    "https://127.0.0.1/",                  # loopback
    "https://[::ffff:127.0.0.1]/",         # IPv4-mapped loopback
    "https://169.254.169.254/",            # AWS/Azure/GCP metadata
    "https://[::ffff:169.254.169.254]/",   # metadata via IPv4-mapped IPv6
    "https://100.100.100.200/",            # Alibaba metadata
])
def test_guard_blocks_loopback_and_metadata(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


@pytest.mark.parametrize("url", [
    "https://93.184.216.34/",   # public literal IP
    "https://10.0.0.5/",        # RFC1918 private — allowed by this narrow guard by design
    "https://192.168.1.10/",
])
def test_guard_allows_public_and_private_literals(url):
    validate_url_not_cloud_metadata(url)   # must not raise


# Two metadata endpoints the deny-list did not know, found while reviewing the
# OPNsense import. They are in the shared guard, so they were reachable from
# every caller: ACME, webhooks, SSO, the update check, the import.
@pytest.mark.parametrize("url", [
    # Oracle Cloud's instance metadata endpoint. The guard blocks metadata and
    # loopback only, on purpose, because UCM is pointed at private addresses
    # all the time -- so being inside a private range does not refuse it.
    "https://192.0.0.192/",
    "https://[::ffff:192.0.0.192]/",
    # The same address as 169.254.169.254, written through the well-known
    # NAT64 prefix: the last 32 bits of 64:ff9b::a9fe:a9fe are exactly
    # 169.254.169.254, and a NAT64 gateway translates it back. The existing
    # collapse only understands the ::ffff: form, and this address is neither
    # loopback nor private, so it went through.
    "https://[64:ff9b::a9fe:a9fe]/",
    "https://[64:ff9b::6464:64c8]/",       # Alibaba, same way
    "https://[64:ff9b::a9fe:aa02]/",       # AWS ECS task credentials, same way
])
def test_guard_blocks_the_endpoints_it_had_not_heard_of(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


@pytest.mark.parametrize("url", [
    # Inside the NAT64 prefix but carrying an ordinary address: refusing the
    # whole prefix would refuse legitimate traffic on an IPv6-only network.
    "https://[64:ff9b::5db8:d822]/",       # 93.184.216.34
    "https://[64:ff9b::a00:5]/",           # 10.0.0.5, private and allowed
])
def test_the_nat64_prefix_is_not_refused_wholesale(url):
    validate_url_not_cloud_metadata(url)   # must not raise
