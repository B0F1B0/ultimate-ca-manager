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


# The same family again: an IPv4 address written as IPv6. The guard understood
# ::ffff: and, since the NAT64 pass, 64:ff9b::/96. `ipaddress` knows two more
# encodings and answers them in one attribute each.
@pytest.mark.parametrize("url", [
    "https://[2002:a9fe:a9fe::1]/",          # 6to4 of 169.254.169.254
    "https://[2002:c000:c0::1]/",            # 6to4 of Oracle's endpoint
    "https://[2001::ffff:0:5601:5601]/",     # Teredo carrying 169.254.169.254
    "https://[64:ff9b:1:a9fe:a9:fe00::]/",   # the local-use NAT64 prefix
    "https://169.254.42.42/",                # Scaleway
    "https://[fd00:42::42]/",                # Scaleway, IPv6
])
def test_guard_blocks_the_other_ways_of_writing_a_denied_address(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


@pytest.mark.parametrize("url", [
    "https://[2002:5db8:d822::1]/",   # 6to4 of a public address
    "https://[2002:a00:5::1]/",       # 6to4 of 10.0.0.5, private and allowed
])
def test_the_other_encodings_are_not_refused_wholesale(url):
    validate_url_not_cloud_metadata(url)   # must not raise


@pytest.mark.parametrize("encoded, prefix_length", [
    # RFC 6052 §2.4's own vectors, every one of them 192.0.2.33. Taken from
    # the document rather than built here: an encoding computed with the same
    # formula as the code under test agrees with it whether or not either is
    # right, which is exactly how a wrong decoding first passed.
    ("2001:db8:122:c000:2:2100::", 48),
    ("64:ff9b::192.0.2.33", 96),
])
def test_the_layout_matches_the_specification(encoded, prefix_length):
    import ipaddress

    from utils.ssrf_protection import _rfc6052_ipv4

    assert _rfc6052_ipv4(int(ipaddress.ip_address(encoded)),
                         prefix_length) == ipaddress.ip_address('192.0.2.33')


def test_a_reserved_byte_that_is_not_zero_is_not_an_embedding():
    """Bits 64 to 71 are reserved and must be zero. Reading them as part of
    the address is what let the metadata service through."""
    import ipaddress

    from utils.ssrf_protection import _nat64_embedded_ipv4

    assert _nat64_embedded_ipv4(
        ipaddress.ip_address('64:ff9b:1:a9fe:a9:fe00::')
    ) == ipaddress.ip_address('169.254.169.254')
    assert _nat64_embedded_ipv4(
        ipaddress.ip_address('64:ff9b:1:a9fe:a900:fe00::')) is None


@pytest.mark.parametrize("url", [
    # The deprecated IPv4-compatible form, ::a.b.c.d (RFC 4291 §2.5.5.1).
    "https://[::169.254.169.254]/",
    "https://[::127.0.0.1]/",
    # A Teredo address whose relay is the metadata service. The client half
    # is ordinary; the relay is a host this server would talk to just the
    # same, so both halves are judged.
    "https://[2001:0:a9fe:a9fe::a247:27dd]/",
])
def test_both_halves_and_the_older_spellings_are_judged(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


def test_the_unspecified_address_is_not_read_as_an_embedding():
    """`::` is in the compatible range and carries nothing; it is already
    refused as unspecified, and must not be read as 0.0.0.0 by accident."""
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata("https://[::]/")
