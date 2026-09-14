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
    ("2001:db8:c000:221::", 32),
    ("2001:db8:1c0:2:21::", 40),
    ("2001:db8:122:c000:2:2100::", 48),
    ("2001:db8:122:3c0:0:221::", 56),
    ("2001:db8:122:344:c0:2:2100:0", 64),
    ("2001:db8:122:344::192.0.2.33", 96),
])
def test_the_layout_matches_the_specification(encoded, prefix_length):
    import ipaddress

    from utils.ssrf_protection import _rfc6052_ipv4

    assert _rfc6052_ipv4(int(ipaddress.ip_address(encoded)),
                         prefix_length) == ipaddress.ip_address('192.0.2.33')


def test_a_reserved_byte_that_is_not_zero_is_still_an_embedding():
    """Bits 64 to 71 are the reserved `u` octet, and refusing to read an
    address whose `u` is not zero was a way of not looking.

    Section 2.2 tells a sender to zero them. Section 2.3 tells a receiver to
    remove the octet and read on, with no validation, so a conforming
    translator forwards the packet either way. Declining to decode meant the
    address fell back on its bare IPv6 judgement, which cannot see through a
    translation prefix at all, and one byte an attacker controls turned the
    whole check off.
    """
    import ipaddress

    from utils.ssrf_protection import _rfc6052_ipv4

    # Same address twice, `u` zero then `u` set. Bits 72 to 103 are
    # a9 fe a9 fe either way.
    for spelling in ('64:ff9b:1:1:a9:fea9:fe00:0',
                     '64:ff9b:1:1:ffa9:fea9:fe00:0',
                     '64:ff9b:1:1:80a9:fea9:fe00:0'):
        assert _rfc6052_ipv4(
            int(ipaddress.ip_address(spelling)), 64
        ) == ipaddress.ip_address('169.254.169.254'), spelling


@pytest.mark.parametrize("url", [
    # The byte is the attacker's to set, and setting it used to turn every
    # reading off and let the address through.
    "https://[64:ff9b:1:1:ffa9:fea9:fe00:0]/",
    "https://[64:ff9b:1:1:80a9:fea9:fe00:0]/",
    "https://[64:ff9b:1:a9fe:ffa9:fe00:1:1]/",
])
def test_the_reserved_byte_does_not_switch_the_guard_off(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


def test_a_ninety_six_reading_ignores_those_bits_as_it_always_did():
    """For a /96 the bits belong to the operator's prefix, not to the `u`
    field, so a reading there has never had anything to check."""
    import ipaddress

    from utils.ssrf_protection import _rfc6052_ipv4

    # One of RFC 8215 section 5's own example prefixes, carrying Alibaba's
    # metadata endpoint. Extending the reserved-byte rule to /96 would have
    # let this through.
    assert _rfc6052_ipv4(
        int(ipaddress.ip_address('64:ff9b:1:fffe:ff00:0:6464:64c8')), 96
    ) == ipaddress.ip_address('100.100.100.200')


@pytest.mark.parametrize("url", [
    # The deprecated IPv4-compatible form, ::a.b.c.d (RFC 4291 §2.5.5.1).
    "https://[::169.254.169.254]/",
    "https://[::127.0.0.1]/",
    # A Teredo address whose *server* is the metadata service: bits 32 to 63
    # hold the server's IPv4 address (RFC 4380 section 4), not a relay's. The
    # client half here is ordinary. Both are named in the same address and
    # both are read.
    "https://[2001:0:a9fe:a9fe::a247:27dd]/",
])
def test_both_halves_and_the_older_spellings_are_judged(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


@pytest.mark.parametrize("url", [
    # RFC 8215 picked a /48 for the local-use prefix because it has to be
    # shorter than any translation prefix cut out of it, so the operator's
    # real prefix is one of several and the address alone does not say which.
    # Read with the container's own /48 layout, as this first did, the
    # metadata service came back as 0.1.0.0 and went through.
    "https://[64:ff9b:1:1::a9fe:a9fe]/",        # a /96 instance
    "https://[64:ff9b:1:1:a9:fea9:fe00:0]/",    # a /64 instance
    "https://[64:ff9b:1:a9fe:a9:fe00::]/",      # the container used directly
    # ISATAP (RFC 5214 section 6.1), both interface identifiers.
    "https://[fe80::5efe:169.254.169.254]/",
    "https://[2001:db8::200:5efe:169.254.169.254]/",
])
def test_no_layout_of_the_local_use_prefix_hides_the_metadata_service(url):
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata(url)


@pytest.mark.parametrize("url", [
    # The mirror image of the test above, and the reason the speculative
    # readings are judged on metadata alone. Every address behind a /96
    # instance reads as 0.0.0.0 under the container's /48 layout, so judging
    # those readings on loopback and unspecified cut off ordinary traffic:
    # each of these is a perfectly good host.
    "https://[64:ff9b:1::5db8:d822]/",          # 93.184.216.34, public
    "https://[64:ff9b:1::a00:5]/",              # 10.0.0.5, on the LAN
    "https://[64:ff9b:1::101:101]/",            # 1.1.1.1
    "https://[64:ff9b:1:7f00::1]/",             # a 7f00: subnet, not loopback
    # Instances from RFC 8215 section 5, which do not read as 0.0.0.0 under
    # the container's layout the way the empty instance does.
    "https://[64:ff9b:1:fffe::5db8:d822]/",
    "https://[64:ff9b:1:abcd:0:5431:5db8:d822]/"
])
def test_an_ordinary_host_behind_a_translation_prefix_is_reachable(url):
    validate_url_not_cloud_metadata(url)


def test_the_prefixs_own_base_address_carries_nothing():
    """When every layout agrees on 0.0.0.0 it is not a misreading: the
    address is the prefix itself and carries no host."""
    with pytest.raises(ValueError):
        validate_url_not_cloud_metadata("https://[64:ff9b:1::]/")
