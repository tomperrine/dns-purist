# dns-purist

The purpose of dns-purist is to find internal inconsistencies and
missing records in multiple DNS zones, especially cases where forward
and reverse records conflict or are incomplete.

It is not intended as a BIND zone file syntax checker,
"named-checkconf" is a better tool for that specific case.

DNS-purist takes multiple zones as either zone files already
downloaded from servers (via AXFR), or by doing its own AXFR for a
zone. Doing the AXFR requires that the host running dns-purist has
permission to actually do zone transfers for the indicated zones from
an appropriate DNS server.

Arguments that end in ".zone" are assumed to be forward zone
files. Arguments that end in ".revzone" are assumed to be reverse zone
files. For non-file zone arguments, those ending in "in-addr.arpa" and
"ip6.arpa" are automatically detected as reverse zones, all others
will be processed as forward zones.

All other arguments are assumed to be the names of zones that should
be AXFR'ed by dns-purist.

Dns-purist works by loading all the named zones into single forward
(A/AAAA/CNAME) and reverse (PTR) internal databases and then looking
for forward/reverse inconsistencies in all the loaded information.

SOA and other tests are on the to-do list.

In general, dns-purist will not look beyond the loaded zones, except
when requested ("--allow_dns_lookups") it can do individual DNS
lookups for PTR records that were not in its loaded zones. This is
because many users are hosted by their ISPs in ways that they cannot
do zone transfers of the reverse zones that contain their PTR records,
but can do regular PTR lookups for individual hosts against public DNS
servers.

Dns-purist handles the cases where there are multiple A records for a
single name. It also handles the case of multiple PTR records for a
single address. (Contrary to popular belief, there is no RFC that
prohibits multiple PTR records for the same address. This is a
cargo-cult DNS belief based on known-broken resolvers in the late
1980s.)

Dns-purist checks for the following issues:

Are there forward records in a reverse zone?

Are there reverse records in a forward zone?

For every entry in a forward zone

   Is there a PTR record that matches the address in every A/AAAA
   record that can be found in an also-loaded reverse zone?

   Using the argument "--allow_dns_lookups" will allow dns-purist to
   go beyond loaded zones and attempt DNS lookups for PTR records that
   were not loaded from a reverse zone.

For every entry in a reverse zone

   Is there a forward record that matches the address listed in every
   PTR record that was loaded?
