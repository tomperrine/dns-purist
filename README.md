# dns-purist

The purpose of dns-purist is to find internal inconsistencies and
missing records in DNS servers and zone files.

It can also build target lists of all the IP addresses from all the
zones, for use with nmap or similar tools. When used to build target
lists, the internal consistency checks are disabled and will not be
performed.

It takes zones as either zone files already downloaded from servers,
or will do its own AXFR for a zone if there is no local copy already
present. Doing the AXFR requires that the host running dns-purist has
permission to actually do zone transfers for the indicated zones.

Arguments that end in ".zone" are assumed to be forward zone
files. Arguments that end in ".revzone" are assumed to be reverse zone
files.

All other arguments are assumed to be the names of zones that should
be AXFR'ed by dns-purist. Arguments ending in "in-addr.arpa" and
"ip6.arpa" are automatically detected as reverse zones, all others
will be processed as forward zones.

Dns-purist works by loading all the named zones into forward and
reverse internal databases and then looking for forward/reverse
inconsistencies in all the loaded information.

In general, dns-purist will not look beyond the loaded zones, except
optionally it can do individual DNS lookups for PTR records that were
not in its loaded zones. This is because many users are hosted by
their ISPs in ways that they cannot do zone transfers of the reverse
zones that contain their PTR records, but can do regular PTR lookups
for individual hosts.

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

   Is there a forward entry that matches the address listed in every
   PTR record that was loaded?
