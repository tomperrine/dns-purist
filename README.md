# dns-purist

The purpose of dns-purist is to find internal inconsistencies and
missing records in multiple DNS zones, especially cases where forward
and reverse records conflict or are incomplete. It also finds cases
where CNAME records point to records that do not exist.

It is not intended as a BIND zone file syntax checker,
"named-checkconf" is a better tool for that specific case.

Dns-purist works by loading all the named zones into three internal
databases: forward records (A/AAAA), reverse (PTR) and CNAME, and then
looking for forward/reverse inconsistencies and missing information in
all the loaded information.

DNS-purist takes multiple zones as either BIND-style zone files
already downloaded from servers (via AXFR), or by doing its own AXFR
for a zone. Doing the AXFR requires that the host running dns-purist
has permission to actually do zone transfers for the indicated zones
from an appropriate DNS server.

During loading, all zones are searched for all record types. This will
catch the case where PTR records are located in a forward zone, and
A/AAAA/CNAME records are included in a reverse zone, for example.

DNS-purist reconizes and processes file arguments based in their
suffix. It recognizes files of forward zones, reverse zones and
external zones.

Arguments that end in ".zone" are assumed to be forward zone
files. Arguments that end in ".revzone" are assumed to be reverse zone
files. Arguments that end in "extzone" are assumed to indicate files
containing "external zones". External zones are lists of DNS zones (as
opposed to actual zone-format files) for which pointers to them (such
as CNAMES) should just be assumed to be correct. Think of them as a
way to pretend that the necessary DNS lookup succeeded. These are
useful when you have CNAMES out to other providers, such as AWS or
Google and you don't want to check those entries.

All other arguments are assumed to be the names of zones that should
be AXFR'ed by dns-purist. For non-file zone arguments, those ending in
"in-addr.arpa" and "ip6.arpa" are automatically detected as reverse
zones, all others will be processed as forward zones.

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

DNS-purist can also create useful lists, such as:

* (--dump_ips) List all IP addresses contained in all loaded forward
  and reverse zones. This is useful for comparing with "live IP"
  reports from security systems such as Security Center. IP addresses
  in DNS and not live could be crufty DNS. Live IPs that are not in
  DNS could be a security issue.

* (--dump_names) List all DNS names contained in all loaded forward
  and reverse zones. This is useful for identifying all zones that may
  be present in your DNS, even if not defined in your DNS. This
  includes CNAME (names and targets) and PTR records to forward zones
  that you don't control. This helps identify external dependencies
  you may have on the DNS or systems outside your control.

* (--dump_records) List all name/IP pairs gathered from all zones,
  forward and reverse. Dumped as "name: IP", whether loaded from A/AAAA
  or PTR records.

* (--csv_output) Append and deliver a CSV summary of the report. First
  line is data names for each field (A records loaded, etc.)  Second
  line is actual numeric data. Suitable for pasting into Excel or
  feeding into GnuPlot.
