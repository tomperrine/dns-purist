#!/bin/bash

# take dns-purist error messages like this
#CNAME_ERR_NOT_RESOLVED: CNAME  zi-cacti.989studios.com ->  zi-monitor02. which does not resolve
#CNAME_ERR_NOT_RESOLVED: CNAME  abpgsql01.scea.com ->  swan001.scea.com. which does not resolve
#CNAME_ERR_NOT_RESOLVED: CNAME  con-admin.scea.com ->  san-10075-dca-asa-vpn01-admin.scea.com. which does not resolve
#
# and make csv that looks like this:
#header-cnamerecord,fqdn*,_new_fqdn,canonical_name,comment,disabled,ttl,view
#cnamerecord,zi-cacti.989studios.com,,zi-monitor02,,,,
#NOTE!! the fqdn* cannot be anchored, eg cannot end in '.' - the cname can be anchored
#
# recommended usage:
# $grep "CNAME_ERR" ERROR-REPORT | grep some-subset-of-zone-errors > errors-ill-handle-today
# $split errors-ill-handle-tday -l 100
#   then for each split file, create and review a CSV
# $./cname-to-csv.sh < a-split-file > a-split-file.csv
#
#
echo "header-cnamerecord,fqdn*,_new_fqdn,canonical_name,comment,disabled,ttl,view"

awk '{printf "cnamerecord,%s,,%s,,,,\n", $3,$5}'
