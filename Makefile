

all-tests: 



test-help:
	./dns-purist.py

# test with dummy data
test-dummy
	./dns-purist.py TEST-DATA/bluehades.com.zone TEST-DATA/13.85.216.in-addr.arpa.revzone

# all the data/output
test-all:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone

# show the domains loading
test-top:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | head -20

# show some AAAA records
test-aaaa:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep "AAAA" | head -20

# show missing PTRs for AAAA records
test-aaaa-ptr:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep ngn-filer

# show a BADREC
test-bad-rec:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep BADREC | head -20


# show some NOPTR errors
test-noptr:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep NOPTR | head -20

# show some NO_FORWARD errors
test-no-forward:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep NO_FORWARD | head -20




