

all-tests: 



# show the domain loading
test-all:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone


test-top:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | head -20


test-aaaa:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep "AAAA" | head -20

test-aaaa-ptr:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep ngn-filer


test-bad-rec:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep BADREC | head -20

test-noptr:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep NOPTR | head -20

test-no-forward:	dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone
	./dns-purist.py TEST-DATA/scea.com.zone TEST-DATA/10.in-addr.arpa.revzone | grep NO_FORWARD | head -20




