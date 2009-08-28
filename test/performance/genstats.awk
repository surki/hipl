#!/usr/bin/awk -f

/type=17/ {
	stl[st++] = $10;
	next
}

/type=18/ {
	etl[et++] = $10;
	next
}

/type=19/ {
	ntl[nt++] = $10;
	next
}

/type=20/ {
	twl[tw++] = $10;
	next
}

/type=21/ {
	tol[to++] = $10;
	next
}

/type=22/ {
	ttl[tt++] = $10;
	next
}

/type=27/ {
	tsl[ts++] = $10;
	next
}

END {
	cnt=0;sum=0;avg=0
	print "type=17: num="st
	for (i in stl) {
		cnt++
		sum+=stl[i]
		print "         "cnt"   "stl[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""

	cnt=0;sum=0;avg=0
	print "type=18: num="et
	for (i in stl) {
		cnt++
		sum+=etl[i]
		print "         "cnt"   "etl[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""

	cnt=0;sum=0;avg=0
	print "type=19: num="nt
	for (i in ntl) {
		cnt++
		sum+=ntl[i]
		print "         "cnt"   "ntl[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""

	cnt=0;sum=0;avg=0
	print "type=20: num="tw
	for (i in twl) {
		cnt++
		sum+=twl[i]
		print "         "cnt"   "twl[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""

	cnt=0;sum=0;avg=0
	print "type=21: num="to
	for (i in tol) {
		cnt++
		sum+=tol[i]
		print "         "cnt"   "tol[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""

	cnt=0;sum=0;avg=0
	print "type=22: num="tt
	for (i in stl) {
		cnt++
		sum+=ttl[i]
		print "         "cnt"   "ttl[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""

	cnt=0;sum=0;avg=0
	print "type=27: num="ts
	for (i in tsl) {
		cnt++
		sum+=tsl[i]
		print "         "cnt"   "tsl[i]
	}
	avg=sum/cnt
	print "         sum: "sum" avg: "avg
	print ""
}	
