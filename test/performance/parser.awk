#!/usr/bin/awk -f

/type/ {
	pos=index($1,"=");
	type=substr($1,pos+1,2);
	if (state == 1) {
		print "ERROR";
		exit 2;
	}
	state=1;
	cnt=0;prob=0;varce=0;mdist=0;sumz=0
	delete table;

}

/sum/	{
	if (state != 1) {
		print "ERROR!";
		exit 1;
	}
	state=0; avg=(sumz/cnt); prob=(1/cnt); varce=0

	for (i in table) {
		varce += (table[i] - avg)^2*prob;
	}
	mdist=sqrt(varce);
	print type" :  "sumz" "(sumz/cnt)" "varce" "mdist
}

{
	if (state == 1) {
		table[$1] = $2;
		cnt++;
		sumz += $2;
	}
}
