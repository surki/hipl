#!/usr/bin/awk -f

BEGIN { 
	num=0; sum=0; first=0; last=0; mindiff = 10000000; maxdiff = 0;
	lastsec=0;
}

{
	if (first == 0) {
		first = $2/1000 + $1*1000000;
		last = 0;
		lastsec = $1;
		next;
	}

        last = $2/1000 + $1*1000000;

	if (lastsec > $1) {
#		/* wrapped */
		diff = last + 60*1000000 - first;
	} else {
		diff = last - first;
	}

	first = last;
	lastsec = $1;
	sum += diff;
	table[cnt] = diff;
	cnt ++;

	if (diff > maxdiff) {
		maxdiff = diff
		next;
	}

	if (diff < mindiff) {
		mindiff = diff;
		next;
	}
}	

END {
	avg = sum/cnt;
	prob = 1/cnt;
	variance = 0;
# variance
	for (i in table) {
		variance += (table[i] - avg)^2*prob;
	}

	mdist = sqrt(variance);

	printf("%d samples, min/avg/max: %d/%d/%d\n",cnt,mindiff,sum/cnt,maxdiff);

# confidence interval

	low = avg - mdist*1.96;
	high = avg + mdist*1.96;

	newsum = 0; mindiff = 100000000; maxdiff = 0;
	for (i in table) {
		if (table[i] < low) {
			lowreject++;
			cnt--;
			continue;
		} else if (table[i] > high) {
			highreject++;
			cnt--;
			continue;
		}
		newsum += table[i];

	        if (table[i] > maxdiff) {
       			maxdiff = table[i];
        	}

        	if (table[i] < mindiff) {
                	mindiff = table[i];
        	}

	}

	printf("Confidence interval 95%. Low/High bound: %d/%d\n",low,high);
	printf("Dropped at low bound %d samples, at upper bound %d samples\n",lowreject,highreject);
	printf("%d samples qualified, min/avg/max: %d/%d/%d\n",cnt,mindiff,newsum/cnt,maxdiff);
	
}
