/*
 * load.c
 *
 *  Created on: Dec 15, 2008
 *      Author: chilli
 */

#include <inttypes.h>

int main(int argc, char ** argv)
{
	uint32_t i = 0;

	while (1)
	{
		i++;

		if (i > 4000000000)
		{
			i = 0;
		}
	}
}
