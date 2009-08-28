/*
 * Authors:
 * 	- Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 */

#include "esp_prot_common.h"
#include "debug.h"

/* returns index, if contained; else -1 */
int esp_prot_check_transform(int num_transforms, uint8_t *preferred_transforms,
		uint8_t transform)
{
	int err = -1, i;

	// check if local preferred transforms contain passed transform
	for (i = 0; i < num_transforms; i++)
	{
		if (preferred_transforms[i] == transform)
		{
			HIP_DEBUG("transform found in preferred transforms\n");

			err = i;
			goto out_err;
		}
	}

	HIP_DEBUG("transform NOT found in local preferred transforms\n");

  out_err:
	return err;
}
