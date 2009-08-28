/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "gui_interface.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Ask GUI, if new hit should be accepted and added.

	@param hit Pointer to hit that should be accepted.
	@return 0 if accept, -1 on other cases.
*/
int check_hit(HIT_Remote *hit, int inout)
{
	/* Variables. */
	HIT_Remote *fhit;
	int err = 0;
	char str[128];

	fhit = hit_db_find(NULL, &hit->hit);

	if (fhit)
	{
		HIP_DEBUG("Found HIT from database.\n");

		if (fhit->g->accept == HIT_ACCEPT) 
			err = 1; /*Changing this to 1 here for letting the callee
						know that hit already exist and is accepted
						this is again changed to zero in callee for this
						case.*/
		else 
			err = -1;
		memcpy(hit, fhit, sizeof(HIT_Remote));

		goto out_err;
	}
	else
	{
		HIP_DEBUG("Did not find HIT from database.\n");
	}

	HIP_DEBUG("Calling GUI for accepting new HIT.\n");
	err = gui_hit_remote_ask(hit, inout);

	/* Add hit info to database, if answer was yes. */
	if (err == 0)
	{
		HIP_DEBUG("Adding new remote HIT to database with type %s.\n",
		          hit->g->accept == HIT_ACCEPT ? "accept" : "deny");
		hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->g, 0);
		if (hit->g->accept == HIT_ACCEPT) err = 0;
		else err = -1;
	}
	else
	{
		HIP_DEBUG("User dropped new HIT, not adding to database, denie the packet.\n");
		print_hit_to_buffer(str, &hit->hit);
		hit->g = hit_db_find_rgroup(" deny");
		if (hit->g) hit_db_add(str, &hit->hit, "none", "0", hit->g, 0);
		err = -1;
	}

out_err:
	/* Return. */
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

