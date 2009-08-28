
/** @fileThis file defines TCP timeout parameters setting for the Host Identity
 * Protocol (HIP) in order to overcome the application time out when handover taking 
 * long time.
 *      
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#include "tcptimeout.h"


void sysctl_set_command(char const *sysctl_with_options, char const *paras, 
                               char const *value, char *command_string) {

	// char tcp_timeout_tuning_command[80];
	char *equal_sign = "=";
	
	strcpy(command_string, sysctl_with_options);
	strcat(command_string, paras);
	strcat(command_string, equal_sign);
	strcat(command_string, value);
}




/* set tcp timeout parameters values */
int set_new_tcptimeout_parameters_value(void) {
	int erro = 0;
	char low_start_after_idle_command[80];
	char tcp_retries_1_command[80];
	char tcp_retries_2_command[80]; 

        /*set commamd "sysctl -w net.ipv4.tcp_slow_start_after_idle 0*/
	
	sysctl_set_command(SYSCTL_SET_COMMAND , TCP_SLOW_START_AFTER_IDLE_STRING,        
			   TCP_SLOW_START_AFTER_IDLE_NEW, &low_start_after_idle_command);

        /*set command "sysctl -w net.ipv4.tcp_retries1 50*/
	
	sysctl_set_command(SYSCTL_SET_COMMAND , TCP_RETRIES_1_STRING,
                                TCP_RETRIES_1_NEW, &tcp_retries_1_command);
	
        /*set command "sysctl -w net.ipv4.tcp_retries2 65 */
	sysctl_set_command(SYSCTL_SET_COMMAND , TCP_RETRIES_2_STRING,
                                TCP_RETRIES_2_NEW, &tcp_retries_2_command);

	if ((erro = system(low_start_after_idle_command)) != 0)
	{
		goto out_err;
	}

	if ((erro = system(tcp_retries_1_command)) != 0)
        {
		goto out_err;
	}

	if ((erro = system(tcp_retries_2_command)) != 0)
        {
		goto out_err;
	}

out_err:
	return erro;

}


/*reset all tcp timeout parameters related to  */
int reset_default_tcptimeout_parameters_value(void) {
	int erro = 0;
	char low_start_after_idle_command[80];
	char tcp_retries_1_command[80];
	char tcp_retries_2_command[80];

        /* set commamd "sysctl -w net.ipv4.tcp_slow_start_after_idle 1*/


	sysctl_set_command(SYSCTL_SET_COMMAND , TCP_SLOW_START_AFTER_IDLE_STRING,
			   TCP_SLOW_START_AFTER_IDLE_DEFAULT, &low_start_after_idle_command);


        /* set command "sysctl -w net.ipv4.tcp_retries1 3*/

	sysctl_set_command(SYSCTL_SET_COMMAND , TCP_RETRIES_1_STRING,
			   TCP_RETRIES_1_DEFAULT, &tcp_retries_1_command);


        /*set command "sysctl -w net.ipv4.tcp_retries2 15 */

	sysctl_set_command(SYSCTL_SET_COMMAND , TCP_RETRIES_2_STRING,
			   TCP_RETRIES_2_DEFAULT, &tcp_retries_2_command);


        if ((erro = system(low_start_after_idle_command)) != 0)
        {
		goto out_err;
	}

	if ((erro = system(tcp_retries_1_command)) != 0)
        {
		goto out_err;
	}

	if ((erro = system(tcp_retries_2_command)) != 0)
        {
		goto out_err;
	}

out_err:
        return erro;

}

