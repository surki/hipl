#include "hipsetup.h"

extern char *optarg;
extern int optind, opterr, optopt;

const char *usage_str = "hipsetup -h for help\n"
	"hipsetup -m            to install hipmod module\n"
	"hipsetup -i peer_name  for Base Exchange Initiator\n"
	"hipsetup -r            for Base Exchange Responder\n"
	"hipsetup -s            for Base Exchange SSH\n"
	"hipsetup -b            for BOS (in initiator)\n"
	"\n"
	;

void usage_f()
{
	printf("Usage:\n%s\n", usage_str);
}

int main(int argc, char *argv[])
{
	int c, err = 0;
	struct hip_common *msg;
	char *peer_name, buf[20];
	extern char *optarg;
	
	if(argc < 2){
		printf("No args specified \n");
		usage_f();
		return 0;
	}

	msg = malloc(HIP_MAX_PACKET);
	if (!msg) {
		HIP_ERROR("malloc failed\n");
		err = -1;
		goto out;
	}
	hip_msg_init(msg);
	
	while ((c = getopt(argc, argv, ":hmrsdbi:")) != -1)
	{
		switch (c){
		case 'h':
			usage_f();
			break;
		case 'm':
			/* Install the modules */
			err = main_install(msg);
			if (err)
				goto out_err;

#if 0
			if (hip_get_msg_type(msg) == 0)
				goto out_err;

			err = hip_send_daemon_info(msg, 0, 0);
			if (err) {
				HIP_ERROR("sending msg failed\n");
				goto out_err;
			}
#endif
			break;
		case 'd':
			/* HIPL_DIR */
			/* I don't know whether this is needed anymore ...*/
			break;
		case 'i':
			/* Base Exchange Initiator */
			printf("Initiator mode\n");
			hip_set_logtype(LOGTYPE_STDERR);
			hip_set_logfmt(LOGFMT_SHORT);
			if (optarg[0] == '0')
				peer_name = NULL;
			else
				peer_name = optarg;
			sprintf(buf, "%d",DEFAULT_PORT);
			main_client_gai(SOCK_STREAM, peer_name, buf, AI_HIP);
			break;
		case 'r':
			printf("Responder mode\n");
			/* Base Exchange Responder */
			main_server(SOCK_STREAM, DEFAULT_PORT);
			break;
		case 's':
			/* Base Exchange SSH  */
			printf("Initiator-responder mode\n");
			break;
		case 'b':
			/* BOS  */
			printf("BOS\n");
#if 0
			HIP_IFEL(hip_conf_handle_bos(msg, 0, (const char **) NULL, 0), -1, "Failed to handle BOS\n");

			/* hipconf new hi does not involve any messages to kernel */
			HIP_IFE((hip_get_msg_type(msg)), -1);

			HIP_IFEL(hip_send_daemon_info(msg), -1, "Sending msg failed\n");
#endif
			err = hip_conf_handle_bos(msg, 0, (const char **) NULL, 0, 0);
			if (err) {
				HIP_ERROR("failed to handle msg\n");
				goto out_err;
			}
			
			if (hip_get_msg_type(msg) == 0)
				goto out_err;
			
			err = hip_send_recv_daemon_info(msg, 0, 0);
			if (err) {
				HIP_ERROR("sending msg failed\n");
				goto out_err;
			}
			break;
		case ':':
			printf("Missing argument %c\n", optopt);
			usage_f();
			return(0);
		case '?':
			printf("Unknown option %c\n", optopt);
			usage_f();
			return(0);
		}
	}

out_err:
	free(msg);
out:
	return err;
}
