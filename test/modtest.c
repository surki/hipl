/*
*  Modtest
*
* Description: Just a simple program to test the 
*              socket handler functions
* 
*
* Authors: 
*   - Tobias Heer <heer@tobobox.de> 2006
* Licence: GNU/GPL
*
*/
#include <sys/socket.h>
#include <stdio.h>

#define PF_HIP 32

int main(int argc, char **argv)
{
	int sock;
	sock = socket(PF_HIP, SOCK_STREAM, 0);
	printf("See dmesg for socket jandler output\n");
	
}
