#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include "network_util.h"


int32_t net_if_status(const char *ifname)
{
	struct ifreq ifr;
	int sock = -1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0){
		fprintf(stderr, "create socket failed!\n");
		return -1;
	}

	strcpy(ifr.ifr_name, ifname);
	if(ioctl(sock, SIOCGIFFLAGS, &ifr) < 0){
		fprintf(stderr, "if %s ioctl SIOCGIFFLAGS failed!\n", ifname);
		close(sock);
		return -1;
	}
	close(sock);

	return (ifr.ifr_flags & IFF_UP);
}


int32_t net_if_mac(const char *ifname, uint8_t *mac)
{
	struct ifreq ifr;
	int sock = -1;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0){
		fprintf(stderr, "create socket failed!\n");
		return -1;
	}

	strcpy(ifr.ifr_name, ifname);
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
		fprintf(stderr, "if %s ioctl SIOCGIFHWADDR failed!\n", ifname);
		close(sock);
		return -1;
	}
	close(sock);

	for(int i = 0; i < 6; i++){
		mac[5-i] = ifr.ifr_hwaddr.sa_data[i];
	}
	return 0;
}
