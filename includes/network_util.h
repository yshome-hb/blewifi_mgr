#ifndef _NETWORK_UTIL_H_
#define _NETWORK_UTIL_H_


int32_t net_if_status(const char *ifname);
int32_t net_if_mac(const char *ifname, uint8_t *mac);


#endif
