#ifndef _GATT_SERVER_H_
#define _GATT_SERVER_H_

#include <stdint.h>
#include "lib/l2cap.h"

int gatt_server_init(bdaddr_t *src, int sec, const char *name);
void gatt_update_bwifi_status(const char *str, int len);
void gatt_server_set_info(const char *ssid, const char *status);
void gatt_recv_bwifi_ssid_callback(char *str, int *len) __attribute__((weak));


#endif
